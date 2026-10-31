// SPDX-License-Identifier: AGPL-3.0-or-later
/// Dash Core v23.1.9 port, item A — the transaction version/type rules.
///
///   * 07494dd62: after DIP3, a tx whose int16 nVersion is negative is
///     consensus-invalid (ContextualCheckTransaction, bad-txns-version). The
///     mempool must not admit one and the template selector must never serve
///     one (the chain-fold side lives in test_dash_replay_fold.cpp and
///     test_dash_mn_state.cpp).
///   * The extra-payload gate parity: dashd reads vExtraPayload iff
///     IsSpecialTxVersion() (int16 nVersion >= 3) && nType != 0. c2pool gated
///     on nVersion == 3, which misparses a low-16 in [4, 0x7FFF] tx with a
///     type. Pinned by a differential sweep against dashcore's own codec (the
///     vendored dashscript CMutableTransaction, via the dash_scriptcheck KAT
///     probe).

#include <gtest/gtest.h>

#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/tx_version_rules.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/vendor/dashscript/c2pool_scriptcheck.h>

#include <core/coin/utxo_view_cache.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

using dash::coin::Mempool;
using dash::coin::MutableTransaction;
using dash::coin::dash_txid;

uint256 h256(uint8_t tag)
{
    uint256 h;
    for (int i = 0; i < 32; ++i) h.data()[i] = static_cast<uint8_t>(tag + i);
    return h;
}

void put_u32(std::vector<uint8_t>& b, uint32_t v)
{
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

/// One-input / one-output tx body for a raw 32-bit version field, built by
/// hand (no codec involved): version | vin | vout | locktime.
std::vector<uint8_t> raw_tx(uint32_t version_field)
{
    std::vector<uint8_t> b;
    put_u32(b, version_field);
    b.push_back(0x01);                                   // vin count
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<uint8_t>(0x11 + i));
    put_u32(b, 7);                                       // prevout n
    b.push_back(0x00);                                   // scriptSig len
    put_u32(b, 0xFFFFFFFFu);                             // sequence
    b.push_back(0x01);                                   // vout count
    for (int i = 0; i < 8; ++i) b.push_back(i == 0 ? 0x40 : 0x00);   // value 64
    b.push_back(0x01); b.push_back(0x51);                // script OP_TRUE
    put_u32(b, 0x01020304u);                             // locktime
    return b;
}

MutableTransaction decode(const std::vector<uint8_t>& bytes, size_t& consumed)
{
    ::PackStream s(bytes);
    MutableTransaction tx;
    s >> tx;
    consumed = bytes.size() - s.cursor_size();
    return tx;
}

/// A fee-paying tx spending a coin minted into `utxo`.
MutableTransaction priced_spend(::core::coin::UTXOViewCache& utxo, uint8_t tag,
                                int32_t version, uint16_t type = 0)
{
    const uint256 prev = h256(tag);
    utxo.add_coin(::core::coin::Outpoint(prev, 0),
                  ::core::coin::Coin(100'000, {}, 1, false));
    MutableTransaction tx;
    tx.version = version;
    tx.type    = type;
    bitcoin_family::coin::TxIn in;
    in.prevout.hash = prev; in.prevout.index = 0; in.sequence = 0xFFFFFFFFu;
    tx.vin.push_back(in);
    bitcoin_family::coin::TxOut out;
    out.value = 90'000;
    out.scriptPubKey.m_data = {0x76, 0xa9, 0x14, tag, 0x88, 0xac};
    tx.vout.push_back(out);
    tx.locktime = tag;
    return tx;
}

} // namespace

// ── The rule itself (tx_version_rules.hpp), dashd's check order ──────────
namespace {
std::string why(int32_t version, uint16_t type, bool coinbase = false)
{
    MutableTransaction t;
    t.version = version;
    t.type    = type;
    const auto r = dash::coin::contextual_tx_check(t, coinbase);
    return r ? std::string(*r) : std::string("ok");
}
} // namespace

TEST(DashTxVersion, ContextualCheckMatchesDashdPostDip3)
{
    EXPECT_EQ(why(1, 0), "ok");
    EXPECT_EQ(why(0xFFFF, 0), "bad-txns-version");          // nVersion -1
    EXPECT_EQ(why(0x8000, 0), "bad-txns-version");          // nVersion -32768
    EXPECT_EQ(why(0x7FFF, 9), "ok");                        // special, known type
    EXPECT_EQ(why(3, 10), "bad-txns-type");                 // unknown special type
    EXPECT_EQ(why(2, 1), "bad-txns-type");                  // typed, not special
    EXPECT_EQ(why(3, 0, /*coinbase=*/true), "bad-txns-cb-type");
    EXPECT_EQ(why(3, 5, /*coinbase=*/true), "ok");
    // A negative version is not special, so a type on it is bad-txns-type
    // first (dashd checks the type branch before the sign).
    EXPECT_EQ(why(0xFFFF, 5), "bad-txns-type");
}

// A1 (GREEN guard): the 16+16 split never sign-extends — a negative nVersion
// parses and re-packs to the miner's exact bytes, and the txid is SHA256d of
// those bytes.
TEST(DashTxVersion, NegativeVersionRoundTripsByteExact)
{
    for (uint32_t field : {0x0000FFFFu, 0xFFFFFFFFu, 0x00008000u, 0x0005FFFFu}) {
        const auto bytes = raw_tx(field);
        size_t consumed = 0;
        const auto tx = decode(bytes, consumed);
        EXPECT_EQ(consumed, bytes.size()) << std::hex << field;
        EXPECT_TRUE(tx.extra_payload.empty()) << std::hex << field;
        auto ps = ::pack(tx);
        auto sp = ps.get_span();
        const std::vector<uint8_t> repacked(
            reinterpret_cast<const uint8_t*>(sp.data()),
            reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
        EXPECT_EQ(repacked, bytes) << std::hex << field;
        uint256 want;
        CHash256().Write(std::span<const unsigned char>(bytes.data(), bytes.size()))
                  .Finalize(std::span<unsigned char>(want.data(), 32));
        EXPECT_EQ(dash_txid(tx), want) << std::hex << field;
    }
}

// A2: the mempool refuses a negative-nVersion tx at admission (the choke point
// for relay, DSTX and inject); the same tx at version 1 is admitted.
TEST(DashTxVersion, MempoolRejectsNegativeVersion)
{
    ::core::coin::UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);
    auto neg = priced_spend(utxo, 0x31, /*version=*/0xFFFF);
    EXPECT_FALSE(mp.add_tx(neg)) << "bad-txns-version must never enter the pool";
    EXPECT_EQ(mp.size(), 0u);
    EXPECT_FALSE(mp.add_dstx(priced_spend(utxo, 0x32, 0x8000)));
    EXPECT_EQ(mp.size(), 0u);

    auto ok = priced_spend(utxo, 0x33, /*version=*/1);
    EXPECT_TRUE(mp.add_tx(ok));
    EXPECT_EQ(mp.size(), 1u);
}

// A2b: the rest of ContextualCheckTransaction at admission — an unknown
// special type and a typed non-special-version tx are bad-txns-type.
TEST(DashTxVersion, MempoolRejectsUnknownOrMisplacedType)
{
    ::core::coin::UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);
    EXPECT_FALSE(mp.add_tx(priced_spend(utxo, 0x41, 3, /*type=*/42)));
    EXPECT_FALSE(mp.add_tx(priced_spend(utxo, 0x42, 1, /*type=*/1)));
    EXPECT_EQ(mp.size(), 0u);
    EXPECT_TRUE(mp.add_tx(priced_spend(utxo, 0x43, 3, /*type=*/8)));
}

// A3: the selector belt — an entry that predates the admission gate (modelled
// by the test seam) is never served; the control rides.
TEST(DashTxVersion, SelectorNeverServesNegativeVersion)
{
    ::core::coin::UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);
    auto neg = priced_spend(utxo, 0x51, /*version=*/0xFFFF);
    auto ok  = priced_spend(utxo, 0x52, /*version=*/2);
    ASSERT_TRUE(mp.add_tx_skipping_contextual_check_for_test(neg));
    ASSERT_TRUE(mp.add_tx(ok));
    ASSERT_EQ(mp.size(), 2u);

    auto [sel, fees] = mp.get_sorted_txs_with_fees(1'000'000);
    bool neg_served = false, ok_served = false;
    for (const auto& s : sel) {
        if (dash_txid(s.tx) == dash_txid(neg)) neg_served = true;
        if (dash_txid(s.tx) == dash_txid(ok))  ok_served  = true;
    }
    EXPECT_FALSE(neg_served) << "a negative-nVersion tx makes the block bad-txns-version";
    EXPECT_TRUE(ok_served);
    EXPECT_EQ(fees, 10'000u) << "only the control's fee is counted";
}

// A4: differential sweep against dashcore's own decoder. Each case is a tx
// followed by a trailer that is EITHER an empty payload field (0x00) or a
// 3-byte payload field; dashd consumes the trailer iff IsSpecialTxVersion()
// && nType != 0, and so must we — any disagreement misaligns every later tx
// of a block body.
TEST(DashTxVersion, ExtraPayloadGateMatchesVendoredDashdCodec)
{
    const int16_t versions[] = {-32768, -1, 0, 1, 2, 3, 4, 0x7FFF};
    const uint16_t types[]   = {0, 1, 5, 6};
    const std::vector<std::vector<uint8_t>> trailers = {{0x00}, {0x03, 0xAA, 0xBB, 0xCC}};
    int checked = 0;
    for (int16_t v : versions) {
        for (uint16_t t : types) {
            for (const auto& trailer : trailers) {
                const uint32_t field = static_cast<uint32_t>(static_cast<uint16_t>(v))
                                     | (static_cast<uint32_t>(t) << 16);
                auto bytes = raw_tx(field);
                bytes.insert(bytes.end(), trailer.begin(), trailer.end());
                bytes.push_back(0xEE);                    // never a tx byte

                c2pool_dash_tx_probe ref{};
                ASSERT_EQ(c2pool_dash_tx_decode_probe(bytes.data(),
                              static_cast<unsigned>(bytes.size()), &ref), 1)
                    << "v=" << v << " t=" << t;
                size_t consumed = 0;
                const auto tx = decode(bytes, consumed);
                const std::string at = "v=" + std::to_string(v) + " t=" + std::to_string(t)
                                     + " trailer=" + std::to_string(trailer.size());
                EXPECT_EQ(static_cast<int16_t>(tx.version & 0xFFFF), ref.n_version) << at;
                EXPECT_EQ(tx.type, ref.n_type) << at;
                EXPECT_EQ(tx.vin.size(), ref.n_vin) << at;
                EXPECT_EQ(tx.vout.size(), ref.n_vout) << at;
                EXPECT_EQ(tx.locktime, ref.lock_time) << at;
                EXPECT_EQ(tx.extra_payload.size(), ref.payload_len) << at;
                EXPECT_EQ(consumed, ref.consumed) << at;
                EXPECT_EQ(dash::coin::tx_has_extra_payload(tx.version, tx.type),
                          v >= 3 && t != 0) << at;
                ++checked;
            }
        }
    }
    EXPECT_EQ(checked, 8 * 4 * 2);
}
