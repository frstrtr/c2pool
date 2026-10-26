// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// BIP 152 compact blocks against a vector produced by bitcoind (rides
// btc_share_test).
//
// btc_regtest_cmpct_fixtures.hpp holds a regtest block with six segwit
// transactions and the cmpctblock payload bitcoind 27.0 sent for it (v2, once
// on a low-bandwidth and once on a high-bandwidth connection). Our SipHash
// keys and short ids must reproduce bitcoind's short ids exactly; anything
// else means every Core peer has to round-trip getblocktxn for the whole
// block we found before it can relay it. Our parser must read the payload and
// re-encode it byte for byte.
// Folded into the allowlisted btc_share_test target (no new executable: #769).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/bip152_shortid.hpp>
#include <btclibs/crypto/siphash.h>
#include <btclibs/util/strencodings.h>

#include <impl/btc/coin/block.hpp>
#include <impl/btc/coin/transaction.hpp>
#include <impl/btc/coin/mempool.hpp>
#include <impl/btc/coin/compact_blocks.hpp>
#include <impl/btc/coin/p2p_messages.hpp>

#include "btc_regtest_cmpct_fixtures.hpp"

namespace {

using namespace btc::coin;
namespace rx = btc_regtest_cmpct_fixture;

BlockType regtest_block()
{
    auto bytes = ParseHex(rx::kBlockHex);
    PackStream ps(bytes);
    BlockType b;
    ps >> b;
    return b;
}

CompactBlock parse_payload(const char* hex)
{
    auto bytes = ParseHex(hex);
    PackStream ps(bytes);
    auto msg = p2p::message_cmpctblock::make(ps);
    return msg->m_compact_block;
}

std::string reencode(const CompactBlock& cb)
{
    PackStream ps;
    ps << cb;
    return HexStr(ps.get_span());
}

uint256 wtxid_of(const MutableTransaction& tx)
{
    auto packed = pack(TX_WITH_WITNESS(tx));
    return Hash(packed.get_span());
}

// The pre-fix key derivation (SHA256d of the header, XOR nonce), kept here
// only to show bitcoind's short ids could never match it.
uint64_t old_shortid(const CompactBlock& cb, const uint256& wtxid)
{
    auto packed = pack(cb.header);
    const uint256 h = Hash(packed.get_span());
    return SipHashUint256(h.GetUint64(0) ^ cb.nonce, h.GetUint64(1) ^ cb.nonce, wtxid) & 0xffffffffffffULL;
}

void expect_bitcoind_shortids(const CompactBlock& cb, const BlockType& b)
{
    ASSERT_EQ(cb.short_ids.size(), rx::kTxCount - 1);
    uint64_t k0 = 0, k1 = 0;
    cb.GetSipHashKeys(k0, k1);
    size_t old_matches = 0;
    for (size_t i = 1; i < b.m_txs.size(); ++i) {
        const uint256 w = wtxid_of(b.m_txs[i]);
        EXPECT_EQ(cb.GetShortID(w).to_uint64(), cb.short_ids[i - 1].to_uint64())
            << "tx " << i << ": our short id differs from bitcoind's";
        EXPECT_EQ(bip152::short_id(k0, k1, w), cb.short_ids[i - 1].to_uint64())
            << "tx " << i << ": the shared helper differs from bitcoind";
        old_matches += old_shortid(cb, w) == cb.short_ids[i - 1].to_uint64() ? 1 : 0;
    }
    EXPECT_EQ(old_matches, 0u) << "the old key derivation never matches bitcoind";
}

} // namespace

TEST(BtcCmpctBitcoindVector, BlockMatchesTheRpcView)
{
    const BlockType b = regtest_block();
    auto packed = pack(static_cast<const BlockHeaderType&>(b));
    EXPECT_EQ(HexStr(packed.get_span()), rx::kHeaderHex);
    EXPECT_EQ(Hash(packed.get_span()).GetHex(), rx::kBlockHash);
    ASSERT_EQ(b.m_txs.size(), rx::kTxCount);
    for (size_t i = 0; i < b.m_txs.size(); ++i) {
        EXPECT_EQ(compute_txid(b.m_txs[i]).GetHex(), rx::kTxIds[i].txid) << i;
        EXPECT_EQ(wtxid_of(b.m_txs[i]).GetHex(), rx::kTxIds[i].wtxid) << i;
        EXPECT_NE(std::string(rx::kTxIds[i].txid), std::string(rx::kTxIds[i].wtxid))
            << "every tx has a witness: the short ids must be by wtxid";
    }
    EXPECT_EQ(ReconstructedMerkleRoot(b.m_txs), b.m_merkle_root);
}

TEST(BtcCmpctBitcoindVector, V2ShortIdsReconstructionAndReencoding)
{
    const BlockType b = regtest_block();
    const CompactBlock cb = parse_payload(rx::kCmpctV2Hex);
    auto hdr = pack(cb.header);
    EXPECT_EQ(HexStr(hdr.get_span()), rx::kHeaderHex);
    ASSERT_EQ(cb.prefilled_txns.size(), 1u);
    EXPECT_EQ(cb.prefilled_txns[0].index, 0u);
    EXPECT_EQ(compute_txid(cb.prefilled_txns[0].tx), compute_txid(b.m_txs[0]));
    EXPECT_EQ(wtxid_of(cb.prefilled_txns[0].tx), wtxid_of(b.m_txs[0])) << "coinbase with witness";

    expect_bitcoind_shortids(cb, b);

    std::map<uint256, MutableTransaction> mempool;
    for (size_t i = 1; i < b.m_txs.size(); ++i)
        mempool.emplace(wtxid_of(b.m_txs[i]), b.m_txs[i]);
    auto rec = ReconstructBlock(cb, mempool);
    ASSERT_TRUE(rec.complete) << "reconstructs from the mempool against bitcoind's short ids";
    auto rh = pack(static_cast<const BlockHeaderType&>(rec.block));
    EXPECT_EQ(Hash(rh.get_span()).GetHex(), rx::kBlockHash);

    EXPECT_EQ(reencode(cb), std::string(rx::kCmpctV2Hex)) << "byte-exact re-encoding";
}

TEST(BtcCmpctBitcoindVector, HbConnectionServedTheSamePayload)
{
    // bitcoind answers getdata(MSG_CMPCT_BLOCK) for its tip from the cached
    // most recent compact block, so the high-bandwidth connection got the same
    // nonce and the same bytes.
    EXPECT_EQ(std::string(rx::kCmpctV2HbHex), std::string(rx::kCmpctV2Hex));
    const BlockType b = regtest_block();
    const CompactBlock cb = parse_payload(rx::kCmpctV2HbHex);
    expect_bitcoind_shortids(cb, b);
    EXPECT_EQ(reencode(cb), std::string(rx::kCmpctV2HbHex));
}
