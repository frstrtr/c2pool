// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_cmpct_shortid_kat — BIP 152 short ids of bip110::coin::CompactBlock
// against a compact block bitcoind itself produced (#2055).
//
// The bip110 coin layer is the BTC twin: same 80-byte pre-fork header, same
// segwit transactions, same BIP 152 v2 wire format (short ids by wtxid). So the
// BTC vector (src/impl/btc/test/btc_regtest_cmpct_fixtures.hpp: a regtest block
// with six segwit transactions and the cmpctblock payload bitcoind 27.0 sent for
// it) is the oracle here too. A found block goes out as a cmpctblock to every
// v2 peer; if our short ids do not match the ones the peer computes, the peer
// has to round-trip getblocktxn for the whole block before it can relay it.
//
// Proves:
//   [A] the fixture block parses into bip110::coin::BlockType and matches the
//       RPC view (header bytes, block hash, txids, wtxids, merkle root).
//   [B] our SipHash keys and short ids reproduce bitcoind's six short ids, via
//       CompactBlock::GetShortID and the shared core/bip152_shortid.hpp helper;
//       the pre-fix derivation (SHA256d(header), nonce XORed in) matches none.
//   [C] the block reconstructs from a wtxid-keyed mempool and hashes to the
//       block hash; the payload re-encodes byte for byte.
//
// Pure decode test — no node, no network, no consensus/reward/share path.

#include <impl/bip110/coin/block.hpp>
#include <impl/bip110/coin/transaction.hpp>
#include <impl/bip110/coin/mempool.hpp>
#include <impl/bip110/coin/compact_blocks.hpp>
#include <impl/bip110/coin/p2p_messages.hpp>

#include <impl/btc/test/btc_regtest_cmpct_fixtures.hpp>

#include <core/bip152_shortid.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <btclibs/crypto/siphash.h>
#include <btclibs/util/strencodings.h>

#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

using namespace bip110::coin;
namespace rx = btc_regtest_cmpct_fixture;

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } \
    else         { std::printf("ok:   %s\n", msg); } \
} while (0)

static uint256 wtxid_of(const MutableTransaction& tx)
{
    auto packed = pack(TX_WITH_WITNESS(tx));
    return Hash(packed.get_span());
}

// The pre-fix key derivation (SHA256d of the header, XOR nonce), kept here
// only to show bitcoind's short ids could never match it.
static uint64_t old_shortid(const CompactBlock& cb, const uint256& wtxid)
{
    auto packed = pack(cb.header);
    const uint256 h = Hash(packed.get_span());
    return SipHashUint256(h.GetUint64(0) ^ cb.nonce, h.GetUint64(1) ^ cb.nonce, wtxid) & 0xffffffffffffULL;
}

// Linked into bip110_explorer_getblock_kat, whose main() calls this: the KAT
// rides an executable already in both build.yml target lists.
int run_cmpct_shortid_kat()
{
    std::printf("=== bip110_cmpct_shortid_kat ===\n");

    // [A] the block, as the RPC reported it
    BlockType b;
    {
        auto bytes = ParseHex(rx::kBlockHex);
        PackStream ps(bytes);
        ps >> b;
    }
    {
        auto packed = pack(static_cast<const BlockHeaderType&>(b));
        CHECK(HexStr(packed.get_span()) == rx::kHeaderHex, "[A] header bytes == getblockheader <h> false");
        CHECK(Hash(packed.get_span()).GetHex() == rx::kBlockHash, "[A] SHA256d(header) == block hash");
    }
    CHECK(b.m_txs.size() == rx::kTxCount, "[A] tx count == getblock <h> 2");
    if (b.m_txs.size() != rx::kTxCount) {
        std::printf("bip110_cmpct_shortid_kat FAIL\n");
        return 1;
    }
    bool ids_ok = true, all_witness = true;
    for (size_t i = 0; i < b.m_txs.size(); ++i) {
        ids_ok = ids_ok && compute_txid(b.m_txs[i]).GetHex() == rx::kTxIds[i].txid
                        && wtxid_of(b.m_txs[i]).GetHex() == rx::kTxIds[i].wtxid;
        all_witness = all_witness && std::string(rx::kTxIds[i].txid) != std::string(rx::kTxIds[i].wtxid);
    }
    CHECK(ids_ok, "[A] every txid and wtxid == getblock <h> 2");
    CHECK(all_witness, "[A] every tx has a witness: the short ids must be by wtxid");
    CHECK(ReconstructedMerkleRoot(b.m_txs) == b.m_merkle_root, "[A] merkle root over the txids == header commitment");

    // [B] bitcoind's short ids
    CompactBlock cb;
    {
        auto bytes = ParseHex(rx::kCmpctV2Hex);
        PackStream ps(bytes);
        auto msg = p2p::message_cmpctblock::make(ps);
        cb = msg->m_compact_block;
    }
    {
        auto hdr = pack(cb.header);
        CHECK(HexStr(hdr.get_span()) == rx::kHeaderHex, "[B] cmpctblock header == the block's header");
    }
    CHECK(cb.prefilled_txns.size() == 1 && cb.prefilled_txns[0].index == 0
              && wtxid_of(cb.prefilled_txns[0].tx) == wtxid_of(b.m_txs[0]),
          "[B] one prefilled tx: the coinbase at index 0");
    CHECK(cb.short_ids.size() == rx::kTxCount - 1, "[B] six short ids");
    if (cb.short_ids.size() != rx::kTxCount - 1) {
        std::printf("bip110_cmpct_shortid_kat FAIL\n");
        return 1;
    }
    uint64_t k0 = 0, k1 = 0;
    cb.GetSipHashKeys(k0, k1);
    size_t ours = 0, helper = 0, old = 0;
    for (size_t i = 1; i < b.m_txs.size(); ++i) {
        const uint256 w = wtxid_of(b.m_txs[i]);
        const uint64_t theirs = cb.short_ids[i - 1].to_uint64();
        const uint64_t mine = cb.GetShortID(w).to_uint64();
        std::printf("      tx%zu bitcoind=%012llx ours=%012llx\n", i,
                    static_cast<unsigned long long>(theirs), static_cast<unsigned long long>(mine));
        ours += mine == theirs ? 1 : 0;
        helper += bip152::short_id(k0, k1, w) == theirs ? 1 : 0;
        old += old_shortid(cb, w) == theirs ? 1 : 0;
    }
    CHECK(ours == rx::kTxCount - 1, "[B] CompactBlock::GetShortID reproduces all six of bitcoind's short ids");
    CHECK(helper == rx::kTxCount - 1, "[B] bip152::short_id with GetSipHashKeys reproduces all six");
    CHECK(old == 0, "[B] the old key derivation matches none of them");

    // [C] reconstruction and re-encoding
    std::map<uint256, MutableTransaction> mempool;
    for (size_t i = 1; i < b.m_txs.size(); ++i)
        mempool.emplace(wtxid_of(b.m_txs[i]), b.m_txs[i]);
    auto rec = ReconstructBlock(cb, mempool);
    CHECK(rec.complete, "[C] reconstructs from the mempool against bitcoind's short ids");
    if (rec.complete) {
        auto rh = pack(static_cast<const BlockHeaderType&>(rec.block));
        CHECK(Hash(rh.get_span()).GetHex() == rx::kBlockHash, "[C] the reconstructed block hashes to the block hash");
    }
    {
        PackStream ps;
        ps << cb;
        CHECK(HexStr(ps.get_span()) == rx::kCmpctV2Hex, "[C] byte-exact re-encoding of the payload");
    }

    std::printf("%s\n", g_fail == 0 ? "bip110_cmpct_shortid_kat PASS" : "bip110_cmpct_shortid_kat FAIL");
    return g_fail;
}
