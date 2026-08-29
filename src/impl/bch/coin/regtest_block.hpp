// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// regtest_block.hpp -- valid-block construction for the leg-C broadcaster-gate
// capture (integrator 2026-06-19). The dual-path gate closes ONLY on one regtest
// capture showing submitblock=accept AND a verbatim BCHN "UpdateTip: new best=..
// height=N" connect-block line. Opaque dummy bytes prove the two sinks FIRE but
// not that the network ACCEPTS -- so a consensus-valid block is the load-bearing
// slice integrator named: GBT-derived coinbase + BIP34 height + merkle + nBits +
// regtest PoW solve.
//
// This builder is the construction half; the live RPC drive + debug.log capture
// lives in src/c2pool/main_bch.cpp (--leg-c-capture mode). Solo-coinbase block:
// a freshly self-provisioned regtest node has an empty mempool, so a single
// coinbase tx is a complete, consensus-valid block. Regtest nBits (0x207fffff)
// has a trivially large target, so the PoW solve is a short nonce sweep.
//
// PER-COIN ISOLATION: src/impl/bch only -- reuses bch BIP34/merkle/block/tx
// primitives, no src/core or bitcoin_family edit. p2pool-merged-v36 surface:
// NONE -- this constructs a parent BCH block for relay, touching no share /
// PPLNS / coinbase-commitment-share bytes. Conformance oracle for the coinbase
// layout: coinbase_commitment.hpp (M3 s19, pinned vs BCHN ContextualCheckBlock).

#include "block.hpp"
#include "header_chain.hpp"            // sha256d_hash, target_from_bits
#include "merkle.hpp"                  // compute_merkle_root (shared SHA256d)
#include "transaction.hpp"
#include "../coinbase_commitment.hpp"  // bch::consensus::build_bip34_height_push

#include <core/opscript.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/uint256.hpp>

#include <btclibs/util/strencodings.h> // HexStr
#include <nlohmann/json.hpp>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace bch {
namespace coin {
namespace regtest {

/// Result of a solved regtest block: the wire bytes both broadcast sinks consume
/// (P2P relay takes `bytes`; submitblock RPC takes `hex`), plus the solved hash
/// for the post-broadcast getblock acceptance check.
struct BuiltBlock {
    std::vector<unsigned char> bytes;        // full serialized block (header||txcount||coinbase)
    std::string                hex;          // HexStr(bytes) for submitblock
    uint256                    hash;         // SHA256d(header) -- solved block hash
    uint256                    merkle_root;  // coinbase txid (solo-coinbase block)
    uint32_t                   nonce  = 0;   // winning nonce
    bool                       solved = false;
};

/// Assemble the coinbase scriptSig: [BIP34 height push]["/c2pool/"][8B extranonce].
/// BIP34 height is consensus-required and MUST be the first push (BCHN
/// ContextualCheckBlock "bad-cb-height"); the tag + extranonce keep distinct
/// coinbases distinct across re-solves. Layout matches coinbase_commitment.hpp.
inline OPScript build_coinbase_script_sig(uint32_t height, uint64_t extranonce)
{
    std::vector<unsigned char> s =
        bch::consensus::build_bip34_height_push(static_cast<int64_t>(height));

    static const unsigned char kTag[8] = {0x2f, 0x63, 0x32, 0x70, 0x6f, 0x6f, 0x6c, 0x2f};  // "/c2pool/"
    s.push_back(static_cast<unsigned char>(sizeof(kTag)));        // push-len
    s.insert(s.end(), kTag, kTag + sizeof(kTag));

    s.push_back(8);                                              // 8-byte extranonce push
    for (int i = 0; i < 8; ++i)
        s.push_back(static_cast<unsigned char>((extranonce >> (8 * i)) & 0xffu));

    return OPScript(s.data(), s.data() + s.size());
}

/// Build the single coinbase MutableTransaction paying `coinbasevalue` to an
/// anyone-can-spend (OP_TRUE) output. Consensus-valid for relay; standardness of
/// the coinbase scriptPubKey is not consensus-checked, so OP_TRUE keeps the
/// builder key-free (no wallet, matching the -DBUILD_BITCOIN_WALLET=OFF posture).
inline MutableTransaction build_coinbase_tx(uint32_t height, int64_t coinbasevalue,
                                            uint64_t extranonce)
{
    MutableTransaction tx;
    tx.version  = 2;
    tx.locktime = 0;

    TxIn in;
    in.prevout.hash  = uint256();        // null prevout
    in.prevout.index = 0xffffffffu;
    in.scriptSig     = build_coinbase_script_sig(height, extranonce);
    in.sequence      = 0xffffffffu;
    tx.vin.push_back(in);

    static const unsigned char kOpTrue[1] = {0x51};
    TxOut out;
    out.value        = coinbasevalue;
    out.scriptPubKey = OPScript(kOpTrue, kOpTrue + 1);
    tx.vout.push_back(out);

    return tx;
}

/// Construct and PoW-solve a solo-coinbase regtest block. `max_tries` bounds the
/// nonce sweep; regtest target is trivially large so this returns on the first
/// (or near-first) nonce -- a non-solve means a misconfigured nBits, surfaced via
/// BuiltBlock::solved=false rather than a silent zero-block.
inline BuiltBlock build_and_solve(const uint256& prev_block_hash, uint32_t bits,
                                  int32_t version, uint32_t timestamp, uint32_t height,
                                  int64_t coinbasevalue, uint64_t extranonce = 0,
                                  uint32_t max_tries = 0xffffffffu)
{
    BuiltBlock r;

    MutableTransaction coinbase = build_coinbase_tx(height, coinbasevalue, extranonce);
    const uint256 coinbase_txid = Hash(pack(coinbase).get_span());
    r.merkle_root = compute_merkle_root({coinbase_txid});  // solo coinbase -> root == txid

    BlockHeaderType hdr;
    hdr.m_version        = version;
    hdr.m_previous_block = prev_block_hash;
    hdr.m_merkle_root    = r.merkle_root;
    hdr.m_timestamp      = timestamp;
    hdr.m_bits           = bits;

    const uint256 target = target_from_bits(bits);
    for (uint64_t n = 0; n <= max_tries; ++n) {
        hdr.m_nonce = static_cast<uint32_t>(n);
        const uint256 h = sha256d_hash(hdr);
        if (h <= target) {
            r.solved = true;
            r.nonce  = hdr.m_nonce;
            r.hash   = h;
            break;
        }
    }
    if (!r.solved)
        return r;  // caller checks .solved; bits almost certainly misconfigured

    BlockType block;
    block.m_version        = version;
    block.m_previous_block = prev_block_hash;
    block.m_merkle_root    = r.merkle_root;
    block.m_timestamp      = timestamp;
    block.m_bits           = bits;
    block.m_nonce          = r.nonce;
    block.m_txs.push_back(coinbase);

    auto packed = pack(block);
    auto span   = packed.get_span();
    r.bytes.assign(reinterpret_cast<const unsigned char*>(span.data()),
                   reinterpret_cast<const unsigned char*>(span.data()) + span.size());
    r.hex = HexStr(span);
    return r;
}

/// Build + solve from a BCHN getblocktemplate result. Reads previousblockhash,
/// bits, height, curtime, version, coinbasevalue. Solo-coinbase: any template
/// `transactions` are intentionally NOT included -- valid only against a node
/// whose mempool we control (the self-provisioned regtest node), which is exactly
/// the leg-C host. Throws if a required field is missing.
inline BuiltBlock build_from_gbt(const nlohmann::json& tmpl, uint64_t extranonce = 0)
{
    if (!tmpl.contains("previousblockhash") || !tmpl.contains("bits") ||
        !tmpl.contains("height") || !tmpl.contains("coinbasevalue"))
        throw std::invalid_argument("regtest::build_from_gbt: incomplete getblocktemplate");

    const uint256 prev = uint256S(tmpl.at("previousblockhash").get<std::string>());
    const uint32_t bits =
        static_cast<uint32_t>(std::stoul(tmpl.at("bits").get<std::string>(), nullptr, 16));
    const uint32_t height = static_cast<uint32_t>(tmpl.at("height").get<int>());
    const int64_t  value  = tmpl.at("coinbasevalue").get<int64_t>();
    const int32_t  version =
        tmpl.contains("version") ? tmpl.at("version").get<int32_t>() : 0x20000000;
    const uint32_t curtime =
        tmpl.contains("curtime") ? tmpl.at("curtime").get<uint32_t>() : 0u;

    return build_and_solve(prev, bits, version, curtime, height, value, extranonce);
}

} // namespace regtest
} // namespace coin
} // namespace bch