// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// doge::coin -- STANDALONE DOGE-aux SUBMIT-BLOCK ASSEMBLER (parent-agnostic).
//
// Assembles the full DOGE submit-block hex for a won DOGE-aux target hit, in the
// EXACT byte layout the canonical LTC+DOGE primary submit path emits
// (src/c2pool/merged/merged_mining.cpp try_submit_merged_blocks -- the path that
// found live merged DOGE block #6308393):
//
//     header80(AuxPoW bit 0x100 set) || CAuxPow proof || varint(n_tx)
//       || coinbase || template txs                 (n_tx = 1 + template txs)
//
// PARENT-AGNOSTIC (integrator scope, 2026-09-06). This module carries NO parent
// (LTC/DGB) state: no MM-manager binding, no dgb include. It takes a frozen DOGE
// child-block template snapshot (the fields build_template froze) plus the
// parent-built CAuxPow proof (already serialized by the parent-neutral producer
// c2pool::merged::build_auxpow_proof -- passed in as hex, NEVER rebuilt here) and
// produces the block hex. That keeps it consumable by EITHER a merged LTC parent
// OR a DGB parent (dgb binds the closure on their side, cf.
// src/impl/dgb/coin/aux_doge_submit.hpp) without either reaching into the other's
// submit path.
//
// SEAM SHAPE. make_doge_aux_block_assembler() adapts a template-provider callback
// into the (share_hash, auxpow_hex) -> optional<block_hex> closure shape -- the
// same std::function injection dgb::coin::AuxDogeBlockAssembler expects, defined
// here INDEPENDENTLY (no dgb include) so the doge module stays leaf-side.
//
// ISOLATION. src/impl/doge/coin/ only. Reuses the established doge<-ltc coin-type
// sharing (ltc::coin::compute_merkle_root is the SSOT merkle used by the parent
// submit path) + core hashing; touches nothing in src/c2pool/merged/ or
// src/impl/dgb/. No parent share format, PoW hash, coinbase commitment, or PPLNS
// math is read or written.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <core/hash.hpp>       // Hash()
#include <core/uint256.hpp>

#include <impl/ltc/coin/template_builder.hpp>  // ltc::coin::compute_merkle_root (SSOT)

namespace doge
{
namespace coin
{

// ─── frozen DOGE child-block template snapshot ──────────────────────────────
// The exact fields the primary submit path reads out of the frozen GBT template
// + the separately-frozen coinbase. Parent-agnostic: DOGE child state only.
struct DogeSubmitTemplate
{
    uint32_t                 version = 0;   // GBT block version; the assembler ORs the AuxPoW bit
    uint256                  prev_hash;     // previousblockhash (as parsed by SetHex)
    uint32_t                 curtime = 0;
    uint32_t                 nbits = 0;
    std::string              coinbase_hex;  // full serialized DOGE coinbase tx (wire hex)
    std::vector<std::string> tx_data_hex;   // template txs, raw wire hex, in template order
    std::vector<uint256>     tx_ids;        // matching txids (as parsed by SetHex). Either empty
                                            // (assembler computes each from tx_data_hex) or exactly
                                            // tx_data_hex.size() entries.
};

// AuxPoW child-block version bit. A DOGE block carrying an AuxPoW proof sets bit 8
// (0x100) in nVersion; mirrors merged_mining.cpp's `version | 0x100`.
static constexpr uint32_t DOGE_AUXPOW_VERSION_BIT = 0x100u;

namespace detail
{

inline std::string to_hex(const uint8_t* data, size_t len)
{
    static const char* H = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        s.push_back(H[data[i] >> 4]);
        s.push_back(H[data[i] & 0xf]);
    }
    return s;
}

inline std::vector<uint8_t> from_hex(const std::string& hex)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    std::vector<uint8_t> v;
    v.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        v.push_back(static_cast<uint8_t>((nib(hex[i]) << 4) | nib(hex[i + 1])));
    return v;
}

// Bitcoin CompactSize varint -- byte-identical to merged_mining.cpp's encoder.
inline std::string varint_hex(uint64_t n)
{
    if (n < 0xfd) {
        uint8_t b[1] = { static_cast<uint8_t>(n) };
        return to_hex(b, 1);
    } else if (n <= 0xffff) {
        uint8_t b[3] = { 0xfd, static_cast<uint8_t>(n & 0xff), static_cast<uint8_t>((n >> 8) & 0xff) };
        return to_hex(b, 3);
    } else if (n <= 0xffffffffull) {
        uint8_t b[5];
        b[0] = 0xfe;
        for (int i = 0; i < 4; ++i) b[1 + i] = (n >> (8 * i)) & 0xff;
        return to_hex(b, 5);
    } else {
        uint8_t b[9];
        b[0] = 0xff;
        for (int i = 0; i < 8; ++i) b[1 + i] = (n >> (8 * i)) & 0xff;
        return to_hex(b, 9);
    }
}

inline std::string encode_le32(uint32_t v)
{
    uint8_t b[4] = { static_cast<uint8_t>(v & 0xFF), static_cast<uint8_t>((v >> 8) & 0xFF),
                     static_cast<uint8_t>((v >> 16) & 0xFF), static_cast<uint8_t>((v >> 24) & 0xFF) };
    return to_hex(b, 4);
}

} // namespace detail

// ─── the assembler ──────────────────────────────────────────────────────────
// Assemble the full DOGE submit-block hex. Returns "" (unassemblable) when the
// coinbase or the AuxPoW proof is missing -- the two inputs a won-block submit
// cannot proceed without. The 80-byte header is rebuilt here (NOT taken from the
// caller) so the AuxPoW bit and the tx-merkle-root are guaranteed consistent with
// the body we emit -- the same self-consistency the primary path verifies before
// submit.
inline std::string assemble_doge_submit_block_hex(const DogeSubmitTemplate& t,
                                                  const std::string& auxpow_hex)
{
    if (t.coinbase_hex.empty() || auxpow_hex.empty())
        return {};
    if (!t.tx_ids.empty() && t.tx_ids.size() != t.tx_data_hex.size())
        return {};

    // Tx-merkle leaves: coinbase hash first, then each template txid. Mirrors
    // merged_mining.cpp collect_tx_hashes -- use the supplied txid when present,
    // else SHA256d the raw tx bytes.
    std::vector<uint256> tx_hashes;
    tx_hashes.reserve(1 + t.tx_data_hex.size());
    tx_hashes.push_back(Hash(detail::from_hex(t.coinbase_hex)));
    for (size_t i = 0; i < t.tx_data_hex.size(); ++i) {
        if (!t.tx_ids.empty())
            tx_hashes.push_back(t.tx_ids[i]);
        else
            tx_hashes.push_back(Hash(detail::from_hex(t.tx_data_hex[i])));
    }
    const uint256 merkle_root = ltc::coin::compute_merkle_root(tx_hashes);

    // 80-byte header: version|0x100 || prev(32) || merkle(32) || time || bits || nonce=0.
    const uint32_t version = t.version | DOGE_AUXPOW_VERSION_BIT;
    const uint32_t nonce = 0;
    uint8_t hdr[80];
    uint8_t* p = hdr;
    std::memcpy(p, &version, 4);            p += 4;
    std::memcpy(p, t.prev_hash.data(), 32); p += 32;
    std::memcpy(p, merkle_root.data(), 32); p += 32;
    std::memcpy(p, &t.curtime, 4);          p += 4;
    std::memcpy(p, &t.nbits, 4);            p += 4;
    std::memcpy(p, &nonce, 4);

    const size_t n_tx = 1 + t.tx_data_hex.size();  // coinbase + template txs

    std::string blk;
    blk += detail::to_hex(hdr, 80);
    blk += auxpow_hex;
    blk += detail::varint_hex(n_tx);
    blk += t.coinbase_hex;
    for (const auto& tx : t.tx_data_hex)
        blk += tx;
    return blk;
}

// ─── seam shapes ─────────────────────────────────────────────────────────────
// Defined here independently of dgb (no dgb include); signature-compatible with
// dgb::coin::AuxDogeBlockAssembler so a parent can bind either.
using AuxDogeBlockAssembler =
    std::function<std::optional<std::string>(const uint256& /*share_hash*/,
                                             const std::string& /*auxpow_hex*/)>;

// Yields the frozen DOGE template for the winning share (parent-side lookup),
// injected so this module never reaches into a parent's frozen-work store.
using DogeSubmitTemplateProvider =
    std::function<std::optional<DogeSubmitTemplate>(const uint256& /*share_hash*/)>;

// Adapt a template-provider into the (share_hash, auxpow_hex) closure the parent
// won-block handler fires. Returns nullopt when the share has no frozen template
// or the block cannot be assembled -- the caller logs + skips submit (never bans).
inline AuxDogeBlockAssembler make_doge_aux_block_assembler(DogeSubmitTemplateProvider provider)
{
    return [provider = std::move(provider)](const uint256& share_hash,
                                            const std::string& auxpow_hex)
               -> std::optional<std::string>
    {
        if (!provider)
            return std::nullopt;
        auto tmpl = provider(share_hash);
        if (!tmpl)
            return std::nullopt;
        auto block_hex = assemble_doge_submit_block_hex(*tmpl, auxpow_hex);
        if (block_hex.empty())
            return std::nullopt;
        return block_hex;
    };
}

} // namespace coin
} // namespace doge
