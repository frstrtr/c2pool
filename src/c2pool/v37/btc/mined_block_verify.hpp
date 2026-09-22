// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/btc/mined_block_verify.hpp   (Dash T1-prep step 3)
//
// THE REWARD A FOLD CONSUMES MUST BE THE REWARD THE BLOCK ACTUALLY MINED.
//
// Before this header the v37 btc-dash arm folded E_b with two unverified
// numbers:
//   * OWN win:  XbtcNode::on_block_won read m_coin->block_reward(H_b), i.e. the
//               CACHED getblocktemplate miner_value (dash_rpc_coin_backend.hpp
//               block_reward/template_for) -- a template that may not be the
//               one the mined coinbase was built from.
//   * PEER win: on_peer_block_won folded w.reward straight off the v0x02 cut
//               descriptor. Nothing checked that the block id existed, that it
//               sat on the best chain at H_b, or that the reward was real, so a
//               single forged descriptor could inflate every peer's owed ledger.
//
// This header is the pure (STL-only) half of the fix:
//   parse_coinbase_outputs()  the coinbase outputs of a serialized DASH block
//                             (80-byte header, compactsize tx count, tx[0]).
//   MinedBlockFacts           what dashd says about a block id: known? on the
//                             active chain? at what height? and the MINED miner
//                             slice = sum(coinbase outputs) - (masternode +
//                             platform-burn payments dashd reports for it).
//   verify_peer_win()         the verdict for one carried descriptor.
//   own_mined_reward()        the winner's own miner slice, read from the block
//                             BYTES it just mined (never the cached template
//                             value): sum(outputs) - the outputs that pay the
//                             template's masternode/burn PAYEE SCRIPTS, with the
//                             AMOUNTS read from the mined outputs themselves.
//
// WHY PAYEE SCRIPTS, NOT THE TEMPLATE'S PAYMENT TOTAL (soak round 899). The
// masternode + platform-burn amounts are a fixed share of (subsidy + FEES OF
// THE MINED BLOCK). The stratum work source builds its coinbase from its OWN
// getblocktemplate; the backend's cached template, fetched separately, can hold
// a different fee set at the same (height, parent). Subtracting the cached
// template's payment total then misstates the slice by the masternode share of
// the fee difference (round 899: winner 59525746, dashd-derived 59526072, a
// 326-duff gap on 434 duffs of fees) and every peer refuses the claim. The
// payee IDENTITIES (scripts) are the same in both templates; only the amounts
// move with fees — so match scripts and read amounts from the mined bytes.
//
// WHAT "MINER SLICE" MEANS HERE. Every DASH coinbase pays, besides the pool:
// the masternode payee, the platform credit-pool burn (an OP_RETURN output, on
// v20+), and, at a superblock height, treasury payees. dashd's
// `masternode payments <bid> 1` reports the first two as one `amount`, and
// getblocktemplate's `masternode[]` array lists the same two, so
//     miner_slice = sum(coinbase vout) - masternode_payments(bid).amount
// is computable by ANY node after the fact and equals what the winner computed
// from its template at mining time. Superblock treasury payments are NOT
// reconstructible after the fact from dashd RPC (the governance trigger
// expires), so AT A SUPERBLOCK-CYCLE HEIGHT the rule is fail-closed on both
// sides: the winner registers the block VALUELESS (reward 0) and a peer
// refuses any non-zero claim there. Both nodes therefore credit nobody at those
// heights and still converge. (Design note docs/dash-pilot/ has the options.)
//
// A reward == 0 descriptor ("the winner registered this block VALUELESS")
// needs no reward proof: it credits nobody. Existence, best-chain and height
// are still checked for it.
//
// Nothing here is consensus canon: it decides whether a node FOLDS a block at
// all, never how the fold, the ledger or any digest is computed.
// ===========================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace c2pool::v37n::btc {

// ── the coinbase outputs of a serialized block ──────────────────────────────
struct CoinbaseOutputs {
    bool          ok = false;
    std::uint64_t total = 0;       // sum of every tx[0] vout value (duffs)
    std::size_t   n_out = 0;
    std::string   error;           // set when !ok
    struct Out { std::uint64_t value = 0; std::vector<std::uint8_t> script; };
    std::vector<Out> outs;         // every tx[0] output, in order
};

namespace mbv_detail {
struct Reader {
    const std::uint8_t* p;
    std::size_t         n;
    std::size_t         i = 0;
    bool take(std::size_t k) { if (k > n - i) return false; i += k; return true; }
    bool u32(std::uint32_t& v) {
        if (4 > n - i) return false;
        v = std::uint32_t(p[i]) | (std::uint32_t(p[i + 1]) << 8) |
            (std::uint32_t(p[i + 2]) << 16) | (std::uint32_t(p[i + 3]) << 24);
        i += 4;
        return true;
    }
    bool u64(std::uint64_t& v) {
        if (8 > n - i) return false;
        v = 0;
        for (int k = 7; k >= 0; --k) v = (v << 8) | p[i + k];
        i += 8;
        return true;
    }
    bool compact(std::uint64_t& v) {
        if (1 > n - i) return false;
        const std::uint8_t b = p[i++];
        if (b < 0xfd) { v = b; return true; }
        if (b == 0xfd) {
            if (2 > n - i) return false;
            v = std::uint64_t(p[i]) | (std::uint64_t(p[i + 1]) << 8);
            i += 2;
            return v >= 0xfd;                         // non-canonical encoding refused
        }
        if (b == 0xfe) {
            std::uint32_t w = 0;
            if (!u32(w)) return false;
            v = w;
            return v > 0xffff;
        }
        return u64(v) && v > 0xffffffffULL;
    }
};
inline int nib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
}  // namespace mbv_detail

// DASH MAX_MONEY (src/consensus/amount.h: 21000000 * COIN). An output above it,
// or a sum that would pass it, is not a real coinbase.
inline constexpr std::uint64_t kDashMaxMoney = 21000000ULL * 100000000ULL;

// `blk` is the whole serialized block (or at least header + tx count + tx[0]).
// DASH tx[0]: int32 nVersion (low 16 = version, high 16 = special-tx type),
// vin (exactly one, the coinbase input), vout, locktime, [extra payload]. Only
// the fields up to the end of vout are read.
inline CoinbaseOutputs parse_coinbase_outputs(const std::uint8_t* blk, std::size_t n) {
    CoinbaseOutputs out;
    mbv_detail::Reader r{blk, n};
    auto fail = [&](const char* why) { out.ok = false; out.error = why; return out; };
    if (!r.take(80)) return fail("short block: no 80-byte header");
    std::uint64_t ntx = 0;
    if (!r.compact(ntx) || ntx == 0) return fail("bad tx count");
    std::uint32_t ver = 0;
    if (!r.u32(ver)) return fail("short coinbase: version");
    std::uint64_t nin = 0;
    if (!r.compact(nin)) return fail("short coinbase: vin count");
    if (nin != 1) return fail("tx[0] is not a coinbase (vin count != 1)");
    if (!r.take(32)) return fail("short coinbase: prevout hash");
    std::uint32_t prev_n = 0;
    if (!r.u32(prev_n)) return fail("short coinbase: prevout index");
    if (prev_n != 0xffffffffu) return fail("tx[0] is not a coinbase (prevout index != 0xffffffff)");
    std::uint64_t slen = 0;
    if (!r.compact(slen) || !r.take(static_cast<std::size_t>(slen))) return fail("short coinbase: scriptSig");
    if (!r.take(4)) return fail("short coinbase: sequence");
    std::uint64_t nout = 0;
    if (!r.compact(nout) || nout == 0) return fail("coinbase has no outputs");
    for (std::uint64_t k = 0; k < nout; ++k) {
        std::uint64_t v = 0;
        if (!r.u64(v)) return fail("short coinbase: output value");
        if (v > kDashMaxMoney) return fail("coinbase output above MAX_MONEY");
        if (out.total + v > kDashMaxMoney) return fail("coinbase output sum above MAX_MONEY");
        out.total += v;
        std::uint64_t pk = 0;
        if (!r.compact(pk)) return fail("short coinbase: scriptPubKey");
        const std::size_t at = r.i;
        if (!r.take(static_cast<std::size_t>(pk))) return fail("short coinbase: scriptPubKey");
        CoinbaseOutputs::Out o;
        o.value = v;
        o.script.assign(blk + at, blk + at + static_cast<std::size_t>(pk));
        out.outs.push_back(std::move(o));
    }
    out.n_out = static_cast<std::size_t>(nout);
    out.ok = true;
    return out;
}
inline CoinbaseOutputs parse_coinbase_outputs(const std::vector<std::uint8_t>& blk) {
    return parse_coinbase_outputs(blk.data(), blk.size());
}
// dashd `getblock <bid> 0` answers the block as hex. Only the prefix up to the
// end of tx[0]'s outputs is needed, but a malformed hex string is refused.
inline CoinbaseOutputs parse_coinbase_outputs_hex(const std::string& hex) {
    if (hex.size() % 2) { CoinbaseOutputs o; o.error = "odd-length block hex"; return o; }
    std::vector<std::uint8_t> b(hex.size() / 2);
    for (std::size_t i = 0; i < b.size(); ++i) {
        const int hi = mbv_detail::nib(hex[2 * i]), lo = mbv_detail::nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) { CoinbaseOutputs o; o.error = "non-hex block"; return o; }
        b[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return parse_coinbase_outputs(b);
}

// A superblock-cycle height (Dash Core governance/classes.cpp
// CSuperblock::IsValidBlockHeight: h >= nSuperblockStartBlock && h % cycle == 0).
// `cycle == 0` means "this chain has no superblocks" (KATs that do not model
// governance). The daemon pins the cycle per network and cross-checks it
// against dashd's getgovernanceinfo at boot.
inline bool is_superblock_height(std::uint64_t h, std::uint64_t cycle, std::uint64_t start) {
    return cycle != 0 && h >= start && (h % cycle) == 0;
}

// ── what dashd says about one block id ──────────────────────────────────────
struct MinedBlockFacts {
    enum class State : std::uint8_t { Have = 0, Missing = 1, Unknown = 2 };
    State         state = State::Unknown;       // Missing = dashd never had it (-5)
    bool          on_active_chain = false;      // getblockheader confirmations >= 0
    std::uint64_t height = 0;                   // getblockheader .height (valid when Have)
    bool          superblock_height = false;    // height is a superblock-cycle height
    // sum(coinbase vout) - masternode_payments(bid).amount; nullopt when either
    // leg could not be read (transport) or the payments exceed the outputs.
    std::optional<std::uint64_t> miner_slice;
    std::string   note;                         // why miner_slice is nullopt, for the log
};

inline std::optional<std::uint64_t> miner_slice_of(std::uint64_t coinbase_total,
                                                   std::uint64_t non_miner_payments) {
    if (non_miner_payments > coinbase_total) return std::nullopt;
    return coinbase_total - non_miner_payments;
}

enum class WinVerdict : std::uint8_t {
    Ok = 0,
    UnknownBlock,        // dashd never had the block (after the bounded wait)
    NotActive,           // dashd knows it, but it is not on the best chain
    HeightMismatch,      // on the best chain, but not at the carried H_b
    Unavailable,         // dashd could not be asked (transport / warm-up / missing leg)
    RewardMismatch,      // the carried reward != the MINED miner slice
    SuperblockNonzero,   // a non-zero reward claimed at a superblock-cycle height
    Unverified,          // verification required, but no facts were attached
};

inline const char* win_verdict_name(WinVerdict v) {
    switch (v) {
        case WinVerdict::Ok:                return "ok";
        case WinVerdict::UnknownBlock:      return "unknown_block";
        case WinVerdict::NotActive:         return "not_active";
        case WinVerdict::HeightMismatch:    return "height_mismatch";
        case WinVerdict::Unavailable:       return "verify_unavailable";
        case WinVerdict::RewardMismatch:    return "reward_mismatch";
        case WinVerdict::SuperblockNonzero: return "superblock_nonzero";
        case WinVerdict::Unverified:        return "unverified";
    }
    return "?";
}

// The verdict for one carried (bid, H_b, reward). `expected` receives the
// mined miner slice when one was computed (for the refusal line).
inline WinVerdict verify_peer_win(const MinedBlockFacts& f, std::uint64_t h_b,
                                  std::uint64_t reward,
                                  std::optional<std::uint64_t>* expected = nullptr) {
    if (expected) *expected = f.miner_slice;
    switch (f.state) {
        case MinedBlockFacts::State::Missing: return WinVerdict::UnknownBlock;
        case MinedBlockFacts::State::Unknown: return WinVerdict::Unavailable;
        case MinedBlockFacts::State::Have:    break;
    }
    if (!f.on_active_chain) return WinVerdict::NotActive;
    if (f.height != h_b)    return WinVerdict::HeightMismatch;
    if (reward == 0)        return WinVerdict::Ok;                // VALUELESS claim: credits nobody
    if (f.superblock_height) return WinVerdict::SuperblockNonzero;
    if (!f.miner_slice)     return WinVerdict::Unavailable;
    if (*f.miner_slice != reward) return WinVerdict::RewardMismatch;
    return WinVerdict::Ok;
}

// The non-miner part of a mined coinbase: each template payee script is
// matched to ONE mined output with that exact script (first unmatched, in
// output order), and that output's MINED amount is counted. nullopt when a
// payee script has no output (the block does not pay a required payee — dashd
// would have rejected it; never guess).
inline std::optional<std::uint64_t> non_miner_amount(
        const CoinbaseOutputs& cb, const std::vector<std::vector<std::uint8_t>>& payee_scripts) {
    std::vector<bool> used(cb.outs.size(), false);
    std::uint64_t sum = 0;
    for (const auto& ps : payee_scripts) {
        bool found = false;
        for (std::size_t k = 0; k < cb.outs.size(); ++k) {
            if (used[k] || cb.outs[k].script != ps) continue;
            used[k] = true;
            sum += cb.outs[k].value;
            found = true;
            break;
        }
        if (!found) return std::nullopt;
    }
    return sum;
}

// ── the winner's OWN miner slice, from the bytes it mined ───────────────────
// `tmpl_height`/`tmpl_prev` identify the template whose PAYEE SCRIPTS
// (masternode + platform burn [+ superblock]) are matched; it must be the
// template at exactly (H_b, parent of the mined header), or the answer is
// nullopt (unverified -> the caller registers the win VALUELESS, loudly).
struct OwnMinedReward {
    std::optional<std::uint64_t> reward;   // the value the own fold consumes
    std::uint64_t coinbase_total = 0;
    std::string   note;                    // why reward is nullopt / forced 0
};
inline OwnMinedReward own_mined_reward(const std::vector<std::uint8_t>& block,
                                       std::uint64_t h_b, const std::string& parent_display_hex,
                                       std::uint64_t tmpl_height, const std::string& tmpl_prev,
                                       const std::vector<std::vector<std::uint8_t>>& payee_scripts,
                                       bool payees_ok, bool superblock_height) {
    OwnMinedReward o;
    const CoinbaseOutputs cb = parse_coinbase_outputs(block);
    if (!cb.ok) { o.note = "mined coinbase unparseable: " + cb.error; return o; }
    o.coinbase_total = cb.total;
    if (superblock_height) {
        o.reward = 0;
        o.note   = "superblock-cycle height: treasury payments are not reconstructible by peers; "
                   "registered VALUELESS on every node";
        return o;
    }
    if (tmpl_height != h_b || tmpl_prev != parent_display_hex) {
        o.note = "no template at the mined block's (height, parent) to read the masternode "
                 "payment total from (template h=" + std::to_string(tmpl_height) + ")";
        return o;
    }
    if (!payees_ok) {
        o.note = "the template's payee list could not be decoded to scripts";
        return o;
    }
    const std::optional<std::uint64_t> nm = non_miner_amount(cb, payee_scripts);
    if (!nm) {
        o.note = "a template payee script has no output in the mined coinbase";
        return o;
    }
    o.reward = miner_slice_of(cb.total, *nm);
    if (!o.reward) o.note = "payee outputs exceed the mined coinbase outputs";
    return o;
}

}  // namespace c2pool::v37n::btc
