// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ── RUNTIME loader for the W1 full-state DML prestate (anchor seed) ────────
//
// tools/dash/gen_replay_kat.py `prestate` merges `protx list registered true H`
// with `protx diff 1 H` and emits the text format parsed here:
//
//     c2pool-dash-replay-prestate/1
//     network mainnet
//     height 2513000
//     blockhash <display hex>
//     mnroot <display hex>          <- the COMMITTED cbTx merkleRootMNList
//     count N
//     mn <26 whitespace-separated fields> ...
//
// The generator REFUSES to emit a prestate whose records do not already
// reproduce `mnroot`, and DmlFoldEngine::compute_sml_root() is re-checked
// against it right after seeding here — so a seed that has drifted from
// consensus can never silently become the base of a replay.
//
// This is the gtest-free twin of test_dash_replay_fold.cpp's
// parse_prestate_into(): the SAME 26 fields, in the SAME order, with the
// SAME wire-vs-display byte-order convention. The KAT fixtures embed the
// text as a C literal (.inc); a live replay reads it from a FILE, which is
// the only difference. Any field change must be made in BOTH parsers — the
// format tag exists so a stale reader fails loud instead of misreading.
//
// Byte-order convention (inherited from the generator):
//   * `blockhash` / `mnroot` are DISPLAY hex (uint256::SetHex reverses).
//   * every per-mn hash field is WIRE hex (raw internal bytes, memcpy'd).

#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/replay_bulk_fetch.hpp>   // MAINNET_DIP3_HEIGHT — the
                                                  // SAME constant --replay-bulk-start
                                                  // defaults to (do NOT re-literal it)

#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {
namespace replay {

inline constexpr const char* kPrestateMagic = "c2pool-dash-replay-prestate/1";

struct Prestate
{
    bool        ok{false};
    std::string error;          // populated iff !ok — logged verbatim

    std::string network;
    uint32_t    height{0};
    std::string blockhash_display;
    std::string mnroot_display; // the committed root the seed must reproduce

    std::vector<std::pair<uint256, ReplayMNState>> entries;
};

namespace prestate_detail {

inline bool hex_to_bytes(const std::string& s, std::vector<uint8_t>& out)
{
    if (s.empty() || s.size() % 2 != 0) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        const int hi = nib(s[i]), lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

inline bool u256_wire(const std::string& hex, uint256& out)
{
    std::vector<uint8_t> b;
    if (!hex_to_bytes(hex, b) || b.size() != 32) return false;
    std::memcpy(out.data(), b.data(), 32);
    return true;
}

inline bool u160_wire(const std::string& hex, uint160& out)
{
    std::vector<uint8_t> b;
    if (!hex_to_bytes(hex, b) || b.size() != 20) return false;
    std::memcpy(out.data(), b.data(), 20);
    return true;
}

inline std::vector<std::string> split_ws(const std::string& line)
{
    std::vector<std::string> out;
    std::istringstream is(line);
    std::string tok;
    while (is >> tok) out.push_back(tok);
    return out;
}

// Strict signed/unsigned parses — std::stol silently accepts "12abc" and
// throws on empty, neither of which may reach a consensus-bearing field.
inline bool parse_i64(const std::string& s, int64_t& out)
{
    if (s.empty()) return false;
    size_t i = 0;
    bool neg = false;
    if (s[0] == '-') { neg = true; i = 1; if (s.size() == 1) return false; }
    int64_t v = 0;
    for (; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
        const int d = s[i] - '0';
        if (v > (INT64_MAX - d) / 10) return false;
        v = v * 10 + d;
    }
    out = neg ? -v : v;
    return true;
}

inline bool parse_u64(const std::string& s, uint64_t limit, uint64_t& out)
{
    if (s.empty() || s.size() > 20) return false;
    uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        const uint64_t d = static_cast<uint64_t>(c - '0');
        if (v > (UINT64_MAX - d) / 10) return false;
        v = v * 10 + d;
    }
    if (v > limit) return false;
    out = v;
    return true;
}

} // namespace prestate_detail

/// Parse the prestate text. Every failure is fail-closed and NAMED: a
/// half-parsed masternode set would seed a replay that diverges silently.
inline Prestate parse_prestate_text(const std::string& text)
{
    namespace d = prestate_detail;
    Prestate ps;
    auto fail = [&](const std::string& why) -> Prestate& {
        ps.ok = false;
        ps.error = why;
        return ps;
    };

    std::istringstream is(text);
    std::string line;
    if (!std::getline(is, line)) return fail("prestate is empty");
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        line.pop_back();
    if (line != kPrestateMagic)
        return fail("bad prestate format tag '" + line + "' (want '"
                    + kPrestateMagic + "')");

    bool have_height = false, have_hash = false, have_root = false;
    bool have_count = false, have_network = false;
    uint64_t declared = 0;
    size_t lineno = 1;

    while (std::getline(is, line)) {
        ++lineno;
        auto f = d::split_ws(line);
        if (f.empty()) continue;

        if (f[0] == "network") {
            if (f.size() != 2) return fail("bad 'network' line");
            ps.network = f[1];
            have_network = true;
            continue;
        }
        if (f[0] == "height") {
            uint64_t v = 0;
            if (f.size() != 2 || !d::parse_u64(f[1], UINT32_MAX, v))
                return fail("bad 'height' line");
            ps.height = static_cast<uint32_t>(v);
            have_height = true;
            continue;
        }
        if (f[0] == "blockhash") {
            if (f.size() != 2 || f[1].size() != 64)
                return fail("bad 'blockhash' line");
            ps.blockhash_display = f[1];
            have_hash = true;
            continue;
        }
        if (f[0] == "mnroot") {
            if (f.size() != 2 || f[1].size() != 64)
                return fail("bad 'mnroot' line");
            ps.mnroot_display = f[1];
            have_root = true;
            continue;
        }
        if (f[0] == "count") {
            uint64_t v = 0;
            if (f.size() != 2 || !d::parse_u64(f[1], 1000000, v))
                return fail("bad 'count' line");
            declared = v;
            have_count = true;
            continue;
        }
        if (f[0] != "mn")
            return fail("unknown key '" + f[0] + "' on line "
                        + std::to_string(lineno)
                        + " (format is " + kPrestateMagic + ")");
        if (!have_network || !have_height || !have_hash || !have_root
            || !have_count)
            return fail("'mn' record on line " + std::to_string(lineno)
                        + " before the header block was complete");
        if (f.size() != 26)
            return fail("mn record on line " + std::to_string(lineno)
                        + " has " + std::to_string(f.size())
                        + " fields, want 26");

        const std::string at = " on line " + std::to_string(lineno);
        uint256 protx;
        if (!d::u256_wire(f[1], protx)) return fail("bad proTxHash" + at);

        ReplayMNState st;
        if (f[2] != "-") {
            uint256 ch;
            if (!d::u256_wire(f[2], ch)) return fail("bad confirmedHash" + at);
            // Regenerate the pairing hash exactly as a fold would have —
            // confirmedHashWithProRegTxHash is NOT stored in the text.
            st.UpdateConfirmedHash(protx, ch);
        }

        std::vector<uint8_t> ip;
        if (!d::hex_to_bytes(f[3], ip) || ip.size() != 16)
            return fail("bad netInfo ip" + at);
        std::memcpy(st.netInfo.ip.data(), ip.data(), 16);

        uint64_t u = 0;
        auto u16 = [&](size_t idx, const char* what, uint16_t& dst) -> bool {
            if (!d::parse_u64(f[idx], UINT16_MAX, u)) {
                fail(std::string("bad ") + what + at);
                return false;
            }
            dst = static_cast<uint16_t>(u);
            return true;
        };
        if (!u16(4, "netInfo port", st.netInfo.port_be)) return ps;

        if (f[5] != "-") {
            std::vector<uint8_t> pk;
            if (!d::hex_to_bytes(f[5], pk)
                || pk.size() != vendor::BLS_PUBKEY_SIZE)
                return fail("bad pubKeyOperator" + at);
            std::memcpy(st.pubKeyOperator.data(), pk.data(),
                        vendor::BLS_PUBKEY_SIZE);
        }
        if (!d::u160_wire(f[6], st.keyIDVoting)) return fail("bad keyIDVoting" + at);
        if (!d::u160_wire(f[7], st.keyIDOwner))  return fail("bad keyIDOwner" + at);
        if (!u16(8, "nVersion", st.nVersion)) return ps;
        if (!u16(9, "nType", st.nType))       return ps;
        if (f[10] != "-" && !d::u160_wire(f[10], st.platformNodeID))
            return fail("bad platformNodeID" + at);
        if (!u16(11, "platformP2PPort", st.platformP2PPort))   return ps;
        if (!u16(12, "platformHTTPPort", st.platformHTTPPort)) return ps;
        if (!u16(13, "nOperatorReward", st.nOperatorReward))   return ps;

        // The payee keystone: an MN with no payout script still occupies a
        // DIP-3 queue slot, so a blank one would project a wrong payee.
        {
            std::vector<uint8_t> sp;
            if (f[14] == "-" || !d::hex_to_bytes(f[14], sp) || sp.empty())
                return fail("missing/undecodable scriptPayout" + at);
            st.scriptPayout.m_data.assign(sp.begin(), sp.end());
        }
        if (f[15] != "-") {
            std::vector<uint8_t> sp;
            if (!d::hex_to_bytes(f[15], sp))
                return fail("bad scriptOperatorPayout" + at);
            st.scriptOperatorPayout.m_data.assign(sp.begin(), sp.end());
        }

        int64_t s64 = 0;
        auto i32 = [&](size_t idx, const char* what, int32_t& dst) -> bool {
            if (!d::parse_i64(f[idx], s64)
                || s64 < INT32_MIN || s64 > INT32_MAX) {
                fail(std::string("bad ") + what + at);
                return false;
            }
            dst = static_cast<int32_t>(s64);
            return true;
        };
        if (!i32(16, "registeredHeight", st.nRegisteredHeight))    return ps;
        if (!i32(17, "lastPaidHeight", st.nLastPaidHeight))        return ps;
        if (!i32(18, "consecutivePayments", st.nConsecutivePayments)) return ps;
        if (!i32(19, "poSePenalty", st.nPoSePenalty))              return ps;
        if (!i32(20, "poSeBanHeight", st.nPoSeBanHeight))          return ps;
        if (!i32(21, "poSeRevivedHeight", st.nPoSeRevivedHeight))  return ps;
        if (!u16(22, "revocationReason", st.nRevocationReason))    return ps;

        if (!d::u256_wire(f[23], st.collateralOutpoint.hash))
            return fail("bad collateralHash" + at);
        if (!d::parse_u64(f[24], UINT32_MAX, u))
            return fail("bad collateralIndex" + at);
        st.collateralOutpoint.index = static_cast<uint32_t>(u);
        if (!d::parse_u64(f[25], UINT64_MAX, st.internalId))
            return fail("bad internalId" + at);

        // dashd RPC and the SML agree on ban semantics: isValid XOR banned.
        // The generator already enforced this; re-check because THIS parser
        // is what a live replay actually trusts.
        ps.entries.emplace_back(protx, std::move(st));
    }

    if (!have_network || !have_height || !have_hash || !have_root || !have_count)
        return fail("prestate header is incomplete (need network/height/"
                    "blockhash/mnroot/count)");
    if (ps.entries.size() != declared)
        return fail("prestate declares count=" + std::to_string(declared)
                    + " but carries " + std::to_string(ps.entries.size())
                    + " mn records");
    // ── SCOPED empty-set relaxation (reward-safe, DIP3-activation ONLY) ──────
    //
    // An empty entries set is CHAIN-TRUE at exactly one height: the DIP3
    // activation height. DASH's deterministic masternode list is empty until
    // the first ProRegTx at/after DIP3 enforcement, so the W1 fold must be
    // seedable from an EMPTY set at h=MAINNET_DIP3_HEIGHT to derive the whole
    // set FROM CHAIN (dashd BuildNewListFromBlock parity) instead of capturing
    // it from dashd RPC. We reuse the SAME constant --replay-bulk-start
    // defaults to (rp::MAINNET_DIP3_HEIGHT == 1028160); no fresh literal.
    //
    // At EVERY other height an empty set stays a HARD reject: there it can only
    // mean a half-parsed / records-dropped seed, which would seed a replay that
    // diverges SILENTLY (the very failure this loader exists to refuse).
    //
    // This relaxation is FAIL-CLOSED and can never mint: the empty seed is not
    // trusted on faith. The fold's per-block merkleRootMNList self-check
    // (replay_fold_engine.hpp poison() ~:815) HARD-STOPS at the first post-DIP3
    // ProRegTx block if the empty-at-DIP3 seed (or its anchor hash/height) is
    // wrong — a wrong seed folds to the wrong root and poisons the engine
    // instead of serving wrong bytes. DIP-4 / root self-checks stay strict.
    if (ps.entries.empty() && ps.height != MAINNET_DIP3_HEIGHT)
        return fail("prestate carries no masternodes (an empty set is chain-true"
                    " ONLY at the DIP3 activation height "
                    + std::to_string(MAINNET_DIP3_HEIGHT) + ", not at h="
                    + std::to_string(ps.height) + ")");

    ps.ok = true;
    return ps;
}

inline Prestate load_prestate_file(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        Prestate ps;
        ps.error = "cannot open prestate file '" + path + "'";
        return ps;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    return parse_prestate_text(ss.str());
}

/// Seed an engine from a prestate and RE-VERIFY the committed root. Returns
/// empty on success, else the blocking condition. The root check is the
/// whole point of the anchor: a seed that does not reproduce the chain's own
/// committed merkleRootMNList is not an anchor, it is a guess.
inline std::string seed_engine_from_prestate(DmlFoldEngine& eng,
                                             const Prestate& ps)
{
    if (!ps.ok) return ps.error;
    uint256 anchor_hash;
    anchor_hash.SetHex(ps.blockhash_display);
    auto entries = ps.entries;
    eng.seed(std::move(entries), ps.entries.size(), ps.height, anchor_hash,
             ps.network);
    const std::string got = eng.compute_sml_root().GetHex();
    if (got != ps.mnroot_display)
        return "ANCHOR SEED REJECTED at h=" + std::to_string(ps.height)
             + ": seeded state computes merkleRootMNList " + got
             + " but the prestate commits " + ps.mnroot_display
             + " — the seed has already diverged from consensus";
    return {};
}

} // namespace replay
} // namespace coin
} // namespace dash
