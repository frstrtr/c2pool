// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// SELF-DERIVED masternode-set checkpoint DUMP (dashd-cut, operator decision
/// 2026-08-17).
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHAT THIS IS, AND WHY IT IS NOT gen_mn_checkpoint.py
/// ─────────────────────────────────────────────────────────────────────────
/// tools/dash/gen_mn_checkpoint.py mints the checkpoint .inc from a dashd
/// `protx list registered true <height>` SNAPSHOT — a set dashd itself never
/// consumes, obtained over RPC. The two payout-bearing fields the DIP-4 wire
/// does NOT carry and merkleRootMNList does NOT commit — `scriptPayout` and
/// `nLastPaidHeight` — are therefore TRUSTED from that snapshot.
///
/// This emitter produces the SAME checkpoint .inc payload (byte-identical in
/// the digest domain, so the runtime parser in mn_checkpoint.hpp accepts it
/// identically), but sourced entirely from the FOLD's own state: a
/// DmlFoldEngine that replayed every block body from DIP-3 activation forward,
/// self-checking each block's computed merkleRootMNList against that block's
/// own committed cbTx root (replay_fold_consumer.hpp). `scriptPayout` is taken
/// VERBATIM from the ProRegTx/ProUpRegTx body the fold replayed
/// (chain-authentic); `nLastPaidHeight` is the payee bookkeeping the fold
/// already keeps (dashd BuildNewListFromBlock parity). No dashd, no RPC, no
/// trusted snapshot.
///
/// REWARD-SAFETY comes from REUSE, not from new code:
///   * the 17-field order + conversions are the SAME the runtime parser reads
///     (mn_checkpoint.hpp:66-83, 417-505) and gen_mn_checkpoint.py writes
///     (build_mn_record), so a dumped set == the parser's expectation by
///     construction;
///   * the digest is the SAME function the parser and the generator agree on
///     (mn_checkpoint_digest, mn_checkpoint.hpp:280);
///   * write_mn_checkpoint_inc() PARSES its own output through
///     parse_mn_checkpoint() before writing — it never emits a file the
///     runtime would refuse;
///   * REGISTERED, not valid-filtered: every entry the fold still holds is
///     emitted, PoSe-banned ones included (they carry poseBanHeight>0, from
///     which the parser re-derives isValid == false). This is the load-bearing
///     property mn_checkpoint.hpp:88-104 spells out.
///
/// ─────────────────────────────────────────────────────────────────────────
/// THE ONE LOAD-BEARING BYTE-ORDER SUBTLETY
/// ─────────────────────────────────────────────────────────────────────────
/// proTxHash / collateralHash are uint256 HASHES the parser reads via
/// uint256S (SetHex → byte-reversed into internal storage). Their .inc column
/// is DISPLAY hex, so we emit them with GetHex() (which reverses back).
///
/// keyIDOwner / keyIDVoting are uint160 CKeyIDs whose .inc column is the RAW
/// hash160 bytes (mn_checkpoint.hpp:201-210 hex_to_uint160 stores the payload
/// bytes DIRECTLY, NOT reversed). We therefore emit them FORWARD (m_data
/// order), NOT GetHex(). GetHex() here would silently byte-reverse the CKeyID
/// and the round trip would fail. Same for pubKeyOperator (a raw 48-byte BLS
/// blob) and the scriptPayout/scriptOperatorPayout byte vectors.
///
/// And the SORT: gen_mn_checkpoint.py sorts records by proTxHash DISPLAY hex
/// ascending. std::map<uint256,...> iterates in INTERNAL (memcmp-LE) order,
/// which is NOT the display order, so we re-sort the formatted lines by the
/// display-hex proTxHash string — never trust the map iteration order for the
/// .inc line order.
///
/// STRICTLY single-coin (src/impl/dash/coin/ only). Header-only, filesystem
/// touch confined to write_mn_checkpoint_inc(). KAT-pinned
/// (test/test_dash_mn_checkpoint.cpp::DashMnCheckpointDump).

#include <impl/dash/coin/replay_fold_engine.hpp>   // DmlFoldEngine, ReplayMNState
#include <impl/dash/coin/mn_checkpoint.hpp>         // mn_checkpoint_digest, kMnCheckpointMagic, parse_mn_checkpoint
#include <impl/dash/coin/vendor/providertx.hpp>     // MnType

#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

namespace mn_dump_detail {

inline std::string hex_lower(const unsigned char* p, size_t n)
{
    static const char* kHex = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(kHex[p[i] >> 4]);
        s.push_back(kHex[p[i] & 0x0f]);
    }
    return s;
}

// FORWARD (little-endian limb) hex of a base_uint — the raw CKeyID bytes the
// checkpoint columns carry. mn_checkpoint.hpp::hex_to_uint160 builds the
// uint160 with `pn[x] = ReadLE32(bytes + x*4)` (core/uint256.cpp vch ctor), so
// the original bytes are recovered with the matching WriteLE32 per limb. NOT
// GetHex(), which emits BE / display order. See the header comment "THE ONE
// LOAD-BEARING BYTE-ORDER SUBTLETY".
template <unsigned int BITS>
inline std::string hex_forward(const ::base_uint<BITS>& b)
{
    unsigned char bytes[::base_uint<BITS>::BYTES];
    for (int x = 0; x < ::base_uint<BITS>::WIDTH; ++x) {
        const uint32_t v = b.pn[x];
        bytes[x * 4 + 0] = static_cast<unsigned char>(v & 0xff);
        bytes[x * 4 + 1] = static_cast<unsigned char>((v >> 8) & 0xff);
        bytes[x * 4 + 2] = static_cast<unsigned char>((v >> 16) & 0xff);
        bytes[x * 4 + 3] = static_cast<unsigned char>((v >> 24) & 0xff);
    }
    return hex_lower(bytes, static_cast<size_t>(::base_uint<BITS>::BYTES));
}

template <unsigned int BITS>
inline bool base_uint_is_null(const ::base_uint<BITS>& b)
{
    for (int x = 0; x < ::base_uint<BITS>::WIDTH; ++x)
        if (b.pn[x]) return false;
    return true;
}

inline bool blob_is_null(const unsigned char* p, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        if (p[i]) return false;
    return true;
}

// dashd's -1 "never" sentinel (and any negative) clamps to 0, byte-exact with
// gen_mn_checkpoint.py::_clamp_height. ReplayMNState carries these as int32_t
// with NEVER == -1 (replay_fold_engine.hpp:186), so a non-banned MN's
// nPoSeBanHeight == -1 emits as 0 and the parser derives isValid == true.
inline int32_t clamp_height(int32_t v) { return v > 0 ? v : 0; }

// ISO-8601 UTC, matching gen_mn_checkpoint.py::_iso_now ("%Y-%m-%dT%H:%M:%SZ").
inline std::string iso8601_utc_now()
{
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
#if defined(_WIN32)
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return std::string(buf);
}

// The .inc C-string-literal wrapper for one payload line, byte-exact with
// gen_mn_checkpoint.py::_c_literal: escape backslash and quote, append \n.
inline std::string c_literal(const std::string& line)
{
    std::string s;
    s.reserve(line.size() + 6);
    s.push_back('"');
    for (char c : line) {
        if (c == '\\') s += "\\\\";
        else if (c == '"') s += "\\\"";
        else s.push_back(c);
    }
    s += "\\n\"";
    return s;
}

// The generated-file banner. The payload it wraps is byte-identical to the
// generator's; this comment is NOT — it names the self-derived provenance.
// It is stripped from the digest domain (mn_checkpoint.hpp in_digest_domain)
// AND by gen_mn_checkpoint.py::unwrap_inc (both drop `//` / comment lines), so
// it is not load-bearing and cannot change the loaded set or the digest.
inline constexpr const char* kSelfDerivedIncHeader =
    "// SPDX-License-Identifier: AGPL-3.0-or-later\n"
    "//\n"
    "// GENERATED FILE -- DO NOT EDIT BY HAND.\n"
    "// Self-derived from chain by c2pool --replay-bulk (dashd BuildNewListFromBlock\n"
    "// parity), NOT captured from a dashd `protx list` snapshot. The trailing\n"
    "// `digest` line commits every other line, so a hand edit is rejected at load\n"
    "// time.\n"
    "//\n"
    "// THIS IS A TRUST ANCHOR. See src/impl/dash/coin/checkpoints/README.md and\n"
    "// the \"DASH daemonless masternode-set checkpoint\" section of README.md.\n"
    "//\n";

} // namespace mn_dump_detail

/// One `mn` .inc line for a registered masternode, in the authoritative
/// 17-field order (mn_checkpoint.hpp:66-83). REUSED by the dumper and the KAT.
inline std::string emit_mn_record_line(const uint256& protx,
                                       const replay::ReplayMNState& st)
{
    using namespace mn_dump_detail;
    std::ostringstream o;
    o << "mn "
      << protx.GetHex() << ' '                                  //  1 proTxHash (display)
      << st.collateralOutpoint.hash.GetHex() << ' '            //  2 collateralHash (display)
      << st.collateralOutpoint.index << ' '                    //  3 collateralIndex
      << ((st.nType == vendor::MnType::EVO) ? 1 : 0) << ' '    //  4 type
      << st.nVersion << ' '                                    //  5 version
      << clamp_height(st.nRegisteredHeight) << ' '             //  6 registeredHeight
      << clamp_height(st.nLastPaidHeight) << ' '               //  7 lastPaidHeight
      << clamp_height(st.nPoSeRevivedHeight) << ' '            //  8 poseRevivedHeight
      << clamp_height(st.nPoSeBanHeight) << ' '                //  9 poseBanHeight
      << clamp_height(st.nConsecutivePayments) << ' '          // 10 consecutivePayments
      << st.nRevocationReason << ' '                           // 11 revocationReason
      << st.nOperatorReward << ' '                             // 12 operatorReward (bps)
      // 13 scriptPayout — REQUIRED, verbatim ProRegTx bytes (chain-authentic).
      << hex_lower(st.scriptPayout.m_data.data(), st.scriptPayout.m_data.size()) << ' ';
    // 14 scriptOperatorPayout — `-` when unset.
    if (st.scriptOperatorPayout.m_data.empty())
        o << "- ";
    else
        o << hex_lower(st.scriptOperatorPayout.m_data.data(),
                       st.scriptOperatorPayout.m_data.size()) << ' ';
    // 15 keyIDOwner — FORWARD hash160 bytes, `-` when null.
    if (base_uint_is_null(st.keyIDOwner))
        o << "- ";
    else
        o << hex_forward(st.keyIDOwner) << ' ';
    // 16 keyIDVoting — FORWARD hash160 bytes, `-` when null.
    if (base_uint_is_null(st.keyIDVoting))
        o << "- ";
    else
        o << hex_forward(st.keyIDVoting) << ' ';
    // 17 pubKeyOperator — FORWARD 48-byte BLS blob, `-` when null.
    if (blob_is_null(st.pubKeyOperator.data(), st.pubKeyOperator.size()))
        o << "-";
    else
        o << hex_lower(st.pubKeyOperator.data(), st.pubKeyOperator.size());
    return o.str();
}

struct MnCheckpointDump {
    bool        ok{false};
    std::string error;      // populated iff !ok
    std::string payload;    // the raw checkpoint payload (what parse_mn_checkpoint reads)
    std::string inc;        // the .inc file (C-string-literal wrapped payload)
    std::string digest;     // the SHA-256 the payload commits to
    uint32_t    height{0};
    uint64_t    count{0};
};

/// Serialize a fold engine's REGISTERED masternode set at its current cursor
/// height to the checkpoint payload + .inc. `source` becomes the `source`
/// line (the operator decision requires it to name the self-derived
/// provenance, e.g. "self-derived from chain via c2pool --replay-bulk at H");
/// `generated` is the ISO-8601 timestamp (mn_dump_detail::iso8601_utc_now()).
inline MnCheckpointDump emit_mn_checkpoint_dump(const replay::DmlFoldEngine& engine,
                                                const std::string& source,
                                                const std::string& generated)
{
    using namespace mn_dump_detail;
    MnCheckpointDump r;
    r.height = engine.height();

    if (engine.poisoned()) {
        r.error = "fold engine is POISONED (" + engine.poison_reason()
                + ") — refusing to dump a diverged set";
        return r;
    }
    if (engine.size() == 0) {
        r.error = "fold holds 0 registered masternodes — refusing to write an"
                  " empty anchor (fail-closed)";
        return r;
    }

    // Format every registered MN; refuse a payee-less one exactly as the
    // runtime parser would (mn_checkpoint.hpp:470-480).
    std::vector<std::pair<std::string, std::string>> rows;  // (protx display hex, line)
    rows.reserve(engine.size());
    for (const auto& [protx, st] : engine.entries()) {
        if (st.scriptPayout.m_data.empty()) {
            r.error = "registered MN " + protx.GetHex().substr(0, 16)
                    + " carries an empty scriptPayout — a payee-less MN would"
                      " project a wrong payee (fail-closed)";
            return r;
        }
        rows.emplace_back(protx.GetHex(), emit_mn_record_line(protx, st));
    }
    // Sort by proTxHash DISPLAY hex ascending — byte-parity with
    // gen_mn_checkpoint.py `records.sort(key=lambda r: r[0])`. Map order is
    // internal-byte order and would NOT match.
    std::sort(rows.begin(), rows.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    std::vector<std::string> mn_lines;
    mn_lines.reserve(rows.size());
    for (auto& kv : rows) mn_lines.push_back(std::move(kv.second));

    // 7-line header, exact order/formatting of gen_mn_checkpoint.py.
    std::vector<std::string> header = {
        std::string(kMnCheckpointMagic),
        "network " + engine.network(),
        "height " + std::to_string(engine.height()),
        "blockhash " + engine.block_hash().GetHex(),
        "source " + source,
        "generated " + generated,
        "count " + std::to_string(mn_lines.size()),
    };

    // Digest over header + mn lines (the digest line itself is never in the
    // domain — mn_checkpoint_digest enforces that anyway).
    std::string domain;
    for (const auto& l : header)   { domain += l; domain += '\n'; }
    for (const auto& l : mn_lines) { domain += l; domain += '\n'; }
    r.digest = mn_checkpoint_digest(domain);

    // Raw payload = header + digest line + mn lines + a trailing blank line
    // (the trailing `"\n"` gen_mn_checkpoint.py::write_inc appends).
    std::string payload;
    for (const auto& l : header)   { payload += l; payload += '\n'; }
    payload += "digest " + r.digest + '\n';
    for (const auto& l : mn_lines) { payload += l; payload += '\n'; }
    payload += '\n';
    r.payload = std::move(payload);

    // .inc = banner + blank + C-string-literal per payload line + trailing
    // `"\n"`, byte-identical to gen_mn_checkpoint.py::write_inc EXCEPT the
    // leading // banner (not in the digest domain; see kSelfDerivedIncHeader).
    std::string inc = kSelfDerivedIncHeader;
    inc += "\n";
    for (const auto& l : header)   { inc += c_literal(l);                 inc += '\n'; }
    inc += c_literal("digest " + r.digest); inc += '\n';
    for (const auto& l : mn_lines) { inc += c_literal(l);                 inc += '\n'; }
    inc += "\"\\n\"\n";
    r.inc = std::move(inc);

    r.count = mn_lines.size();
    r.ok = true;
    return r;
}

/// Dump + SELF-VERIFY + write the .inc. Never writes a file the runtime parser
/// would refuse: the payload is round-tripped through parse_mn_checkpoint()
/// (with the engine's own network) before the file is opened. Returns true on
/// success; on failure `error` names the blocking condition and no file is
/// written (or a partial write is reported).
inline bool write_mn_checkpoint_inc(const replay::DmlFoldEngine& engine,
                                    const std::string& path,
                                    const std::string& source,
                                    const std::string& generated,
                                    std::string& error)
{
    MnCheckpointDump d = emit_mn_checkpoint_dump(engine, source, generated);
    if (!d.ok) { error = d.error; return false; }

    // The reward-safety gate: our own output must parse clean under the very
    // parser the runtime cold-start uses, or we do not ship it.
    MnCheckpoint cp = parse_mn_checkpoint(d.payload, engine.network());
    if (!cp.ok) {
        error = "self-check FAILED — the dumped payload was rejected by"
                " parse_mn_checkpoint(): " + cp.error;
        return false;
    }
    if (cp.entries.size() != d.count) {
        error = "self-check FAILED — parsed " + std::to_string(cp.entries.size())
              + " entries, dumped " + std::to_string(d.count);
        return false;
    }

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) { error = "cannot open '" + path + "' for writing"; return false; }
    f << d.inc;
    f.flush();
    if (!f.good()) { error = "write to '" + path + "' failed"; return false; }
    return true;
}

} // namespace coin
} // namespace dash
