// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// E2d (#738): the release-pinned masternode-set CHECKPOINT — the daemonless
/// cold-start seed for the payout-bearing DMN set.
///
/// ─────────────────────────────────────────────────────────────────────────
/// THIS IS A TRUST ANCHOR. READ THIS BEFORE YOU RELY ON IT.
/// ─────────────────────────────────────────────────────────────────────────
/// The checkpoint compiled into the binary is data that the c2pool release
/// build ASSERTS is the deterministic masternode set as of a specific block.
/// It is NOT derived from the chain by this node, and it CANNOT be
/// header-authenticated: the P2P Simplified MN List (DIP-0004 mnlistdiff)
/// omits `scriptPayout` and `nLastPaidHeight`, and neither field is committed
/// in `merkleRootMNList`. There is therefore no consensus commitment against
/// which a payout-bearing set can be checked. A node that cold-starts from
/// this checkpoint is TRUSTING THE RELEASE BUILD for the contents of that
/// set — exactly the trust posture of an assumeutxo/assumevalid anchor.
///
/// What IS independently verified, and what is not:
///
///   VERIFIED (locally, no trust)
///     • CHAIN POSITION. `blockhash` must equal the hash our own X11-PoW +
///       DGW-validated HeaderChain holds at `height`. A checkpoint minted on
///       another chain, another fork, or a wrong height is rejected outright.
///     • INTEGRITY. A SHA-256 digest over every non-digest line detects a
///       truncated / hand-edited / partially-applied checkpoint. (It is an
///       integrity check on the FILE, NOT a signature: anyone who can change
///       the source can recompute the digest. It catches accident, not
///       malice.)
///     • FORWARD CONSISTENCY. Every block replayed forward from `height`
///       cross-checks the anchor: MnStateMachine::apply_block projects the
///       DIP-3 payee from the anchored set and compares it against the
///       block's actual coinbase. A wrong anchor desyncs within a few blocks
///       and the bridge FAILS CLOSED — it never publishes. The anchor is
///       thus trusted at h=`height` and progressively falsifiable after it.
///
///   NOT VERIFIED (this is the trust)
///     • The membership and per-MN payout state of the set AT `height`.
///       Nothing on the wire can prove it. If the pinned bytes are wrong in
///       a way that happens not to change the projected payee for the whole
///       bridge window, the error survives.
///
/// The fully trustless alternative — replaying every block body from DIP-3
/// activation (~1.5M blocks) — is deliberately NOT built here. It remains
/// available as a later opt-in verify-mode. See
/// src/impl/dash/coin/checkpoints/README.md and the README section
/// "DASH daemonless masternode-set checkpoint".
///
/// ─────────────────────────────────────────────────────────────────────────
/// FILE FORMAT (`c2pool-dash-mn-checkpoint/1`)
/// ─────────────────────────────────────────────────────────────────────────
/// ASCII, LF-separated. Blank lines and `#` comment lines are ignored
/// everywhere EXCEPT that they are also excluded from the digest domain.
///
///   c2pool-dash-mn-checkpoint/1
///   network   <mainnet|testnet|devnet|regtest>
///   height    <uint32>                   chain height the set is current AT
///   blockhash <64 lowercase hex>         X11 block hash at `height`
///   source    <free text, one line>      provenance (who/what produced it)
///   generated <ISO-8601 UTC>             when it was produced
///   count     <uint32>                   number of `mn` lines that follow
///   digest    <64 lowercase hex>         SHA-256, see DIGEST DOMAIN
///   mn <18 fields>                       ... exactly `count` of these
///
/// `mn` line columns (space separated, all present, `-` = absent):
///    1 proTxHash            64 hex
///    2 collateralHash       64 hex
///    3 collateralIndex      uint32
///    4 type                 0 = Regular, 1 = Evo
///    5 version              uint16 (ProTxVersion)
///    6 registeredHeight     uint32
///    7 lastPaidHeight       uint32   (0 = never; dashd's -1 clamps to 0)
///    8 poseRevivedHeight    uint32   (0 = never)
///    9 poseBanHeight        uint32   (0 = not banned)
///   10 consecutivePayments  uint32
///   11 revocationReason     uint16
///   12 operatorReward       uint16   internal 0..10000 fixed point
///   13 scriptPayout         hex, REQUIRED (a payee-less MN is rejected)
///   14 scriptOperatorPayout hex or `-`
///   15 keyIDOwner           40 hex or `-`
///   16 keyIDVoting          40 hex or `-`
///   17 pubKeyOperator       96 hex (BLS) or `-`
///
/// `isValid` is DERIVED as (poseBanHeight == 0) — the same projection
/// mn_seed.hpp makes from `protx list registered true`. It is never stored.
///
/// THE ANCHOR CARRIES THE **REGISTERED** SET, NOT THE VALID SET, AND THAT IS
/// LOAD-BEARING. `protx list valid` filters PoSe-banned masternodes OUT, so in
/// a valid-filtered anchor "banned at the anchor height" and "does not exist"
/// are the SAME observation: absence. The forward replay's only insertion path
/// is ProRegTx, which a long-registered masternode will never emit again — so
/// a ProUpServTx REVIVE inside the replay window finds no entry, is dropped as
/// an unknown masternode (ApplyResult::revive_dropped_unknown), and that
/// masternode can never re-enter the DIP-3 payment queue. Our queue head then
/// stays permanently one slot ahead of dashd's, which is a served
/// bad-cb-payee. (Mainnet: proTx 7afbd798… banned at 2511957, revived by a
/// ProUpServTx in 2513357, absent from a `valid`-based 2513000 anchor; at
/// h=2515416 dashd's payee IS 7afbd798….) Carrying the banned masternodes
/// present-but-INELIGIBLE makes eligibility COMPUTED rather than implied by
/// absence, and the revive path works as written.
///
/// `count` therefore counts REGISTERED masternodes. The number comparable to
/// dashd's `protx list valid <height>` is MnStateMachine::eligible_size().
///
/// DIGEST DOMAIN: SHA-256 over every line of the file EXCEPT the `digest`
/// line itself and except blank/`#` comment lines, each line stripped of
/// trailing whitespace and terminated by a single '\n', in file order. The
/// rule is deliberately trivial so `tools/dash/gen_mn_checkpoint.py --verify`
/// and this parser can never disagree about what was committed.
///
/// ─────────────────────────────────────────────────────────────────────────
/// FAIL-CLOSED CONTRACT
/// ─────────────────────────────────────────────────────────────────────────
/// parse_mn_checkpoint() returns ok=false with a human-readable `error` for
/// EVERY defect — unknown magic, wrong network, bad digest, count mismatch,
/// duplicate proTxHash, duplicate collateral outpoint, empty scriptPayout,
/// any unparseable field, or an UNPINNED (comment-only) payload. There is no
/// partial success and no "best effort" mode: a partially-loaded masternode
/// set projects a WRONG payee, and a wrong payee is a coinbase the network
/// rejects (bad-cb-payee) — i.e. a lost block. Refusing to serve is always
/// cheaper than serving a wrong payee.
///
/// STRICTLY single-coin: src/impl/dash/coin/ only. Pure function over a
/// string — network-free, filesystem-free, KAT-pinned
/// (test/test_dash_mn_checkpoint.cpp).

#include <impl/dash/coin/mn_state_db.hpp>        // MNState
#include <impl/dash/coin/vendor/providertx.hpp>  // MnType / ProTxVersion / BLS_PUBKEY_SIZE

#include <core/log.hpp>
#include <core/uint256.hpp>

#include <btclibs/crypto/sha256.h>

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

/// The format tag this parser accepts. Bumping the trailing integer is a
/// BREAKING format change: an older binary must reject a newer file rather
/// than misread it, which the exact-string compare below guarantees.
inline constexpr const char* kMnCheckpointMagic = "c2pool-dash-mn-checkpoint/1";

struct MnCheckpoint {
    bool        ok{false};
    std::string error;          // populated iff !ok — logged verbatim
    bool        unpinned{false};// payload carries no anchor at all (release TODO)

    std::string network;        // "mainnet" / "testnet" / ...
    uint32_t    height{0};      // the set is current AS OF this height
    uint256     blockhash;      // must match our header chain at `height`
    std::string source;         // provenance string, free text
    std::string generated;      // ISO-8601 UTC
    std::string digest;         // the committed digest (lowercase hex)

    std::vector<std::pair<uint256, MNState>> entries;
};

namespace ckpt_detail {

inline bool is_hex_n(const std::string& s, size_t n)
{
    if (s.size() != n) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
              || (c >= 'A' && c <= 'F')))
            return false;
    return true;
}

inline bool hex_to_bytes(const std::string& s, std::vector<unsigned char>& out)
{
    if (s.size() % 2 != 0) return false;
    out.clear();
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = -1, lo = -1;
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        hi = nib(s[i]);
        lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

// hash160 hex -> uint160 in INTERNAL byte order (the payload bytes ARE the
// CKeyID raw bytes; SetHex would byte-reverse them). Mirrors
// mn_seed.hpp::hash160_hex_to_uint160 exactly so an RPC seed and a
// checkpoint seed produce byte-identical MNState for the same masternode.
inline uint160 hex_to_uint160(const std::string& hex)
{
    std::vector<unsigned char> b;
    if (hex.size() != 40 || !hex_to_bytes(hex, b)) return uint160();
    return uint160(b);
}

// Strict unsigned parse — no sign, no whitespace, no overflow, no trailing
// junk. strtoul silently accepts "-1" (wraps) and "12abc" (stops early);
// both would smuggle a wrong height into the payment-queue cursor.
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

inline std::string rstrip(std::string s)
{
    while (!s.empty() && (s.back() == '\r' || s.back() == ' ' || s.back() == '\t'))
        s.pop_back();
    return s;
}

// A line participates in the digest domain iff it is neither blank nor a
// `#` comment nor the `digest` line itself.
inline bool in_digest_domain(const std::string& line)
{
    if (line.empty()) return false;
    if (line[0] == '#') return false;
    if (line.rfind("digest", 0) == 0
        && (line.size() == 6 || line[6] == ' ' || line[6] == '\t'))
        return false;
    return true;
}

inline std::string sha256_hex(const std::string& data)
{
    unsigned char out[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(data.data()),
                    data.size())
             .Finalize(out);
    static const char* kHex = "0123456789abcdef";
    std::string hex;
    hex.reserve(CSHA256::OUTPUT_SIZE * 2);
    for (unsigned char c : out) {
        hex.push_back(kHex[c >> 4]);
        hex.push_back(kHex[c & 0x0f]);
    }
    return hex;
}

// key + " " + value split on the FIRST run of whitespace.
inline bool split_kv(const std::string& line, std::string& key, std::string& val)
{
    const size_t sp = line.find_first_of(" \t");
    if (sp == std::string::npos) return false;
    key = line.substr(0, sp);
    size_t v = line.find_first_not_of(" \t", sp);
    val = (v == std::string::npos) ? std::string() : line.substr(v);
    return true;
}

} // namespace ckpt_detail

/// Compute the digest a checkpoint payload commits to. Exposed so the
/// generator's `--verify` mode and the KAT can assert the identical rule.
inline std::string mn_checkpoint_digest(const std::string& payload)
{
    std::string domain;
    domain.reserve(payload.size());
    std::istringstream in(payload);
    std::string raw;
    while (std::getline(in, raw)) {
        const std::string line = ckpt_detail::rstrip(raw);
        if (!ckpt_detail::in_digest_domain(line)) continue;
        domain += line;
        domain += '\n';
    }
    return ckpt_detail::sha256_hex(domain);
}

/// Parse + fully validate a checkpoint payload.
///
/// `expected_network` is the network the node is actually running
/// ("mainnet" / "testnet" / ...). A mismatch is a hard error: a testnet
/// masternode set on mainnet would project a payee that exists nowhere.
///
/// NOTE the deliberate asymmetry with `parse_protx_list_seed`: that parser
/// takes address strings and decodes them; this one takes raw scriptPayout
/// HEX. The checkpoint is our own artifact, so there is no reason to route
/// the payee through a base58 round trip and inherit its failure modes — the
/// generator does that conversion once, at release time, where a failure is
/// a human-visible build error rather than a silent runtime degradation.
inline MnCheckpoint parse_mn_checkpoint(const std::string& payload,
                                        const std::string& expected_network)
{
    MnCheckpoint cp;

    // ── Pre-scan: is there anything here at all? ────────────────────────
    // An UNPINNED payload (the state a fresh checkout ships in) is called
    // out distinctly so the operator-facing message can say "this release
    // was built without an anchor" rather than "your file is corrupt".
    {
        bool any_content = false;
        std::istringstream in(payload);
        std::string raw;
        while (std::getline(in, raw)) {
            const std::string l = ckpt_detail::rstrip(raw);
            if (!l.empty() && l[0] != '#') { any_content = true; break; }
        }
        if (!any_content) {
            cp.unpinned = true;
            cp.error = "checkpoint is UNPINNED: this build carries no DASH"
                       " masternode-set anchor (see"
                       " src/impl/dash/coin/checkpoints/README.md — the anchor"
                       " is pinned at release time by"
                       " tools/dash/gen_mn_checkpoint.py)";
            return cp;
        }
    }

    bool     have_magic = false, have_height = false, have_hash = false;
    bool     have_count = false, have_digest = false, have_network = false;
    uint64_t declared_count = 0;
    std::set<uint256>                       seen_protx;
    std::set<std::pair<uint256, uint32_t>>  seen_collateral;

    std::istringstream in(payload);
    std::string raw;
    size_t lineno = 0;

    auto fail = [&cp](const std::string& why) -> MnCheckpoint& {
        cp.ok = false;
        cp.error = why;
        cp.entries.clear();
        return cp;
    };

    while (std::getline(in, raw)) {
        ++lineno;
        const std::string line = ckpt_detail::rstrip(raw);
        if (line.empty() || line[0] == '#') continue;

        if (!have_magic) {
            if (line != kMnCheckpointMagic)
                return fail("bad magic on line " + std::to_string(lineno)
                            + ": expected '" + kMnCheckpointMagic
                            + "', got '" + line + "'");
            have_magic = true;
            continue;
        }

        std::string key, val;
        if (!ckpt_detail::split_kv(line, key, val))
            return fail("unparseable line " + std::to_string(lineno)
                        + ": '" + line + "'");

        if (key == "network") {
            if (have_network) return fail("duplicate 'network' line");
            cp.network = val;
            have_network = true;
        } else if (key == "height") {
            if (have_height) return fail("duplicate 'height' line");
            uint64_t h = 0;
            if (!ckpt_detail::parse_u64(val, UINT32_MAX, h))
                return fail("bad height '" + val + "'");
            if (h == 0)
                return fail("height 0 is not a valid anchor (genesis has no"
                            " deterministic masternode list)");
            cp.height = static_cast<uint32_t>(h);
            have_height = true;
        } else if (key == "blockhash") {
            if (have_hash) return fail("duplicate 'blockhash' line");
            if (!ckpt_detail::is_hex_n(val, 64))
                return fail("bad blockhash '" + val + "' (want 64 hex)");
            cp.blockhash = uint256S(val);
            if (cp.blockhash.IsNull())
                return fail("blockhash is all-zero — an anchor MUST name a"
                            " real block so its chain position can be checked");
            have_hash = true;
        } else if (key == "source") {
            cp.source = val;
        } else if (key == "generated") {
            cp.generated = val;
        } else if (key == "count") {
            if (have_count) return fail("duplicate 'count' line");
            if (!ckpt_detail::parse_u64(val, 1000000, declared_count))
                return fail("bad count '" + val + "'");
            have_count = true;
        } else if (key == "digest") {
            if (have_digest) return fail("duplicate 'digest' line");
            if (!ckpt_detail::is_hex_n(val, 64))
                return fail("bad digest '" + val + "' (want 64 hex)");
            cp.digest = val;
            for (auto& c : cp.digest) c = static_cast<char>(std::tolower(c));
            have_digest = true;
        } else if (key == "mn") {
            if (!have_magic || !have_height || !have_hash || !have_count
                || !have_network)
                return fail("'mn' record on line " + std::to_string(lineno)
                            + " before the header block was complete");

            std::vector<std::string> f;
            {
                std::istringstream fs(val);
                std::string tok;
                while (fs >> tok) f.push_back(tok);
            }
            if (f.size() != 17)
                return fail("mn record on line " + std::to_string(lineno)
                            + " has " + std::to_string(f.size())
                            + " fields, want 17");

            MNState mn;
            if (!ckpt_detail::is_hex_n(f[0], 64))
                return fail("mn line " + std::to_string(lineno)
                            + ": bad proTxHash '" + f[0] + "'");
            const uint256 protx = uint256S(f[0]);
            if (!ckpt_detail::is_hex_n(f[1], 64))
                return fail("mn line " + std::to_string(lineno)
                            + ": bad collateralHash '" + f[1] + "'");
            mn.collateralOutpoint.hash = uint256S(f[1]);

            uint64_t v = 0;
            auto num = [&](size_t idx, uint64_t limit, const char* what,
                           uint64_t& dst) -> bool {
                if (!ckpt_detail::parse_u64(f[idx], limit, v)) {
                    fail("mn line " + std::to_string(lineno) + ": bad " + what
                         + " '" + f[idx] + "'");
                    return false;
                }
                dst = v;
                return true;
            };
            uint64_t tmp = 0;
            if (!num(2, UINT32_MAX, "collateralIndex", tmp)) return cp;
            mn.collateralOutpoint.index = static_cast<uint32_t>(tmp);
            if (!num(3, 1, "type", tmp)) return cp;
            mn.nType = (tmp == 1) ? vendor::MnType::EVO : vendor::MnType::REGULAR;
            if (!num(4, UINT16_MAX, "version", tmp)) return cp;
            mn.nVersion = static_cast<uint16_t>(tmp);
            if (!num(5, UINT32_MAX, "registeredHeight", tmp)) return cp;
            mn.nRegisteredHeight = static_cast<uint32_t>(tmp);
            if (!num(6, UINT32_MAX, "lastPaidHeight", tmp)) return cp;
            mn.nLastPaidHeight = static_cast<uint32_t>(tmp);
            if (!num(7, UINT32_MAX, "poseRevivedHeight", tmp)) return cp;
            mn.nPoSeRevivedHeight = static_cast<uint32_t>(tmp);
            if (!num(8, UINT32_MAX, "poseBanHeight", tmp)) return cp;
            mn.nPoSeBanHeight = static_cast<uint32_t>(tmp);
            if (!num(9, UINT32_MAX, "consecutivePayments", tmp)) return cp;
            mn.nConsecutivePayments = static_cast<uint32_t>(tmp);
            if (!num(10, UINT16_MAX, "revocationReason", tmp)) return cp;
            mn.nRevocationReason = static_cast<uint16_t>(tmp);
            if (!num(11, 10000, "operatorReward", tmp)) return cp;
            mn.nOperatorReward = static_cast<uint16_t>(tmp);

            // THE payee keystone. Empty is NOT tolerated: an MN with no
            // payout script still occupies a slot in the DIP-3 queue, so a
            // blank one would make our projection disagree with dashd's at
            // the moment it is scheduled — a served bad-cb-payee.
            if (f[12] == "-" || f[12].empty()
                || !ckpt_detail::hex_to_bytes(f[12], mn.scriptPayout.m_data)
                || mn.scriptPayout.m_data.empty())
                return fail("mn line " + std::to_string(lineno)
                            + ": missing/undecodable scriptPayout '" + f[12]
                            + "' (fail-closed: a payee-less MN would project"
                              " a wrong payee)");
            if (f[13] != "-"
                && !ckpt_detail::hex_to_bytes(f[13], mn.scriptOperatorPayout.m_data))
                return fail("mn line " + std::to_string(lineno)
                            + ": bad scriptOperatorPayout '" + f[13] + "'");
            if (f[14] != "-") {
                if (!ckpt_detail::is_hex_n(f[14], 40))
                    return fail("mn line " + std::to_string(lineno)
                                + ": bad keyIDOwner '" + f[14] + "'");
                mn.keyIDOwner = ckpt_detail::hex_to_uint160(f[14]);
            }
            if (f[15] != "-") {
                if (!ckpt_detail::is_hex_n(f[15], 40))
                    return fail("mn line " + std::to_string(lineno)
                                + ": bad keyIDVoting '" + f[15] + "'");
                mn.keyIDVoting = ckpt_detail::hex_to_uint160(f[15]);
            }
            if (f[16] != "-") {
                std::vector<unsigned char> pk;
                if (!ckpt_detail::is_hex_n(f[16], vendor::BLS_PUBKEY_SIZE * 2)
                    || !ckpt_detail::hex_to_bytes(f[16], pk))
                    return fail("mn line " + std::to_string(lineno)
                                + ": bad pubKeyOperator '" + f[16] + "'");
                for (size_t i = 0; i < vendor::BLS_PUBKEY_SIZE; ++i)
                    mn.pubKeyOperator[i] = pk[i];
            }

            // DERIVED, never stored — same projection mn_seed.hpp makes.
            mn.isValid = (mn.nPoSeBanHeight == 0);

            // The checkpoint format is generated from `protx list registered
            // true` and carries the payout split EXPLICITLY (field 11 = bps,
            // field 13 = operator script, `-` = provably unset). A row that
            // reaches here has both fields validated above — the payout SET
            // is proven (incident h=2516595: this very anchor carried mn
            // 0037c2c5… bps=800 + its operator script; the omission was in
            // the consumer, not the data).
            mn.payoutSplitProvenance = MNState::SPLIT_KNOWN;

            if (!seen_protx.insert(protx).second)
                return fail("duplicate proTxHash " + protx.GetHex().substr(0, 16)
                            + " on line " + std::to_string(lineno));
            // MnStateMachine::load() keys a collateral index by outpoint, so
            // duplicates would silently shadow each other there. DIP-3
            // consensus makes collaterals unique; a duplicate means this is
            // not a real masternode set.
            if (!seen_collateral.emplace(mn.collateralOutpoint.hash,
                                         mn.collateralOutpoint.index).second)
                return fail("duplicate collateral outpoint on line "
                            + std::to_string(lineno)
                            + " — not a real DIP-3 set");

            cp.entries.emplace_back(protx, std::move(mn));
        } else {
            // Unknown keys are REJECTED, not skipped: a future format may
            // add a semantically load-bearing key, and an old binary that
            // ignored it would load a set it does not actually understand.
            return fail("unknown key '" + key + "' on line "
                        + std::to_string(lineno)
                        + " (format is " + kMnCheckpointMagic + ")");
        }
    }

    if (!have_magic)  return fail("empty/headerless checkpoint payload");
    if (!have_network) return fail("missing 'network' line");
    if (!have_height) return fail("missing 'height' line");
    if (!have_hash)   return fail("missing 'blockhash' line");
    if (!have_count)  return fail("missing 'count' line");
    if (!have_digest) return fail("missing 'digest' line");

    if (cp.network != expected_network)
        return fail("network mismatch: checkpoint is for '" + cp.network
                    + "' but this node is running '" + expected_network + "'");

    if (cp.entries.size() != declared_count)
        return fail("count mismatch: header declares "
                    + std::to_string(declared_count) + " masternodes, found "
                    + std::to_string(cp.entries.size())
                    + " (truncated or over-long checkpoint)");

    if (cp.entries.empty())
        return fail("checkpoint declares 0 masternodes — an empty set cannot"
                    " back a payee (fail-closed)");

    const std::string actual = mn_checkpoint_digest(payload);
    if (actual != cp.digest)
        return fail("DIGEST MISMATCH: checkpoint declares " + cp.digest
                    + " but its contents hash to " + actual
                    + " — the checkpoint has been edited or truncated;"
                      " regenerate it with tools/dash/gen_mn_checkpoint.py");

    cp.ok = true;
    return cp;
}

} // namespace coin
} // namespace dash
