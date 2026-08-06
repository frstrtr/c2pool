// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Daemonless chain queries for DASH — getbestblockhash / getblockhash /
/// getblockchaininfo answered from the PoW-validated header chain we already
/// hold on disk, instead of from an external dashd.
///
/// WHY THESE THREE, AND ONLY THESE THREE
/// ------------------------------------
/// HeaderChain (header_chain.hpp) is an SPV header chain: every entry past the
/// anchor carries a real X11 PoW check plus a DarkGravityWave-v3 difficulty
/// check, is indexed by height on the active branch, and is persisted to
/// LevelDB. That is precisely the state the three queries below need:
///
///   getbestblockhash   -> HeaderChain::tip()->hash
///   getblockhash <h>   -> HeaderChain::get_header_by_height(h)->hash
///   getblockchaininfo  -> chain name / tip height / tip hash / tip time
///                         + an HONEST sync indicator
///
/// It is NOT enough for the other six daemon RPCs (getblock, getpeerinfo,
/// getrawmempool, getnetworkinfo, getmininginfo, protx) — those need block
/// bodies, peer tables, a mempool or the masternode set, none of which the
/// header chain owns. This header deliberately answers three and no more.
///
/// WHAT THIS FILE REFUSES TO DO
/// ---------------------------
/// A field that cannot be sourced from owned state is OMITTED and listed in
/// `unavailable` with the reason — it is never emitted as a plausible zero.
/// Three concrete cases this actually hits in production:
///
///  1. `chainwork`. HeaderChain seeds its anchor entry (fast-start checkpoint,
///     dynamic checkpoint, or genesis stub) with chain_work = 1, so
///     cumulative_work() is work-ABOVE-THE-ANCHOR, not dashd's absolute
///     chainwork. It is never comparable to a daemon's value, so it is never
///     emitted.
///  2. `difficulty` / `mediantime` at a synthetic anchor. A checkpoint entry
///     has a DEFAULT-CONSTRUCTED header: m_bits == 0, m_timestamp == 0.
///     Deriving difficulty from bits==0 divides by a null target and
///     median_time_past() returns 0. Both would be fabricated zeros, so both
///     are withheld until a real header lands on top.
///  3. Everything under a stale tip. When the tip is older than
///     TIP_MAX_AGE_SECONDS we do not know the network best block, so
///     bestblockhash/blocks/headers move OUT of the answer and into `stale`,
///     clearly labelled, with the measured age and the threshold.

#include "header_chain.hpp"

#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

namespace dash {
namespace coin {
namespace chain_rpc {

/// Tip-age window separating "our header chain tracks the network" from "we
/// are behind". Mirrors HeaderChain::is_synced()'s 24 h window; the
/// SyncStatusMatchesHeaderChainIsSynced test asserts the two never drift.
inline constexpr int64_t TIP_MAX_AGE_SECONDS = 86400;

/// Heights within this many blocks of a STALE tip are not served by
/// getblockhash: a chain we know is behind may still be reorged across its
/// own last few blocks, so those hashes are not yet ours to assert. Buried
/// heights below the margin are PoW-final enough to answer regardless.
inline constexpr uint32_t STALE_TIP_REORG_MARGIN = 6;

/// A checkpoint/genesis stub entry is injected WITHOUT a real header (see
/// HeaderChain::init and set_dynamic_checkpoint): m_bits and m_timestamp are
/// default-constructed. Real headers always carry a nonzero compact target —
/// bits == 0 encodes a zero target, which no valid block can satisfy — so
/// bits == 0 is an exact synthetic-anchor discriminator.
inline bool is_synthetic_anchor(const IndexEntry& e) { return e.header.m_bits == 0; }

inline std::string hex8(uint32_t v) {
    char b[16];
    std::snprintf(b, sizeof b, "%08x", v);
    return std::string(b);
}

/// What we know about tip freshness, with the numbers that decided it.
struct SyncStatus {
    bool     has_tip{false};
    bool     synced{false};
    bool     tip_is_synthetic_anchor{false};
    uint32_t tip_height{0};
    uint32_t tip_time{0};
    int64_t  tip_age_seconds{0};
    int64_t  max_age_seconds{TIP_MAX_AGE_SECONDS};
    uint256  tip_hash;
    /// Empty when synced. Otherwise names the condition, the measured value
    /// and the threshold — never a bare "not synced".
    std::string blocked_by;
};

inline uint32_t now_unix() { return static_cast<uint32_t>(std::time(nullptr)); }

/// Freshness of the header chain, computed only from HeaderChain's public API
/// so this file needs no edit to header_chain.hpp.
inline SyncStatus sync_status(const HeaderChain& hc, uint32_t now = now_unix())
{
    SyncStatus s;
    auto t = hc.tip();
    if (!t) {
        s.blocked_by = "header chain has no tip (0 headers indexed, threshold >=1)";
        return s;
    }
    s.has_tip    = true;
    s.tip_hash   = t->hash;
    s.tip_height = t->height;
    s.tip_time   = t->header.m_timestamp;
    s.tip_is_synthetic_anchor = is_synthetic_anchor(*t);

    if (s.tip_is_synthetic_anchor) {
        s.blocked_by = "tip is a synthetic anchor (checkpoint/genesis stub at height "
                     + std::to_string(s.tip_height)
                     + " with bits=0, threshold: a real header must be connected)";
        return s;
    }

    s.tip_age_seconds = static_cast<int64_t>(now) - static_cast<int64_t>(s.tip_time);
    if (s.tip_age_seconds >= s.max_age_seconds) {
        s.blocked_by = "tip age " + std::to_string(s.tip_age_seconds)
                     + "s >= threshold " + std::to_string(s.max_age_seconds)
                     + "s (tip height " + std::to_string(s.tip_height)
                     + ", tip time " + std::to_string(s.tip_time) + ")";
        return s;
    }
    s.synced = true;
    return s;
}

/// Lowest height present in the active-branch height index. HeaderChain
/// indexes [anchor .. tip] contiguously (rebuild_height_index walks prev_hash
/// from the tip; linear extension appends), so a binary search finds the
/// anchor in ~log2(len) lookups rather than walking the whole chain.
inline std::optional<uint32_t> first_indexed_height(const HeaderChain& hc)
{
    auto t = hc.tip();
    if (!t) return std::nullopt;
    uint32_t lo = 0, hi = t->height;   // hi is known present
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (hc.get_header_by_height(mid)) hi = mid;
        else                              lo = mid + 1;
    }
    return lo;
}

/// One query outcome. `available == false` always carries a reason naming the
/// blocking condition, the measured value and the threshold.
struct Answer {
    bool           available{false};
    nlohmann::json value;
    std::string    unavailable_reason;

    static Answer ok(nlohmann::json v) { Answer a; a.available = true; a.value = std::move(v); return a; }
    static Answer no(std::string why)  { Answer a; a.unavailable_reason = std::move(why); return a; }
};

/// The daemonless answer source, echoed on every response so a consumer can
/// never confuse it with a real dashd reply.
inline constexpr const char* SOURCE_TAG = "c2pool-embedded-header-chain";

/// ── THE REFUSAL CONTRACT ────────────────────────────────────────────────────
///
/// An unwired seam in this tree used to answer with a well-formed EMPTY
/// document under HTTP 200 (core's fallback stubs: web_server.cpp:2907 window,
/// :3313 delta). That is why the DASH dashboard drew blank panels for months
/// with no error in the UI, no line in the log and nothing red in CI. The
/// lesson generalises:
///
///     ABSENCE OF DATA AND ABSENCE OF CAPABILITY ARE DIFFERENT ANSWERS
///     AND MUST NEVER SHARE A REPRESENTATION.
///
/// "This block has no transactions we can show you" (empty) and "this node
/// cannot show transactions at all" (incapable) look identical if both are
/// `{"tx":[]}` with status 200. So a refusal here is built to be impossible to
/// mistake for emptiness, by a machine AND by a human:
///
///   machine — HTTP 501 Not Implemented, plus a `code` field naming the
///             missing capability as a stable enum. No successful answer in
///             this file ever carries `code`, and no empty collection can
///             synthesise one. A caller's whole check is:
///                 if (status === 501 || body.code) -> capability refusal
///             501 is chosen deliberately over 404: 404 means "that block does
///             not exist", which is a statement about the CHAIN. 501 means
///             "this node does not implement that", which is a statement about
///             THIS NODE. Those are different facts and callers act on them
///             differently.
///
///   human   — `error` is a sentence naming the blocking condition, what we DO
///             retain, and the two concrete remedies. Never a bare "failed".
///
/// A partially-answerable query (getblock verbosity 1: we own every header
/// field but not the transaction list) is NOT a refusal. It answers 200 with
/// `partial: true` and lists each withheld field under `unavailable` with its
/// reason — the same shape getblockchaininfo has always used. Critically the
/// withheld fields are ABSENT, never emitted as `[]` or `0`: a consumer that
/// blindly reads `result.tx.length` must throw, not silently render an empty
/// transaction table. Emitting `tx: []` there would recreate the exact bug
/// this contract exists to prevent.

/// Stable machine-readable refusal codes. Additive only — callers match on
/// these strings.
inline constexpr const char* CODE_REQUIRES_BLOCK_BODIES = "REQUIRES_BLOCK_BODIES";
inline constexpr const char* CODE_REQUIRES_TX_INDEX     = "REQUIRES_TX_INDEX";
inline constexpr const char* CODE_UNKNOWN_METHOD        = "UNKNOWN_METHOD";
inline constexpr const char* CODE_BAD_PARAMS            = "BAD_PARAMS";
inline constexpr const char* CODE_CHAIN_STATE           = "CHAIN_STATE";

/// What this node retains today. Emitted on every refusal so the answer is
/// self-describing without the caller consulting docs.
inline constexpr const char* RETAINED_HEADERS_ONLY = "headers-only";

/// HTTP status a refusal must be served with. Kept here, next to the codes, so
/// the transport cannot drift from the contract.
inline constexpr int REFUSAL_HTTP_STATUS = 501;

/// Build the refusal envelope. `remedies` names what would make the query
/// answerable — the operator's product choice is explicit in the payload
/// itself, not buried in documentation.
inline nlohmann::json refusal(const std::string& method,
                              const char*        code,
                              const std::string& reason,
                              std::vector<std::string> remedies = {})
{
    nlohmann::json r;
    r["error"]              = reason;
    // Retained for the callers of the original three queries, which already
    // read this key.
    r["unavailable_reason"] = reason;
    r["code"]               = code;
    r["method"]             = method;
    r["source"]             = SOURCE_TAG;
    r["retained"]           = RETAINED_HEADERS_ONLY;
    r["http_status"]        = REFUSAL_HTTP_STATUS;
    if (!remedies.empty()) r["requires"] = remedies;
    return r;
}

/// The two ways an operator can make body-backed queries work. Symmetric by
/// design: one costs an external process, the other costs disk.
inline std::vector<std::string> body_remedies()
{
    return {"external-daemon-rpc", "archive-mode"};
}

/// Reason text shared by every body-requiring query, so the wording cannot
/// drift between endpoints.
inline std::string body_reason(const std::string& what)
{
    return what + " requires transaction bodies; this node retains block "
                  "HEADERS ONLY (X11+DGW validated, genesis..tip). Replay "
                  "streams every block body through the fold and prunes it "
                  "immediately, so no body store exists. Remedies: connect an "
                  "external daemon RPC, or enable archive mode to retain "
                  "bodies (materially larger disk footprint).";
}

/// getbestblockhash. Answerable only while the chain is synced: the tip of a
/// chain we know is behind is not the network best block, and returning it
/// anyway is exactly the stale answer this path exists to avoid.
inline Answer getbestblockhash(const HeaderChain& hc, uint32_t now = now_unix())
{
    auto s = sync_status(hc, now);
    if (!s.synced)
        return Answer::no("getbestblockhash withheld: " + s.blocked_by);
    return Answer::ok(s.tip_hash.GetHex());
}

/// getblockhash <height>. Answerable for any height on the active branch that
/// we actually hold, i.e. [anchor .. tip]. Below the anchor the header is not
/// ours to serve (fast-start skipped it); above the tip it does not exist yet.
/// Within STALE_TIP_REORG_MARGIN of a stale tip we decline rather than assert
/// a hash the network may already have reorged away.
inline Answer getblockhash(const HeaderChain& hc, uint32_t height,
                           uint32_t now = now_unix())
{
    auto s = sync_status(hc, now);
    if (!s.has_tip)
        return Answer::no("getblockhash withheld: " + s.blocked_by);

    if (height > s.tip_height)
        return Answer::no("getblockhash withheld: requested height "
                          + std::to_string(height) + " above owned tip height "
                          + std::to_string(s.tip_height)
                          + " (threshold: height <= tip height)");

    auto e = hc.get_header_by_height(height);
    if (!e) {
        auto anchor = first_indexed_height(hc);
        return Answer::no("getblockhash withheld: requested height "
                          + std::to_string(height)
                          + " below owned anchor height "
                          + (anchor ? std::to_string(*anchor) : std::string("n/a"))
                          + " (threshold: height >= anchor height; headers below "
                            "the fast-start anchor were never downloaded)");
    }

    if (!s.synced && height + STALE_TIP_REORG_MARGIN > s.tip_height)
        return Answer::no("getblockhash withheld: height " + std::to_string(height)
                          + " is within " + std::to_string(STALE_TIP_REORG_MARGIN)
                          + " of a tip that is not synced (tip height "
                          + std::to_string(s.tip_height) + "); " + s.blocked_by);

    if (is_synthetic_anchor(*e))
        return Answer::no("getblockhash withheld: height " + std::to_string(height)
                          + " is the synthetic anchor entry (bits=0, no real "
                            "header connected; threshold: a real header at this height)");

    return Answer::ok(e->hash.GetHex());
}

/// getblockchaininfo. Emits only fields backed by owned state; every field we
/// cannot source is listed under `unavailable` with its reason and is NOT
/// emitted as a zero. When the tip is stale, blocks/headers/bestblockhash move
/// into `stale` so an operator still sees where we are without any consumer
/// mistaking it for the network tip.
inline nlohmann::json getblockchaininfo(const HeaderChain& hc,
                                        uint32_t now = now_unix())
{
    const auto& p = hc.params();
    auto s = sync_status(hc, now);

    nlohmann::json r;
    nlohmann::json unavailable = nlohmann::json::object();

    r["chain"]  = p.allow_min_difficulty ? "test" : "main";
    r["source"] = SOURCE_TAG;
    // SPV: headers are PoW+DGW validated, block BODIES are not fully validated
    // here. Say so, so `blocks` is never read as dashd's fully-validated height.
    r["validation"] = "x11-pow + dgw-v3 headers (SPV; block bodies not validated here)";
    r["synced"] = s.synced;
    r["tip_max_age_seconds"] = s.max_age_seconds;
    r["headers_stored"] = static_cast<uint64_t>(hc.size());

    // Fields no header chain can source. Named individually, never zeroed.
    unavailable["chainwork"] =
        "header chain anchors its first entry at chain_work=1 (fast-start "
        "checkpoint / genesis stub), so cumulative work is relative to the "
        "anchor and not comparable to a daemon's absolute chainwork";
    unavailable["verificationprogress"] =
        "requires the network's total work estimate, which is daemon state we "
        "do not hold";
    unavailable["size_on_disk"] =
        "measures the daemon's block store; we keep headers only";
    unavailable["pruned"] =
        "block-store property of a daemon; not applicable to a header chain";
    unavailable["softforks"] =
        "requires a full-node deployment/BIP9 state machine we do not run";
    unavailable["warnings"] =
        "daemon-level warning surface; not owned";

    if (!s.has_tip) {
        for (const char* f : {"blocks", "headers", "bestblockhash", "mediantime", "difficulty"})
            unavailable[f] = s.blocked_by;
        r["sync_blocked_by"] = s.blocked_by;
        r["unavailable"] = unavailable;
        return r;
    }

    if (auto anchor = first_indexed_height(hc)) r["first_indexed_height"] = *anchor;

    if (s.synced) {
        r["blocks"]        = s.tip_height;
        r["headers"]       = s.tip_height;
        r["bestblockhash"] = s.tip_hash.GetHex();
        r["tip_age_seconds"] = s.tip_age_seconds;
    } else {
        // We own these numbers but they are NOT the network tip. Label them.
        r["sync_blocked_by"] = s.blocked_by;
        nlohmann::json stale;
        stale["tip_height"] = s.tip_height;
        stale["tip_hash"]   = s.tip_hash.GetHex();
        if (s.tip_is_synthetic_anchor) {
            stale["tip_time"]        = nullptr;
            stale["tip_age_seconds"] = nullptr;
        } else {
            stale["tip_time"]        = s.tip_time;
            stale["tip_age_seconds"] = s.tip_age_seconds;
        }
        r["stale"] = stale;
        for (const char* f : {"blocks", "headers", "bestblockhash"})
            unavailable[f] = s.blocked_by + " -- last owned value reported under \"stale\"";
    }

    auto tip = hc.tip();
    if (tip && is_synthetic_anchor(*tip)) {
        const std::string why =
            "tip is a synthetic anchor entry with bits=0 and timestamp=0 (no "
            "real header connected yet); deriving this would emit a fabricated "
            "zero (threshold: a real header at the tip)";
        unavailable["difficulty"] = why;
        unavailable["mediantime"] = why;
    } else if (tip) {
        uint256 target = target_from_bits(tip->header.m_bits);
        if (target.IsNull()) {
            unavailable["difficulty"] =
                "tip bits 0x" + hex8(tip->header.m_bits)
                + " decode to a null target; the difficulty ratio is undefined "
                  "(threshold: nonzero target)";
        } else {
            r["difficulty"] = p.pow_limit.getdouble() / target.getdouble();
        }
        uint32_t mtp = hc.median_time_past();
        if (mtp == 0)
            unavailable["mediantime"] =
                "median_time_past() returned 0, which only happens with no "
                "timestamped headers indexed (threshold: >=1 real header)";
        else
            r["mediantime"] = mtp;
    }

    r["unavailable"] = unavailable;
    return r;
}

/// Header-level fields for one indexed entry, in dashd's getblockheader shape.
/// Every field here is owned: it comes out of the stored IndexEntry, which was
/// X11-PoW and DGW-validated before it was indexed.
inline nlohmann::json header_fields(const HeaderChain& hc, const IndexEntry& e,
                                    const SyncStatus& s)
{
    const auto& p = hc.params();
    nlohmann::json r;
    r["hash"]              = e.hash.GetHex();
    r["height"]            = e.height;
    r["version"]           = e.header.m_version;
    r["versionHex"]        = hex8(static_cast<uint32_t>(e.header.m_version));
    r["merkleroot"]        = e.header.m_merkle_root.GetHex();
    r["time"]              = e.header.m_timestamp;
    r["bits"]              = hex8(e.header.m_bits);
    r["nonce"]             = e.header.m_nonce;
    r["source"]            = SOURCE_TAG;
    // confirmations counts against OUR tip, which is only the network tip when
    // synced. Under a stale tip the number would overstate finality, so it is
    // withheld rather than quietly computed from a tip we know is behind.
    if (s.synced)
        r["confirmations"] = static_cast<int64_t>(s.tip_height) - static_cast<int64_t>(e.height) + 1;

    // Genesis has no predecessor; every other entry carries one.
    if (!e.prev_hash.IsNull())
        r["previousblockhash"] = e.prev_hash.GetHex();

    // nextblockhash exists only if we hold the successor on the active branch.
    if (auto nxt = hc.get_header_by_height(e.height + 1))
        r["nextblockhash"] = nxt->hash.GetHex();

    uint256 target = target_from_bits(e.header.m_bits);
    if (!target.IsNull())
        r["difficulty"] = p.pow_limit.getdouble() / target.getdouble();

    return r;
}

/// Locate an entry by hash, with a refusal that distinguishes "we do not hold
/// that height" from "no such block". Returns nullopt on failure and fills
/// `out_refusal`.
inline std::optional<IndexEntry> lookup_by_hash(const HeaderChain& hc,
                                                const std::string& method,
                                                const std::string& hash_hex,
                                                nlohmann::json&    out_refusal)
{
    uint256 h;
    if (hash_hex.size() != 64) {
        out_refusal = refusal(method, CODE_BAD_PARAMS,
                              method + " withheld: block hash '" + hash_hex
                              + "' is not 64 hex characters (threshold: a "
                                "64-char block hash)");
        return std::nullopt;
    }
    h.SetHex(hash_hex);
    auto e = hc.get_header(h);
    if (e) return e;

    // Not indexed. Say WHICH of the two reasons applies — an operator asking
    // for a pre-anchor block needs a different action than one asking for a
    // hash that is not on our chain at all.
    auto anchor = first_indexed_height(hc);
    out_refusal = refusal(
        method, CODE_CHAIN_STATE,
        method + " withheld: block " + hash_hex + " is not in our header index. "
        "We index the active branch from height "
        + (anchor ? std::to_string(*anchor) : std::string("n/a"))
        + " to the tip; the hash is either below that anchor, on a branch we "
          "did not follow, or not a Dash block.");
    return std::nullopt;
}

/// getblockheader <hash>. FULLY answerable — a header chain is exactly the
/// state this query names. verbose=false returns the serialised header hex.
inline nlohmann::json getblockheader(const HeaderChain& hc,
                                     const std::string& hash_hex,
                                     bool verbose = true,
                                     uint32_t now = now_unix())
{
    nlohmann::json ref;
    auto e = lookup_by_hash(hc, "getblockheader", hash_hex, ref);
    if (!e) return ref;

    if (is_synthetic_anchor(*e))
        return refusal("getblockheader", CODE_CHAIN_STATE,
                       "getblockheader withheld: height " + std::to_string(e->height)
                       + " is the synthetic anchor entry (bits=0, timestamp=0; no "
                         "real header was ever connected there), so every field "
                         "would be a fabricated zero (threshold: a real header)");

    auto s = sync_status(hc, now);
    if (!verbose) {
        auto packed = pack(e->header);
        auto span   = packed.get_span();   // std::span<const std::byte>
        std::string out;
        out.reserve(span.size() * 2);
        static const char* HEX = "0123456789abcdef";
        for (auto sb : span) {
            const auto b = static_cast<unsigned char>(sb);
            out += HEX[b >> 4];
            out += HEX[b & 0x0f];
        }
        return nlohmann::json(out);
    }
    return header_fields(hc, *e, s);
}

/// getblock <hash> [verbosity].
///
///   verbosity 0 — the raw serialised BLOCK. Needs the body. REFUSED.
///   verbosity 1 — header fields + the txid list. We own every header field
///                 and none of the txid list, so this answers PARTIAL: owned
///                 fields present, `tx`/`nTx`/`size`/`strippedsize` ABSENT and
///                 named under `unavailable`. Never `tx: []`.
///   verbosity 2 — header + fully decoded transactions. Needs bodies. REFUSED.
///
/// The merkle root commits to the transaction set but does not reveal it: no
/// amount of header data can reconstruct a txid list, which is why verbosity 1
/// cannot be completed rather than merely being unimplemented.
inline nlohmann::json getblock(const HeaderChain& hc,
                               const std::string& hash_hex,
                               int verbosity = 1,
                               uint32_t now = now_unix())
{
    if (verbosity <= 0)
        return refusal("getblock", CODE_REQUIRES_BLOCK_BODIES,
                       body_reason("getblock verbosity 0 (raw serialised block)"),
                       body_remedies());
    if (verbosity >= 2)
        return refusal("getblock", CODE_REQUIRES_BLOCK_BODIES,
                       body_reason("getblock verbosity 2 (decoded transactions)"),
                       body_remedies());

    nlohmann::json ref;
    auto e = lookup_by_hash(hc, "getblock", hash_hex, ref);
    if (!e) return ref;

    if (is_synthetic_anchor(*e))
        return refusal("getblock", CODE_CHAIN_STATE,
                       "getblock withheld: height " + std::to_string(e->height)
                       + " is the synthetic anchor entry (bits=0, timestamp=0); "
                         "every header field would be a fabricated zero "
                         "(threshold: a real header)");

    auto s = sync_status(hc, now);
    nlohmann::json r = header_fields(hc, *e, s);

    // The honest half. These are ABSENT above, not zeroed, and each says why.
    const std::string why = body_reason("the transaction list");
    nlohmann::json unavailable = nlohmann::json::object();
    for (const char* f : {"tx", "nTx", "size", "strippedsize", "weight"})
        unavailable[f] = why;
    r["unavailable"] = unavailable;
    // The one flag a consumer must branch on before treating this like a
    // daemon's getblock. Present ONLY when fields were withheld.
    r["partial"] = true;
    r["requires"] = body_remedies();
    if (!s.synced) r["sync_blocked_by"] = s.blocked_by;
    return r;
}

/// getrawtransaction <txid>. Doubly unanswerable: it needs the block body the
/// transaction lives in AND a txid->block index to find which body that is.
/// Both are named, because archive mode alone does not fix this one.
inline nlohmann::json getrawtransaction(const std::string& txid)
{
    auto r = refusal(
        "getrawtransaction", CODE_REQUIRES_BLOCK_BODIES,
        "getrawtransaction withheld for txid '" + txid + "': this node retains "
        "block HEADERS ONLY. Serving a transaction needs (1) the block body it "
        "is in, which replay prunes immediately after folding, and (2) a "
        "txid->block index, which is not built even in archive mode unless "
        "transaction indexing is also enabled. Remedies: connect an external "
        "daemon RPC, or enable archive mode WITH transaction indexing.",
        {"external-daemon-rpc", "archive-mode+txindex"});
    // Second code so a caller can tell this apart from a plain body refusal:
    // enabling archive mode alone will NOT make this succeed.
    r["also_requires"] = CODE_REQUIRES_TX_INDEX;
    return r;
}

/// Single dispatch entry point for the three queries, shaped for the web
/// server's coin-chain-query hook. Returns the bare dashd-compatible result on
/// success; on refusal an object carrying the named blocking condition.
/// `params` follows the JSON-RPC positional convention (getblockhash takes
/// [height]).
inline nlohmann::json chain_query(const HeaderChain& hc,
                                  const std::string& method,
                                  const nlohmann::json& params,
                                  uint32_t now = now_unix())
{
    auto refuse = [&](const Answer& a) {
        return nlohmann::json{{"error", a.unavailable_reason},
                              {"unavailable_reason", a.unavailable_reason},
                              {"method", method},
                              {"source", SOURCE_TAG}};
    };

    if (method == "getblockchaininfo")
        return getblockchaininfo(hc, now);

    if (method == "getbestblockhash") {
        auto a = getbestblockhash(hc, now);
        return a.available ? a.value : refuse(a);
    }

    if (method == "getblockhash") {
        if (!params.is_array() || params.empty() || !params[0].is_number()) {
            return nlohmann::json{
                {"error", "getblockhash withheld: missing or non-numeric height "
                          "parameter (threshold: params[0] must be a number)"},
                {"method", method},
                {"source", SOURCE_TAG}};
        }
        auto a = getblockhash(hc, params[0].get<uint32_t>(), now);
        return a.available ? a.value : refuse(a);
    }

    if (method == "getblockheader") {
        if (!params.is_array() || params.empty() || !params[0].is_string())
            return refusal(method, CODE_BAD_PARAMS,
                           "getblockheader withheld: missing or non-string block "
                           "hash (threshold: params[0] must be a 64-char hash)");
        bool verbose = true;
        if (params.size() > 1 && params[1].is_boolean()) verbose = params[1].get<bool>();
        return getblockheader(hc, params[0].get<std::string>(), verbose, now);
    }

    if (method == "getblock") {
        if (!params.is_array() || params.empty() || !params[0].is_string())
            return refusal(method, CODE_BAD_PARAMS,
                           "getblock withheld: missing or non-string block hash "
                           "(threshold: params[0] must be a 64-char hash)");
        int verbosity = 1;
        if (params.size() > 1) {
            if (params[1].is_number())       verbosity = params[1].get<int>();
            else if (params[1].is_boolean()) verbosity = params[1].get<bool>() ? 1 : 0;
        }
        return getblock(hc, params[0].get<std::string>(), verbosity, now);
    }

    if (method == "getrawtransaction") {
        std::string txid;
        if (params.is_array() && !params.empty() && params[0].is_string())
            txid = params[0].get<std::string>();
        return getrawtransaction(txid);
    }

    return refusal(method, CODE_UNKNOWN_METHOD,
                   std::string("method '") + method +
                   "' is not answerable from the header chain (owned: "
                   "getbestblockhash, getblockhash, getblockchaininfo, "
                   "getblockheader, getblock[verbosity=1, partial]; refused with "
                   "a named reason: getblock[verbosity 0|2], getrawtransaction)");
}

} // namespace chain_rpc
} // namespace coin
} // namespace dash
