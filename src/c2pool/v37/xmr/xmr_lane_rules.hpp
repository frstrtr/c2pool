// SPDX-License-Identifier: AGPL-3.0-or-later
//
// LANE-RULES: the XMR lane's pool id covers EVERY consensus-relevant lane rule
// (operator ruling R3, 2026-10-02: "pool-id first").
//
// Before this header, two halves of a pool id existed and both were partial:
// the relay HELLO compared chain_id, the LaneParams digest, the roundabout
// lane_tag, the pool genesis and (flip 1) the DROPS enrol/rule digest; the
// block-level pool_tag folded only lane_tag and genesis. Every settlement rule
// outside LaneParams -- D_conf, the owed floor, the output cap, the root-age
// bound, the booking order, the demo seed, the fee-OFF residual sink and every
// compiled-in rule constant (arm floor, dust decay, salted ties, spend floor,
// commit_total, anchor cut, Merkle rows, the DROPS rule bits, the input weight,
// maturity, the pool-rules version) -- rode in NO digest. Two nodes that
// differed in one of them exchanged a clean HELLO, took each other's blocks as
// their own lane blocks and booked them Mismatch / debit-only: a silent
// owed_digest fork.
//
// LaneRules is ONE canonical list of those rules, serialised as a TLV list
//
//     entry = u8 id | u8 len | value (little-endian; b32 raw)
//
// with strictly ascending ids, and
//
//     rules_digest = sha256d( "c2pool-v37-xmr-lane-rules-v1" || tlv )
//
// The SAME bytes feed both bindings:
//   * HELLO carries the list in the clear (xmr_relay_wire.hpp), so a refusal
//     names the parameter and both values: LANE_RULES_MISMATCH field=d_conf
//     ours=60 theirs=61;
//   * the on-chain pool_tag folds rules_digest (xmr_pool_tag.hpp), so a node
//     with other rules classifies our lane blocks Foreign ("not-lane": an
//     ordinary Monero block) and books nothing of them -- never debit-only.
//
// A field added later is appended with a new id. A reader that meets an id it
// does not know keeps it (`unknown`) and refuses the peer by name
// (field=rules_unknown_id N: a newer build). Every known id must be present.
//
// Integer-only, no allocation beyond the byte vectors; no relay / impl deps.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <sharechain/v37/v37_hash.hpp>   // ::v37::bytes32, ::v37::sha256d

namespace c2pool::v37n::xmr::lanerules {

using bytes32 = ::v37::bytes32;

// The field table: id, name, wire type. Ids are frozen once shipped; a new
// rule takes the next id. 23-25 are the drain rule's placeholders (operator
// ruling R2): 0 = no drain = master's coinbase bytes.
#define C2POOL_XMR_LANE_RULES_FIELDS(X)              \
    X( 1, d_conf,             std::uint64_t)         \
    X( 2, settle_h_min,       std::uint64_t)         \
    X( 3, output_cap,         std::uint32_t)         \
    X( 4, recon_max_root_age, std::uint64_t)         \
    X( 5, book_deferral,      std::uint8_t)          \
    X( 6, arm_floor,          std::int64_t)          \
    X( 7, rotate_on_payment,  std::uint8_t)          \
    X( 8, decay_horizon,      std::uint64_t)         \
    X( 9, decay_half_life,    std::uint64_t)         \
    X(10, anchor_cut,         std::uint8_t)          \
    X(11, merkle_rows,        std::uint8_t)          \
    X(12, drops_rule,         std::uint32_t)         \
    X(13, drops_window_rw,    std::uint64_t)         \
    X(14, kfair_salted_ties,  std::uint8_t)          \
    X(15, commit_total,       std::uint8_t)          \
    X(16, input_weight,       std::uint64_t)         \
    X(17, tail_subsidy,       std::uint64_t)         \
    X(18, coinbase_maturity,  std::uint64_t)         \
    X(19, fee_version,        std::uint32_t)         \
    X(20, residual_sink_id,   ::v37::bytes32)        \
    X(21, pool_rules_version, std::uint32_t)         \
    X(22, owed_demo_amount,   std::uint64_t)         \
    X(23, drain_q,            std::uint32_t)         \
    X(24, drain_h_cap,        std::uint32_t)         \
    X(25, drain_rule_version, std::uint32_t)         \
    X(26, pool_tag_codec,     std::uint8_t)          \
    X(27, lane_params_digest, ::v37::bytes32)        \
    X(28, enrol_digest,       ::v37::bytes32)        \
    X(29, spend_floor,        std::uint8_t)

// The two fields HELLO already compares through its own refusals (the
// LaneParams digest and the rule-tagged enrol digest): a list that differs
// ONLY there is left to those texts (they name geometry / share_diff / bind /
// enrol set / DROPS rule).
inline constexpr std::uint8_t kFieldLaneParamsDigest = 27;
inline constexpr std::uint8_t kFieldEnrolDigest      = 28;

struct LaneRules {
#define C2POOL_LR_MEMBER(id, name, T) T name{};
    C2POOL_XMR_LANE_RULES_FIELDS(C2POOL_LR_MEMBER)
#undef C2POOL_LR_MEMBER
    // Entries with ids this build does not know (a newer peer), in wire order.
    std::vector<std::pair<std::uint8_t, std::vector<std::uint8_t>>> unknown;
    bool operator==(const LaneRules&) const = default;
};

struct FieldInfo {
    std::uint8_t id;
    const char*  name;
};
inline constexpr FieldInfo kFields[] = {
#define C2POOL_LR_INFO(id, name, T) {id, #name},
    C2POOL_XMR_LANE_RULES_FIELDS(C2POOL_LR_INFO)
#undef C2POOL_LR_INFO
};
inline constexpr std::size_t kFieldCount = sizeof(kFields) / sizeof(kFields[0]);
static_assert(kFieldCount == 29, "the v1 lane-rules list has 29 fields");

inline const char* field_name(std::uint8_t id) {
    for (const auto& f : kFields)
        if (f.id == id) return f.name;
    return nullptr;
}

namespace detail {
template <class T> inline constexpr std::size_t width() {
    if constexpr (std::is_same_v<T, bytes32>) return 32;
    else return sizeof(T);
}
template <class T> inline void put(std::vector<std::uint8_t>& b, const T& v) {
    if constexpr (std::is_same_v<T, bytes32>) {
        b.insert(b.end(), v.begin(), v.end());
    } else {
        using U = std::make_unsigned_t<T>;
        const U u = static_cast<U>(v);
        for (std::size_t i = 0; i < sizeof(T); ++i) b.push_back(static_cast<std::uint8_t>(static_cast<std::uint64_t>(u) >> (8 * i)));
    }
}
template <class T> inline T get(const std::uint8_t* p) {
    if constexpr (std::is_same_v<T, bytes32>) {
        bytes32 r{};
        for (std::size_t i = 0; i < 32; ++i) r[i] = p[i];
        return r;
    } else {
        using U = std::make_unsigned_t<T>;
        std::uint64_t u = 0;
        for (std::size_t i = 0; i < sizeof(T); ++i) u |= static_cast<std::uint64_t>(p[i]) << (8 * i);
        return static_cast<T>(static_cast<U>(u));
    }
}
inline std::string hex(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(2 * n);
    for (std::size_t i = 0; i < n; ++i) { s.push_back(d[p[i] >> 4]); s.push_back(d[p[i] & 15]); }
    return s;
}
template <class T> inline std::string text(const T& v) {
    if constexpr (std::is_same_v<T, bytes32>) return hex(v.data(), 16);   // 16 bytes = 32 hex digits, enough to tell
    else if constexpr (std::is_signed_v<T>) return std::to_string(static_cast<long long>(v));
    else return std::to_string(static_cast<unsigned long long>(v));
}
} // namespace detail

// ── codec ────────────────────────────────────────────────────────────────────
inline std::vector<std::uint8_t> encode_tlv(const LaneRules& r) {
    std::vector<std::uint8_t> b;
    b.reserve(300);
#define C2POOL_LR_PUT(id, name, T)                                        \
    b.push_back(id);                                                     \
    b.push_back(static_cast<std::uint8_t>(detail::width<T>()));          \
    detail::put<T>(b, r.name);
    C2POOL_XMR_LANE_RULES_FIELDS(C2POOL_LR_PUT)
#undef C2POOL_LR_PUT
    for (const auto& [id, v] : r.unknown) {   // a newer peer's entries, re-encoded as received
        b.push_back(id);
        b.push_back(static_cast<std::uint8_t>(v.size()));
        b.insert(b.end(), v.begin(), v.end());
    }
    return b;
}

// Strict: ids strictly ascending and never 0, each known id with its exact
// width and present exactly once, unknown ids kept, no trailing bytes.
inline bool decode_tlv(const std::uint8_t* p, std::size_t n, LaneRules& out, std::string* why = nullptr) {
    auto bad = [&](const std::string& m) { if (why) *why = "rules: " + m; return false; };
    LaneRules r;
    std::uint64_t seen = 0;
    unsigned last = 0;
    std::size_t off = 0;
    while (off < n) {
        if (n - off < 2) return bad("truncated entry header");
        const std::uint8_t id = p[off], len = p[off + 1];
        off += 2;
        if (n - off < len) return bad("entry " + std::to_string(id) + " runs past the list");
        if (id == 0 || id <= last) return bad("ids not strictly ascending at " + std::to_string(id));
        last = id;
        bool known = false;
        switch (id) {
#define C2POOL_LR_GET(fid, name, T)                                                       \
        case fid:                                                                        \
            if (len != detail::width<T>()) return bad("field " #name " has width " +     \
                                                      std::to_string(len));              \
            r.name = detail::get<T>(p + off);                                            \
            known = true;                                                                \
            break;
            C2POOL_XMR_LANE_RULES_FIELDS(C2POOL_LR_GET)
#undef C2POOL_LR_GET
        default: break;
        }
        if (known) seen |= std::uint64_t{1} << id;
        else r.unknown.emplace_back(id, std::vector<std::uint8_t>(p + off, p + off + len));
        off += len;
    }
    for (const auto& f : kFields)
        if (!(seen & (std::uint64_t{1} << f.id))) return bad(std::string("field ") + f.name + " missing");
    out = std::move(r);
    return true;
}
inline bool decode_tlv(const std::vector<std::uint8_t>& t, LaneRules& out, std::string* why = nullptr) {
    return decode_tlv(t.data(), t.size(), out, why);
}

inline constexpr char kRulesDomain[] = "c2pool-v37-xmr-lane-rules-v1";

inline bytes32 rules_digest(const LaneRules& r) {
    std::vector<std::uint8_t> b(kRulesDomain, kRulesDomain + sizeof(kRulesDomain) - 1);
    const auto t = encode_tlv(r);
    b.insert(b.end(), t.begin(), t.end());
    return ::v37::sha256d(b);
}

// One line, every field as name=value (the operator diffs two nodes' logs).
inline std::string to_text(const LaneRules& r) {
    std::string s;
#define C2POOL_LR_TEXT(id, name, T) s += (s.empty() ? "" : " "); s += #name "="; s += detail::text<T>(r.name);
    C2POOL_XMR_LANE_RULES_FIELDS(C2POOL_LR_TEXT)
#undef C2POOL_LR_TEXT
    for (const auto& [id, v] : r.unknown) s += " id" + std::to_string(id) + "=" + detail::hex(v.data(), v.size());
    return s;
}

// ── the named refusal ────────────────────────────────────────────────────────
inline constexpr char kLaneRulesMismatch[] = "LANE_RULES_MISMATCH";
inline bool is_lane_rules_mismatch(const std::string& why) { return why.rfind(kLaneRulesMismatch, 0) == 0; }
inline constexpr char kLaneRulesWhy[] =
    " (every node of a pool runs the same lane rules; a peer with other rules builds ANOTHER pool: "
    "its lane blocks are ordinary Monero blocks here and ours there)";

struct FieldDiff {
    std::uint8_t id = 0;
    const char*  name = "";
    std::string  ours, theirs;
};
inline std::vector<FieldDiff> diff_fields(const LaneRules& ours, const LaneRules& theirs) {
    std::vector<FieldDiff> d;
#define C2POOL_LR_DIFF(id, name, T) \
    if (ours.name != theirs.name) d.push_back(FieldDiff{id, #name, detail::text<T>(ours.name), detail::text<T>(theirs.name)});
    C2POOL_XMR_LANE_RULES_FIELDS(C2POOL_LR_DIFF)
#undef C2POOL_LR_DIFF
    return d;
}

// "" = the same lane rules (or neither side carries a list: the pre-LANE-RULES
// comparison). Else ONE line naming the first differing field with both
// values, then every other differing field as name ours/theirs. With
// `defer_hello_digests` a list that differs ONLY in fields 27/28 returns ""
// so the HELLO's own LaneParams / enrol / DROPS refusal names it; the caller
// asks again without it once those checks passed (an inconsistent peer).
inline std::string lane_rules_mismatch(const std::optional<LaneRules>& ours, const std::optional<LaneRules>& theirs,
                                       bool defer_hello_digests = false) {
    const std::string head = std::string(kLaneRulesMismatch) + " field=";
    if (!ours && !theirs) return "";
    if (!theirs)
        return head + "rules_absent (the peer HELLO carries no lane-rules list: a pre-LANE-RULES build; upgrade it)" + kLaneRulesWhy;
    if (!ours)
        return head + "rules_absent (this node carries no lane-rules list, the peer does: upgrade this node)" + kLaneRulesWhy;
    std::vector<FieldDiff> d = diff_fields(*ours, *theirs);
    std::size_t lead = d.size();
    for (std::size_t i = 0; i < d.size(); ++i)
        if (!defer_hello_digests || (d[i].id != kFieldLaneParamsDigest && d[i].id != kFieldEnrolDigest)) { lead = i; break; }
    if (lead == d.size()) {   // no known field to name first
        if (ours->unknown == theirs->unknown) return "";
        for (const auto& [id, v] : theirs->unknown) {
            bool mine = false;
            for (const auto& e : ours->unknown) if (e.first == id && e.second == v) mine = true;
            if (!mine)
                return head + "rules_unknown_id " + std::to_string(id) +
                       " (the peer carries a lane-rules field this build does not know: a newer build; upgrade this node)" + kLaneRulesWhy;
        }
        return head + "rules_unknown_id " + std::to_string(ours->unknown.front().first) +
               " (this node carries a lane-rules field the peer does not)" + kLaneRulesWhy;
    }
    std::string s = head + d[lead].name + " ours=" + d[lead].ours + " theirs=" + d[lead].theirs;
    if (d.size() > 1) {
        s += " (+" + std::to_string(d.size() - 1) + " more:";
        bool first = true;
        for (std::size_t i = 0; i < d.size(); ++i) {
            if (i == lead) continue;
            s += std::string(first ? " " : ", ") + d[i].name + " " + d[i].ours + "/" + d[i].theirs;
            first = false;
        }
        s += ")";
    }
    if (ours->unknown != theirs->unknown) s += " (+ unknown lane-rules ids: a newer build)";
    return s + kLaneRulesWhy;
}

} // namespace c2pool::v37n::xmr::lanerules
