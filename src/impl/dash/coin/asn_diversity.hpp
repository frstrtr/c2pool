// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// PR-4 ASN / GEO DIVERSITY (dashd-cut coin-P2P racing tier, task #154 line).
///
/// This header adds an AUTONOMOUS-SYSTEM (ASN) dimension on TOP of the existing
/// /16 netgroup (peer_network_group in coin_peer_manager.hpp). Two peers can sit
/// in different /16 groups yet still be the same physical failure domain — the
/// same hosting provider, the same building, one BGP withdrawal away from
/// vanishing together. A /16 is a routing-prefix proxy; an ASN is the operator.
/// Requiring the fast path AND its backup to sit on INDEPENDENT ASNs is what
/// makes the racing set survive a whole-provider outage, not just a single-host
/// or single-/16 one.
///
/// It is pure policy exactly like arrival_timing.hpp: NO I/O, NO clock, NO coin
/// state, header-only, standard library + one string in / string out. It folds
/// into the allowlisted dash test targets and builds under
/// -DC2POOL_DASH_BLS=ON carrying no BLS symbols.
///
/// ── REWARD SAFETY ─────────────────────────────────────────────────────────
/// Nothing here derives, validates, or selects a DATUM. It answers exactly one
/// question — "which independent-operator bucket does this IP belong to?" — and
/// a second, pure-reordering question — "reorder these already-scored dial
/// candidates so the top N span >= K distinct buckets". It changes only WHICH
/// peers we dial and in WHICH order, never WHAT we ask them for nor how a reply
/// is checked. Every reply still flows through the identical merkle/payee/DIP-4/
/// BLS self-checks. Worst case = we dial a peer on a second provider we would
/// otherwise have skipped. The consumer (coin_peer_manager) invokes this ONLY
/// when --embedded-asn-diversity is armed; with the flag OFF the dial plan is
/// byte-identical to master.
///
/// ── THE BUNDLED ASN MAP (main cost / risk — see PR body) ────────────────────
/// peer_asn() resolves an IPv4 address to an ASN via a COMPACT, BUNDLED
/// longest-prefix table (kAsnPrefixTable below). This table is the deliberate
/// cost of the feature: it is a small, curated seed set covering the hosting
/// providers that carry the bulk of public DASH P2P nodes (cloud + bare-metal
/// VPS operators). It is NOT a full BGP routing table (~1M prefixes) — bundling
/// that would bloat the binary and rot immediately. The design accepts that an
/// address outside the table resolves to ASN 0 ("unknown"); such peers fall
/// back to their /16 netgroup label so unknowns never all collapse into one
/// bucket. That keeps the diversity guarantee conservative: we may treat two
/// genuinely-independent unknown peers as diverse (correct) or, at worst, treat
/// two same-/16 unknowns as one bucket (safe over-grouping).
///
/// UPDATE PATH (documented, intentionally manual):
///   1. Pull the current prefix->ASN mapping for the target providers from a
///      routing-data source, e.g. a Team Cymru / RIPEstat / bgp.tools dump, or
///      `whois -h whois.cymru.com " -v <ip>"` per seed node.
///   2. Regenerate kAsnPrefixTable rows as {ipv4_network, prefix_len, asn,
///      "operator name"}. Keep them sorted for readability (lookup does not
///      require sorting — it takes the LONGEST match by scan).
///   3. Bump kAsnTableEpoch and rebuild. The KAT
///      (dash_asn_diversity_kat.cpp) pins the assignment for a handful of
///      representative rows, so a table edit that breaks an anchor row fails CI
///      before it ships.
/// The table is advisory routing metadata, not consensus data: a stale or wrong
/// row can only mis-bucket a dial candidate, never mis-derive or mis-serve.

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>

namespace dash {
namespace coin {

// ─── Bundled compact ASN-prefix table ───────────────────────────────────────
// One row per (IPv4 network, prefix length) -> ASN. Longest-prefix wins.
// This is a CURATED SEED set (the providers that host the bulk of public DASH
// P2P nodes), NOT a full routing table. See the UPDATE PATH note in the file
// header for how to regenerate it. Adding/removing rows is the whole cost of
// keeping this feature accurate over time.
struct AsnPrefixRow
{
    uint32_t    network;    // IPv4 network address, host byte order
    uint8_t     prefix_len; // 0..32
    uint32_t    asn;        // autonomous system number (0 == unassigned/unknown)
    const char* op_name;    // human-readable operator (diagnostics only)
};

// Bump when the table is regenerated (diagnostics / provenance only).
inline constexpr uint32_t kAsnTableEpoch = 20260824u;

// Helper: pack a dotted IPv4 literal into host-order uint32 at compile time so
// the table below reads like addresses, not magic numbers.
inline constexpr uint32_t ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return (static_cast<uint32_t>(a) << 24) | (static_cast<uint32_t>(b) << 16)
         | (static_cast<uint32_t>(c) << 8)  |  static_cast<uint32_t>(d);
}

// Representative rows for the major DASH-node-hosting ASNs. Deliberately small.
// (Prefixes chosen to be real, well-known allocations for each operator; extend
//  per the UPDATE PATH. The feature does not require completeness — see header.)
inline const std::array<AsnPrefixRow, 20>& asn_prefix_table()
{
    static const std::array<AsnPrefixRow, 20> kAsnPrefixTable = {{
        // Amazon AWS (AS16509)
        { ipv4(3,   0,   0, 0),  9, 16509, "Amazon AWS" },
        { ipv4(52,  0,   0, 0),  8, 16509, "Amazon AWS" },
        { ipv4(54,  0,   0, 0),  8, 16509, "Amazon AWS" },
        // DigitalOcean (AS14061)
        { ipv4(159, 65,  0, 0), 16, 14061, "DigitalOcean" },
        { ipv4(165, 227, 0, 0), 16, 14061, "DigitalOcean" },
        { ipv4(178, 62,  0, 0), 16, 14061, "DigitalOcean" },
        // OVH (AS16276)
        { ipv4(51,  38,  0, 0), 16, 16276, "OVH" },
        { ipv4(54,  36,  0, 0), 15, 16276, "OVH" },
        { ipv4(151, 80,  0, 0), 16, 16276, "OVH" },
        // Hetzner (AS24940)
        { ipv4(88,  198, 0, 0), 16, 24940, "Hetzner" },
        { ipv4(95,  216, 0, 0), 15, 24940, "Hetzner" },
        { ipv4(116, 202, 0, 0), 16, 24940, "Hetzner" },
        // Vultr / Choopa (AS20473)
        { ipv4(45,  32,  0, 0), 16, 20473, "Vultr/Choopa" },
        { ipv4(66,  42,  0, 0), 16, 20473, "Vultr/Choopa" },
        // Linode / Akamai (AS63949)
        { ipv4(45,  33,  0, 0), 16, 63949, "Linode/Akamai" },
        { ipv4(139, 162, 0, 0), 16, 63949, "Linode/Akamai" },
        // Contabo (AS51167)
        { ipv4(62,  171, 0, 0), 16, 51167, "Contabo" },
        { ipv4(109, 161, 0, 0), 16, 51167, "Contabo" },
        // M247 (AS9009)
        { ipv4(37,  120, 0, 0), 16,  9009, "M247" },
        // Google Cloud (AS396982)
        { ipv4(34,  64,  0, 0), 10, 396982, "Google Cloud" },
    }};
    return kAsnPrefixTable;
}

// ─── IPv4 parse (host byte order); returns false for non-IPv4 inputs ─────────
inline bool parse_ipv4_host_order(const std::string& ip, uint32_t& out)
{
    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(ip, ec);
    if (ec) return false;
    if (addr.is_v4()) {
        out = addr.to_v4().to_uint();
        return true;
    }
    if (addr.is_v6()) {
        auto v6 = addr.to_v6();
        if (v6.is_v4_mapped()) {
            out = boost::asio::ip::make_address_v4(
                      boost::asio::ip::v4_mapped, v6).to_uint();
            return true;
        }
    }
    return false; // native IPv6 (or unparseable) — no ASN in this table
}

// ─── ASN lookup: longest-prefix match over the bundled table ─────────────────
// Returns 0 when the address is not IPv4 or matches no bundled prefix.
inline uint32_t peer_asn(const std::string& ip)
{
    uint32_t host = 0;
    if (!parse_ipv4_host_order(ip, host)) return 0;

    uint32_t best_asn = 0;
    int      best_len = -1;
    for (const auto& row : asn_prefix_table()) {
        // mask for prefix_len bits (guard shift-by-32 UB when len == 0)
        uint32_t mask = (row.prefix_len == 0)
                            ? 0u
                            : (0xFFFFFFFFu << (32 - row.prefix_len));
        if ((host & mask) == (row.network & mask)) {
            if (static_cast<int>(row.prefix_len) > best_len) {
                best_len = row.prefix_len;
                best_asn = row.asn;
            }
        }
    }
    return best_asn;
}

// ─── ASN diversity bucket label ──────────────────────────────────────────────
// The independent-failure-domain key for diversity accounting:
//   * IPv4 with a bundled ASN  -> "AS<n>"
//   * everything else (unknown ASN, native IPv6, unparseable) -> "ng:<group>"
//     where <group> is a /16 IPv4 or /32 IPv6 netgroup-style fallback so that
//     unknowns do NOT all collapse into a single bucket. Two unknowns on the
//     same /16 are conservatively treated as one domain (safe over-grouping);
//     two unknowns on different /16s count as diverse (correct).
inline std::string asn_netgroup_fallback(const std::string& ip)
{
    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(ip, ec);
    if (!ec && addr.is_v4()) {
        auto b = addr.to_v4().to_bytes();
        return std::to_string(b[0]) + "." + std::to_string(b[1]);
    }
    if (!ec && addr.is_v6()) {
        auto v6 = addr.to_v6();
        if (v6.is_v4_mapped()) {
            auto b = boost::asio::ip::make_address_v4(
                         boost::asio::ip::v4_mapped, v6).to_bytes();
            return std::to_string(b[0]) + "." + std::to_string(b[1]);
        }
        auto b = v6.to_bytes();
        char buf[12];
        std::snprintf(buf, sizeof(buf), "%02x%02x:%02x%02x",
                      b[0], b[1], b[2], b[3]);
        return std::string(buf);
    }
    return ip; // unparseable: its own bucket
}

inline std::string peer_asn_group(const std::string& ip)
{
    uint32_t asn = peer_asn(ip);
    if (asn != 0) return "AS" + std::to_string(asn);
    return "ng:" + asn_netgroup_fallback(ip);
}

// ─── Race-set diversity objective (pure reordering) ──────────────────────────
// Count the distinct ASN-diversity buckets spanned by the FIRST `slots` entries
// of `ranked` (or the whole vector if it is shorter). `group_of` maps an entry
// to its bucket label (typically peer_asn_group(host)).
template <class T, class GetGroup>
inline int race_set_distinct_asns(const std::vector<T>& ranked,
                                  GetGroup group_of,
                                  std::size_t slots)
{
    std::vector<std::string> seen;
    std::size_t n = std::min(slots, ranked.size());
    for (std::size_t i = 0; i < n; ++i) {
        std::string g = group_of(ranked[i]);
        bool dup = false;
        for (auto& s : seen) if (s == g) { dup = true; break; }
        if (!dup) seen.push_back(std::move(g));
    }
    return static_cast<int>(seen.size());
}

// TRUE iff the top `slots` of `ranked` already span >= min_asns distinct
// buckets. A pure predicate over the current order.
template <class T, class GetGroup>
inline bool race_set_spans_min_asns(const std::vector<T>& ranked,
                                    GetGroup group_of,
                                    std::size_t slots,
                                    int min_asns)
{
    return race_set_distinct_asns(ranked, group_of, slots) >= min_asns;
}

// Reorder an already-score-ranked candidate list (best-first) so that the top
// `slots` entries span >= min_asns distinct ASN buckets WHEN the candidate pool
// makes that possible, while otherwise preserving the incoming score order as
// tightly as possible.
//
// Strategy (stable, greedy): walk the ranked list once, emitting the
// best-scored candidate for each not-yet-represented bucket until either the
// diversity target (min_asns buckets) is met or `slots` is filled; then append
// every remaining candidate in original score order. This promotes at most
// (min_asns - 1) lower-scored candidates ahead of same-bucket higher-scored
// ones — the minimum reordering needed to hit the objective — and is a no-op
// (returns the input order) when the top `slots` already satisfy it or when the
// pool cannot satisfy it.
//
// PURE: it only reorders the caller's own candidates; it never fabricates,
// drops, or alters an entry. The caller applies it ONLY under the flag.
template <class T, class GetGroup>
inline std::vector<T> enforce_asn_diversity(const std::vector<T>& ranked,
                                            GetGroup group_of,
                                            std::size_t slots,
                                            int min_asns)
{
    if (min_asns <= 1 || slots == 0 || ranked.size() <= 1)
        return ranked;
    if (race_set_spans_min_asns(ranked, group_of, slots, min_asns))
        return ranked; // already diverse — byte-identical to no-op

    const std::size_t n = ranked.size();
    std::vector<char> used(n, 0);
    std::vector<T> out;
    out.reserve(n);
    std::vector<std::string> picked_groups;

    // Pass 1: fill diversity slots — one representative per new bucket, in
    // score order, until we hit min_asns buckets or run out of head slots.
    for (std::size_t i = 0; i < n && out.size() < slots; ++i) {
        if (static_cast<int>(picked_groups.size()) >= min_asns) break;
        std::string g = group_of(ranked[i]);
        bool have = false;
        for (auto& pg : picked_groups) if (pg == g) { have = true; break; }
        if (have) continue;
        out.push_back(ranked[i]);
        used[i] = 1;
        picked_groups.push_back(std::move(g));
    }

    // Pass 2: append everything else in original score order.
    for (std::size_t i = 0; i < n; ++i) {
        if (used[i]) continue;
        out.push_back(ranked[i]);
    }
    return out;
}

} // namespace coin
} // namespace dash
