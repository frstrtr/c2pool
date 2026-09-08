#pragma once
// V37 dashboard frozen tab-descriptor v1 — the steward -> renderer contract.
// Task #926.
//
// One record per coin lane the dashboard renders as a tab. The field set, the
// field order, and the canonical byte serialization are FROZEN and pinned by a
// golden digest (see v37_dashboard_tab_test.cpp). The renderer binds to this
// stable shape; adding or renaming a field is a v2 (new struct, new digest),
// never an in-place change to v1. This lets the renderer lane and the steward
// lane advance independently against a byte-stable contract.
//
// Field semantics (each field is one thing, defined exactly):
//
//   * coin     — canonical lane key (machine id). Lowercase ASCII, config-
//                driven; the stable join key between steward and renderer
//                (e.g. "bitcoin", "dash", "digibyte"). NEVER inferred from a
//                node's self-report: an unknown lane yields an EMPTY coin, and
//                the renderer then shows "unknown" rather than a wrong coin
//                (honesty rule, mirrors web_server's "never fabricate a coin
//                label"). Identity/join key — compared verbatim.
//
//   * symbol   — display ticker (e.g. "BTC", "DASH"). UPPERCASE ASCII. MAY be
//                empty when the backend has not asserted a symbol (honesty:
//                never fabricate). Display-only — it is NOT an identity key and
//                MUST NOT be used to join or dedup; two lanes may legitimately
//                share a symbol while differing in `coin`.
//
//   * active   — lane liveness for THIS render tick. true iff a live backend is
//                currently bound and the lane is eligible to render live data
//                now; false = a configured-but-idle lane. A false lane is
//                rendered greyed/disabled, NOT hidden — the tab set is stable
//                across liveness flaps so the renderer layout does not reflow.
//
//   * location — the data-source locator the renderer queries for THIS lane's
//                live payload (a route or endpoint, e.g. "/api/v37/lane/dash").
//                Opaque ASCII to the renderer: it is dereferenced, not parsed.
//                An empty location means no source is bound yet and therefore
//                implies !active (see is_consistent()).
//
// Serialization (matches the v37 descriptor canon: fixed field order,
// fixed-width little-endian lengths, no varints):
//     coin_len(u32 LE) coin bytes
//     symbol_len(u32 LE) symbol bytes
//     active(u8: 0 or 1)
//     location_len(u32 LE) location bytes
// Identity/pin key = SHA-256d of the canonical bytes (spec §6.3 S-3 idiom).

#include <cstdint>
#include <string>
#include <vector>

#include "v37_hash.hpp"

namespace v37 {

struct DashboardTab {
    std::string coin;      // canonical lane key (machine id); may be empty
    std::string symbol;    // display ticker; may be empty (never fabricated)
    bool        active = false;  // live-this-tick vs configured-but-idle
    std::string location;  // data-source locator for the renderer; may be empty

    friend bool operator==(const DashboardTab& a, const DashboardTab& b) {
        return a.coin == b.coin && a.symbol == b.symbol &&
               a.active == b.active && a.location == b.location;
    }
    friend bool operator!=(const DashboardTab& a, const DashboardTab& b) {
        return !(a == b);
    }

    // Stable ordering for a canonical tab set: by coin, the identity key.
    friend bool operator<(const DashboardTab& a, const DashboardTab& b) {
        return a.coin < b.coin;
    }

    // Validity invariant tying the fields together: an unbound source cannot be
    // live. Consumers MAY assert this; the renderer treats a violating record
    // defensively (render as idle).
    bool is_consistent() const {
        return !(active && location.empty());
    }
};

namespace detail {

inline void put_u32_le(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xff));
}

inline void put_str(std::vector<std::uint8_t>& out, const std::string& s) {
    put_u32_le(out, static_cast<std::uint32_t>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
}

}  // namespace detail

// Canonical bytes of a single tab record (fixed field order, u32 LE lengths).
inline std::vector<std::uint8_t> canonical_bytes(const DashboardTab& t) {
    std::vector<std::uint8_t> out;
    detail::put_str(out, t.coin);
    detail::put_str(out, t.symbol);
    out.push_back(t.active ? 1 : 0);
    detail::put_str(out, t.location);
    return out;
}

// Pin key of a single tab record.
inline bytes32 pin_digest(const DashboardTab& t) {
    return sha256d(canonical_bytes(t));
}

// Canonical bytes of an ordered tab set: count(u32 LE) then each record in the
// GIVEN order. The caller fixes the order (the renderer's tab order); the pin
// is over exactly that sequence, so a reorder is a different set.
inline std::vector<std::uint8_t> canonical_bytes(const std::vector<DashboardTab>& tabs) {
    std::vector<std::uint8_t> out;
    detail::put_u32_le(out, static_cast<std::uint32_t>(tabs.size()));
    for (const auto& t : tabs) {
        std::vector<std::uint8_t> rec = canonical_bytes(t);
        out.insert(out.end(), rec.begin(), rec.end());
    }
    return out;
}

// Pin key of an ordered tab set.
inline bytes32 pin_digest(const std::vector<DashboardTab>& tabs) {
    return sha256d(canonical_bytes(tabs));
}

}  // namespace v37
