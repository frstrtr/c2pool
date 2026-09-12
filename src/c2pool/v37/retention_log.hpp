#pragma once
// V37 — the RETENTION-PROMOTION instance of the generic record log
// (record_log.hpp). CONSUMER-tree code (src/c2pool/v37/), view-layer only.
//
// ── WHAT THIS IS, AND WHAT IT IS EMPHATICALLY NOT ────────────────────────
// This is a SECOND, SEPARATE RecordLog instance with its OWN domain tag
// ("V37R"). It is NOT the owed-event log (owed_event_log.hpp, tag "V37L") and
// it MUST NOT be appended into it: that log's whole invariant is
// leaf_count() == ledger_seq(), one leaf per OWED-ledger mutation and nothing
// else. A retention promotion is not a ledger mutation, so a retention leaf in
// that log would break the bijection outright. Hence: its own instance, its own
// tag, its own root, persisted beside — never inside — the owed-event root.
//
// NON-CONSENSUS by default and by construction (R-RT4 / OQ-M1 ruling): the
// retention root is computed and persisted VIEW-LAYER. It is NOT a coinbase
// field, NOT a leaf of the w5 StateCommitment tree, and NOT an input to
// owed_digest(). Nothing in this header — or in retention_view.hpp — can move a
// committed root, reject a share, or change a payout. A retention request that
// is unpaid, over-quota or malformed is IGNORED; the carrying share stands.
// (Miner-messages §3.4, OQ-M1: ignore, don't reject.)
//
// ── THE LEAF BYTES ───────────────────────────────────────────────────────
//   payload = "V37R"                      (4 bytes, domain tag; free in the
//                                          tree — V37A/B/C/D/E/H/L/M/O/P/S/V
//                                          are taken, R is not)
//           || u8  evkind                 (1 PIN, 2 RENEW, 3 HASH)
//           || b32 sender                 (the payout-bound sender identity)
//           || b32 record_hash            (what is being retained; for HASH
//                                          this is the ONLY thing that survives)
//           || u64 LE anchor_bin          (the bin clock value the tier is
//                                          measured from — PINNED expiry is
//                                          anchor_bin + H_pin)
//           || u32 LE bytes               (the record body size the rent was
//                                          priced on)
//           || u64 LE price_mwu           (what was actually debited)
//   leaf    = sha256d(0x00 || payload)     (the lane leaf rule, via RecordLog)
//
// NOTHING NODE-LOCAL ENTERS A LEAF: no wall-clock time, no peer, no cursor, no
// sequence number (the position is the sequence). Every field is either a
// consensus-visible input (the bin clock, the sender identity) or a pure
// function of the request and the ruled price law.
//
// ── WHY THE PRICE IS IN THE LEAF ─────────────────────────────────────────
// The price is a pure function of (tier, bytes) — price_mwu() in
// retention_view.hpp — so recording it is redundant in the honest case. It is
// recorded anyway because it is what makes the log AUDITABLE against the rent
// law without replaying the whole view: a verifier holding only the leaves can
// re-derive price_mwu(tier, bytes) and refuse any leaf that under-charged.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <c2pool/v37/record_log.hpp>
#include <sharechain/v37/v37_fixed.hpp>      // u64
#include <sharechain/v37/v37_hash.hpp>       // bytes32

namespace c2pool::v37n::retention {

using ::v37::bytes32;
using ::v37::u64;

// Same numbering discipline as owedevent::EvKind: 1-based, stable, never reused.
enum RetEvKind : std::uint8_t {
    RET_PIN   = 1,   // first paid promotion of a record into the PINNED tier
    RET_RENEW = 2,   // a later payment that RESETS the PINNED anchor (no chaining)
    RET_HASH  = 3,   // paid permanent 32-byte leaf; the body is dropped
};

inline constexpr char RET_LEAF_TAG[4] = {'V', '3', '7', 'R'};

namespace detail {
inline void put_u32(std::vector<std::uint8_t>& b, std::uint32_t x) {
    for (int i = 0; i < 4; ++i) b.push_back(std::uint8_t((x >> (8 * i)) & 0xff));
}
inline void put_u64(std::vector<std::uint8_t>& b, u64 x) {
    for (int i = 0; i < 8; ++i) b.push_back(std::uint8_t((x >> (8 * i)) & 0xff));
}
} // namespace detail

// The leaf payload is FIXED WIDTH, which is what lets a restore replay the
// promotion journal without a length prefix per field.
inline constexpr std::size_t RET_LEAF_BYTES = 4 + 1 + 32 + 32 + 8 + 4 + 8;   // 89

inline std::vector<std::uint8_t> ret_leaf_payload(std::uint8_t evkind,
                                                  const bytes32& sender,
                                                  const bytes32& record_hash,
                                                  u64 anchor_bin,
                                                  std::uint32_t bytes,
                                                  u64 price_mwu) {
    std::vector<std::uint8_t> p;
    p.reserve(4 + 1 + 32 + 32 + 8 + 4 + 8);
    p.insert(p.end(), RET_LEAF_TAG, RET_LEAF_TAG + 4);
    p.push_back(evkind);
    p.insert(p.end(), sender.begin(), sender.end());
    p.insert(p.end(), record_hash.begin(), record_hash.end());
    detail::put_u64(p, anchor_bin);
    detail::put_u32(p, bytes);
    detail::put_u64(p, price_mwu);
    return p;
}

// ── reading a promotion leaf back (the restore path) ─────────────────────
inline bool ret_leaf_valid(const std::vector<std::uint8_t>& p) {
    return p.size() == RET_LEAF_BYTES &&
           p[0] == 'V' && p[1] == '3' && p[2] == '7' && p[3] == 'R' &&
           (p[4] == RET_PIN || p[4] == RET_RENEW || p[4] == RET_HASH);
}
inline std::uint8_t ret_leaf_kind(const std::vector<std::uint8_t>& p) { return p[4]; }
inline bytes32 ret_leaf_sender(const std::vector<std::uint8_t>& p) {
    bytes32 b{};
    for (std::size_t i = 0; i < 32; ++i) b[i] = p[5 + i];
    return b;
}
inline bytes32 ret_leaf_record_hash(const std::vector<std::uint8_t>& p) {
    bytes32 b{};
    for (std::size_t i = 0; i < 32; ++i) b[i] = p[37 + i];
    return b;
}
inline u64 ret_leaf_anchor_bin(const std::vector<std::uint8_t>& p) {
    u64 x = 0;
    for (int i = 0; i < 8; ++i) x |= u64(p[69 + i]) << (8 * i);
    return x;
}
inline std::uint32_t ret_leaf_bytes(const std::vector<std::uint8_t>& p) {
    std::uint32_t x = 0;
    for (int i = 0; i < 4; ++i) x |= std::uint32_t(p[77 + i]) << (8 * i);
    return x;
}
inline u64 ret_leaf_price(const std::vector<std::uint8_t>& p) {
    u64 x = 0;
    for (int i = 0; i < 8; ++i) x |= u64(p[81 + i]) << (8 * i);
    return x;
}

// ── the VIEW-LAYER store face ────────────────────────────────────────────
// A two-method key/value interface so this header stays stdlib-only. The
// daemon adapts w6's persist::ISettleStore to it in three lines; the KAT uses
// an in-memory map. It is deliberately NOT a dependency on w6_persistence.hpp:
// the retention root is a VIEW artefact, restored best-effort, and a missing
// or corrupt retention record must never be able to fail a settlement
// recovery. Both restore paths below therefore return false and start EMPTY
// rather than throwing or aborting.
struct IRetentionStore {
    virtual ~IRetentionStore() = default;
    virtual void put(const std::string& key, const std::string& value) = 0;
    virtual std::optional<std::string> get(const std::string& key) = 0;
};

// ─────────────────────────────────────────────────────────────────────────
// The instance. A thin typed face on the generic RecordLog, exactly the shape
// OwedEventLog uses: it owns ONE thing the primitive does not — the canonical
// leaf bytes above — and hands the primitive out so a caller can prove,
// serialize or restore with the primitive's own API.
// ─────────────────────────────────────────────────────────────────────────
class RetentionLog {
public:
    using PrefixProof = ::c2pool::v37n::recordlog::RecordLog::PrefixProof;

    u64 append_payload(const std::vector<std::uint8_t>& payload) {
        return m_log.append(payload);
    }
    u64 append_pin(const bytes32& sender, const bytes32& rh, u64 anchor_bin,
                   std::uint32_t bytes, u64 price_mwu) {
        return m_log.append(ret_leaf_payload(RET_PIN, sender, rh, anchor_bin, bytes, price_mwu));
    }
    u64 append_renew(const bytes32& sender, const bytes32& rh, u64 anchor_bin,
                     std::uint32_t bytes, u64 price_mwu) {
        return m_log.append(ret_leaf_payload(RET_RENEW, sender, rh, anchor_bin, bytes, price_mwu));
    }
    u64 append_hash(const bytes32& sender, const bytes32& rh, u64 anchor_bin,
                    std::uint32_t bytes, u64 price_mwu) {
        return m_log.append(ret_leaf_payload(RET_HASH, sender, rh, anchor_bin, bytes, price_mwu));
    }

    bytes32 root() const { return m_log.root(); }
    u64 leaf_count() const { return m_log.leaf_count(); }
    const ::v37::PeakSet& peaks() const { return m_log.peaks(); }
    bool consistent() const { return m_log.consistent(); }

    const ::c2pool::v37n::recordlog::RecordLog& log() const { return m_log; }
    ::c2pool::v37n::recordlog::RecordLog& log() { return m_log; }

    // The view-layer persistence key. Deliberately NOT under the w6 settlement
    // prefixes the owed-event root uses: this root is a view artefact, so it is
    // restored best-effort and its absence is never a recovery failure.
    static std::string store_key(u64 chain) {
        std::string k = "v37v:rmmr:";
        for (int i = 7; i >= 0; --i) {
            static const char* d = "0123456789abcdef";
            k.push_back(d[(chain >> (8 * i + 4)) & 0xf]);
            k.push_back(d[(chain >> (8 * i)) & 0xf]);
        }
        return k;
    }

private:
    ::c2pool::v37n::recordlog::RecordLog m_log;
};

} // namespace c2pool::v37n::retention
