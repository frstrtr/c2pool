#pragma once
// ============================================================================
// V37 sub-threshold work estimator — the "raindrops -> bucket" DROPS half.
//
// Whitepaper purple-paper (src/sharechain/v37/purple-paper.html) Section 5:
//   "we now credit work that never met [the target] ... retain a bounded number
//    of its best and carry them as receipts ... use the estimate only where a
//    worker's shares do not already account for its work."
//
// The BUCKET half (owed-ledger carry-forward + h_min + oldest-owed-first K_fair)
// is ALREADY MERGED in src/c2pool/v37/w4_settlement.hpp (OwedLedger) and
// w5_coinbase.hpp; this header adds only the DROPS half: crediting a worker's
// below-target work as an unbiased estimate of the hashes it performed.
//
// ★★ PRIME SAFETY INVARIANT
//   The whole feature sits behind an EXPERIMENTAL gate,
//   SubthresholdParams::enabled, DEFAULT false. With the gate OFF this header
//   contributes ZERO bytes to any consensus commitment: apply_credit() returns
//   an empty delta, so no estimator credit enters the OwedLedger, and the
//   owed_digest / receipt digest / lane digest are byte-identical to master.
//   Turning the gate ON is a consensus change (the RDWR-OQ2 ruling); it is NOT
//   activated here. Every share/receipt extension for the K-best sub-threshold
//   receipts is ADD-ONLY and materialises only when enabled == true.
//
// THE STATISTIC (proven exactly unbiased — implemented, not re-derived):
//   Hhat = (K-1) * D_K,  D_K = 2^256 / (h_(K) + 1),  h_(K) = K-th smallest hash
//   (= K-th largest achieved difficulty) among a worker's below-target hashes in
//   an interval.  E[Hhat] = H exactly for all K >= 2; K >= 3 is REQUIRED
//   (K = 2 has infinite variance).  Hhat is a hash count, a 256-bit integer,
//   with ONE floor.  Overshoot-as-weight stays FORBIDDEN.
//
// THE CORRECTED CREDIT RULE (the E-2 fix — this header implements ONLY this):
//   The clamp rule  max(S*T, Hhat)  is WRONG: S*T already unbiased-estimates the
//   same H, so Hhat is a *second* estimate, not extra work — it over-credits
//   1.28..1.92x and is sybil-profitable (a 2000-identity split collects ~1.98x).
//   The fix ships exactly ONE unbiased estimator per (worker, interval):
//     - EST_ONLY  : credit the estimate ONLY where the worker's shares do not
//                   already account for its work (S == 0 in the interval);
//     - COMBINED  : the sybil-neutral estimator Hhat_comb = (S + K - 1) * D'_K
//                   (<= 1.00, no sybil profit), when shares and near-misses are
//                   fused into one estimator over the same stream.
//   clamp() below is provided ONLY as a *negative reference* for the KAT to
//   prove it is rejected; it is never on the crediting path.
//
// Self-contained, stdlib-only (no Boost, no core link): a small uint256/uint320,
// a compact SHA-256, the estimator arithmetic, receipt collection, and the gate.
// C++20.
// ============================================================================
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace c2pool::v37::subthreshold {

// --------------------------------------------------------------------------- //
//  Fixed-width unsigned integers (little-endian limbs).
//  u256 holds a 256-bit hash; u320 holds (K-1)*2^256 and division results.
// --------------------------------------------------------------------------- //
struct u256 {
    std::array<std::uint64_t, 4> w{};  // w[0] = least significant
    bool is_zero() const { return !(w[0] | w[1] | w[2] | w[3]); }
    static u256 from_be_bytes(const std::array<std::uint8_t, 32>& b) {
        u256 r;
        for (int limb = 0; limb < 4; ++limb) {
            std::uint64_t v = 0;
            for (int j = 0; j < 8; ++j)
                v = (v << 8) | b[static_cast<std::size_t>((3 - limb) * 8 + j)];
            r.w[static_cast<std::size_t>(limb)] = v;
        }
        return r;
    }
    // strict weak ordering (ascending numeric)
    bool operator<(const u256& o) const {
        for (int i = 3; i >= 0; --i)
            if (w[static_cast<std::size_t>(i)] != o.w[static_cast<std::size_t>(i)])
                return w[static_cast<std::size_t>(i)] < o.w[static_cast<std::size_t>(i)];
        return false;
    }
    bool operator==(const u256& o) const { return w == o.w; }
};

struct u320 {
    std::array<std::uint64_t, 5> w{};  // up to 320 bits; holds (K-1)<<256 etc.

    bool bit(int i) const {
        return (w[static_cast<std::size_t>(i >> 6)] >> (i & 63)) & 1ULL;
    }
    void set_bit(int i) {
        w[static_cast<std::size_t>(i >> 6)] |= (1ULL << (i & 63));
    }
    void shl1() {
        std::uint64_t carry = 0;
        for (auto& limb : w) {
            std::uint64_t nc = limb >> 63;
            limb = (limb << 1) | carry;
            carry = nc;
        }
    }
    // this >= o ?
    bool ge(const u320& o) const {
        for (int i = 4; i >= 0; --i)
            if (w[static_cast<std::size_t>(i)] != o.w[static_cast<std::size_t>(i)])
                return w[static_cast<std::size_t>(i)] > o.w[static_cast<std::size_t>(i)];
        return true;  // equal
    }
    void sub(const u320& o) {  // assumes *this >= o
        std::uint64_t borrow = 0;
        for (std::size_t i = 0; i < 5; ++i) {
            unsigned __int128 cur =
                (unsigned __int128)w[i] - o.w[i] - borrow;
            w[i] = (std::uint64_t)cur;
            borrow = (cur >> 64) ? 1 : 0;
        }
    }
    bool is_zero() const {
        for (auto l : w)
            if (l) return false;
        return true;
    }
    // decimal string (for golden vectors / diagnostics).
    std::string to_dec() const {
        u320 t = *this;
        if (t.is_zero()) return "0";
        std::string s;
        while (!t.is_zero()) {
            // divide t by 10, capture remainder
            unsigned __int128 rem = 0;
            for (int i = 4; i >= 0; --i) {
                unsigned __int128 cur =
                    (rem << 64) | t.w[static_cast<std::size_t>(i)];
                t.w[static_cast<std::size_t>(i)] = (std::uint64_t)(cur / 10);
                rem = cur % 10;
            }
            s.push_back(static_cast<char>('0' + (int)rem));
        }
        std::string r(s.rbegin(), s.rend());
        return r;
    }
};

inline u320 promote(const u256& a) {
    u320 r;
    for (std::size_t i = 0; i < 4; ++i) r.w[i] = a.w[i];
    return r;
}

// coeff * 2^256  (coeff < 2^64), exact in u320.
inline u320 coeff_times_2_256(std::uint64_t coeff) {
    u320 r;
    r.w[4] = coeff;
    return r;
}

// floor(N / D), schoolbook bit-by-bit long division. D must be non-zero.
inline u320 divfloor(const u320& N, const u320& D) {
    u320 q, r;
    for (int i = 319; i >= 0; --i) {
        r.shl1();
        if (N.bit(i)) r.w[0] |= 1ULL;
        if (r.ge(D)) {
            r.sub(D);
            q.set_bit(i);
        }
    }
    return q;
}

// D_K denominator (h_(K) + 1), exact in u320 (handles h_K == 2^256 - 1).
inline u320 denom_hk_plus1(const u256& h_K) {
    u320 d = promote(h_K);
    // + 1 with carry into the 5th limb
    unsigned __int128 cur = (unsigned __int128)d.w[0] + 1;
    d.w[0] = (std::uint64_t)cur;
    std::uint64_t carry = (cur >> 64) ? 1 : 0;
    for (std::size_t i = 1; i < 5 && carry; ++i) {
        cur = (unsigned __int128)d.w[i] + carry;
        d.w[i] = (std::uint64_t)cur;
        carry = (cur >> 64) ? 1 : 0;
    }
    return d;
}

// --------------------------------------------------------------------------- //
//  The estimator arithmetic. All are hash counts (u320), ONE floor each.
// --------------------------------------------------------------------------- //

// K >= 3 is REQUIRED (K = 2 has infinite variance). The gate refuses K < 3.
inline bool k_guard_ok(std::uint32_t K) { return K >= 3; }

// Hhat = (K-1) * D_K = floor( (K-1) * 2^256 / (h_(K) + 1) ).  E[Hhat] = H.
inline u320 estimate_hashes(std::uint32_t K, const u256& h_K) {
    if (!k_guard_ok(K)) return u320{};  // guard: no estimate for K < 3
    return divfloor(coeff_times_2_256((std::uint64_t)K - 1), denom_hk_plus1(h_K));
}

// COMBINED sybil-neutral estimator: Hhat_comb = (S + K - 1) * D'_K
//   = floor( (S + K - 1) * 2^256 / (h_(K) + 1) ).  <= 1.00, no sybil profit.
inline u320 estimate_combined(std::uint64_t S, std::uint32_t K, const u256& h_K) {
    if (!k_guard_ok(K)) return u320{};
    return divfloor(coeff_times_2_256(S + (std::uint64_t)K - 1),
                    denom_hk_plus1(h_K));
}

// Censoring-corrected receipts-only form (submission threshold h_T, i.e. only
// hashes with hash-value > h_T are visible):
//   (K-1) / (1/D'_K - 1/T) = floor( (K-1) * 2^256 / (h_(K) + 1 - h_T) ).
// Requires h_K > h_T (a near-miss lies strictly below target). h_T is the
// boundary hash value h_T = floor(2^256 / T) for share target difficulty T.
inline std::optional<u320> estimate_censoring_corrected(std::uint32_t K,
                                                        const u256& h_K,
                                                        const u256& h_T) {
    if (!k_guard_ok(K)) return std::nullopt;
    // denom = (h_K + 1) - h_T ; require positive.
    u320 num_d = denom_hk_plus1(h_K);
    u320 hT = promote(h_T);
    if (!num_d.ge(hT)) return std::nullopt;  // h_K + 1 <= h_T: not a near-miss
    num_d.sub(hT);
    if (num_d.is_zero()) return std::nullopt;
    return divfloor(coeff_times_2_256((std::uint64_t)K - 1), num_d);
}

// NEGATIVE REFERENCE ONLY — the broken clamp rule max(S*T, Hhat). It is NEVER
// on the crediting path (see apply_credit). Exposed purely so the KAT can prove
// it double-counts / is sybil-profitable and is therefore rejected.
//   work(T) per share, in hashes, = T = 2^256 / h_T  => S*T = S * 2^256 / h_T.
inline u320 broken_clamp_NEVER_CONSENSUS(std::uint64_t S, std::uint32_t K,
                                         const u256& h_K, const u256& h_T) {
    u320 est = estimate_hashes(K, h_K);
    u320 sT = divfloor(coeff_times_2_256(S), promote(h_T));  // S * 2^256 / h_T
    return sT.ge(est) ? sT : est;  // max(S*T, Hhat) — DOUBLE COUNTS
}

// --------------------------------------------------------------------------- //
//  Receipt collection: retain the K-best (smallest-hash / largest-difficulty)
//  below-target near-misses for one worker in one interval. Bounded memory.
// --------------------------------------------------------------------------- //
class ReceiptCollector {
public:
    // target_hash h_T: a hash <= h_T is a SHARE (accounted by shares); a hash in
    // (h_T, ...] is a below-target near-miss eligible to be retained.
    ReceiptCollector(std::uint32_t K, const u256& target_hash)
        : m_K(K), m_hT(target_hash) {}

    // Present one hash. Shares (hash <= h_T) increment S; near-misses compete for
    // the K best (we keep the K SMALLEST near-miss hash values).
    void observe(const u256& hash) {
        if (!(m_hT < hash)) {  // hash <= h_T  => share
            ++m_S;
            return;
        }
        // near-miss: keep K smallest hashes (ascending).
        m_best.push_back(hash);
        std::size_t n = m_best.size();
        // insertion toward front while smaller
        while (n > 1 && m_best[n - 1] < m_best[n - 2]) {
            std::swap(m_best[n - 1], m_best[n - 2]);
            --n;
        }
        if (m_best.size() > m_K) m_best.pop_back();  // drop the largest
    }

    std::uint64_t shares() const { return m_S; }
    std::size_t near_miss_count() const { return m_best.size(); }
    bool has_K() const { return m_best.size() >= m_K; }
    // h_(K): the K-th smallest retained near-miss hash.
    const u256& h_K() const { return m_best[m_K - 1]; }
    const u256& target_hash() const { return m_hT; }
    std::uint32_t K() const { return m_K; }

private:
    std::uint32_t m_K;
    u256 m_hT;
    std::uint64_t m_S = 0;
    std::vector<u256> m_best;  // K smallest near-miss hashes, ascending
};

// --------------------------------------------------------------------------- //
//  The EXPERIMENTAL gate + credit wiring.
// --------------------------------------------------------------------------- //
enum class CreditMode {
    EstimateOnly,  // credit the estimate ONLY where shares don't account (S==0)
    Combined       // fuse shares+near-misses into one estimator (S+K-1)*D'_K
};

struct SubthresholdParams {
    bool enabled = false;                       // ★ DEFAULT OFF (RDWR-OQ2)
    std::uint32_t K = 4;                         // digest-committed; K>=3 guard
    CreditMode mode = CreditMode::EstimateOnly;
    // J < K (fewer than K near-misses) => 0 credit (no fallback inflation).
};

// The dedup key for interval-straddle protection: estimate-dedup is per
// (payee, sequence element), NOT hash-level. A given (payee, seq) yields at
// most ONE estimator credit no matter how many carriers replay the stream.
struct DedupKey {
    std::array<std::uint8_t, 32> payee{};
    std::uint64_t seq = 0;
    bool operator<(const DedupKey& o) const {
        if (payee != o.payee) return payee < o.payee;
        return seq < o.seq;
    }
};

// apply_credit: the ONLY entry point that turns receipts into OwedLedger credit.
//   Gate OFF  => returns {} (empty). No key touched, no digest byte changes.
//   Gate ON   => returns the additive per-payee credit delta, ADD-ONLY, deduped
//                per (payee, seq). Never emits the broken clamp.
// `already_seen` is the caller's per-interval dedup set (mutated).
inline std::map<std::array<std::uint8_t, 32>, long long> apply_credit(
    const SubthresholdParams& p,
    const DedupKey& key,
    const ReceiptCollector& rc,
    std::map<DedupKey, bool>& already_seen) {
    std::map<std::array<std::uint8_t, 32>, long long> delta;
    if (!p.enabled) return delta;                 // ★ gate OFF: nothing enters
    if (!k_guard_ok(p.K)) return delta;           // K>=3 guard
    if (already_seen.count(key)) return delta;    // straddle dedup: one per (payee,seq)
    if (!rc.has_K()) return delta;                // J < K => 0
    // no-double-count: in EstimateOnly, a worker whose shares already account
    // for its work (S > 0) is credited by its shares, NOT the estimate.
    u320 est{};
    if (p.mode == CreditMode::EstimateOnly) {
        if (rc.shares() > 0) return delta;        // shares account for it
        est = estimate_hashes(p.K, rc.h_K());
    } else {                                      // Combined (sybil-neutral)
        est = estimate_combined(rc.shares(), p.K, rc.h_K());
    }
    already_seen[key] = true;
    // OwedLedger credit is i64 hashes-of-work; clamp the (bounded) estimate.
    // In practice the interval estimate fits in i64 for any real worker; here we
    // fold the low 63 bits deterministically (production uses the ledger's own
    // saturating add). This value only enters the digest when enabled == true.
    long long amt = 0;
    for (int i = 62; i >= 0; --i) amt = (amt << 1) | (est.bit(i) ? 1 : 0);
    if (amt != 0) delta[key.payee] += amt;
    return delta;
}

// --------------------------------------------------------------------------- //
//  ADD-ONLY, gated sub-threshold-receipt carrier — the "receipt/share digest"
//  half of the PRIME invariant. The K-best sub-threshold receipts are an
//  ADD-ONLY trailer appended AFTER the master receipt/share body: PRESENT only
//  when the gate is ON, ABSENT (zero bytes) when OFF. Gate OFF => the committed
//  body is byte-identical to master (which has no such trailer at all), so the
//  receipt/share digest — like the owed_digest — is unchanged. The carrier is a
//  deterministic, domain-separated ("V37D") serialization of the harvested
//  receipts of the UNCOVERED, J>=K intervals (interval-straddle dedup is per
//  (payee, interval); see ReceiptCollector / apply_credit above).
// --------------------------------------------------------------------------- //
struct HarvestedInterval {
    std::array<std::uint8_t, 32> payee{};  // canonical identity key
    std::uint64_t interval = 0;            // buried-height bin index (sequence elt)
    std::vector<u256> best;                // K smallest near-miss hashes, ascending
};

// Serialize the ADD-ONLY carrier. GATE OFF => empty (0 bytes): the trailer does
// not exist, so a caller that appends it appends nothing.
inline std::vector<std::uint8_t> serialize_receipt_carrier(
    const SubthresholdParams& p,
    const std::vector<HarvestedInterval>& rows) {
    std::vector<std::uint8_t> v;
    if (!p.enabled) return v;                      // ★ 0 bytes when gated OFF
    auto put32 = [&](std::uint32_t x) {
        for (int i = 0; i < 4; ++i) v.push_back((std::uint8_t)(x >> (8 * i)));
    };
    auto put64 = [&](std::uint64_t x) {
        for (int i = 0; i < 8; ++i) v.push_back((std::uint8_t)(x >> (8 * i)));
    };
    const char tag[4] = {'V', '3', '7', 'D'};      // Drops carrier tag
    v.insert(v.end(), tag, tag + 4);
    put32(p.K);
    put32((std::uint32_t)rows.size());
    for (const auto& r : rows) {
        v.insert(v.end(), r.payee.begin(), r.payee.end());
        put64(r.interval);
        put32((std::uint32_t)r.best.size());
        for (const auto& h : r.best)               // big-endian 256-bit each
            for (std::size_t limb = 4; limb-- > 0;) {
                std::uint64_t x = h.w[limb];
                for (int b = 7; b >= 0; --b) v.push_back((std::uint8_t)(x >> (b * 8)));
            }
    }
    return v;
}

// --------------------------------------------------------------------------- //
//  Compact SHA-256 / sha256d — used ONLY to reproduce the w4_settlement
//  owed_digest shape ("V37O" || key || i64 finalW || u64 first_eligible) so the
//  KAT can prove gate-off byte-identity of the consensus commitment, and to hash
//  the receipt/share body (below) for the same gate-off proof on that digest.
// --------------------------------------------------------------------------- //
namespace detail {
inline std::uint32_t rotr(std::uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}
inline void sha256(const std::vector<std::uint8_t>& msg,
                   std::array<std::uint8_t, 32>& out) {
    static const std::uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    std::uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::vector<std::uint8_t> m = msg;
    std::uint64_t bitlen = (std::uint64_t)m.size() * 8;
    m.push_back(0x80);
    while (m.size() % 64 != 56) m.push_back(0x00);
    for (int i = 7; i >= 0; --i) m.push_back((std::uint8_t)(bitlen >> (8 * i)));
    for (std::size_t off = 0; off < m.size(); off += 64) {
        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = ((std::uint32_t)m[off + i * 4] << 24) |
                   ((std::uint32_t)m[off + i * 4 + 1] << 16) |
                   ((std::uint32_t)m[off + i * 4 + 2] << 8) |
                   ((std::uint32_t)m[off + i * 4 + 3]);
        for (int i = 16; i < 64; ++i) {
            std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5],
                      g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            std::uint32_t ch = (e & f) ^ (~e & g);
            std::uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            std::uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 4; ++j)
            out[static_cast<std::size_t>(i * 4 + j)] =
                (std::uint8_t)(h[i] >> (24 - j * 8));
}
inline std::array<std::uint8_t, 32> sha256d(const std::vector<std::uint8_t>& msg) {
    std::array<std::uint8_t, 32> a, b;
    sha256(msg, a);
    std::vector<std::uint8_t> mid(a.begin(), a.end());
    sha256(mid, b);
    return b;
}
}  // namespace detail

// Faithful re-implementation of w4_settlement.hpp OwedLedger::owed_digest():
//   domain-separated sha256d, sorted by key (32-byte), zero rows skipped:
//   "V37O" || key || i64 finalW (LE) || u64 first_eligible (LE).
inline std::array<std::uint8_t, 32> owed_digest(
    const std::map<std::array<std::uint8_t, 32>, long long>& finalW,
    const std::map<std::array<std::uint8_t, 32>, std::uint64_t>& first_eligible) {
    std::vector<std::uint8_t> pre = {'V', '3', '7', 'O'};
    for (const auto& [k, w] : finalW) {  // std::map iterates sorted by key
        if (w == 0) continue;
        pre.insert(pre.end(), k.begin(), k.end());
        std::uint64_t uw = (std::uint64_t)w;
        for (int i = 0; i < 8; ++i) pre.push_back((std::uint8_t)(uw >> (8 * i)));
        std::uint64_t fe = 0;
        auto it = first_eligible.find(k);
        if (it != first_eligible.end()) fe = it->second;
        for (int i = 0; i < 8; ++i) pre.push_back((std::uint8_t)(fe >> (8 * i)));
    }
    return detail::sha256d(pre);
}

// The receipt/share body digest WITH the add-only carrier appended. GATE OFF =>
// serialize_receipt_carrier() is empty => this equals sha256d(master_body) =>
// byte-identical to master. GATE ON => the "V37D" trailer changes the digest.
// This is the receipt/share-digest analogue of owed_digest()'s gate-off proof.
inline std::array<std::uint8_t, 32> receipt_body_digest(
    const SubthresholdParams& p,
    const std::vector<std::uint8_t>& master_body,
    const std::vector<HarvestedInterval>& rows) {
    std::vector<std::uint8_t> pre = master_body;
    auto carrier = serialize_receipt_carrier(p, rows);
    pre.insert(pre.end(), carrier.begin(), carrier.end());
    return detail::sha256d(pre);
}

}  // namespace c2pool::v37::subthreshold
