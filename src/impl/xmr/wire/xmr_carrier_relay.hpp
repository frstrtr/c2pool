// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef C2POOL_IMPL_XMR_XMR_CARRIER_RELAY_HPP
#define C2POOL_IMPL_XMR_XMR_CARRIER_RELAY_HPP
//
// xmr_carrier_relay.hpp — W3 relay-ingress SKELETON for a keyed_heavy (RandomX)
// lane. It is the control flow that ties three pieces together and NOTHING else:
//
//   * the wire codec               (xmr_carrier_wire.hpp)          — this leg
//   * the consensus admission order (xmr_admission.hpp)             — share-format leg
//   * the relay DoS budget          (xmr_carrier_dos_budget.hpp)    — this leg
//
// It owns the ORDER and the token seam; all crypto, the mainchain index, and the
// RandomX verify body are INJECTED (std::function) so this header pulls in no
// heavy dependency and is unit-testable with fakes (see check/w3_wire_check.cpp).
// The live wiring — registering message_xmr_carrier with the pool MessageHandler,
// the peer-id source, and the actual disconnect/ban-list call — is the reception
// slice, deliberately out of scope here (cf. src/impl/dash/min_protocol_gate.hpp,
// whose live handle_version site is likewise out of scope).
//
// THE TOKEN SEAM (why this is a skeleton and not just a call):
//   admit_receipt_keyed_heavy() runs the five consensus stages internally with
//   RandomX LAST. To meter RandomX WITHOUT reordering consensus, the budget's
//   grant is injected INTO the admission `seed_for_bin` hook (stage-5 entry, run
//   just before rx_check):
//       seed_for_bin: resolve seed; if not resident -> false (defer, no penalty);
//                     else grant_randomx(peer); if denied -> false (defer, no
//                     penalty); else hold the token and return true.
//   So rx_check runs IFF a token was granted, which makes its result unambiguous:
//       Accept      -> valid PoW      -> refund token, ACCEPT, push
//       BelowTarget -> invalid PoW    -> (UNSTABLE-HARDWARE re-verify) -> BAN
//       Not*/Seed*  -> our-side fault -> refund token, DEFER (never ban the peer)
//   A carrier rejected before stage 5 (spent_randomx == false, stage < RandomX)
//   cost microseconds and only bumps the soft misbehavior score.

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "xmr_carrier_wire.hpp"       // v37::xmr::wire::CarrierMessage, decode_carrier
#include "xmr_carrier_dos_budget.hpp" // c2pool::xmr::CarrierDosBudget, Action
#include "xmr_admission.hpp"          // v37::xmr::admit_receipt_keyed_heavy et al.

namespace c2pool {
namespace xmr {

// Mirrors c2pool::xmr::VerifyStatus (randomx_verify.hpp) without pulling in
// randomx.h, so this header and its test compile cache-free. The injected
// rx_verify returns one of these AND writes the raw 32-B hash it computed.
enum class RxVerdict : std::uint8_t {
    Accept,           // PoW valid AND meets the opened T_origin
    BelowTarget,      // PoW computed, hash * difficulty >= 2^256 (fails R-1)
    SeedNotResident,  // seed not prefetched (our fault after a grant) — defer
    NotInitialized,   // VM alloc/OOM (our fault) — defer
};

// The per-carrier terminal outcome the relay produces (for logging / the push).
enum class RelayResult : std::uint8_t {
    Accepted,   // admitted; caller performs the §4 push and dedup insert
    Deferred,   // not verifiable now (budget/seed/our-fault) — drop or queue
    DroppedCheap, // stage 1-4 reject (structural/expiry/dedup) — soft score bump
    Banned,     // confirmed invalid PoW (or score crossed threshold) — disconnect
    BadFrame,   // wire decode failed — treated as a cheap structural fault
};

// Injected environment: the crypto + index oracles the admission order needs,
// plus the ONE heavy call (rx_verify). Everything here is supplied by the node
// (monero-primitives + monerod-adapter index + randomx-vendor LightVerifier).
struct LaneEnv {
    // --- cheap oracles (admission stages 1-4) --------------------------------
    std::function<v37::xmr::bytes32(const v37::xmr::HashingBlob&)>          cheap_digest;
    std::function<bool(const v37::xmr::bytes32&)>                          seen;
    std::function<bool(const v37::xmr::HashingBlob&, std::uint64_t&)>       bin_of;
    std::function<bool(const v37::xmr::MoneroReceipt&, const v37::xmr::bytes32&,
                       std::uint32_t, v37::xmr::OpenedCommitment&)>         open_and_bind;
    std::function<bool(std::uint64_t, v37::xmr::Difficulty&)>               consensus_difficulty;

    // --- seed resolution (stage 5 entry; residency check, NO hashing) --------
    // Resolve the RandomX seed for `bin` per the receipt's SeedRefPolicy. Returns
    // false iff the seed is NOT resident (caller must prefetch; NOT a peer fault).
    std::function<bool(std::uint64_t bin, const v37::xmr::SeedRef&,
                       v37::xmr::bytes32& out_seed)>                        seed_resolve;

    // --- the ONE heavy call (stage 5): light-mode RandomX verify -------------
    // Computes rx_slow_hash(seed, blob) and tests it against difficulty d
    // (c2pool::xmr::LightVerifier::verify). Writes the raw hash to out_hash.
    std::function<RxVerdict(const v37::xmr::bytes32& seed,
                            const v37::xmr::HashingBlob&,
                            const v37::xmr::Difficulty& d,
                            std::uint8_t out_hash[32])>                     rx_verify;

    // --- optional UNSTABLE-HARDWARE re-verify (p2pool force_light_mode) -------
    // Independently re-hash the same (seed, blob) once more before trusting a
    // BelowTarget verdict. If absent, a BelowTarget is trusted directly (confirmed
    // == true). If present, ban only when confirm_invalid() agrees.
    std::function<RxVerdict(const v37::xmr::bytes32& seed,
                            const v37::xmr::HashingBlob&,
                            const v37::xmr::Difficulty& d,
                            std::uint8_t out_hash[32])>                     rx_reverify;
};

// The captured state of the (at most one) RandomX evaluation for a single
// admission call, so the post-admission code can act on the true stage-5 result
// rather than only the boolean the admission hook returned.
struct RxProbe {
    bool      token_held = false;               // a grant was taken for this carrier
    RxVerdict verdict    = RxVerdict::NotInitialized;
    bool      ran        = false;               // rx_verify actually executed
    std::uint8_t hash[32] = {0};
};

// Admit ONE MoneroReceipt (the carrier itself, or a receipt riding it) through
// the consensus order with the DoS budget metering RandomX. Pure orchestration.
inline RelayResult admit_one(std::uint32_t             peer_id,
                             std::uint32_t             lane_chain_id,
                             const v37::xmr::bytes32&   carrier_identity,
                             std::uint64_t             carrier_bin,
                             const v37::xmr::MoneroReceipt& r,
                             const v37::xmr::LaneKeyedHeavy& lp,
                             const LaneEnv&            env,
                             CarrierDosBudget&         dos,
                             nanos_t                   now)
{
    if (dos.banned(peer_id)) return RelayResult::Banned;

    RxProbe probe;

    v37::xmr::AdmissionHooks h;
    h.cheap_digest         = env.cheap_digest;
    h.seen                 = env.seen;
    h.bin_of               = env.bin_of;
    h.open_and_bind        = env.open_and_bind;
    h.consensus_difficulty = env.consensus_difficulty;

    // seed_for_bin: the TOKEN SEAM. Residency check, then the grant. Returning
    // false yields a stage-5 reject with spent_randomx == FALSE (a no-penalty
    // defer), and rx_check is never reached.
    h.seed_for_bin = [&](std::uint64_t bin, const v37::xmr::SeedRef& sr,
                         v37::xmr::bytes32& out_seed) -> bool {
        if (!env.seed_resolve(bin, sr, out_seed)) return false;   // not resident: defer
        if (!dos.grant_randomx(peer_id, now))     return false;   // no budget: defer
        probe.token_held = true;
        return true;
    };

    // rx_check: runs IFF a token was granted. Captures the true verdict.
    h.rx_check = [&](const v37::xmr::bytes32& seed, const v37::xmr::HashingBlob& blob,
                     const v37::xmr::Difficulty& d, v37::xmr::bytes32& out_pow) -> bool {
        probe.ran = true;
        probe.verdict = env.rx_verify(seed, blob, d, probe.hash);
        for (int i = 0; i < 32; ++i) out_pow[i] = probe.hash[i];
        return probe.verdict == RxVerdict::Accept;
    };

    const v37::xmr::AdmitOutcome oc =
        v37::xmr::admit_receipt_keyed_heavy(r, carrier_identity, carrier_bin,
                                            lane_chain_id, lp, h);

    // ---- map the consensus outcome + the captured probe to a relay action ----
    if (oc.ok) {
        // Valid PoW: refund (honest work is already PoW-rate-limited).
        dos.on_valid_pow(peer_id, now);
        return RelayResult::Accepted;
    }

    if (oc.stage == v37::xmr::AdmitStage::RandomX && probe.token_held) {
        // A token was taken; branch on what actually happened at the VM.
        switch (probe.verdict) {
            case RxVerdict::BelowTarget: {
                // Provable invalid PoW. Optionally re-verify to rule out our own
                // unstable hardware before banning (p2pool force_light_mode).
                bool confirmed = true;
                if (env.rx_reverify) {
                    std::uint8_t hb[32] = {0};
                    // Re-resolve seed for the re-hash (residency already held).
                    v37::xmr::bytes32 seed{};
                    std::uint64_t bin = 0;
                    if (env.bin_of(r.hashing_blob, bin) &&
                        env.seed_resolve(bin, r.seed_ref, seed)) {
                        v37::xmr::Difficulty d{};        // opened target for the re-check
                        env.consensus_difficulty(bin, d);
                        RxVerdict v2 = env.rx_reverify(seed, r.hashing_blob, d, hb);
                        confirmed = confirm_invalid(probe.hash, hb,
                                                    /*a_below*/true,
                                                    /*b_below*/v2 == RxVerdict::BelowTarget);
                    }
                }
                Action a = dos.on_invalid_pow(peer_id, confirmed);
                return a == Action::Ban ? RelayResult::Banned : RelayResult::DroppedCheap;
            }
            case RxVerdict::Accept:
                // Can't normally happen (oc.ok would be true); refund defensively.
                dos.on_valid_pow(peer_id, now);
                return RelayResult::Accepted;
            case RxVerdict::SeedNotResident:
            case RxVerdict::NotInitialized:
                // Our-side fault AFTER a grant: refund and defer; never a peer ban.
                dos.on_valid_pow(peer_id, now);   // returns the token (refund path)
                return RelayResult::Deferred;
        }
    }

    if (oc.stage == v37::xmr::AdmitStage::RandomX) {
        // Reached stage 5 but no token was held (seed not resident, or budget
        // exhausted): a no-penalty defer.
        return RelayResult::Deferred;
    }

    // Stages 1-4: cheap reject (structural / expiry / dedup / R-1). Soft bump.
    Action a = dos.on_cheap_reject(peer_id);
    return a == Action::Ban ? RelayResult::Banned : RelayResult::DroppedCheap;
}

// The per-message summary (what the relay hands back to the reception slice).
struct CarrierIngestReport {
    RelayResult carrier = RelayResult::Deferred;   // the transport share's verdict
    std::vector<RelayResult> receipts;             // one per receipt (in order)
    bool banned = false;
    bool bad_frame = false;
};

// handle_xmr_carrier — the top-level ingress. Frame -> cap -> decode -> verify
// the CARRIER (its own RandomX at the carrier target) -> then each receipt (at
// its R-1 target). Receipts are only looked at once the carrier is Accepted:
// an unverified transport share carries nothing. `on_accept` is the caller's
// §4 push + dedup-insert callback (out of scope here).
inline CarrierIngestReport handle_xmr_carrier(
        std::uint32_t             peer_id,
        std::uint32_t             lane_chain_id,
        const std::uint8_t*       frame,
        std::size_t               frame_len,
        const v37::xmr::LaneKeyedHeavy& lp,
        const LaneEnv&            env,
        CarrierDosBudget&         dos,
        nanos_t                   now,
        const std::function<void(const v37::xmr::MoneroReceipt&, bool is_carrier)>& on_accept)
{
    CarrierIngestReport rep;

    if (dos.banned(peer_id)) { rep.banned = true; return rep; }

    // Transport-level frame cap BEFORE any parse (cheapest DoS: an oversize frame).
    if (frame_len > v37::xmr::wire::cap::MSG_MAX) {
        Action a = dos.on_cheap_reject(peer_id);
        rep.bad_frame = true;
        rep.banned = (a == Action::Ban);
        return rep;
    }

    v37::xmr::wire::CarrierMessage msg;
    try {
        msg = v37::xmr::wire::decode_carrier(frame, frame_len);
    } catch (const v37::xmr::wire::WireError&) {
        Action a = dos.on_cheap_reject(peer_id);
        rep.bad_frame = true;
        rep.banned = (a == Action::Ban);
        return rep;
    }

    if (msg.chain_id != lane_chain_id) {
        Action a = dos.on_cheap_reject(peer_id);   // wrong lane: cheap structural fault
        rep.bad_frame = true;
        rep.banned = (a == Action::Ban);
        return rep;
    }

    // The carrier's identity binds the receipts (self-carriage check inside
    // open_and_bind). Derive it once from the carrier's own info_digest binding.
    const v37::xmr::bytes32 carrier_identity = msg.carrier.info_digest;

    // bin(carrier) from the carrier's own prev_id; needed to bound receipt bins.
    std::uint64_t carrier_bin = 0;
    if (!env.bin_of(msg.carrier.hashing_blob, carrier_bin)) {
        Action a = dos.on_cheap_reject(peer_id);   // carrier prev_id unknown
        rep.carrier = RelayResult::DroppedCheap;
        rep.banned = (a == Action::Ban);
        return rep;
    }

    // 1) verify the CARRIER (RandomX at the carrier target).
    rep.carrier = admit_one(peer_id, lane_chain_id, carrier_identity, carrier_bin,
                            msg.carrier, lp, env, dos, now);
    if (rep.carrier == RelayResult::Banned) { rep.banned = true; return rep; }
    if (rep.carrier == RelayResult::Accepted && on_accept) on_accept(msg.carrier, true);

    // No valid carrier => carry nothing. (Deferred carrier: retry later; do not
    // spend RandomX on its receipts now.)
    if (rep.carrier != RelayResult::Accepted) return rep;

    // 2) verify each receipt (RandomX at the R-1 receipt target).
    rep.receipts.reserve(msg.receipts.size());
    for (const auto& r : msg.receipts) {
        RelayResult rr = admit_one(peer_id, lane_chain_id, carrier_identity, carrier_bin,
                                   r, lp, env, dos, now);
        rep.receipts.push_back(rr);
        if (rr == RelayResult::Banned) { rep.banned = true; return rep; }
        if (rr == RelayResult::Accepted && on_accept) on_accept(r, false);
    }
    return rep;
}

} // namespace xmr
} // namespace c2pool

#endif // C2POOL_IMPL_XMR_XMR_CARRIER_RELAY_HPP
