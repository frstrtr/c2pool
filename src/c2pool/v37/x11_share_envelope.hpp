#pragma once
// V37 Track A2 / S-1 — REAL DASH X11 SHARE ENVELOPE: the BIND/CREDIT layer (L3).
// CONSUMER-tree code (src/c2pool/v37/). Header-only, so it links into the v37
// unit suites AND the daemon exactly like w2_receipt.hpp / w3_relay.hpp. Does NOT
// touch src/sharechain/v37 canon.
//
// ── THE THREE-LAYER SPLIT (why this file no longer carries a codec) ─────────
//   L1  WIRE      c2pool/v37/w3_relay_x11.hpp    stdlib-only. The ONE carrier-wire
//                 0x02 layout, the ONE codec (X11CarrierWire), the ONE golden
//                 (wire_x11::kGoldenHexX), the dual-accept front door
//                 (decode_any), X11WorkEvent as a pure POD, X11Carrier.
//   L2  VERIFY    impl/dash/x11_share_verify.hpp  the SOLE consensus authority:
//                 dash::verify_x11_share over the DASH SSOT (hash_x11,
//                 serialize_header80, target_from_nbits, meets_target,
//                 coinbase_txid, fold_merkle_branch,
//                 extract_op_return_commitment). UNCHANGED by this layer.
//   L3  BIND      THIS FILE. Includes L1 + L2 and closes the seam between them:
//                 the free functions that used to be X11ShareEvent members, the
//                 X11WorkEvent -> dash::X11ShareEnvelope adapter, the hook
//                 installer, and the W2 credit path (X11ReceiptAdmitter).
//
//   Before this split the tree shipped TWO byte-incompatible 0x02 layouts under
//   the SAME version byte (an X11ShareEvent codec here and X11CarrierWire in L1),
//   both defining c2pool::v37n::X11Carrier — so no single translation unit could
//   include both, and encode+verify could not be proven together. There is now
//   exactly ONE X11Carrier, ONE codec, ONE golden, ONE PoW implementation and ONE
//   OP_RETURN extractor, and v37_a2_x11_real_pow_kat.cpp includes L1+L2+L3 in a
//   single TU to prove encode -> decode_any -> to_dash_envelope ->
//   dash::verify_x11_share end to end against a REAL accepted DASH share.
//
// ── WHAT THE 0x02 ENVELOPE EARNS (PAPER §2/§15) ────────────────────────────
//   The v0x01 synthetic WorkEvent is a header-SHAPED sha256d preimage: it FAKES
//   PoW (a leading-zero count) and FAKES the payout binding (the identity simply
//   sits inside the hashed preimage). A peer "verifying" it learns nothing about
//   DASH mainchain work. The 0x02 event carries the 80-byte header the miner
//   actually X11-hashed plus the coinbase + merkle branch, so ANY peer can prove,
//   without trusting the sender, that (a) X11 over the reconstructed header met a
//   target = real work, (b) header.hashPrevBlock pins that work to a DASH bin, and
//   (c) the coinbase whose OP_RETURN names WHO is paid folds through the branch
//   into the merkle_root the same PoW commits. The RDWR identity binding MIGRATES
//   from "sits in the sha256d preimage" to "committed by merkle_root -> coinbase
//   -> OP_RETURN ref_hash". merkle_root is never carried raw, so a forged root
//   cannot survive the X11 recompute.
//
// ── REQUIRED-OPERATOR-RULING (paper-silent; NOT self-picked here) ───────────
//   X11-OQ1  Is last_txout_nonce a wire field at all? It is also readable from the
//            coinbase OP_RETURN tail (dash::extract_op_return_commitment returns
//            it), so the 0x02 layout carries it redundantly. Dropping it changes
//            the frame by 8 bytes and regenerates every 0x02 golden.
//   X11-OQ2  Field ORDER inside event02 (prev_block_hash before prev_own_share, as
//            L1 ships, vs the reverse). Cosmetic to a decoder, but it is a frozen
//            consensus byte-map once a peer ships it.
//   X11-OQ4  Does the 0x02 wire carry the CLAIMED payout ref_hash explicitly, so
//            the commitment is self-binding on the wire, or does the receiving
//            node derive the claim from the RDWR tuple + its own PPLNS window?
//            Today the wire carries NO claim, so to_dash_envelope() takes the
//            claimed ref_hash as an explicit argument and the caller decides —
//            this file picks neither. Until it is ruled, the structural chain
//            (X11 -> merkle -> coinbase -> an OP_RETURN is PRESENT) is enforced
//            unconditionally and the deep PPLNS re-derivation is the injected
//            X11PayoutOracle.
//   Until X11-OQ1/OQ2 are ruled the L1 layout and its golden stand as shipped;
//   the PR body's 360-byte real-capture hex was generated under the OTHER (now
//   deleted) layout and is regenerated under the canonical one — see the PR.
//
//   X11-OQ3 (OP_RETURN extraction) is NOT an open question: the two candidate
//   implementations were a reverse byte SEARCH for 0x6a 0x28 and the SSOT's
//   proper vin/vout walk. A byte search can be spoofed by a coincidental 0x6a28
//   run inside a scriptSig, so it is a security defect, not a style choice. Both
//   local copies are deleted; dash::extract_op_return_commitment (the walk) is
//   the sole extractor.
//
// SSOT REUSED, NEVER REINVENTED (every one of them is dash::, none is local):
//   dash::crypto::hash_x11                    X11 PoW
//   dash::coin::serialize_header80            the 80-byte header layout
//   dash::coin::target_from_nbits/meets_target compact target math + PoW gate
//   dash::coin::coinbase_txid                 sha256d(coinbase)
//   dash::fold_merkle_branch                  index-0 branch fold (DASH v16)
//   dash::extract_op_return_commitment        proper vin/vout walk to the payout
//                                             commitment (never a byte search)
//   dash::verify_x11_share                    the fail-closed inbound verifier
//   c2pool::v37n::work_from_target            credit basis §4.1 (unchanged)

#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "w3_relay_x11.hpp"                     // L1: X11WorkEvent, X11Carrier,
                                                // X11CarrierWire, decode_any,
                                                // x11_hash_fn/set_x11_hash; pulls
                                                // w3_relay + w2_admission + w2_receipt
#include <impl/dash/x11_share_verify.hpp>       // L2: the SSOT verifier (+ block_producer,
                                                // hash_x11, uint256 transitively)
#include <impl/dash/crypto/hash_x11.hpp>        // dash::crypto::hash_x11 (explicit)

namespace c2pool::v37n {

// ── uint256 (internal LE) <-> bytes32 bridges ───────────────────────────────
// The 80-byte DASH header carries prev_block / merkle_root in uint256 INTERNAL
// (little-endian data()) byte order — the same order hash_x11 consumes. bytes32
// mirrors that order 1:1. work_from_target() instead wants a BIG-ENDIAN target
// (b[0] = most significant byte), so be_from_u256 reverses.
inline uint256 u256_from_internal(const bytes32& b) {
    uint256 u;
    std::memcpy(u.data(), b.data(), 32);
    return u;
}
inline bytes32 internal_from_u256(const uint256& u) {
    bytes32 b{};
    std::memcpy(b.data(), u.data(), 32);
    return b;
}
inline bytes32 be_from_u256(const uint256& u) {
    bytes32 be{};
    const unsigned char* d = u.data();
    for (int i = 0; i < 32; ++i) be[i] = d[31 - i];
    return be;
}

// ═══════════════════════════════════════════════════════════════════════════
// L3 free functions — what used to be X11ShareEvent's members. Each is a thin,
// literal delegation to the DASH SSOT; none reimplements anything. They take the
// L1 POD (X11WorkEvent) so the wire layer stays stdlib-only and the crypto stays
// in one place.
// ═══════════════════════════════════════════════════════════════════════════

// The committed coinbase preimage: the base coinbase tx followed by the DIP4
// CbTx extra_payload, exactly as DASHWorkSource::MintShareInputs concatenates
// {coinbase_bytes, coinbase_payload} before hashing.
inline std::vector<unsigned char> x11_full_coinbase(const X11WorkEvent& e) {
    std::vector<unsigned char> v;
    v.reserve(e.coinbase.size() + e.coinbase_payload.size());
    v.insert(v.end(), e.coinbase.begin(), e.coinbase.end());
    v.insert(v.end(), e.coinbase_payload.begin(), e.coinbase_payload.end());
    return v;
}

// coinbase txid = sha256d(full coinbase)  — dash::coin::coinbase_txid.
inline uint256 x11_coinbase_txid_u(const X11WorkEvent& e) {
    return dash::coin::coinbase_txid(x11_full_coinbase(e));
}

// Fold the coinbase txid up through the branch (DASH v16 index 0, so the running
// hash is always the left leaf) — dash::fold_merkle_branch.
inline uint256 x11_merkle_root_u(const X11WorkEvent& e) {
    std::vector<uint256> branch;
    branch.reserve(e.merkle_branch.size());
    for (const bytes32& b : e.merkle_branch) branch.push_back(u256_from_internal(b));
    return dash::fold_merkle_branch(x11_coinbase_txid_u(e), branch);
}

// The 80-byte header — dash::coin::serialize_header80, with the RECONSTRUCTED
// merkle root (never a carried one).
inline void x11_fill_header80(const X11WorkEvent& e, unsigned char out[80]) {
    dash::coin::serialize_header80(out, static_cast<std::int32_t>(e.header_version),
                                   u256_from_internal(e.prev_block_hash),
                                   x11_merkle_root_u(e), e.ntime, e.nbits, e.nonce);
}

// The real PoW — dash::crypto::hash_x11 over that header. This IS the share id.
inline uint256 x11_pow_hash_u(const X11WorkEvent& e) {
    unsigned char hdr[80];
    x11_fill_header80(e, hdr);
    return dash::crypto::hash_x11(hdr, 80);
}

// Canonical consensus share id = X11(header), in uint256 internal byte order (so
// it compares directly against dash::X11VerifyResult::pow_hash). Replaces the
// v0x01 sha256d(preimage) dedup key. NOTE: recomputed on every call — X11 is not
// free, so hoist it into a local where a caller needs it more than once (the
// admitter below does).
inline bytes32 x11_share_id(const X11WorkEvent& e) {
    return internal_from_u256(x11_pow_hash_u(e));
}

// The REAL "meets_own_target": X11 pow <= the sharechain (credit) target.
inline bool x11_meets_own_target(const X11WorkEvent& e) {
    return dash::coin::meets_target(x11_pow_hash_u(e), e.share_bits);
}
// A solved DASH block: X11 pow also <= the mainchain block target.
inline bool x11_meets_block_target(const X11WorkEvent& e) {
    return dash::coin::meets_target(x11_pow_hash_u(e), e.nbits);
}

// Credit = work of the SHARE target (target-based, ingestion-spec §4.1), via the
// saturating floor(2^256/(T+1)) narrow shared with the synthetic path.
inline u64 x11_work(const X11WorkEvent& e) {
    return work_from_target(be_from_u256(dash::coin::target_from_nbits(e.share_bits)));
}

// The W3-MUST binding: the credited descriptor's identity key IS the carried
// identity. Version-agnostic; identical to X11CarrierWire::identity_bound, which
// is the decode-time guard.
inline bool x11_identity_bound(const X11WorkEvent& e) {
    return e.identity == e.descriptor.identity_key();
}

// ═══════════════════════════════════════════════════════════════════════════
// SEAM CLOSER 1 — the L1 POD -> L2 SSOT envelope adapter. This is the whole
// reason a single TU can now carry encode AND verify.
//
// `claimed_ref_hash` is the payout commitment the CALLER asserts this share pays
// to. The 0x02 wire carries no such claim today (X11-OQ4 above), so it is an
// explicit argument and this file picks no policy: pass the value your layer
// considers authoritative and verify with require_payout_commitment=true, or
// leave it defaulted and verify with require_payout_commitment=false to get the
// committed value merely EXTRACTED and exposed (a coinbase with no OP_RETURN is
// rejected either way).
// ═══════════════════════════════════════════════════════════════════════════
inline dash::X11ShareEnvelope to_dash_envelope(const X11WorkEvent& e,
                                               const uint256& claimed_ref_hash = uint256{}) {
    dash::X11ShareEnvelope env;
    env.version         = static_cast<std::int32_t>(e.header_version);
    env.prev_block_hash = u256_from_internal(e.prev_block_hash);
    env.ntime           = e.ntime;
    env.nbits           = e.nbits;
    env.nonce           = e.nonce;
    env.coinbase        = x11_full_coinbase(e);
    env.merkle_branch.clear();
    env.merkle_branch.reserve(e.merkle_branch.size());
    for (const bytes32& b : e.merkle_branch) env.merkle_branch.push_back(u256_from_internal(b));
    env.share_bits      = e.share_bits;
    env.max_bits        = e.max_bits;
    env.ref_hash        = claimed_ref_hash;
    return env;
}

// ═══════════════════════════════════════════════════════════════════════════
// SEAM CLOSER 2 — install the genuine 11-primitive pipeline behind L1's
// stdlib-only hook. This single line is what turns the injected stub into the
// real DASH permutation; the daemon calls it at boot (at S-1 activation time),
// and v37_a2_x11_real_pow_kat (RX-12) asserts byte-for-byte that what the hook
// returns after this call IS dash::crypto::hash_x11 — the one assertion that
// proves the daemon's seam and the KAT's SSOT are the same function.
//
// Byte order: uint256 INTERNAL (data()) order, matching
// dash::X11VerifyResult::pow_hash and x11_share_id() above.
// ═══════════════════════════════════════════════════════════════════════════
inline void install_dash_x11_hook() {
    set_x11_hash(+[](const std::uint8_t* hdr80) -> bytes32 {
        return internal_from_u256(dash::crypto::hash_x11(hdr80, 80));
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// The peer-verify seams (steps 7 + 8 of the recipe). Reuse the SAME W2 seams
// (IMainchainIndex::height_of, IShareTracker::has_prev_own) unchanged.
// ═══════════════════════════════════════════════════════════════════════════

// R-1 consensus-target oracle: the node's authority on the DASH mainchain BLOCK
// bits and the sharechain SHARE bits in force at a given origin bin (height).
// Replaces the synthetic consensus_lz(bin) check. nullopt => the node cannot
// confirm the bits for that bin, so R-1 fails closed.
struct IConsensusTargets {
    virtual ~IConsensusTargets() = default;
    virtual std::optional<std::uint32_t> block_bits_at(u64 bin) const = 0;
    virtual std::optional<std::uint32_t> share_bits_at(u64 bin) const = 0;
};

// The DEEP payout oracle (optional). The node binds dash::generate_share_transaction
// + dash::verify_payout_commitment (which need its share-tracker chain) here:
// given the event and the ref_hash extracted from its coinbase OP_RETURN, return
// true iff (a) ref_hash recomputes from the share fields AND (b) the coinbase pays
// the correct PPLNS window (committed gentx txid == expected). Unset (nullptr) =>
// the structural chain still holds — an OP_RETURN commitment is PRESENT and was
// committed under X11 via the branch, and identity is W3-MUST bound — the node
// just hasn't wired the PPLNS re-derivation yet (fail-open ONLY on the deep
// re-derivation, never on the cryptographic chain, which is always enforced).
using X11PayoutOracle =
    std::function<bool(const X11WorkEvent& e, const bytes32& ref_hash)>;

// ═══════════════════════════════════════════════════════════════════════════
// X11ReceiptAdmitter — the 0x02 analogue of ReceiptAdmitter. Same consensus
// disposition order (PoW -> R-1 -> identity -> prev-own -> chain -> expiry ->
// dedup), same push sequence (carrier, then receipts flagged L0F_RECEIPT), same
// target-based credit. Only step-1 PoW recompute and the step-3 identity binding
// change from synthetic-sha256d to real-X11 + coinbase-commitment. Reuses the W2
// DedupWindow / EmittedPush / seam interfaces verbatim.
//
// NOT WIRED INTO CONSENSUS BY THIS PR. The S-1 activation — swapping
// w2_admission's synthetic PoW/identity path for this one, the daemon's
// emit-0x02 flip, owed_digest-at-template and LaneParams::shipped() — is the
// operator's hard-fork tap and is deliberately out of scope here.
// ═══════════════════════════════════════════════════════════════════════════
class X11ReceiptAdmitter {
public:
    struct Result {
        CarrierStatus carrier_status = CarrierStatus::OK;
        std::vector<std::pair<std::string, Disposition>> receipts;  // (tag, disp)
        std::vector<EmittedPush> pushes;                            // emission order
    };

    X11ReceiptAdmitter(std::uint32_t chain_id, const IMainchainIndex& index,
                       IShareTracker& tracker, const IConsensusTargets& targets,
                       X11PayoutOracle oracle = {}, u64 incarnation = 1)
        : m_chain(chain_id), m_index(index), m_tracker(tracker), m_targets(targets),
          m_oracle(std::move(oracle)), m_window(chain_id, incarnation),
          m_incarnation(incarnation) {}

    void reset_incarnation(u64 new_incarnation) {
        m_incarnation = new_incarnation;
        m_window = DedupWindow(m_chain, new_incarnation);
        m_next_pos = 0;
        m_raw_total = 0;
    }

    // R-1: the header's mainchain bits AND the share bits both match consensus for
    // the resolved bin (replaces lz_bits == consensus_lz). Fail-closed when the
    // oracle cannot supply the bits.
    bool r1_ok(const X11WorkEvent& e, u64 bin) const {
        auto bb = m_targets.block_bits_at(bin);
        auto sb = m_targets.share_bits_at(bin);
        return bb.has_value() && sb.has_value() && e.nbits == *bb && e.share_bits == *sb;
    }

    // The migrated RDWR payout/identity binding (step 8): the credited descriptor
    // owns the carried identity (W3-MUST), the coinbase carries a ref_hash payout
    // commitment (committed under X11 via the branch, and located by the SSOT's
    // proper vin/vout walk — never a byte search), and — where wired — the deep
    // PPLNS re-derivation agrees.
    bool payout_bound(const X11WorkEvent& e) const {
        if (!x11_identity_bound(e)) return false;
        uint256 ref;
        std::uint64_t nonce64 = 0;
        if (!dash::extract_op_return_commitment(x11_full_coinbase(e), ref, nonce64)) return false;
        if (m_oracle && !m_oracle(e, internal_from_u256(ref))) return false;
        return true;
    }

    Disposition validate_receipt(const X11WorkEvent& r, const X11WorkEvent& carrier,
                                 u64 carrier_bin) const {
        // 1. PoW: X11 over the reconstructed header meets the share target.
        if (!x11_meets_own_target(r)) return Disposition::REJECT_POW;
        // 2. R-1: mainchain + share bits pin to consensus for bin(receipt), when
        //    the bin resolves (an unresolvable bin is caught at step 4).
        std::optional<u64> rb = m_index.height_of(r.prev_block_hash);
        if (rb.has_value() && !r1_ok(r, *rb)) return Disposition::REJECT_R1_TARGET;
        // 3a. self-carriage + migrated coinbase-commitment identity binding.
        if (!(r.identity == carrier.identity)) return Disposition::REJECT_IDENTITY;
        if (!payout_bound(r)) return Disposition::REJECT_IDENTITY;
        // 3b. prev-own-share on the miner's chain (durable tracker).
        if (!m_tracker.has_prev_own(r.identity, r.prev_own_share))
            return Disposition::REJECT_PREV_OWN;
        // 3c. chain id.
        if (r.chain_id != m_chain) return Disposition::REJECT_CHAIN;
        // 4. context window: unresolvable / future / older than N_CTX.
        if (!rb.has_value() || *rb > carrier_bin || carrier_bin - *rb > W2_N_CTX)
            return Disposition::REJECT_EXPIRED;
        // 5. dedup (the single window dedup), keyed on the X11 share id.
        if (m_window.contains(x11_share_id(r))) return Disposition::REJECT_DEDUP;
        return Disposition::OK;
    }

    Result admit(const X11WorkEvent& carrier, const std::vector<X11WorkEvent>& receipts,
                 const RecordSink& sink = {}) {
        Result out;
        if (receipts.size() > W2_R_MAX) { out.carrier_status = CarrierStatus::REJECT_RMAX; return out; }

        std::optional<u64> carrier_bin = m_index.height_of(carrier.prev_block_hash);
        if (!carrier_bin.has_value() || !x11_meets_own_target(carrier) ||
            !r1_ok(carrier, *carrier_bin) || carrier.chain_id != m_chain ||
            !payout_bound(carrier)) {
            out.carrier_status = CarrierStatus::REJECT_POW;
            return out;
        }
        // X11 is not free: hoist the carrier's share id (used three times below).
        const bytes32 carrier_id = x11_share_id(carrier);
        m_window.prune(*carrier_bin);
        if (m_window.contains(carrier_id)) { out.carrier_status = CarrierStatus::REJECT_DEDUP; return out; }

        // §4.2 step 1: the carrier push (carrier position, no receipt flag).
        emit(out, sink, carrier.identity, carrier.descriptor, x11_work(carrier),
             W2_CARRIER_FLAGS, *carrier_bin, *carrier_bin, carrier.tag);
        m_window.add(carrier_id, *carrier_bin);
        m_tracker.record_share(carrier.identity, carrier_id);

        // §4.2 step 2: receipts in WIRE order; invalid entries ignored in place.
        // NOTE the dedup key is added at *carrier_bin, not at origin_bin — that is
        // BYTE-PARITY with the frozen v0x01 admitter (w2_admission.hpp:216,230),
        // deliberate, not a bug.
        for (const X11WorkEvent& r : receipts) {
            Disposition disp = validate_receipt(r, carrier, *carrier_bin);
            out.receipts.emplace_back(r.tag, disp);
            if (disp != Disposition::OK) continue;
            u64 origin_bin = *m_index.height_of(r.prev_block_hash);
            emit(out, sink, carrier.identity, carrier.descriptor, x11_work(r),
                 W2_CARRIER_FLAGS | W2_L0F_RECEIPT, origin_bin, *carrier_bin, r.tag);
            m_window.add(x11_share_id(r), *carrier_bin);
        }
        return out;
    }

    const DedupWindow& window() const { return m_window; }
    u64 next_pos() const { return m_next_pos; }
    ::v37::u128 raw_total() const { return m_raw_total; }
    u64 incarnation() const { return m_incarnation; }
    std::uint32_t chain() const { return m_chain; }

private:
    void emit(Result& out, const RecordSink& sink, const bytes32& identity,
              const ::v37::PayoutDescriptor& desc, u64 w_raw, std::uint32_t flags,
              u64 origin_bin, u64 carrier_bin, const std::string& tag) {
        EmittedPush p;
        p.identity = identity;
        p.descriptor = desc;
        p.w_raw = w_raw;
        p.flags = flags;
        p.pos = m_next_pos;
        p.origin_bin = origin_bin;
        p.carrier_bin = carrier_bin;
        p.tag = tag;
        ++m_next_pos;
        m_raw_total += w_raw;
        out.pushes.push_back(p);
        if (sink) sink(p);
    }

    std::uint32_t m_chain;
    const IMainchainIndex& m_index;
    IShareTracker& m_tracker;
    const IConsensusTargets& m_targets;
    X11PayoutOracle m_oracle;
    DedupWindow m_window;
    u64 m_incarnation;
    u64 m_next_pos = 0;
    ::v37::u128 m_raw_total = 0;
};

} // namespace c2pool::v37n
