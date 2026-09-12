// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// dash::x11_share_verify — INBOUND real-X11-share verifier (V37 Track A2, S-1).
//
// WHAT THIS IS
//   The verifier a receiving peer runs on a decoded 0x02 (real X11) WorkEvent
//   envelope. It reproduces the honest half of DASHWorkSource::mining_submit
//   (work_source.cpp:2518-2570) and dash::share_init_verify (share_check.hpp:
//   211-355): recompute the DASH X11 PoW over the reconstructed 80-byte miner
//   header, check it meets the share target, and validate the coinbase/merkle
//   path — folding coinbase_txid through the branch into the header's
//   merkle_root (which the X11 PoW commits) and extracting the coinbase's
//   OP_RETURN ref_hash payout commitment. FAIL-CLOSED: any short read, absent
//   commitment, unmet target, or commitment mismatch REJECTS the share; a peer
//   accepts only a share whose real work is provably expended on a coinbase
//   that carries the claimed payout commitment.
//
//   This REPLACES the synthetic WorkEvent::meets_own_target() (a sha256d
//   leading-zero test over a 112-byte preimage, w2_receipt.hpp:230) with the
//   real X11-over-header test, and adds the coinbase/merkle verification the
//   synthetic frame could not support (there was no coinbase, no branch, no
//   real header). It is the step-1 PoW recompute + step-2..5/8 coinbase gates
//   of the W2 peer-verify path (v37-a2-w2-ingestion-spec §3); the chain-context
//   gates (bin resolve / R-1 target pinning / prev-own / dedup / PPLNS payout
//   recompute) stay in w2_admission.hpp + the DASH share SSOT and consume this
//   verifier's outputs (see the boundary note at the bottom).
//
// PER-COIN ISOLATION: header-only, src/impl/dash only. Reuses the DASH SSOT
// primitives verbatim (dash::crypto::hash_x11, dash::coin::serialize_header80 /
// target_from_nbits / meets_target / coinbase_txid / bp_sha256d) — it invents
// no new hashing, no new target math, no new header layout. It does NOT touch
// src/sharechain/v37 canon and it does NOT depend on the coin-agnostic W2/W3
// consumer layer, so the c2pool/v37 relay stays coin-neutral and this DASH
// verifier stays a pure, stateless function of the carried envelope.
//
// Byte order: prev_block_hash and every merkle-branch node are INTERNAL LE
// (uint256::data() order) — the same order serialize_header80 and hash_x11
// consume, and the order mining_submit obtains from ParseHex+memcpy (NOT
// SetHex, which reverses). The OP_RETURN ref_hash is likewise the raw 32 bytes
// as they sit in the coinbase (share_check.hpp:806-808 writes ref_hash.data()).
// ---------------------------------------------------------------------------

#include <impl/dash/coin/block_producer.hpp>   // serialize_header80, target_from_nbits,
                                                // meets_target, coinbase_txid, bp_sha256d,
                                                // and (transitively) dash::crypto::hash_x11
#include <core/uint256.hpp>

#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

namespace dash {

// ── the decoded real-X11 share envelope (the DASH-relevant fields of a 0x02
//    WorkEvent). This is the DASHWorkSource::MintShareInputs tuple
//    (work_source.hpp:154-185) in the shape a peer decodes off the wire:
//    everything needed to RECONSTRUCT the 80-byte header and VERIFY the share,
//    with merkle_root RECONSTRUCTED (folded), never carried raw. ────────────
struct X11ShareEnvelope {
    // ── 80-byte header reconstruction fields ──
    std::int32_t                version = 0;        // header nVersion
    uint256                     prev_block_hash;    // header hashPrevBlock (internal LE);
                                                    // also RDWR member 3 -> origin bin
    std::uint32_t               ntime = 0;          // header nTime
    std::uint32_t               nbits = 0;          // header nBits = the mainchain BLOCK
                                                    // target in force (won-block test + R-1)
    std::uint32_t               nonce = 0;          // header nNonce (u32 grind field)

    // ── coinbase + branch (the payout-verification core) ──
    std::vector<unsigned char>  coinbase;           // full reassembled coinbase tx bytes
                                                    // (coinb1||en1||en2||coinb2). txid =
                                                    // sha256d(coinbase). Carries the DIP4
                                                    // CbTx extra_payload in its tail already.
    std::vector<uint256>        merkle_branch;      // dash::MerkleLink branch (index 0 for
                                                    // DASH v16); folds txid -> merkle_root

    // ── sharechain's own (easier) target the work is CREDITED at ──
    std::uint32_t               share_bits = 0;     // share_info.bits — the share target
    std::uint32_t               max_bits = 0;       // share_info.max_bits (carried; the
                                                    // consensus max/floor is a W2 R-1 check)

    // ── payout commitment the coinbase must carry (MintShareInputs.ref_hash) ──
    // The producer's PPLNS OP_RETURN commitment. The verifier requires the
    // coinbase the PoW actually committed to carry EXACTLY this ref_hash in its
    // OP_RETURN, so the carried value is provably the one under this PoW (and is
    // then trustworthy as the mint's frozen-job registry key). The full trustless
    // recompute of ref_hash from the share's own fields (share_init_verify) and
    // of the PPLNS payout (verify_payout_commitment) is the chain-context SSOT
    // hand-off — see the boundary note at the bottom.
    uint256                     ref_hash;
};

// ── verification options (all default to the strict, fail-closed policy) ────
struct X11VerifyOptions {
    // Require the coinbase's OP_RETURN commitment to equal env.ref_hash. When
    // false, the commitment is still EXTRACTED and exposed (a coinbase with no
    // OP_RETURN is always rejected) but not compared — for callers that complete
    // the ref_hash recompute against a reconstructed full DashShare instead.
    bool require_payout_commitment = true;

    // Structural share-target validity (share_check.hpp:187 check_share_target_valid
    // parity): the share target must be non-null. When max_target is non-null it
    // must additionally be no easier than max_target (target <= max_target). The
    // per-coin max_target is a consensus param, so it is injected, not hard-coded;
    // left null it defers that specific bound to the params-aware W2 R-1 check.
    uint256 max_target;   // null (default) => only the non-null check runs
};

// ── dispositions (fail-closed; the FIRST failure in verification order) ─────
enum class X11VerifyStatus {
    OK,
    REJECT_STRUCTURE,        // malformed coinbase / short read while walking it
    REJECT_SHARE_TARGET,     // share_bits yields a null/invalid share target
    REJECT_POW,              // X11(header) does not meet the share target (real
                             // "meets_own_target" — the SSOT replacement for the
                             // synthetic leading_zero_bits >= lz_bits test)
    REJECT_NO_COMMITMENT,    // coinbase carries no OP_RETURN ref_hash output
    REJECT_PAYOUT_COMMITMENT // OP_RETURN ref_hash != env.ref_hash (payout misbound)
};

inline const char* x11_verify_status_name(X11VerifyStatus s) {
    switch (s) {
    case X11VerifyStatus::OK:                       return "OK";
    case X11VerifyStatus::REJECT_STRUCTURE:         return "REJECT_STRUCTURE";
    case X11VerifyStatus::REJECT_SHARE_TARGET:      return "REJECT_SHARE_TARGET";
    case X11VerifyStatus::REJECT_POW:               return "REJECT_POW";
    case X11VerifyStatus::REJECT_NO_COMMITMENT:     return "REJECT_NO_COMMITMENT";
    case X11VerifyStatus::REJECT_PAYOUT_COMMITMENT: return "REJECT_PAYOUT_COMMITMENT";
    }
    return "?";
}

// ── the verification result ─────────────────────────────────────────────────
struct X11VerifyResult {
    X11VerifyStatus status = X11VerifyStatus::REJECT_STRUCTURE;  // fail-closed default

    // Filled progressively; every field below the point of failure is left at
    // its default. A caller keys on status; the values are the hand-off to W2.
    uint256       coinbase_txid;      // sha256d(coinbase)
    uint256       merkle_root;        // fold of coinbase_txid through the branch
    uint256       pow_hash;           // X11(80-byte header) — the SSOT share id + PoW
    uint256       share_target;       // target_from_nbits(share_bits)
    uint256       block_target;       // target_from_nbits(nbits)
    uint256       committed_ref_hash; // ref_hash read from the coinbase OP_RETURN
    std::uint64_t committed_nonce64 = 0;  // nonce64 read from the OP_RETURN tail

    bool          meets_share_target = false;  // pow_hash <= share_target (== status OK gate)
    bool          won_block = false;           // pow_hash <= block_target (§4 unconditional
                                               // append: this share is ALSO a mainchain block)

    bool ok() const { return status == X11VerifyStatus::OK; }
};

namespace detail {

// Minimal Bitcoin/DASH CompactSize ("varint") reader. Advances `p`; returns
// nullopt on a short read or a non-minimal/oversized encoding (fail-closed).
inline std::optional<std::uint64_t> read_compact_size(
    const std::vector<unsigned char>& b, std::size_t& p) {
    if (p + 1 > b.size()) return std::nullopt;
    std::uint8_t ch = b[p++];
    if (ch < 0xfd) return static_cast<std::uint64_t>(ch);
    if (ch == 0xfd) {
        if (p + 2 > b.size()) return std::nullopt;
        std::uint64_t v = std::uint64_t(b[p]) | (std::uint64_t(b[p + 1]) << 8);
        p += 2;
        return v;
    }
    if (ch == 0xfe) {
        if (p + 4 > b.size()) return std::nullopt;
        std::uint64_t v = 0;
        for (int i = 0; i < 4; ++i) v |= std::uint64_t(b[p + i]) << (8 * i);
        p += 4;
        return v;
    }
    // 0xff
    if (p + 8 > b.size()) return std::nullopt;
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= std::uint64_t(b[p + i]) << (8 * i);
    p += 8;
    return v;
}

} // namespace detail

// ── extract_op_return_commitment ────────────────────────────────────────────
// Walk the coinbase tx and locate the OP_RETURN payout commitment output whose
// scriptPubKey is exactly 0x6a 0x28 || ref_hash(32) || nonce64(8) (42 bytes;
// share_check.hpp:754-814). Returns false (fail-closed) on any malformed field
// or if no such output is present. Does a proper vin/vout walk rather than a
// byte search so a coincidental 0x6a28 inside scriptSig or another script can
// never be mistaken for the commitment.
inline bool extract_op_return_commitment(const std::vector<unsigned char>& cb,
                                         uint256& out_ref_hash,
                                         std::uint64_t& out_nonce64) {
    std::size_t p = 0;
    // nVersion (4)
    if (p + 4 > cb.size()) return false;
    p += 4;
    // vin count
    auto vin_n = detail::read_compact_size(cb, p);
    if (!vin_n) return false;
    for (std::uint64_t i = 0; i < *vin_n; ++i) {
        if (p + 36 > cb.size()) return false;      // prevout hash(32) + index(4)
        p += 36;
        auto slen = detail::read_compact_size(cb, p);   // scriptSig
        if (!slen || p + *slen > cb.size()) return false;
        p += static_cast<std::size_t>(*slen);
        if (p + 4 > cb.size()) return false;       // sequence(4)
        p += 4;
    }
    // vout count
    auto vout_n = detail::read_compact_size(cb, p);
    if (!vout_n) return false;
    for (std::uint64_t i = 0; i < *vout_n; ++i) {
        if (p + 8 > cb.size()) return false;       // value(8)
        p += 8;
        auto slen = detail::read_compact_size(cb, p);   // scriptPubKey
        if (!slen || p + *slen > cb.size()) return false;
        const std::size_t script_at = p;
        const std::size_t script_len = static_cast<std::size_t>(*slen);
        p += script_len;
        // OP_RETURN commitment: 0x6a 0x28 then 40 bytes (32 ref_hash + 8 nonce64).
        if (script_len == 42 && cb[script_at] == 0x6a && cb[script_at + 1] == 0x28) {
            std::memcpy(out_ref_hash.data(), cb.data() + script_at + 2, 32);
            std::uint64_t nonce = 0;
            for (int k = 0; k < 8; ++k)
                nonce |= std::uint64_t(cb[script_at + 2 + 32 + k]) << (8 * k);
            out_nonce64 = nonce;
            return true;
        }
    }
    return false;   // no commitment output found
}

// ── fold_merkle_branch ────────────────────────────────────────────────────────
// Ascend the coinbase txid through the branch to the header's merkle_root.
// DASH v16 uses index 0 (share_types.hpp:22-28), so every step is
// sha256d(cur || sibling) — byte-identical to work_source.cpp:88 merkle_pair
// and to dash::check_merkle_link (share_check.hpp:88) with m_index == 0.
inline uint256 fold_merkle_branch(const uint256& coinbase_txid,
                                  const std::vector<uint256>& branch) {
    uint256 cur = coinbase_txid;
    for (const uint256& sib : branch) {
        unsigned char buf[64];
        std::memcpy(buf,      cur.data(), 32);
        std::memcpy(buf + 32, sib.data(), 32);
        cur = dash::coin::bp_sha256d(std::span<const unsigned char>(buf, 64));
    }
    return cur;
}

// ═══════════════════════════════════════════════════════════════════════════
// verify_x11_share — the fail-closed inbound-share verifier.
//
// Reproduces mining_submit steps 1-6 + the payout-commitment bind, in the fixed
// order the W2 disposition list expects (PoW before payout). Never throws; a bad
// share yields a REJECT_* status with the values computed up to that point.
// ═══════════════════════════════════════════════════════════════════════════
inline X11VerifyResult verify_x11_share(const X11ShareEnvelope& env,
                                        const X11VerifyOptions& opts = {}) {
    X11VerifyResult r;

    // 1. Coinbase must be a plausible tx (share_check.hpp:215 bounds a share
    //    coinbase scriptSig at 2..100; here we bound the whole tx minimally so
    //    the walk and the txid are meaningful).
    if (env.coinbase.size() < 10) {
        r.status = X11VerifyStatus::REJECT_STRUCTURE;
        return r;
    }

    // 2. coinbase txid = sha256d(coinbase)  (block_producer.hpp:182).
    r.coinbase_txid = dash::coin::coinbase_txid(env.coinbase);

    // 3. Fold the branch (index 0) -> merkle_root.
    r.merkle_root = fold_merkle_branch(r.coinbase_txid, env.merkle_branch);

    // 4. Serialize the 80-byte header with the RECONSTRUCTED root (a forged root
    //    would change the X11 hash and fail step 6).
    unsigned char header[80];
    dash::coin::serialize_header80(header, env.version, env.prev_block_hash,
                                   r.merkle_root, env.ntime, env.nbits, env.nonce);

    // 5. X11 PoW — the SSOT (hash_x11.hpp:44). This IS the share id.
    r.pow_hash = dash::crypto::hash_x11(header, 80);

    // 6. Targets. Share target validity first (structural), then the PoW gate.
    r.share_target = dash::coin::target_from_nbits(env.share_bits);
    r.block_target = dash::coin::target_from_nbits(env.nbits);
    if (r.share_target.IsNull() ||
        (!opts.max_target.IsNull() && r.share_target > opts.max_target)) {
        r.status = X11VerifyStatus::REJECT_SHARE_TARGET;
        return r;
    }
    // Won-block classification is computed regardless (an unconditional-append
    // caller needs it even alongside a share-target verdict).
    r.won_block = !r.block_target.IsNull() &&
                  dash::coin::meets_target(r.pow_hash, env.nbits);
    // The real "meets_own_target": X11 hash must clear the share target.
    r.meets_share_target = (r.pow_hash <= r.share_target);
    if (!r.meets_share_target) {
        r.status = X11VerifyStatus::REJECT_POW;
        return r;
    }

    // 7. Coinbase payout commitment. The PoW above proves the coinbase (hence
    //    this OP_RETURN) is committed by real work; extract it and bind it.
    if (!extract_op_return_commitment(env.coinbase, r.committed_ref_hash,
                                      r.committed_nonce64)) {
        r.status = X11VerifyStatus::REJECT_NO_COMMITMENT;
        return r;
    }
    if (opts.require_payout_commitment && !(r.committed_ref_hash == env.ref_hash)) {
        r.status = X11VerifyStatus::REJECT_PAYOUT_COMMITMENT;
        return r;
    }

    r.status = X11VerifyStatus::OK;
    return r;
}

// ═══════════════════════════════════════════════════════════════════════════
// BOUNDARY (what this verifier does NOT do — completed by the W2 / share SSOT):
//   * bin resolve + R-1 pinning: IMainchainIndex::height_of(prev_block_hash) ->
//     bin, and nbits/share_bits == consensus bits for that bin. Chain context —
//     w2_admission.hpp:169-181,200. This verifier exposes prev_block_hash,
//     nbits, share_bits, block_target for it.
//   * identity binding to the descriptor (W3-MUST): identity ==
//     PayoutDescriptor::identity_key() stays in w3_relay.hpp:208 identity_bound.
//   * full trustless payout recompute: ref_hash recomputed from the share's own
//     fields (dash::share_init_verify) + the PPLNS coinbase recomputed from the
//     on-chain window (dash::verify_payout_commitment, share_check.hpp:872) once
//     the envelope is promoted to a full DashShare — needs the tracker, which a
//     stateless envelope verifier has no access to. committed_ref_hash /
//     coinbase_txid / pow_hash are the hand-off values for that step.
//   * work/credit: target-based, work(share_target) — w2 narrows r.share_target
//     with c2pool::v37n::work_from_target (which takes a BIG-ENDIAN bytes32, so
//     reverse r.share_target.data() before the call). ingestion-spec §4.1.
//   * dedup on the share id: keyed on r.pow_hash (the X11 header hash), replacing
//     sha256d(preimage) — w2_admission.hpp DedupWindow, shape unchanged.
// ═══════════════════════════════════════════════════════════════════════════

} // namespace dash
