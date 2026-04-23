#pragma once

// Phase L step 1: thin C++ wrapper around dashbls's BLS signature
// verification. Hides bls::G1Element/G2Element/SchemeMPL details
// behind a byte-oriented API that takes the same opaque 48/96-byte
// arrays we store in vendor::CFinalCommitment.
//
// Two scheme variants:
//   - basic (BasicSchemeMPL):  used post-DIP-0024 / v19 hard fork.
//                              Current Dash mainnet baseline for new
//                              quorums.
//   - legacy (LegacySchemeMPL): pre-DIP-0024. Older quorums still
//                              encode pubkeys/sigs with this scheme.
//
// Per-quorum scheme is selected by CFinalCommitment.nVersion: legacy
// for nVersion ∈ {1, 2}, basic for nVersion ∈ {3, 4} (see the
// ProTxVersion → bls-scheme mapping in dashcore commitment.h).
//
// Pure verification surface — no signing, no aggregation, no DKG.
// Phase L step 3 wires this into message_clsig handler. Step 2 handles
// "which quorum should have signed?". Aggregation (BLS aggregate sig
// verification) is not needed for ChainLocks, which use a single
// recovered threshold sig per quorum.

#include <dashbls/bls.hpp>
#include <dashbls/elements.hpp>
#include <dashbls/schemes.hpp>
#include <dashbls/util.hpp>

#include <core/log.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace dash {
namespace coin {

namespace bls_detail {

// Get the scheme singleton for a given legacy/basic flag. Constructed
// once per process; both BasicSchemeMPL and LegacySchemeMPL are
// stateless so a single instance is safe to share across threads
// (dashbls's verification path is read-only).
inline bls::CoreMPL& get_scheme(bool fLegacy)
{
    static bls::BasicSchemeMPL  s_basic;
    static bls::LegacySchemeMPL s_legacy;
    return fLegacy ? static_cast<bls::CoreMPL&>(s_legacy)
                   : static_cast<bls::CoreMPL&>(s_basic);
}

// Common verification body shared between the basic + legacy entry
// points. Catches every exception bls might throw and returns false
// — we never want a malformed peer-supplied pubkey/sig to crash the
// node.
inline bool verify_impl(const std::array<uint8_t, 48>& pubkey,
                        std::span<const uint8_t>       message,
                        const std::array<uint8_t, 96>& signature,
                        bool                            fLegacy)
{
    try {
        bls::G1Element pk = bls::G1Element::FromBytes(
            bls::Bytes(pubkey.data(), pubkey.size()), fLegacy);
        bls::G2Element sg = bls::G2Element::FromBytes(
            bls::Bytes(signature.data(), signature.size()), fLegacy);
        return get_scheme(fLegacy).Verify(
            pk, bls::Bytes(message.data(), message.size()), sg);
    } catch (const std::exception& e) {
        LOG_DEBUG_COIND << "[BLS] verify exception: " << e.what()
                        << " (fLegacy=" << fLegacy << ")";
        return false;
    } catch (...) {
        LOG_DEBUG_COIND << "[BLS] verify unknown exception"
                        << " (fLegacy=" << fLegacy << ")";
        return false;
    }
}

} // namespace bls_detail

// Verify a BLS signature using the BASIC scheme (post-v19 quorums).
inline bool verify_bls_basic(const std::array<uint8_t, 48>& pubkey,
                             std::span<const uint8_t>       message,
                             const std::array<uint8_t, 96>& signature)
{
    return bls_detail::verify_impl(pubkey, message, signature,
                                   /*fLegacy=*/false);
}

// Verify a BLS signature using the LEGACY scheme (pre-v19 quorums).
inline bool verify_bls_legacy(const std::array<uint8_t, 48>& pubkey,
                              std::span<const uint8_t>       message,
                              const std::array<uint8_t, 96>& signature)
{
    return bls_detail::verify_impl(pubkey, message, signature,
                                   /*fLegacy=*/true);
}

// Self-test invoked at startup (parallel to the X11 self-test in
// main_dash.cpp). Generates a deterministic BLS keypair from a fixed
// seed, signs a fixed message, then verifies positive AND negative
// (bit-flipped) cases. Returns true if BOTH the positive verification
// passes AND the negative verification fails — i.e. the verifier is
// actually checking signatures, not just always returning true.
//
// Failure modes this catches:
//   - dashbls failed to link properly (missing symbols at runtime)
//   - relic_conf.h was generated for the wrong arch
//   - relic init failed
//   - bls::CoreMPL Verify is silently broken
inline bool bls_self_test_basic()
{
    try {
        // Deterministic seed — verification is what we test, not
        // randomness, so a fixed seed gives a reproducible self-test.
        std::vector<uint8_t> seed(32, 0xa5);
        bls::PrivateKey sk =
            bls::BasicSchemeMPL().KeyGen(seed);
        bls::G1Element pk = sk.GetG1Element();

        const std::vector<uint8_t> msg{'c','2','p','o','o','l','-','d','a','s','h'};
        bls::G2Element sig = bls::BasicSchemeMPL().Sign(
            sk, msg);

        // Positive case: verify should return true.
        if (!bls::BasicSchemeMPL().Verify(pk, bls::Bytes(msg), sig))
            return false;

        // Negative case: bit-flip the message, verify should fail.
        std::vector<uint8_t> bad_msg = msg;
        bad_msg[0] ^= 0x01;
        if (bls::BasicSchemeMPL().Verify(pk, bls::Bytes(bad_msg), sig))
            return false;

        return true;
    } catch (...) {
        return false;
    }
}

} // namespace coin
} // namespace dash
