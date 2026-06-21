#pragma once
// ---------------------------------------------------------------------------
// submit_classify.hpp -- the Stage 4d mining_submit decision SSOT.
//
// mining_submit (stratum/work_source.cpp) reconstructs the 80-byte block header
// from the miner submission, runs scrypt_pow_hash (#286 SSOT) to obtain the
// DGB-Scrypt pow_hash u256, then must place the result in EXACTLY ONE of three
// outcome classes. THIS header is the single place that three-way decision is
// made, so the hot path and its KATs can never disagree on the boundary
// semantics, and the eventual dual-path broadcaster + sharechain-mint dispatch
// both read their trigger from one function.
//
// The ladder, in strict tighten-first order. The block target is always <= the
// share target, so a hash that meets the block target necessarily meets the
// share target: a won block is a SUPERSET of an accepted share, never a
// disjoint class. Check the block target FIRST so the rarer, higher-value
// outcome wins the classification:
//
//   pow_hash <= block_target  -> WonBlock     (submit_block_fn_: broadcast)
//   pow_hash <= share_target  -> ShareAccept  (try_mint_share: sharechain mint)
//   otherwise                 -> Reject       (low-difficulty stratum error)
//
// The comparison is the EXACT inclusive gate the header_chain satisfaction
// check and the nonce grinder run: pow <= target == !(pow > target), MSB-first
// via u256::operator>. Inclusive at BOTH boundaries -- a hash exactly equal to
// a target satisfies it. This matches Bitcoin / DigiByte Core CheckProofOfWork
// (hash > target is the ONLY reject) and p2pool s share-accept gate, so
// c2pool-dgb stays bit-compatible with the daemon AND with p2pool-merged-v36.
//
// Header-only, depends ONLY on dgb_arith256.hpp (u256): no core, no daemon, no
// scrypt (the caller supplies the already-computed digest). Same no-link
// discipline as scrypt_pow.hpp / nonce_grinder.hpp -- a pure decision over
// three integers, trivially testable without the stratum string machinery.
// ---------------------------------------------------------------------------

#include <impl/dgb/coin/dgb_arith256.hpp>   // dgb::coin::u256

namespace dgb::coin {

// The three mutually-exclusive outcomes of a stratum submission, in increasing
// difficulty order. Values are stable (logged / asserted by the KATs).
enum class SubmitClass {
    Reject      = 0,   // pow_hash > share_target: below share difficulty
    ShareAccept = 1,   // share_target >= pow_hash > block_target: mint a share
    WonBlock    = 2,   // pow_hash <= block_target: a full network block was found
};

// Classify a submission s Scrypt pow_hash against the two targets.
//
// Precondition (caller-guaranteed): block_target <= share_target -- the share
// target is always looser. The tighten-first ladder is SAFE even if a malformed
// job inverts them: a hash is only ever called WonBlock when it genuinely meets
// the block target, so an inverted pair can never promote a share into a
// spurious block broadcast (it would at worst mis-Reject, never mis-WonBlock).
inline SubmitClass classify_submission(const u256& pow_hash,
                                       const u256& block_target,
                                       const u256& share_target)
{
    if (!(pow_hash > block_target)) return SubmitClass::WonBlock;     // <= block
    if (!(pow_hash > share_target)) return SubmitClass::ShareAccept;  // <= share
    return SubmitClass::Reject;
}

}  // namespace dgb::coin
