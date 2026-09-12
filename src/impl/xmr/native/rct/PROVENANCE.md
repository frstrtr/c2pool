# RingCT non-input consensus — provenance (c2pool XMR native node, component C3)

This directory carries the **non-input consensus** half of Monero transaction
validation: commitment balance, Bulletproofs+ range proofs, and the key-image
domain check. It is what makes ruling **R-VAL** implementable — the relayed
txpool admits a transaction on `Structural | NonInputConsensus` evidence and
leaves key-image double-spend detection (which needs the full historical spent
set) to monerod parity and to the network.

## What is here, and what it is derived from

Upstream: **monero-project/monero**, commit
`9e3a31032ee2cf3cb65c908e107a9952d03bbc4f` (branch `master`, fetched
2026-09-11), files `src/ringct/bulletproofs_plus.cc`, `src/ringct/rctOps.cpp`,
`src/ringct/rctSigs.cpp` (`verRctSemanticsSimple`), `src/ringct/rctTypes.h`
(`serialize_rctsig_prunable`) and `src/ringct/multiexp.cc`. Upstream licence:
**BSD-3-Clause**. c2pool is AGPL-3.0; BSD-3 combines into AGPL-3 without issue.

The distinction this file records, because it is not the same as the
`../../coin/vendor/` case:

* `src/impl/xmr/coin/vendor/` holds files copied **byte-for-byte** from upstream
  (rule LIC-1). The ed25519 group arithmetic (`crypto-ops.c`,
  `crypto-ops-data.c`) and Keccak (`keccak.c`, `hash.c`) that everything here
  stands on are exactly those files, reached through the `xmr_coin` library.
  Nothing in this directory duplicates them.
* the files in **this** directory are a **derived port**, not a verbatim copy.
  A verbatim copy was attempted first and rejected: `bulletproofs_plus.cc`
  includes `misc_log_ex.h`, `span.h`, `cryptonote_config.h`, `rctOps.h` (which
  reaches `rctTypes.h`, the monero serialization framework and `hw::device`),
  `multiexp.h` and `boost/thread`. Vendoring the verifier verbatim means
  vendoring epee and half of `cryptonote_basic`, which is a far larger trusted
  surface than the arithmetic it was supposed to bring in.

So the *algorithm* is upstream's, transcribed step for step with upstream's
notation and comments where they explain a step; the *scaffolding* (key type,
error handling, generator cache, multi-scalar multiplication) is authored here
against the STL and the already-vendored `ge_*` / `sc_*` API.

| file | derived from | nature of the change |
|---|---|---|
| `xmr_rct_ops.{hpp,cpp}` | `rctOps.cpp` (`hash_to_scalar`, `hash_to_p3`, `scalarmult8`, `scalarmultH`, `addKeys`, `d2h`, `toPointCheckOrder`), `rctOps.h` / `rctTypes.h` constants (`H`, `INV_EIGHT`, `identity`, curve order) | `rct::key` becomes `std::array<std::uint8_t,32>`; every throwing `CHECK_AND_ASSERT_THROW_MES` becomes a `bool` return, because the input is bytes an unauthenticated peer chose |
| `xmr_multiexp.{hpp,cpp}` | `multiexp.cc` (Straus) | authored 4-bit-window Straus over `ge_cached` tables, built per call. Upstream's cached-generator Straus and Pippenger paths are a throughput optimisation for a node verifying every block; a pool verifying its own relay backlog does not need them, and they are the part of `multiexp.cc` that carries the boost and cache-lifetime machinery |
| `xmr_bulletproofs_plus.{hpp,cpp}` | `bulletproofs_plus.cc` (`bulletproof_plus_VERIFY` and the helpers it calls) | transcribed; the PROVER is deliberately absent (a pool never proves), the generator cache uses `std::once_flag` instead of `boost::mutex`, and the batch weight comes from `<random>` |
| `xmr_rct_verify.{hpp,cpp}` | `rctSigs.cpp` `verRctSemanticsSimple`, plus `cryptonote_core.cpp`'s key-image domain check | the *non-input* half only: shape, commitment balance, range proofs, key-image subgroup. `verRctNonSemanticsSimple` (CLSAG over the ring members) is NOT here and is not reachable without the global output set |

## Scope fence (fail-closed)

Only rct type **6 (`RCTTypeBulletproofPlus`)** is verifiable here. Types 1-5 are
refused with `UnsupportedType` rather than guessed at: type 5 (CLSAG) carries
*Bulletproof*, not Bulletproof+, range proofs, and porting a second verifier to
admit transactions that no post-HF15 relay will ever carry would double this
directory for nothing. The refusal is exercised by the KAT against the seven
real type-5 transactions in the tx-weight golden.

## Regenerating the comparison

    git clone --filter=blob:none --no-checkout https://github.com/monero-project/monero
    git -C monero sparse-checkout set src/ringct src/crypto
    git -C monero checkout 9e3a31032ee2cf3cb65c908e107a9952d03bbc4f

The authoritative check on this port is not a diff against those files: it is
`xmr_native_rct_verify_kat`, which verifies real stagenet transactions that a
real monerod already accepted, and which asserts that value-mutated copies of
those same transactions are refused.
