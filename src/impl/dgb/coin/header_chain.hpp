#pragma once
// DGB header-chain validation. Mirrors src/impl/btc/coin/header_chain.hpp,
// shares the Scrypt PoW path with src/impl/ltc (identical Scrypt to LTC).
//
// >>> SCRYPT-ONLY VALIDATION POINT (M1 §2, project_v36_dgb_scrypt_only) <<<
// DGB is a 5-algo chain (Scrypt, SHA256d, Skein, Qubit, Odocrypt). In V36
// c2pool-dgb validates the SCRYPT path ONLY:
//   - Scrypt block header        -> full PoW validate (this slice)
//   - non-Scrypt block header     -> accept-by-continuity (extend headers,
//                                    do NOT PoW-validate) OR ignore
//   - malformed / wrong-magic     -> reject
// Algo is selected from the DGB version field (multi-algo encoding). Full
// 5-algo validation is V37 scope — do NOT add Skein/Qubit/Odocrypt/SHA256d
// PoW here.
//
// >>> THIRD INVARIANT: ACCEPT-BY-CONTINUITY HEADERS ARE WORK-NEUTRAL <<<
// (PR #60, dash-consensus review)
// A non-Scrypt header accepted by continuity extends the header chain, but its
// un-validated PoW MUST NOT contribute to sharechain cumulative work or
// best-chain selection. Continuity headers carry zero weight in work
// accounting. Otherwise an attacker feeds cheap non-Scrypt headers to inflate
// cumulative work — a consensus divergence vs p2pool-merged-v36 AND a DoS
// surface. This is the multi-algo analogue of the DASH case where DGW fully
// overrides the base 2016-block retarget (the base path is never reached).
// M3 MUST honor this in BOTH HeaderChain::validate() (no work credited for
// continuity headers) and the DigiShield window (continuity headers excluded
// from the retarget walk — see below).
//
// >>> DIGISHIELD INSERTION POINT (M1 §2) <<<
// DGB uses DigiShield/MultiShield per-algo difficulty retarget, NOT BTC's
// 2016-block retarget. TODO(M3): port per-algo DigiShield target calc for the
// Scrypt algo lane only.
// TODO(M3): the DigiShield difficulty window MUST walk Scrypt-algo ancestors
// ONLY — never the interleaved multi-algo header chain. On a mixed-algo chain
// the previous-block / window walk must skip non-Scrypt (continuity) headers;
// folding them into the window corrupts the Scrypt retarget and re-introduces
// the work-neutrality break above. Easy to get wrong on a mixed-algo chain.
namespace c2pool::dgb { /* TODO(M3): HeaderChain w/ Scrypt-only validate() + accept-by-continuity */ }
