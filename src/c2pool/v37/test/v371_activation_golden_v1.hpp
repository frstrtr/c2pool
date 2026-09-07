#pragma once
// Frozen golden vector for v37_1_activation_test.cpp (RDWR-OQ2 V37.1 activation).
//
// These pin the WIRING-LEVEL digests of the fixed activation schedule the KAT
// drives against the REAL c2pool::v37n::settle::OwedLedger and the REAL
// ::v37::Lane, selecting the shipped consensus version through the add-only
// LaneParams version marker (LaneParams::v37_0() / v37_1() / shipped()):
//
//   OWED_DIGEST_GATE_OFF_HEX  — owed_digest() after the schedule under V37.0
//       (LaneParams::v37_0(), gate OFF). BYTE-IDENTICAL to master on the SAME
//       schedule AND to the pre-existing V37.0 gate-OFF golden
//       (w4_estimator_wiring_golden_v1::OWED_DIGEST_GATE_OFF_HEX). A change here
//       is a non-destructiveness / PRIME-invariant violation.
//   OWED_DIGEST_GATE_ON_HEX   — owed_digest() after the SAME schedule under V37.1
//       (LaneParams::v37_1() == LaneParams::shipped(), gate ON, Combined): the
//       RDWR-OQ2 consensus activation. Differs from gate-OFF because the buried
//       sub-threshold workers (C uncovered S=0, D S=2) are credited by the
//       sybil-neutral combined estimator Hhat_comb=(S+K-1)*D'_K.
//   LANE_DIGEST_HEX           — ::v37::Lane::digest() after a fixed push schedule.
//       IDENTICAL under v37_0() and v37_1() (the gate is not digested geometry):
//       the lane digest is version-invariant.
//   C_CREDIT_DEC / D_CREDIT_DEC — the exact combined-estimator credits (low-63
//       fold) the V37.1 path adds: C=(0+K-1)*D'_K, D=(2+K-1)*D'_K, K=4, same h_K,
//       so D/C == 5/3 — the (S+K-1) coefficient is a witness that S enters the
//       ACTIVE rule (the corrected combined estimator, never the broken clamp).
//
// The STAMP is sha256(v371_activation_golden_v1.json); the JSON mirrors these
// values. Case "golden stamp" re-derives the stamp in-CI (with a --neg negative
// control that flips one byte and proves the check goes red), so the pin is not
// hollow.
#include <cstdint>
namespace c2pool::v37n::settle::v371_golden {
inline constexpr const char* STAMP = "cffdfd30991c8856d1d114aa050bf0ea955705ebfb23a7b019569cbd227a10bd";
inline constexpr const char* JSON_FILE = "v371_activation_golden_v1.json";
inline constexpr const char* OWED_DIGEST_GATE_OFF_HEX = "3ba6481a99a1e3db15b0b6034f950343daaf6c4dfc31934919bd64867a4010ae";
inline constexpr const char* OWED_DIGEST_GATE_ON_HEX  = "2a7dc41dcc231ce8a81f93801b495d65d6841e8067f58e48894985c9ebd8e692";
inline constexpr const char* LANE_DIGEST_HEX          = "37756e9fa59be4aa30acfa6a18b0e1c131c9601cfceec802f19133a1ecde1a50";
inline constexpr const char* C_CREDIT_DEC = "374999";
inline constexpr const char* D_CREDIT_DEC = "624999";
}  // namespace
