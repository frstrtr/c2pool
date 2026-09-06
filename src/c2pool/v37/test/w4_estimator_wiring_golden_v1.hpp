#pragma once
// Frozen golden vector for v37_w4_estimator_wiring_test.cpp (RDWR-OQ2 wiring KAT).
//
// These pin the WIRING-LEVEL digests of the fixed schedule the KAT drives
// against the REAL c2pool::v37n::settle::OwedLedger and the REAL ::v37::Lane:
//
//   OWED_DIGEST_GATE_OFF_HEX  — OwedLedger::owed_digest() after the schedule with
//       the estimator gate OFF (the default). This MUST equal the digest master
//       produces on the identical schedule (proven by the cross-checkout probe
//       AND, in-binary, by the master-style plain-on_block_found ledger). A
//       change here is a PRIME-invariant violation.
//   OWED_DIGEST_GATE_ON_HEX   — owed_digest() after the SAME schedule with the
//       gate ON (EstimateOnly): the RDWR-OQ2 consensus activation. Differs from
//       gate-OFF because the uncovered worker's corrected estimate is credited.
//   LANE_DIGEST_HEX           — ::v37::Lane::digest() after a fixed push schedule.
//       IDENTICAL whether the LaneParams::subthreshold gate is OFF or ON (the
//       gate field is not part of the digested geometry) — the lane-digest half
//       of the PRIME invariant.
//   UNCOVERED_CREDIT_LOW63_DEC — the exact estimator credit (low-63-bit fold of
//       Hhat=(K-1)*D_K, K=8) the gate-ON path adds for the uncovered worker.
//
// The STAMP is sha256(w4_estimator_wiring_golden_v1.json); the JSON mirrors these
// values. Case "golden stamp" re-derives the stamp in-CI (with a --neg negative
// control that flips one byte and proves the check goes red), so the pin is not
// hollow.
#include <cstdint>
namespace c2pool::v37n::settle::wiring_golden {
inline constexpr const char* STAMP = "ff19a742898a54d0e298b0ab288dbd0343e96f6476e14b2d63e81db6f07b133b";
inline constexpr const char* JSON_FILE = "w4_estimator_wiring_golden_v1.json";
inline constexpr const char* OWED_DIGEST_GATE_OFF_HEX = "3ba6481a99a1e3db15b0b6034f950343daaf6c4dfc31934919bd64867a4010ae";
inline constexpr const char* OWED_DIGEST_GATE_ON_HEX  = "56caec4cff671eed36d53e11140f0a0de44f35e98900df3010cdd296ea5a0f58";
inline constexpr const char* LANE_DIGEST_HEX          = "37756e9fa59be4aa30acfa6a18b0e1c131c9601cfceec802f19133a1ecde1a50";
inline constexpr const char* UNCOVERED_CREDIT_LOW63_DEC = "874999";
}  // namespace
