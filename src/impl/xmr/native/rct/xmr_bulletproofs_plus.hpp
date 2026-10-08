// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// Derived from monero-project/monero src/ringct/bulletproofs_plus.cc
// (BSD-3-Clause) -- the VERIFIER only. See PROVENANCE.md in this directory.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/rct/xmr_bulletproofs_plus.hpp
//
// Bulletproofs+ range-proof verification: the proof that every output amount a
// transaction commits to lies in [0, 2^64), without revealing it.
//
// This is the leg of ruling R-VAL that makes a BAD-VALUE transaction a rejected
// transaction. Without it the pool would happily template a transaction whose
// output commitments encode an amount larger than the money supply, or a
// negative one; monerod would reject the block and the pool would lose the
// reward. With it, the only class of invalid transaction the pool can still
// admit is a double spend -- which needs the historical spent set, which is
// exactly what the native node does not carry, and which is why the ruling
// leaves it to monerod parity and to the network.
//
// The PROVER is deliberately not ported: a pool never constructs a range proof.
//
// Preprint: https://eprint.iacr.org/2020/735 (Bulletproofs+, 17 Jun 2020).
// Notation follows upstream, including its warning that the roles of `g` and
// `h` in the preprint are swapped in Monero's construction.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <vector>

#include "xmr_rct_ops.hpp"

namespace c2pool::xmr::native::rct {

// The aggregation limit: at most 16 outputs share one proof (upstream
// BULLETPROOF_PLUS_MAX_OUTPUTS).
inline constexpr std::size_t BULLETPROOF_PLUS_MAX_OUTPUTS = 16;
// Range width in bits.
inline constexpr std::size_t BULLETPROOF_PLUS_BITS = 64;

// One proof, exactly the fields the wire carries plus V.
//
// V is NOT serialized: monerod reconstructs it from the transaction's own
// output commitments as V_i = outPk_i * 8^-1 (cryptonote_format_utils.cpp
// expand_transaction_1). That reconstruction is what BINDS the range proof to
// the commitments the balance check sums -- a proof verified against V it
// carried itself would prove nothing about the transaction.
struct BulletproofPlus {
    KeyV V;
    Key  A{}, A1{}, B{};
    Key  r1{}, s1{}, d1{};
    KeyV L, R;
};

// Verify a batch. Every proof must pass; the batch is a single weighted
// multi-scalar multiplication compared against the identity, so one bad proof
// fails the whole call and the caller re-verifies singly if it needs to know
// which. False is also returned for a structurally impossible proof (unreduced
// scalar, mismatched L/R, wrong number of rounds for the number of
// commitments, a proof element that is not a point).
bool verify_bulletproofs_plus(const std::vector<const BulletproofPlus*>& proofs);
bool verify_bulletproof_plus(const BulletproofPlus& proof);

// The number of amounts a proof of this shape can carry: 2^(L.size() - 6).
// Upstream n_bulletproof_plus_max_amounts; the transaction decoder uses it to
// refuse a proof whose shape does not match the output count before any
// arithmetic happens.
std::size_t bulletproof_plus_max_amounts(const BulletproofPlus& proof) noexcept;

} // namespace c2pool::xmr::native::rct
