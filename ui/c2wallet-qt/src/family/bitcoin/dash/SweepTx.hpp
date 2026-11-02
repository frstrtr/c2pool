// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Zero-fee SWEEP / consolidation builder for c2pool tx injection — the SIGNING
// half. The planner, the shared types and the unsigned serializer are key-free
// and live in SweepPlan.hpp (library c2wallet-dash-plan, SweepPlan.cpp); this
// header adds the declarations that need a key and live in c2wallet-dash-tx
// (SweepSign.cpp): sign_sweep, sign_external_unsigned and
// verify_signed_funding_tx, which sign or verify through the M3-A signer.
// This header is std-only, so either side (and a Qt page) can include it.
//
// Every refusal throws DashAbort and emits nothing. A signing call is
// all-or-nothing: if any tx fails, no tx is returned.

#include "CollateralTx.hpp"
#include "KeyScan.hpp"
#include "SweepPlan.hpp"

#include <string>
#include <vector>

namespace c2w::dash {

// Sign every planned tx with ONE key, self-verify every input (finalize), and
// re-check the signed size against the node cap. Refuses unless confirm_spend,
// if the key is not the funding key, if a planned tx's bytes are not the
// planned ones, or if its amounts do not balance: inject mode needs a fee of
// exactly 0 (inputs == output); relay mode needs inputs == output + fee with a
// fee in (0, kMaxRelayFeePerByte x the worst-case signed size for this key] and,
// after signing, at least kMinRelayFeePerByte x the actual signed size.
std::vector<SignedTx> sign_sweep(const SweepBatchPlan& plan, const FoundKey& key,
                                 bool confirm_spend);

// python c2wallet.py sign / sign-batch parity: sign operator-supplied unsigned
// legacy txs whose every input pays `funding_address`. ALL blobs are parsed and
// validated before the key is touched: refused for bad hex, a segwit
// serialization, trailing bytes, a special-tx type or a version other than 2, a
// scriptSig already present, an input sequence with bit 31 clear (BIP68 opt-in,
// which the node's inject gate refuses), no outputs, or over the input/output
// caps. Legacy sighash commits no input amounts, so none are needed.
std::vector<SignedTx> sign_external_unsigned(const std::vector<std::string>& raw_hexes,
                                             const std::string& funding_address,
                                             bool testnet,
                                             const FoundKey& key,
                                             bool confirm_spend);

// Independent re-verification of a signed tx whose every input spends the
// funding P2PKH: re-parse, re-serialize byte-exact, and run every scriptSig
// through the vendored interpreter. Throws DashAbort on the first failure.
void verify_signed_funding_tx(const std::string& signed_hex,
                              const std::string& funding_address,
                              bool testnet);

} // namespace c2w::dash
