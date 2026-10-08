// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// M6 slice-2c — the UNSIGNED <-> SIGNED confusion guard for the Air-Gap page
// (design docs/design/c2wallet-qt.md §5.4 / §5.1 threat model).
//
// The offline signer has two visually distinct transfer slots — an UNSIGNED
// slot (online -> offline; must be a C2WU container) and a SIGNED slot (offline
// -> online; must be a finished, fully-signed raw tx). Feeding one into the
// other is a real operator-error / tamper path: e.g. accepting the still-
// unsigned bytes as if they were signed, or pushing a container into the loader
// slot. This module is the std-only, Qt-free structural check that refuses both.
//
// It does a STRUCTURAL parse only (byte framing: legacy or BIP144 segwit); it
// does NOT run scripts (that is the signer core, behind the G3 boundary). It
// answers exactly the guard's questions: does the blob start with the C2WU
// container magic, and does EVERY input carry a non-empty scriptSig or witness?

#include "Digest.hpp" // Bytes

#include <cstdint>
#include <string>

namespace c2w::artifact {

struct RawTxShape {
    bool        parsed = false;             // structurally well-formed as a tx
    std::string error;                      // why it did not parse
    bool        segwit = false;             // BIP144 marker/flag present
    uint64_t    vin = 0;
    uint64_t    vout = 0;
    bool        every_input_has_sig = false; // each input: scriptSig OR witness non-empty
    bool        any_input_has_sig = false;   // at least one input carries a sig/witness
    bool        has_c2wu_magic = false;      // bytes begin with the C2WU container magic
};

// True iff `raw` begins with the UnsignedContainer 'C2WU' magic.
bool has_c2wu_magic(const Bytes& raw);

// Structural parse of a raw Bitcoin/Dash-style transaction. Trailing bytes
// after locktime (e.g. a Dash special-tx extra payload) are tolerated.
RawTxShape inspect_raw_tx(const Bytes& raw);

// The SIGNED-slot acceptor: true iff `raw` is a plausible finished signed tx —
// it parses, it is NOT a C2WU container, it has >=1 input, and EVERY input
// carries a scriptSig or a witness. `why` is set on refusal.
bool accept_as_signed(const Bytes& raw, std::string& why);

} // namespace c2w::artifact
