// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DASH governance-proposal collateral commitment — the gobject collateral hash
// and its OP_RETURN proof-of-burn script (design §4.1.1). Byte-exact port of
// frstrtr/dash-proposal-collateral `proto_hash.py` / `dash_collateral_tx.py`
// gov_object_hash(), which reproduces Dash Core Governance::Object::GetHash()
// (governance/common.cpp:23-39) and object.cpp:488-489's findScript. Ported
// from MIT to AGPL on inclusion (see the module CMakeLists provenance note).
//
// Serialization (CHashWriter(SER_GETHASH), the exact field order Dash Core uses):
//   hashParent (uint256, 32 raw LE bytes)
//   revision   (int32  LE)
//   time       (int64  LE)
//   HexStr(vchData) as std::string (compactsize length + lowercase-hex ASCII)
//   null masternodeOutpoint (32x00 + ffffffff)
//   dummy uint8_t{} + 0xffffffff   ("to match old hashing")
//   empty vchSig (compactsize 0)
//   => double-SHA256
//
// This header is deliberately dependency-light (std types only) so the DASH
// signing translation unit — which pulls the vendored dashscript closure — can
// include it without dragging in the btclibs closure the .cpp uses.

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace c2w::dash {

// The gobject collateral hash in INTERNAL byte order — i.e. what
// ToByteVector(uint256) yields and what the OP_RETURN push must contain. The
// operator-facing DISPLAY hash is the reverse of this. `parent_hash_hex` is
// given in DISPLAY order (default all-zero for a top-level proposal). Throws
// DashAbort on a non-32-byte parent or invalid data-hex.
std::array<uint8_t, 32> gov_object_hash(const std::string& parent_hash_hex,
                                        int32_t revision,
                                        int64_t time_,
                                        const std::string& data_hex);

// Display-order hex (the string a `gobject submit` call takes; the reverse of
// the internal bytes).
std::string gov_hash_display(const std::array<uint8_t, 32>& internal);

// CScript() << OP_RETURN << ToByteVector(nExpectedHash) — object.cpp:488-489.
// Exactly 34 bytes: 0x6a 0x20 followed by the 32 internal-order hash bytes.
std::vector<uint8_t> collateral_op_return_script(const std::array<uint8_t, 32>& internal);

} // namespace c2w::dash
