// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// ui/c2wallet-qt/src/family/monero/multisig/MoneroMmsMessage.hpp
//
// MMS (Multisig Messaging System) round-message import/export -- design §4.2
// phase M4-X-MMS. These are the artifacts participants exchange during the
// multisig key-exchange rounds and during a cooperative signing.
//
//   *** EXPERIMENTAL ***  Not wired to the UI; needs independent review.
//
// WIRE FORMAT (faithful + documented, NOT yet byte-verbatim monero MMS):
//   monero-wallet-cli's MMS wraps these payloads in a boost-serialized envelope
//   with per-message signatures and a coordinator round counter. This module
//   ships the PAYLOAD codec -- a compact, self-describing, endian-fixed layout
//   -- so c2wallet participants can round-trip round messages among themselves
//   and so the KAT can prove import(export(x)) == x. Interop with a stock
//   monero-wallet-cli MMS exchange (the boost envelope + its signature) is the
//   documented follow-on; the payloads carried here are the same field set.
//
//   Layout (all integers little-endian):
//     magic[6]      = "C2MMS\x01"
//     type          : 1 byte  (MmsType)
//     round         : 4 bytes (kex/sign round number, coordinator-assigned)
//     signer_index  : 4 bytes
//     item_count    : 4 bytes
//     items         : item_count * (aux:4 bytes, key:32 bytes)
//   The `aux` word carries a partner index (Round2) or is 0. Every 32-byte key
//   is a public curve point or a shared/public scalar -- NO spend secret is
//   ever serialized (the only secret a message legitimately carries is a shared
//   view-secret share, which is common to the group by construction).
// ===========================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "family/monero/MoneroCrypto.hpp"            // Bytes32
#include "family/monero/multisig/MoneroMultisig.hpp" // KexRound1, KexRound2
#include "family/monero/multisig/MoneroMultisigSign.hpp" // PartialNonce

namespace c2wallet::monero::multisig {

enum class MmsType : std::uint8_t {
    KexRound1     = 1,   // blinded spend pub share + shared view secret share
    KexRound2     = 2,   // pairwise subset public points D_ij (M=(N-1)/N)
    SignNonce     = 3,   // a cosigner's Round-1 nonce commitments + partial image
    SignResponse  = 4,   // a cosigner's Round-2 scalar response
};

// A decoded generic MMS payload. The typed helpers below convert to/from the
// protocol structs; this is the on-wire shape.
struct MmsMessage {
    MmsType              type{MmsType::KexRound1};
    std::uint32_t        round{0};
    std::uint32_t        signer_index{0};
    std::vector<std::uint32_t> aux;   // per-item aux word (partner index / 0)
    std::vector<Bytes32> keys;        // per-item 32-byte value
};

// Raw codec.
std::vector<std::uint8_t> mms_serialize(const MmsMessage& m);
bool mms_deserialize(const std::uint8_t* data, std::size_t len, MmsMessage& out);

// Hex convenience (for QR/text transport in the companion).
std::string mms_to_hex(const MmsMessage& m);
bool mms_from_hex(const std::string& hex, MmsMessage& out);

// Typed export.
MmsMessage to_mms(const KexRound1& r, std::uint32_t round = 1);
MmsMessage to_mms(const KexRound2& r, std::uint32_t round = 2);
MmsMessage to_mms(const PartialNonce& n, std::uint32_t round);
MmsMessage response_to_mms(std::uint32_t signer_index, const Bytes32& response, std::uint32_t round);

// Typed import. Return false on a type/shape mismatch.
bool from_mms(const MmsMessage& m, KexRound1& out);
bool from_mms(const MmsMessage& m, KexRound2& out);
bool from_mms(const MmsMessage& m, PartialNonce& out);
bool response_from_mms(const MmsMessage& m, std::uint32_t& signer_index, Bytes32& response);

} // namespace c2wallet::monero::multisig
