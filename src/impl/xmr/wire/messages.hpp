// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// messages.hpp — the v37 pool-protocol message that carries a Monero/RandomX
// carrier + its bounded receipts on the relay (Family-B, keyed_heavy lane).
//
// This is the c2pool-native registration in the BEGIN_MESSAGE / MESSAGE_FIELDS
// idiom (core/message_macro.hpp), the peer of btc/ltc/dgb/... messages.hpp. It
// adds ONE new pool message type, `xmr_carrier`; it does not alter any existing
// message and is fenced to src/impl/xmr/ (per-coin isolation).
//
// INTEGRATION TARGET: this file is written against the in-tree core headers and
// is meant to compile once dropped under src/impl/xmr/ in the c2pool tree. It is
// NOT part of this leg's standalone KAT (that exercises the schema via the
// dependency-free codec in xmr_carrier_wire.hpp, whose bytes are identical to
// what m_payload carries here). Kept minimal on purpose.
//
// WIRE FRAMING. The pool p2p layer already frames every message as
//     command[...] || length || payload
// (RawMessage; pack.hpp WriteCompactSize for the vector length). The `xmr_carrier`
// payload is exactly the byte string produced by
//     v37::xmr::wire::encode_carrier(CarrierMessage)
// so there is ONE schema definition (the codec) and this message is a thin,
// length-checked envelope over it. Carrying the payload as a single
// length-prefixed byte vector (rather than re-listing MoneroReceipt fields in a
// second READWRITE body) keeps the schema single-source and avoids drift; the
// field-by-field alternative is noted at the bottom.

#include <cstdint>
#include <vector>

#include <core/message.hpp>
#include <core/message_macro.hpp>

#include "xmr_carrier_wire.hpp"   // v37::xmr::wire::{CarrierMessage, encode/decode, cap}

namespace xmr
{

// message_xmr_carrier — one carrier (the difficulty-gated transport share) plus
// 0..R_MAX_XMR receipts riding it, as a single length-prefixed codec payload.
//
//   m_payload := v37::xmr::wire::encode_carrier(msg)     // the schema bytes
//
// The pool length prefix already bounds the frame; the handler additionally
// rejects any payload longer than v37::xmr::wire::cap::MSG_MAX before decoding,
// and decode_carrier() re-checks every internal bound (see the codec). A frame
// that survives this is structurally sound but NOT yet PoW-verified — that is
// the relay's job (xmr_carrier_relay.hpp) under the DoS budget.
BEGIN_MESSAGE(xmr_carrier)
    MESSAGE_FIELDS
    (
        (std::vector<uint8_t>, m_payload)
    )
    {
        READWRITE(obj.m_payload);
    }

    // Convenience: build the payload from a typed CarrierMessage (sender side).
    static std::vector<uint8_t> encode(const v37::xmr::wire::CarrierMessage& m)
    {
        return v37::xmr::wire::encode_carrier(m);
    }

    // Convenience: decode this message's payload to a typed CarrierMessage
    // (receiver side). Throws v37::xmr::wire::WireError on any bound violation.
    v37::xmr::wire::CarrierMessage decode() const
    {
        return v37::xmr::wire::decode_carrier(m_payload);
    }
END_MESSAGE()

// The XMR pool-protocol handler set. An XMR lane node reuses the shared p2pool
// pool handshake/relay messages (version/ping/addrs/... — the bitcoin_family
// pool protocol is coin-agnostic) and ADDS this one carrier type. When wired,
// `xmr_carrier` is appended to the node's MessageHandler<...> variant and to
// core::obs::P2PMessage (p2p_message_stats.hpp) so the /p2p_stats endpoint
// reports it like every other message.
using Handler = MessageHandler<
    message_xmr_carrier
>;

} // namespace xmr

// -----------------------------------------------------------------------------
// ALTERNATIVE (documented, not used): a field-by-field READWRITE body that
// serializes MoneroReceipt natively via c2pool FORMAT_METHODS instead of the
// byte-vector payload. It would require FORMAT_METHODS wrappers for
// v37::xmr::{MoneroReceipt, HashingBlob, SeedRef, CoinbaseOpening, TreeBranch}
// that re-list the exact field order of xmr_carrier_wire.hpp. Rejected here
// because it duplicates the schema in two places (drift risk) for no wire-size
// gain — the codec already emits the identical CompactSize/LE framing pack.hpp
// would. If the tree later prefers native fields, port the field order from the
// codec's encode_receipt()/encode_carrier() verbatim and delete the payload
// envelope; the bytes on the wire are unchanged.
// -----------------------------------------------------------------------------
