// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// c2wallet-qt COMPANION — QR reassembly on the ONLINE side (design §5.4
// "Transport"). Reuses the M5-A QrTransport codec: the online side scans the
// animated QR frames of the offline-signed artifact and reassembles them back
// into a SignedContainer to submit. Also provides the symmetric produce-leg
// helper that chunks the unsigned artifact hex into frames to DISPLAY. NO keys.

#include "TransferContainer.hpp" // c2w::artifact::SignedContainer

#include <optional>
#include <string>
#include <vector>

namespace c2w::companion {

// Reassemble the offline-signed artifact received via animated QR. `frames` are
// the wire-text frames scanned online (M5-A QrTransport form). qr_decode
// tolerates duplicate/out-of-order frames and detects a missing frame or a
// per-frame digest mismatch (tamper). On success the reassembled bytes are the
// SignedContainer.emit() text, re-parsed with the exact c2pool-loader rules.
// Returns nullopt + err on any QR-decode or signed-artifact-parse failure.
std::optional<c2w::artifact::SignedContainer>
reassemble_signed_from_qr(const std::vector<std::string>& frames, std::string& err);

// Produce-leg helper: chunk the unsigned artifact hex into animated-QR frames
// (reuses qr_encode). Refuses (nullopt + err) on the 100 kB oversize ceiling or
// chunk_size==0.
std::optional<std::vector<std::string>>
frames_for_unsigned_hex(const std::string& unsigned_hex, size_t chunk_size, std::string& err);

} // namespace c2w::companion
