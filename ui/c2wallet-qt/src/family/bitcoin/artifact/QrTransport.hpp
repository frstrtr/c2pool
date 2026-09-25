// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// M5-A QR transport (design docs/design/c2wallet-qt.md §5.4 "Transport"): a
// multi-frame animated-QR codec for a diode gap. Each frame carries a sequence
// index + total + a per-frame sha256 digest; the 100 kB oversize ceiling
// bounds the frame count.
//
// This is the DATA LAYER only — frame CHUNKING + reassembly + digest. Rendering
// the frames as QR bitmaps is a later UI concern; here a frame is a compact
// self-describing text line, which is exactly what a QR alphanumeric/byte
// segment carries.

#include "Digest.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace c2w::artifact {

// One animated-QR frame. Text wire form:
//   c2wqr/1|<seq>|<total>|<chunk_sha256_hex>|<chunk_hex>
struct QrFrame {
    uint32_t seq   = 0; // 0-based frame index
    uint32_t total = 0; // total frame count
    Hash32   chunk_digest{}; // sha256 of THIS frame's chunk bytes
    Bytes    chunk;          // this frame's payload slice

    std::string to_text() const;
    static std::optional<QrFrame> from_text(const std::string& s, std::string& err);
};

struct QrEncodeResult {
    bool                     ok = false;
    std::string              error;
    std::vector<std::string> frames; // wire text, one per frame
};

// Chunk `payload` into frames of at most `chunk_size` bytes each, each stamped
// with its own sha256 digest. REFUSES (ok=false) if the payload exceeds
// MAX_TRANSFER_BYTES (the oversize ceiling that bounds frame count) or if
// chunk_size is 0. A zero-length payload yields exactly one empty frame.
QrEncodeResult qr_encode(const Bytes& payload, size_t chunk_size);

struct QrDecodeResult {
    bool        ok = false;
    std::string error;
    Bytes       payload; // reassembled bytes on success
};

// Reassemble frames back into the payload. Tolerates DUPLICATE frames and
// OUT-OF-ORDER arrival; detects a per-frame digest MISMATCH (tamper/corruption),
// a MISSING frame (a gap in 0..total-1), an inconsistent `total`, and two
// frames that claim the same seq but carry different bytes.
QrDecodeResult qr_decode(const std::vector<std::string>& frames);

} // namespace c2w::artifact
