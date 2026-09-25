// SPDX-License-Identifier: AGPL-3.0-or-later
#include "QrReassembly.hpp"

#include "Digest.hpp"      // c2w::artifact::Bytes
#include "QrTransport.hpp" // c2w::artifact::qr_encode / qr_decode

namespace c2w::companion {

std::optional<c2w::artifact::SignedContainer>
reassemble_signed_from_qr(const std::vector<std::string>& frames, std::string& err) {
    err.clear();
    auto dec = c2w::artifact::qr_decode(frames);
    if (!dec.ok) { err = "QR reassembly failed: " + dec.error; return std::nullopt; }

    // The reassembled payload is the SignedContainer.emit() text bytes.
    std::string text(dec.payload.begin(), dec.payload.end());
    return c2w::artifact::SignedContainer::parse(text, err);
}

std::optional<std::vector<std::string>>
frames_for_unsigned_hex(const std::string& unsigned_hex, size_t chunk_size, std::string& err) {
    err.clear();
    c2w::artifact::Bytes payload(unsigned_hex.begin(), unsigned_hex.end());
    auto enc = c2w::artifact::qr_encode(payload, chunk_size);
    if (!enc.ok) { err = "QR encode failed: " + enc.error; return std::nullopt; }
    return enc.frames;
}

} // namespace c2w::companion
