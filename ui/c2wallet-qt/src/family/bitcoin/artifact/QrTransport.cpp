// SPDX-License-Identifier: AGPL-3.0-or-later
#include "QrTransport.hpp"
#include "TransferContainer.hpp" // MAX_TRANSFER_BYTES

#include <map>
#include <sstream>

namespace c2w::artifact {

static const char* kFramePrefix = "c2wqr/1";

std::string QrFrame::to_text() const {
    std::string s = kFramePrefix;
    s += '|';
    s += std::to_string(seq);
    s += '|';
    s += std::to_string(total);
    s += '|';
    s += to_hex(chunk_digest);
    s += '|';
    s += to_hex(chunk);
    return s;
}

// Split on '|' into exactly 5 fields (the chunk hex is the last field and never
// contains '|', so a plain split is unambiguous).
static bool split5(const std::string& s, std::string out[5]) {
    size_t start = 0;
    for (int i = 0; i < 4; ++i) {
        size_t bar = s.find('|', start);
        if (bar == std::string::npos) return false;
        out[i] = s.substr(start, bar - start);
        start = bar + 1;
    }
    if (s.find('|', start) != std::string::npos) return false; // a 6th field
    out[4] = s.substr(start);
    return true;
}

std::optional<QrFrame> QrFrame::from_text(const std::string& s, std::string& err) {
    err.clear();
    std::string f[5];
    if (!split5(s, f)) { err = "malformed frame (expected 5 |-fields)"; return std::nullopt; }
    if (f[0] != kFramePrefix) { err = "unknown frame prefix"; return std::nullopt; }

    QrFrame fr;
    try {
        unsigned long seq   = std::stoul(f[1]);
        unsigned long total = std::stoul(f[2]);
        fr.seq   = static_cast<uint32_t>(seq);
        fr.total = static_cast<uint32_t>(total);
    } catch (...) {
        err = "non-numeric seq/total";
        return std::nullopt;
    }
    if (fr.total == 0) { err = "total is zero"; return std::nullopt; }
    if (fr.seq >= fr.total) { err = "seq out of range for total"; return std::nullopt; }

    auto dig = from_hex(f[3]);
    if (!dig || dig->size() != 32) { err = "bad digest field"; return std::nullopt; }
    std::copy(dig->begin(), dig->end(), fr.chunk_digest.begin());

    auto chunk = from_hex(f[4]);
    if (!chunk) { err = "bad chunk hex"; return std::nullopt; }
    fr.chunk = std::move(*chunk);
    return fr;
}

QrEncodeResult qr_encode(const Bytes& payload, size_t chunk_size) {
    QrEncodeResult r;
    if (chunk_size == 0) { r.error = "chunk_size must be non-zero"; return r; }
    if (payload.size() > MAX_TRANSFER_BYTES) {
        r.error = "payload exceeds the 100 kB oversize ceiling";
        return r;
    }

    // ceil division; a zero-length payload still produces exactly one frame.
    size_t total = payload.empty() ? 1 : (payload.size() + chunk_size - 1) / chunk_size;

    for (size_t i = 0; i < total; ++i) {
        size_t off = i * chunk_size;
        size_t len = std::min(chunk_size, payload.size() - off);
        QrFrame fr;
        fr.seq   = static_cast<uint32_t>(i);
        fr.total = static_cast<uint32_t>(total);
        fr.chunk.assign(payload.begin() + off, payload.begin() + off + len);
        fr.chunk_digest = sha256(fr.chunk);
        r.frames.push_back(fr.to_text());
    }
    r.ok = true;
    return r;
}

QrDecodeResult qr_decode(const std::vector<std::string>& frames) {
    QrDecodeResult r;
    if (frames.empty()) { r.error = "no frames"; return r; }

    uint32_t total = 0;
    std::map<uint32_t, Bytes> chunks; // seq -> chunk (de-duplicated)

    for (const auto& text : frames) {
        std::string err;
        auto fr = QrFrame::from_text(text, err);
        if (!fr) { r.error = "frame parse: " + err; return r; }

        // Per-frame digest check (tamper / corruption detection).
        if (sha256(fr->chunk) != fr->chunk_digest) {
            r.error = "frame " + std::to_string(fr->seq) + ": digest mismatch";
            return r;
        }

        if (total == 0) total = fr->total;
        else if (total != fr->total) {
            r.error = "inconsistent total across frames";
            return r;
        }

        auto it = chunks.find(fr->seq);
        if (it != chunks.end()) {
            // Duplicate frame: tolerated iff byte-identical.
            if (it->second != fr->chunk) {
                r.error = "conflicting duplicate for seq " + std::to_string(fr->seq);
                return r;
            }
            continue;
        }
        chunks.emplace(fr->seq, fr->chunk);
    }

    // Missing-frame detection: every seq in 0..total-1 must be present.
    for (uint32_t i = 0; i < total; ++i) {
        if (chunks.find(i) == chunks.end()) {
            r.error = "missing frame " + std::to_string(i) + " of " + std::to_string(total);
            return r;
        }
    }

    for (uint32_t i = 0; i < total; ++i) {
        const Bytes& c = chunks[i];
        r.payload.insert(r.payload.end(), c.begin(), c.end());
    }
    r.ok = true;
    return r;
}

} // namespace c2w::artifact
