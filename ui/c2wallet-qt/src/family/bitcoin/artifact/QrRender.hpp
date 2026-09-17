// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// M6 slice-2c — GAP-8 QR EXPORT bitmap layer (design docs/design/c2wallet-qt.md
// §5.4 "Transport"). This is the Qt-FREE bridge from a QR frame TEXT line (the
// existing c2w::artifact::qr_encode framing) to a black/white MODULE MATRIX, so
// the Qt page can paint it with QPainter. It embeds the single-file, dependency-
// free nayuki qrcodegen encoder (MIT; see qrcodegen/). No network, no Qt, no
// camera — export only (there is no QR DECODE from an image; frame input is
// paste/file/keyboard-wedge text, decoded by qr_decode()).

#include <cstdint>
#include <string>
#include <vector>

namespace c2w::artifact {

// A rendered QR symbol as a square grid of modules (1 = dark, 0 = light).
struct QrModules {
    int                  size = 0;   // modules per side; 0 => encode failed
    std::vector<uint8_t> cells;      // size*size, row-major

    bool ok() const { return size > 0; }
    bool at(int x, int y) const { return cells[static_cast<size_t>(y) * size + x] != 0; }
};

// Encode one QR frame line (a c2wqr/1|... text frame) into a module matrix,
// byte mode, ECC LOW (max capacity so a fat frame still fits version 1..40).
// Returns size==0 if the text is too large for a single symbol (the caller
// keeps the per-frame chunk small enough that this never trips in practice).
QrModules qr_render_modules(const std::string& text);

} // namespace c2w::artifact
