// SPDX-License-Identifier: AGPL-3.0-or-later
#include "QrRender.hpp"

#include <cstring>

#include "qrcodegen/qrcodegen.h" // embedded nayuki encoder (MIT), extern "C"

namespace c2w::artifact {

QrModules qr_render_modules(const std::string& text) {
    QrModules out;

    // encodeBinary reuses `data` as its scratch buffer, so it must be sized for
    // the max version; dataLen is the real payload length.
    std::vector<uint8_t> data(qrcodegen_BUFFER_LEN_MAX, 0);
    std::vector<uint8_t> qrbuf(qrcodegen_BUFFER_LEN_MAX, 0);
    if (text.size() > data.size()) return out; // does not fit any symbol
    if (!text.empty()) std::memcpy(data.data(), text.data(), text.size());

    const bool ok = qrcodegen_encodeBinary(
        data.data(), text.size(), qrbuf.data(),
        qrcodegen_Ecc_LOW, qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
        qrcodegen_Mask_AUTO, /*boostEcl=*/true);
    if (!ok) return out;

    const int sz = qrcodegen_getSize(qrbuf.data());
    if (sz <= 0) return out;
    out.size = sz;
    out.cells.resize(static_cast<size_t>(sz) * static_cast<size_t>(sz), 0);
    for (int y = 0; y < sz; ++y)
        for (int x = 0; x < sz; ++x)
            out.cells[static_cast<size_t>(y) * sz + x] =
                qrcodegen_getModule(qrbuf.data(), x, y) ? 1 : 0;
    return out;
}

} // namespace c2w::artifact
