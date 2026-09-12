// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Submit.hpp"

#include <fstream>

namespace c2w::companion {

std::optional<c2w::artifact::SignedContainer>
parse_signed_artifact(const std::string& text, std::string& err) {
    return c2w::artifact::SignedContainer::parse(text, err);
}

bool write_pin_local_tx_file(const std::string& path,
                             const c2w::artifact::SignedContainer& sc,
                             std::string& err) {
    err.clear();
    if (sc.tx_hexes.empty()) { err = "signed container is empty — nothing to write"; return false; }

    const std::string bytes = sc.emit(); // one raw hex per line, '\n'-terminated
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) { err = "cannot open file for write: " + path; return false; }
    f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (!f) { err = "write failed: " + path; return false; }
    f.close();
    if (!f) { err = "close/flush failed: " + path; return false; }
    return true;
}

c2w::artifact::SeamRequest build_submit_request(const std::string& coin,
                                                const std::string& tx_hex) {
    c2w::artifact::SeamRequest r;
    r.op     = c2w::artifact::SeamOp::Submit;
    r.coin   = coin;
    r.tx_hex = tx_hex;
    r.dry_run = false;
    return r;
}

} // namespace c2w::companion
