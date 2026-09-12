// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Fatal, operator-facing error for the DASH special-tx modules — the C++ analog
// of dash_collateral_tx.py's `Abort`. It NEVER carries secret material (no
// mnemonic, no scalar): the porting rule from the reference tool is that a
// wrong path/index/network/checksum must hard-abort with a non-sensitive
// message, never silently sign or leak the phrase. Design §4.1.1 ("hard-abort
// on mismatch") and §5.3.

#include <stdexcept>
#include <string>

namespace c2w::dash {

class DashAbort : public std::runtime_error {
public:
    explicit DashAbort(const std::string& what) : std::runtime_error(what) {}
};

} // namespace c2w::dash
