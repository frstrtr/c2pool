// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Scan & Plan (companion) — dashd RPC credentials, read from a file at the
// moment of use and never from argv or the environment (argv is
// world-readable through /proc; there is no --dashd-auth VALUE).
//
// The file is dashd's `.cookie` ("__cookie__:<hex>") or an rpcauth pair
// "user:password" on one line. Rules (the control-token file's, with the
// length relaxed for an rpcauth password): opened once with O_NOFOLLOW and
// checked on the fd, a regular file, owned by the effective uid, no access for
// group or other (0600 / 0400), at most 4096 bytes; after trimming one line of
// printable ASCII with no whitespace, a non-empty user, a ':' and a non-empty
// password. A refusal names the rule, never the content.

#include "../../secure/SecureString.hpp"

#include <string>

namespace c2w::companion::scan {

bool read_rpc_auth_file(const std::string& path, c2w::secure::SecureString& out, std::string& why);

// The HTTP Basic credential for `user:password` (base64, no "Basic " prefix),
// in a zeroizing buffer.
c2w::secure::SecureString basic_auth_value(const c2w::secure::SecureString& user_colon_password);

} // namespace c2w::companion::scan
