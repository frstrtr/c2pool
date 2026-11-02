// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Inject scheduler — the control-token file reader.
//
// The node's submit and config routes take the loopback control token in the
// POST body. The companion reads it from a file at the moment of use, applying
// the SAME rules as the node's loader (src/core/config_endpoint.cpp,
// load_control_token_file) so a file the node accepts is a file the companion
// accepts: opened once with O_NOFOLLOW and checked on the fd, a regular file,
// mode exactly 0600, owned by the effective uid, at most 4096 bytes, trimmed
// token 32..128 printable ASCII characters with no interior whitespace.
//
// The token lives only in a zeroizing SecureString for the duration of a tick
// and in the request body, which the caller wipes after the POST. It is never
// placed in argv, the environment, the queue file or a log line.

#include "../../secure/SecureString.hpp"

#include <cstdint>
#include <string>

namespace c2w::companion::sched {

class TokenFile {
public:
    // Read + validate. On refusal `out` is cleared and `why` names the rule
    // (never the file content).
    static bool read(const std::string& path, c2w::secure::SecureString& out, std::string& why);

    // Identity of the file without reading it: "ino:size:mtime_ns", or
    // "missing" when it cannot be stat'ed. A blocked_token item retries when
    // this changes (the operator fixed or rotated the file).
    static std::string fingerprint(const std::string& path);
};

// Append `bytes` as the body of a JSON string literal (the quotes are the
// caller's). Used to place the token into a request body without passing it
// through a JSON library's own (non-wiping) buffers.
void append_json_escaped(std::string& out, const uint8_t* bytes, size_t n);

// {"control_token":"<token>",<rest>} where `rest` is a serialized JSON member
// list (no braces). The result is reserved up front so it never reallocates
// while holding the token; the caller wipes it with wipe_string() after use.
std::string build_token_body(const c2w::secure::SecureString& token, const std::string& rest);

// Overwrite a string's bytes with zeros (compiler-barrier'd), then clear it.
void wipe_string(std::string& s) noexcept;

// True iff `haystack` contains the token bytes (the journal belt).
bool contains_secret(const std::string& haystack, const c2w::secure::SecureString& secret);
bool contains_secret(const std::string& haystack, const std::string& secret);

} // namespace c2w::companion::sched
