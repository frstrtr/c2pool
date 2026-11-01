// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Inject scheduler — runner configuration rules shared by the headless daemon
// (slice S2) and the GUI (slice S3): the node URL must be loopback, and the
// command line has no way to pass the token by value.
//
//   * node.url: "http://" + host 127.0.0.1 | [::1] | localhost + optional port,
//     no path, no user info, no TLS. A remote node is reached with
//     `ssh -L 18080:127.0.0.1:8080 host` and configured as
//     http://127.0.0.1:18080 (the node's own routes are loopback-only anyway).
//   * CLI: --node-url URL, --token-file PATH, --queue PATH, --poll-sec N
//     (also --opt=value). There is deliberately NO --token VALUE: argv is
//     world-readable through /proc; it is a usage error.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace c2w::companion::sched {

bool validate_node_url(const std::string& url, std::string& why);

struct CliOverrides {
    std::optional<std::string> node_url;
    std::optional<std::string> token_file;
    std::optional<std::string> queue;
    std::optional<int64_t> poll_sec;
    std::vector<std::string> rest; // everything else, in order (subcommand arguments)
};

// Parse the shared options out of `args` (argv without the program name).
// false + why on a usage error: --token in any spelling, a missing value, a
// non-loopback --node-url, or a --poll-sec outside 1..3600.
bool parse_cli_overrides(const std::vector<std::string>& args, CliOverrides& out, std::string& why);

} // namespace c2w::companion::sched
