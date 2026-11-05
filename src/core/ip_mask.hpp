// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <string>
#include <string_view>

namespace core {

// #1985: miner and peer IP masking for web viewers that are not direct local.
//
// /stratum_stats, /peer_list, /pings, /peer_versions, /peer_txpool_sizes and
// /ban_stats are public routes. Before #1985 they showed each miner's
// "ip:port" and each incoming peer's address to any internet viewer. Now a
// viewer that is not core::is_direct_local_request() gets a token in place of
// the address:
//
//   "h:" + first 8 hex digits of HMAC-SHA256(key, bare host)
//
// The key is 32 bytes drawn once per process from the OS CSPRNG, so a token
// cannot be reversed by hashing the 2^32 IPv4 space. The port is dropped, so
// all connections from one host share one token (the per-IP grouping in
// stratum.html still works). If the CSPRNG draw fails the token is
// "h:unavailable", never a weak or reversible value.

/// "h:" + 8 lowercase hex of HMAC-SHA256(key, host).
std::string mask_host_with_key(const unsigned char* key, std::size_t key_len,
                               std::string_view host);

/// Mask an "ip", "ip:port", "[v6]:port" or bare v6 value with the process key.
/// The port is dropped; "[2001:db8::1]:3333" and "2001:db8::1" give one token.
std::string mask_ip_endpoint(std::string_view endpoint);

/// True when the host part of `s` is an IPv4 or IPv6 literal.
bool is_ip_endpoint(std::string_view s);

}  // namespace core
