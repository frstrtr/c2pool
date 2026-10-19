// SPDX-License-Identifier: AGPL-3.0-or-later
#include "ip_mask.hpp"

#include <array>
#include <cstdio>
#include <fstream>
#include <optional>

#include <errno.h>
#if defined(__linux__)
#include <sys/random.h>   // getrandom(2)
#endif
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>       // BCryptGenRandom (system CSPRNG)
#pragma comment(lib, "bcrypt")
#endif

#include <boost/asio/ip/address.hpp>
#include <btclibs/crypto/hmac_sha256.h>

#include "host_port.hpp"

namespace core {
namespace {

using IpMaskKey = std::array<unsigned char, 32>;

// OS CSPRNG only. A std::random_device / mt19937 key could be recovered and
// would let anyone reverse a token by hashing every IPv4 address.
bool os_random_bytes(unsigned char* buf, std::size_t len)
{
#if defined(_WIN32)
    return ::BCryptGenRandom(nullptr, buf, static_cast<ULONG>(len),
                             BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
#if defined(__linux__)
    std::size_t off = 0;
    while (off < len) {
        ssize_t n = ::getrandom(buf + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        off += static_cast<std::size_t>(n);
    }
    if (off == len) return true;
#endif
    std::ifstream ur("/dev/urandom", std::ios::binary);
    if (!ur) return false;
    ur.read(reinterpret_cast<char*>(buf), static_cast<std::streamsize>(len));
    return static_cast<std::size_t>(ur.gcount()) == len;
#endif
}

// Drawn once per process; nullopt if the CSPRNG failed.
const std::optional<IpMaskKey>& process_key()
{
    static const std::optional<IpMaskKey> key = []() -> std::optional<IpMaskKey> {
        IpMaskKey k{};
        if (!os_random_bytes(k.data(), k.size()))
            return std::nullopt;
        return k;
    }();
    return key;
}

}  // namespace

std::string mask_host_with_key(const unsigned char* key, std::size_t key_len,
                               std::string_view host)
{
    unsigned char mac[CHMAC_SHA256::OUTPUT_SIZE];
    CHMAC_SHA256(key, key_len)
        .Write(reinterpret_cast<const unsigned char*>(host.data()), host.size())
        .Finalize(mac);
    char hex[9];
    for (int i = 0; i < 4; ++i)
        std::snprintf(hex + i * 2, 3, "%02x", static_cast<unsigned>(mac[i]));
    return std::string("h:") + std::string(hex, 8);
}

std::string mask_ip_endpoint(std::string_view endpoint)
{
    const auto& key = process_key();
    if (!key)
        return "h:unavailable";
    return mask_host_with_key(key->data(), key->size(),
                              parse_host_port(endpoint).host);
}

bool is_ip_endpoint(std::string_view s)
{
    boost::system::error_code ec;
    boost::asio::ip::make_address(parse_host_port(s).host, ec);
    return !ec;
}

}  // namespace core
