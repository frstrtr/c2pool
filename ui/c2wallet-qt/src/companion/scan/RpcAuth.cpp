// SPDX-License-Identifier: AGPL-3.0-or-later
#include "RpcAuth.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace c2w::companion::scan {

namespace {

bool is_ws(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

} // namespace

bool read_rpc_auth_file(const std::string& path, c2w::secure::SecureString& out, std::string& why)
{
    out.clear();
    if (path.empty()) {
        why = "no dashd credentials file (--dashd-auth-file PATH: the .cookie or a 0600 user:password file)";
        return false;
    }
#if defined(_WIN32)
    why = "dashd credentials file reader unsupported on this platform";
    return false;
#else
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        why = errno == ELOOP ? "dashd credentials file is a symlink; refusing (give the real file)"
                             : std::string("cannot open the dashd credentials file (") + std::strerror(errno) + ")";
        return false;
    }
    auto refuse = [&](const std::string& w) {
        ::close(fd);
        why = w;
        return false;
    };
    struct stat st {};
    if (::fstat(fd, &st) != 0) return refuse(std::string("cannot stat the dashd credentials file (") + std::strerror(errno) + ")");
    if (!S_ISREG(st.st_mode)) return refuse("dashd credentials file is not a regular file");
    if ((st.st_mode & 0077) != 0) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "%04o", static_cast<unsigned>(st.st_mode & 07777));
        return refuse(std::string("dashd credentials file must not be readable by group or other (0600), found 0") + buf);
    }
    if (st.st_uid != ::geteuid()) return refuse("dashd credentials file is not owned by the current (effective) user");
    if (st.st_size > 4096) return refuse("dashd credentials file is implausibly large (>4096 bytes)");

    char raw[4097];
    size_t len = 0;
    for (;;) {
        const ssize_t n = ::read(fd, raw + len, sizeof(raw) - len);
        if (n < 0) {
            if (errno == EINTR) continue;
            c2w::secure::secure_wipe(raw, sizeof(raw));
            return refuse(std::string("cannot read the dashd credentials file (") + std::strerror(errno) + ")");
        }
        if (n == 0) break;
        len += static_cast<size_t>(n);
        if (len > 4096) {
            c2w::secure::secure_wipe(raw, sizeof(raw));
            return refuse("dashd credentials file is implausibly large (>4096 bytes)");
        }
    }
    ::close(fd);

    size_t b = 0, e = len;
    while (b < e && is_ws(static_cast<unsigned char>(raw[b]))) ++b;
    while (e > b && is_ws(static_cast<unsigned char>(raw[e - 1]))) --e;
    std::string rule;
    size_t colon = 0;
    bool seen_colon = false;
    for (size_t i = b; rule.empty() && i < e; ++i) {
        const unsigned char c = static_cast<unsigned char>(raw[i]);
        if (is_ws(c)) rule = "dashd credentials contain whitespace (one line user:password expected)";
        else if (c < 0x21 || c > 0x7e) rule = "dashd credentials contain a non-printable or non-ASCII character";
        else if (c == ':' && !seen_colon) {
            seen_colon = true;
            colon = i;
        }
    }
    if (rule.empty() && (!seen_colon || colon == b || colon + 1 == e))
        rule = "dashd credentials must be user:password (the .cookie or an rpcauth pair)";
    if (rule.empty()) out.assign(raw + b, e - b);
    c2w::secure::secure_wipe(raw, sizeof(raw));
    if (!rule.empty()) {
        why = rule;
        return false;
    }
    return true;
#endif
}

c2w::secure::SecureString basic_auth_value(const c2w::secure::SecureString& in)
{
    static const char* k = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const uint8_t* p = in.bytes();
    const size_t n = in.size();
    char buf[8192];
    size_t o = 0;
    for (size_t i = 0; i < n && o + 4 < sizeof(buf); i += 3) {
        const uint32_t v = (static_cast<uint32_t>(p[i]) << 16) | (i + 1 < n ? static_cast<uint32_t>(p[i + 1]) << 8 : 0u) |
                           (i + 2 < n ? static_cast<uint32_t>(p[i + 2]) : 0u);
        buf[o++] = k[(v >> 18) & 63];
        buf[o++] = k[(v >> 12) & 63];
        buf[o++] = i + 1 < n ? k[(v >> 6) & 63] : '=';
        buf[o++] = i + 2 < n ? k[v & 63] : '=';
    }
    c2w::secure::SecureString s;
    s.assign(buf, o);
    c2w::secure::secure_wipe(buf, sizeof(buf));
    return s;
}

} // namespace c2w::companion::scan
