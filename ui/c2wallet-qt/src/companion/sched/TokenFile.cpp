// SPDX-License-Identifier: AGPL-3.0-or-later
#include "TokenFile.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string_view>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace c2w::companion::sched {

namespace {

bool is_ws(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

} // namespace

bool TokenFile::read(const std::string& path, c2w::secure::SecureString& out, std::string& why)
{
    out.clear();
    if (path.empty()) {
        why = "no token file configured (--token-file PATH)";
        return false;
    }
#if defined(_WIN32)
    why = "token-file reader unsupported on this platform";
    return false;
#else
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        why = errno == ELOOP ? "token file is a symlink; refusing (provide a real regular file)"
                             : std::string("cannot open token file (") + std::strerror(errno) + ")";
        return false;
    }
    auto refuse = [&](const std::string& w) {
        ::close(fd);
        why = w;
        return false;
    };
    struct stat st {};
    if (::fstat(fd, &st) != 0) return refuse(std::string("cannot stat token file (") + std::strerror(errno) + ")");
    if (!S_ISREG(st.st_mode)) return refuse("token file is not a regular file");
    const mode_t perm = st.st_mode & 07777;
    if (perm != 0600) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "%04o", static_cast<unsigned>(perm));
        return refuse(std::string("token file mode must be exactly 0600, found 0") + buf);
    }
    if (st.st_uid != ::geteuid()) return refuse("token file is not owned by the current (effective) user");
    if (st.st_size > 4096) return refuse("token file is implausibly large (>4096 bytes)");

    // Read into a fixed buffer we wipe; never into a growing std::string.
    char raw[4097];
    size_t len = 0;
    for (;;) {
        const ssize_t n = ::read(fd, raw + len, sizeof(raw) - len);
        if (n < 0) {
            if (errno == EINTR) continue;
            c2w::secure::secure_wipe(raw, sizeof(raw));
            return refuse(std::string("cannot read token file (") + std::strerror(errno) + ")");
        }
        if (n == 0) break;
        len += static_cast<size_t>(n);
        if (len > 4096) {
            c2w::secure::secure_wipe(raw, sizeof(raw));
            return refuse("token file is implausibly large (>4096 bytes)");
        }
    }
    ::close(fd);

    size_t b = 0, e = len;
    while (b < e && is_ws(static_cast<unsigned char>(raw[b]))) ++b;
    while (e > b && is_ws(static_cast<unsigned char>(raw[e - 1]))) --e;
    const size_t tlen = e - b;
    bool good = tlen >= 32 && tlen <= 128;
    std::string rule = good ? "" : "token length must be 32-128 chars after trimming";
    for (size_t i = b; good && i < e; ++i) {
        const unsigned char c = static_cast<unsigned char>(raw[i]);
        if (is_ws(c)) { good = false; rule = "token contains interior whitespace"; }
        else if (c < 0x21 || c > 0x7e) { good = false; rule = "token contains a non-printable/non-ASCII character"; }
    }
    if (good) out.assign(raw + b, tlen);
    c2w::secure::secure_wipe(raw, sizeof(raw));
    if (!good) {
        why = rule;
        return false;
    }
    return true;
#endif
}

std::string TokenFile::fingerprint(const std::string& path)
{
#if defined(_WIN32)
    (void)path;
    return "missing";
#else
    struct stat st {};
    if (path.empty() || ::lstat(path.c_str(), &st) != 0) return "missing";
#if defined(__APPLE__)
    const struct timespec mt = st.st_mtimespec;
#else
    const struct timespec mt = st.st_mtim;
#endif
    const long long mtime_ns = static_cast<long long>(mt.tv_sec) * 1000000000LL + static_cast<long long>(mt.tv_nsec);
    return std::to_string(static_cast<unsigned long long>(st.st_ino)) + ":" +
           std::to_string(static_cast<long long>(st.st_size)) + ":" + std::to_string(mtime_ns) + ":" +
           std::to_string(static_cast<unsigned>(st.st_mode & 07777));
#endif
}

void append_json_escaped(std::string& out, const uint8_t* bytes, size_t n)
{
    static const char* hex = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = bytes[i];
        if (c == '"' || c == '\\') {
            out += '\\';
            out += static_cast<char>(c);
        } else if (c < 0x20) {
            out += "\\u00";
            out += hex[c >> 4];
            out += hex[c & 15];
        } else {
            out += static_cast<char>(c);
        }
    }
}

std::string build_token_body(const c2w::secure::SecureString& token, const std::string& rest)
{
    static const std::string head = "{\"control_token\":\"";
    std::string body;
    // Worst case every token byte escapes to 6 chars; reserve once so the
    // buffer holding the token never reallocates (and leaves no stale copy).
    body.reserve(head.size() + token.size() * 6 + 3 + rest.size());
    body += head;
    append_json_escaped(body, token.bytes(), token.size());
    body += "\"";
    if (!rest.empty()) {
        body += ",";
        body += rest;
    }
    body += "}";
    return body;
}

void wipe_string(std::string& s) noexcept
{
    if (!s.empty()) c2w::secure::secure_wipe(s.data(), s.size());
    s.clear();
}

bool contains_secret(const std::string& haystack, const c2w::secure::SecureString& secret)
{
    if (secret.empty()) return false;
    const std::string_view needle(reinterpret_cast<const char*>(secret.bytes()), secret.size());
    return std::string_view(haystack).find(needle) != std::string_view::npos;
}

bool contains_secret(const std::string& haystack, const std::string& secret)
{
    return !secret.empty() && haystack.find(secret) != std::string::npos;
}

} // namespace c2w::companion::sched
