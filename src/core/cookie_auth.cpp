#include "cookie_auth.hpp"
#include "random.hpp"
#include "log.hpp"

#include <fstream>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace core {

std::string CookieAuth::s_active_cookie;

std::string CookieAuth::generate(const std::filesystem::path& datadir)
{
    // Generate 32 random bytes -> 64-char hex string
    auto bytes = core::random::random_bytes(32);
    static const char* hex = "0123456789abcdef";
    std::string token;
    token.reserve(64);
    for (unsigned char b : bytes) {
        token += hex[b >> 4];
        token += hex[b & 0x0f];
    }

    // Write to .cookie file
    const auto cookie_path = datadir / kCookieFilename;
    const auto tmp_path = datadir / ".cookie.tmp";

    // Write to temp file first, then atomic rename
    {
        std::ofstream out(tmp_path, std::ios::trunc);
        if (!out.is_open()) {
            LOG_ERROR << "CookieAuth: failed to write " << tmp_path;
            return {};
        }
        out << token;
        out.close();
    }

#ifndef _WIN32
    // Set permissions to 0600 (owner read/write only)
    chmod(tmp_path.c_str(), S_IRUSR | S_IWUSR);
#endif

    // Atomic rename
    std::error_code ec;
    std::filesystem::rename(tmp_path, cookie_path, ec);
    if (ec) {
        LOG_ERROR << "CookieAuth: failed to rename cookie file: " << ec.message();
        std::filesystem::remove(tmp_path, ec);
        return {};
    }

    s_active_cookie = token;
    LOG_INFO << "CookieAuth: generated auth cookie at " << cookie_path;
    return token;
}

std::string CookieAuth::read(const std::filesystem::path& datadir)
{
    const auto cookie_path = datadir / kCookieFilename;
    std::ifstream in(cookie_path);
    if (!in.is_open())
        return {};

    std::string token;
    std::getline(in, token);
    return token;
}

void CookieAuth::cleanup(const std::filesystem::path& datadir)
{
    const auto cookie_path = datadir / kCookieFilename;
    std::error_code ec;
    if (std::filesystem::remove(cookie_path, ec)) {
        LOG_INFO << "CookieAuth: removed cookie file";
    }
    s_active_cookie.clear();
}

bool CookieAuth::validate(const std::string& token)
{
    if (s_active_cookie.empty() || token.empty())
        return false;
    return token == s_active_cookie;
}

const std::string& CookieAuth::active_cookie()
{
    return s_active_cookie;
}

} // namespace core
