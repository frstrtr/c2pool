// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Inject scheduler — the injected clock and the UTC text form used in the
// queue file. The scheduler core never reads the system time directly: the
// runner passes a SystemClock, the KATs a fake one, so every transition is
// deterministic. The clock that matters is the ONLINE host's (NTP-disciplined);
// the air-gapped signer's clock is never trusted, which is why the manifest
// carries no timestamp.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>

namespace c2w::companion::sched {

struct Clock {
    virtual ~Clock() = default;
    // Seconds since the Unix epoch (UTC).
    virtual int64_t now_unix() const = 0;
    // A monotonic millisecond counter (attempt durations only).
    virtual int64_t monotonic_ms() const = 0;
};

struct SystemClock : Clock {
    int64_t now_unix() const override
    {
        using namespace std::chrono;
        return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
    }
    int64_t monotonic_ms() const override
    {
        using namespace std::chrono;
        return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
    }
};

namespace utc_detail {
// Howard Hinnant's days_from_civil / civil_from_days (public domain), so the
// conversion needs neither timegm nor a locale.
inline int64_t days_from_civil(int64_t y, unsigned m, unsigned d)
{
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}
inline void civil_from_days(int64_t z, int64_t& y, unsigned& m, unsigned& d)
{
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y = static_cast<int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp + (mp < 10 ? 3 : -9);
    y += m <= 2;
}
} // namespace utc_detail

// "2026-11-02T00:10:12Z".
inline std::string format_utc(int64_t t)
{
    int64_t days = t / 86400;
    int64_t rem = t % 86400;
    if (rem < 0) { rem += 86400; --days; }
    int64_t y = 0;
    unsigned m = 0, d = 0;
    utc_detail::civil_from_days(days, y, m, d);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04lld-%02u-%02uT%02lld:%02lld:%02lldZ",
                  static_cast<long long>(y), m, d, static_cast<long long>(rem / 3600),
                  static_cast<long long>((rem / 60) % 60), static_cast<long long>(rem % 60));
    return buf;
}

// Strict ISO-8601 UTC: exactly "YYYY-MM-DDTHH:MM:SSZ". A timestamp without the
// trailing 'Z' (a naive local time) or with an offset is refused: the queue
// stores UTC only, and the UI renders local time next to it.
inline bool parse_utc(const std::string& s, int64_t& out, std::string& why)
{
    auto digits = [&](size_t pos, size_t n, int64_t& v) {
        v = 0;
        for (size_t i = pos; i < pos + n; ++i) {
            if (s[i] < '0' || s[i] > '9') return false;
            v = v * 10 + (s[i] - '0');
        }
        return true;
    };
    if (s.size() != 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':' || s[19] != 'Z') {
        why = "time '" + s + "' is not UTC ISO-8601 YYYY-MM-DDTHH:MM:SSZ (the trailing Z is required)";
        return false;
    }
    int64_t y, mo, d, h, mi, se;
    if (!digits(0, 4, y) || !digits(5, 2, mo) || !digits(8, 2, d) || !digits(11, 2, h) ||
        !digits(14, 2, mi) || !digits(17, 2, se)) {
        why = "time '" + s + "' has a non-digit field";
        return false;
    }
    static const int kDays[] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    if (mo < 1 || mo > 12 || d < 1 || d > kDays[mo - 1] || (mo == 2 && d == 29 && !leap) || h > 23 ||
        mi > 59 || se > 59) {
        why = "time '" + s + "' is out of range";
        return false;
    }
    out = utc_detail::days_from_civil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d)) * 86400 +
          h * 3600 + mi * 60 + se;
    return true;
}

} // namespace c2w::companion::sched
