#pragma once
// What the standalone header-sync driver (c2pool-btc with no --bitcoind) does
// on one tick: re-send getheaders to the current peer, fail over to the next
// candidate, both, or neither.
//
// Catching up: getheaders on a fresh handshake or when the tip did not advance
// since the last tick; fail over after kNoProgressFailoverSec without progress.
// Caught up: getheaders on a fresh handshake, and when no header arrived for
// kCaughtUpRefreshSec (at most once per kCaughtUpRefreshSec); fail over after
// kCaughtUpFailoverSec without a header. A peer that stops relaying blocks
// therefore no longer holds the tip.

#include <cstdint>

namespace btc::coin {

struct HeaderSourceStep {
    bool getheaders{false};
    bool failover{false};
};

inline constexpr int64_t kNoProgressFailoverSec = 40;
inline constexpr int64_t kCaughtUpRefreshSec    = 20 * 60;
inline constexpr int64_t kCaughtUpFailoverSec   = 60 * 60;

/// quiet_sec: seconds since the header tip last advanced (or since the last
/// failover); since_getheaders_sec: seconds since the driver last sent one.
inline HeaderSourceStep header_source_step(bool caught_up, bool handshaked,
                                           bool fresh_handshake, bool advanced,
                                           int64_t quiet_sec,
                                           int64_t since_getheaders_sec)
{
    HeaderSourceStep s;
    if (!caught_up) {
        s.getheaders = handshaked && (fresh_handshake || !advanced);
        s.failover   = quiet_sec >= kNoProgressFailoverSec;
        return s;
    }
    s.getheaders = handshaked
        && (fresh_handshake
            || (quiet_sec >= kCaughtUpRefreshSec
                && since_getheaders_sec >= kCaughtUpRefreshSec));
    s.failover = quiet_sec >= kCaughtUpFailoverSec;
    return s;
}

} // namespace btc::coin
