#pragma once

#include <cstdint>

namespace core
{

// Wall-clock seconds since the Unix epoch.
//
// Lives in the dependency-free core_util leaf so that the pool / ltc /
// c2pool libraries can reference it without linking the full core static
// library. Moving this single out-of-line symbol out of core breaks the
// core <-> {pool, ltc, c2pool} static-link cycle (V36 SCC gate).
uint32_t timestamp();

// Raise the process RLIMIT_NOFILE soft limit to `target` (default 65536),
// clamped to the hard limit. Interim hardening fix #4: a capped node
// still holds one fd per stratum session + HTTP + RPC + P2P + LevelDB —
// distro defaults (1024) starve the accept loop under miner churn.
//
// Returns the soft limit actually in effect after the call (even if raising
// failed), or 0 where unsupported (non-POSIX). Deliberately log-free (this
// leaf is dependency-free) — callers log the returned value at startup.
uint64_t raise_nofile_limit(uint64_t target = 65536);

// What raise_nofile_limit did: the soft limit before and after, the hard
// limit, and the highest soft limit the platform admits (the hard limit, or
// kern.maxfilesperproc on macOS, whose setrlimit refuses a soft limit above
// it even under an unlimited hard limit). UINT64_MAX stands for unlimited;
// all 0 where unsupported (non-POSIX). Never lowers the soft limit: on a
// refused raise it asks again for half as much, down to the current limit.
struct NofileLimit {
    uint64_t before = 0;
    uint64_t after = 0;
    uint64_t hard = 0;
    uint64_t ceiling = 0;
};
NofileLimit raise_nofile_limit_report(uint64_t target = 65536);

} // namespace core
