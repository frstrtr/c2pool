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
// clamped to the hard limit. Mining-hotel interim fix #4: a capped node
// still holds one fd per stratum session + HTTP + RPC + P2P + LevelDB —
// distro defaults (1024) starve the accept loop under miner churn.
//
// Returns the soft limit actually in effect after the call (even if raising
// failed), or 0 where unsupported (non-POSIX). Deliberately log-free (this
// leaf is dependency-free) — callers log the returned value at startup.
uint64_t raise_nofile_limit(uint64_t target = 65536);

} // namespace core
