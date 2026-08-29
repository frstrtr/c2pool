#include <core/core_util.hpp>

#include <ctime>

#ifndef _WIN32
#include <sys/resource.h>
#endif

namespace core
{

uint32_t timestamp()
{
    return std::time(nullptr);
}

uint64_t raise_nofile_limit(uint64_t target)
{
#ifndef _WIN32
    struct rlimit rl{};
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
        return 0;

    if (rl.rlim_cur != RLIM_INFINITY && static_cast<uint64_t>(rl.rlim_cur) < target) {
        struct rlimit want = rl;
        // Clamp to the hard limit — unprivileged processes cannot exceed it.
        if (rl.rlim_max == RLIM_INFINITY
            || static_cast<uint64_t>(rl.rlim_max) >= target)
            want.rlim_cur = static_cast<rlim_t>(target);
        else
            want.rlim_cur = rl.rlim_max;
        // Best effort: on failure the original soft limit stays in effect.
        (void)setrlimit(RLIMIT_NOFILE, &want);
    }

    if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
        return 0;
    if (rl.rlim_cur == RLIM_INFINITY)
        return UINT64_MAX;
    return static_cast<uint64_t>(rl.rlim_cur);
#else
    // Windows: no setrlimit; socket handles are not fd-table bound the same
    // way. Report "unsupported" and let the caller log accordingly.
    (void)target;
    return 0;
#endif
}

} // namespace core
