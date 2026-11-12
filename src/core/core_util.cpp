#include <core/core_util.hpp>

#include <algorithm>
#include <ctime>

#ifndef _WIN32
#include <sys/resource.h>
#endif
#ifdef __APPLE__
#include <sys/syslimits.h>   // OPEN_MAX
#include <sys/sysctl.h>
#endif

namespace core
{

uint32_t timestamp()
{
    return std::time(nullptr);
}

#ifndef _WIN32
namespace {

uint64_t as_u64(rlim_t v)
{
    return v == RLIM_INFINITY ? UINT64_MAX : static_cast<uint64_t>(v);
}

/// The highest soft limit setrlimit admits here: the hard limit, and on
/// macOS also kern.maxfilesperproc (setrlimit fails with EINVAL above it).
uint64_t nofile_ceiling(const struct rlimit& rl)
{
    uint64_t ceiling = as_u64(rl.rlim_max);
#ifdef __APPLE__
    int per_proc = 0;
    size_t len = sizeof(per_proc);
    if (sysctlbyname("kern.maxfilesperproc", &per_proc, &len, nullptr, 0) == 0 && per_proc > 0)
        ceiling = std::min<uint64_t>(ceiling, static_cast<uint64_t>(per_proc));
    else
        ceiling = std::min<uint64_t>(ceiling, OPEN_MAX);
#endif
    return ceiling;
}

} // namespace
#endif

NofileLimit raise_nofile_limit_report(uint64_t target)
{
    NofileLimit r;
#ifndef _WIN32
    struct rlimit rl{};
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
        return r;
    r.before = as_u64(rl.rlim_cur);
    r.hard = as_u64(rl.rlim_max);
    r.ceiling = nofile_ceiling(rl);

    uint64_t want = std::min(target, r.ceiling);
    // Best effort: a refused raise asks for half as much, down to the
    // current limit, which stays in effect when nothing above it is admitted.
    while (want > r.before) {
        struct rlimit next = rl;
        next.rlim_cur = static_cast<rlim_t>(want);
        if (setrlimit(RLIMIT_NOFILE, &next) == 0)
            break;
        want = want / 2;
    }

    if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
        return r;
    r.after = as_u64(rl.rlim_cur);
#else
    // Windows: no setrlimit; socket handles are not fd-table bound the same
    // way. Report "unsupported" and let the caller log accordingly.
    (void)target;
#endif
    return r;
}

uint64_t raise_nofile_limit(uint64_t target)
{
    return raise_nofile_limit_report(target).after;
}

} // namespace core
