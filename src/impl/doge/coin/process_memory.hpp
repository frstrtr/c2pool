// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Embedded DOGE, the full UTXO set: the process's memory as the kernel
/// counts it, and the bounds the full set's node runs with (FRESH-NODE §6.5,
/// §8: RSS <= 2 GB during the set's IBD, <= 1 GB after).
///
/// The IBD node (ee4c882f0, 14.6-17.1 M coins) at RSS 2.5 GB: RssAnon 1.26 GB
/// (heap 450 MB, anonymous mappings 813 MB: malloc's thread arenas, the
/// LevelDB memtables and block caches) and RssFile 1.24 GB: LevelDB table
/// files mapped by the table caches, the full set's DB 809 MB of it (514
/// files of a 1.1 GB DB). The UTXO view cache is not the cause: the lane
/// flushes it after every block (buffer_bytes 3.3 MB). Bounds:
///   - the full set's DB reads its tables with pread, not mmap (no RssFile),
///     in 32 MB files (LevelDBOptions::mmap_reads, max_file_size);
///   - malloc keeps at most MALLOC_ARENAS arenas, and gives free pages back
///     to the kernel every TRIM_EVERY (glibc; elsewhere nothing to do).

#include <chrono>
#include <cstdio>
#include <cstring>
#if defined(__GLIBC__)
#include <malloc.h>
#endif

namespace doge {
namespace coin {

struct ProcessMemory {
    static constexpr int MALLOC_ARENAS = 4;
    static constexpr std::chrono::seconds TRIM_EVERY{60};

    long rss_kb{0};   // VmRSS
    long anon_kb{0};  // RssAnon: heap, arenas, anonymous mappings
    long file_kb{0};  // RssFile: mapped files (LevelDB tables read through mmap)

    /// /proc/self/status (Linux); zeros elsewhere.
    static ProcessMemory read()
    {
        ProcessMemory m;
        if (FILE* f = std::fopen("/proc/self/status", "r")) {
            char line[256];
            while (std::fgets(line, sizeof(line), f)) {
                long v = 0;
                if (std::sscanf(line, "VmRSS: %ld kB", &v) == 1)
                    m.rss_kb = v;
                else if (std::sscanf(line, "RssAnon: %ld kB", &v) == 1)
                    m.anon_kb = v;
                else if (std::sscanf(line, "RssFile: %ld kB", &v) == 1)
                    m.file_kb = v;
            }
            std::fclose(f);
        }
        return m;
    }

    /// At most `arenas` malloc arenas from now on: a thread's frees stay in
    /// its own arena, so each thread that allocated a lot keeps its own
    /// partly used heaps.
    static void limit_arenas(int arenas = MALLOC_ARENAS)
    {
#if defined(__GLIBC__)
        ::mallopt(M_ARENA_MAX, arenas);
#else
        (void)arenas;
#endif
    }

    /// Free pages of every arena back to the kernel; true when any was.
    static bool trim()
    {
#if defined(__GLIBC__)
        return ::malloc_trim(0) != 0;
#else
        return false;
#endif
    }
};

} // namespace coin
} // namespace doge
