// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Embedded DOGE: how many tables the stores that read with pread keep open
/// (one fd each; with mmap the fd closed once the table was mapped), drawn
/// from the process's soft fd limit (c2pool raises it to 65536 at start
/// where the hard limit allows; macOS keeps 256 when the raise fails). The
/// header store (with the hash schedule) and the full UTXO set together take
/// at most half of it: the rest is for the other DBs' files and the sockets
/// (VERIFY7 B3, VERIFY8 C2). LevelDB keeps max_open_files - 10 tables and
/// takes at least 74.

#include <algorithm>
#include <cstdint>

namespace doge {
namespace coin {

struct StoreFds {
    /// The DOGE header store: 64..256 (2 MB tables; ~330 MB in all).
    static int header_store(uint64_t nofile)
    {
        return nofile == 0 ? 256 : static_cast<int>(std::clamp<uint64_t>(nofile / 8, 64, 256));
    }
    /// The full UTXO set's DB: 64..512 (32 MB tables).
    static int full_set(uint64_t nofile)
    {
        return nofile == 0 ? 512 : static_cast<int>(std::clamp<uint64_t>(nofile / 4, 64, 512));
    }

    /// LevelDB keeps max(max_open_files, 74) - 10 tables open.
    static uint64_t tables(int max_open_files) { return static_cast<uint64_t>(std::max(max_open_files, 74) - 10); }

    /// The LTC full UTXO set's DB (#2137) beside DOGE's two stores: what half
    /// the limit leaves after them, read with pread (64..512 tables); with
    /// less than 64 tables left (a 256 soft limit), mapped tables, which keep
    /// no fd (LevelDB closes the file once the table is mapped).
    struct Share {
        int  max_open_files;
        bool mmap_reads;
    };
    static Share ltc_full_set(uint64_t nofile)
    {
        if (nofile == 0)
            return {512, false};
        const uint64_t used = tables(header_store(nofile)) + tables(full_set(nofile));
        const uint64_t left = nofile / 2 > used ? nofile / 2 - used : 0;
        if (left < 64)
            return {74, true};
        return {static_cast<int>(std::min<uint64_t>(left, 502) + 10), false};
    }
};

} // namespace coin
} // namespace doge
