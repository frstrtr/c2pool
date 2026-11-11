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
#include <cstddef>
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

/// What the node opens, as configured: its LevelDB stores and the socket
/// caps (0 stratum = unlimited, as StratumConfig).
struct FdWants {
    bool   doge_headers = true;   // DOGE header store (pread)
    bool   doge_full = true;      // DOGE full UTXO set (pread)
    bool   ltc_full = false;      // LTC full UTXO set (pread while it fits)
    int    other_dbs = 5;         // DBs with LevelDB's default Env (tables mapped)
    int    ltc_peers = 20;        // the LTC broadcaster (PeerManagerConfig)
    int    merged_chains = 1;     // merged broadcasters, merged_peers each
    int    merged_peers = 20;
    int    sharechain_peers = 30; // p2p_max_peers
    size_t stratum = 100;         // max_stratum_connections
    size_t http = 32;             // concurrent HTTP sessions (the dashboard, the API)
};

/// The process's fd limit split between the stores and the sockets, so that
/// neither runs out: LevelDB turns a refused table open into a read error
/// and, in a compaction, into a background error after which the DB refuses
/// writes until reopened; accept() refuses with EMFILE.
///
/// Counted at their ceilings: a DB's non-table files (LevelDB keeps 10 of
/// max_open_files for them: LOCK, LOG, MANIFEST, the log, compaction
/// outputs); a pread store's table cache (one fd per open table); and the
/// fds LevelDB's default Env keeps once more tables are mapped than its mmap
/// limit (1000) allows, at most a fifth of the limit. A reserve covers stdio,
/// log files, the event loops, the listeners with one accept each, DNS and
/// outbound HTTP.
///
/// When the configured caps do not fit, the stores' tables are mapped first
/// (no fd kept per table; more resident memory): the LTC full set, then
/// DOGE's full set, then its header store. Then the socket caps are lowered
/// in proportion above their floors. fits is false when even the floors do
/// not fit: the node then refuses to start rather than fail at run time.
struct FdPlan {
    StoreFds::Share doge_headers{0, false};
    StoreFds::Share doge_full{0, false};
    StoreFds::Share ltc_full{0, false};
    int      ltc_peers = 0;
    int      merged_peers = 0;
    int      sharechain_peers = 0;
    size_t   stratum = 0;
    size_t   http = 0;
    uint64_t stores = 0;    // fds the stores hold at most
    uint64_t sockets = 0;   // fds the socket caps allow
    bool     mapped = false;
    bool     trimmed = false;
    bool     fits = true;

    static constexpr uint64_t kPerDb = 10;
    static constexpr uint64_t kReserve = 48;
    static constexpr int      kPeerFloor = 4;
    static constexpr int      kSharechainFloor = 8;
    static constexpr size_t   kStratumFloor = 8;
    static constexpr size_t   kHttpFloor = 4;
    /// A stratum cap of 0 (unlimited) is planned as the default's 100, then
    /// given what the limit leaves.
    static constexpr size_t   kStratumUnlimited = 100;

    static FdPlan make(uint64_t nofile, const FdWants& w)
    {
        FdPlan p;
        p.doge_headers = {StoreFds::header_store(nofile), false};
        p.doge_full = {StoreFds::full_set(nofile), false};
        p.ltc_full = StoreFds::ltc_full_set(nofile);
        p.ltc_peers = w.ltc_peers;
        p.merged_peers = w.merged_peers;
        p.sharechain_peers = w.sharechain_peers;
        p.stratum = w.stratum;
        p.http = w.http;
        if (nofile == 0 || nofile == UINT64_MAX)
            return p;   // unknown (no RLIMIT_NOFILE) or unlimited: as configured

        const uint64_t dbs = static_cast<uint64_t>(std::max(w.other_dbs, 0)) + (w.doge_headers ? 1 : 0)
                           + (w.doge_full ? 1 : 0) + (w.ltc_full ? 1 : 0);
        const auto table_fds = [&]() {
            uint64_t n = 0;
            if (w.doge_headers && !p.doge_headers.mmap_reads)
                n += StoreFds::tables(p.doge_headers.max_open_files);
            if (w.doge_full && !p.doge_full.mmap_reads)
                n += StoreFds::tables(p.doge_full.max_open_files);
            if (w.ltc_full && !p.ltc_full.mmap_reads)
                n += StoreFds::tables(p.ltc_full.max_open_files);
            return n;
        };
        const auto stores = [&]() { return dbs * kPerDb + table_fds() + nofile / 5; };
        const size_t stratum_want = w.stratum == 0 ? kStratumUnlimited : w.stratum;
        const uint64_t merged = static_cast<uint64_t>(std::max(w.merged_chains, 0));
        const auto sockets = [&](int ltc, int mp, int sc, size_t st, size_t ht) {
            return static_cast<uint64_t>(std::max(ltc, 0)) + merged * static_cast<uint64_t>(std::max(mp, 0))
                 + static_cast<uint64_t>(std::max(sc, 0)) + st + ht;
        };
        const uint64_t want = sockets(w.ltc_peers, w.merged_peers, w.sharechain_peers, stratum_want, w.http);
        const auto fit = [&]() { return stores() + kReserve + want <= nofile; };

        // 1. Map the stores' tables, the LTC full set first.
        StoreFds::Share* order[] = {&p.ltc_full, &p.doge_full, &p.doge_headers};
        const bool open[] = {w.ltc_full, w.doge_full, w.doge_headers};
        for (int i = 0; i < 3 && !fit(); ++i) {
            if (!open[i] || order[i]->mmap_reads)
                continue;
            *order[i] = {74, true};
            p.mapped = true;
        }
        p.stores = stores();
        if (fit()) {
            // What the limit leaves beyond the caps goes to HTTP (a reverse
            // proxy keeps a pool of connections), and to stratum as well
            // when its cap is unlimited.
            const uint64_t slack = nofile - p.stores - kReserve - want;
            if (w.stratum == 0) {
                p.stratum = static_cast<size_t>(stratum_want + slack / 2);
                p.http = static_cast<size_t>(w.http + slack - slack / 2);
            } else {
                p.http = static_cast<size_t>(w.http + slack);
            }
            p.sockets = nofile - p.stores - kReserve;
            return p;
        }

        // 2. Lower the socket caps in proportion above their floors.
        const uint64_t room = nofile > p.stores + kReserve ? nofile - p.stores - kReserve : 0;
        const int ltc_floor = std::min(w.ltc_peers, kPeerFloor);
        const int mp_floor = std::min(w.merged_peers, kPeerFloor);
        const int sc_floor = std::min(w.sharechain_peers, kSharechainFloor);
        const size_t st_floor = std::min(stratum_want, kStratumFloor);
        const size_t ht_floor = std::min(w.http, kHttpFloor);
        const uint64_t floors = sockets(ltc_floor, mp_floor, sc_floor, st_floor, ht_floor);
        p.trimmed = true;
        if (floors > room) {
            p.fits = false;
            p.ltc_peers = ltc_floor;
            p.merged_peers = mp_floor;
            p.sharechain_peers = sc_floor;
            p.stratum = st_floor;
            p.http = ht_floor;
            p.sockets = floors;
            return p;
        }
        const uint64_t spare = room - floors, above = want - floors;
        const auto share = [&](uint64_t wanted, uint64_t floor) {
            return floor + (wanted - floor) * spare / above;   // rounds down: the sum stays within room
        };
        p.ltc_peers = static_cast<int>(share(w.ltc_peers, ltc_floor));
        p.merged_peers = static_cast<int>(merged == 0 ? w.merged_peers
                                                      : share(w.merged_peers, mp_floor));
        p.sharechain_peers = static_cast<int>(share(w.sharechain_peers, sc_floor));
        p.stratum = static_cast<size_t>(share(stratum_want, st_floor));
        p.http = static_cast<size_t>(share(w.http, ht_floor));
        p.sockets = sockets(p.ltc_peers, p.merged_peers, p.sharechain_peers, p.stratum, p.http);
        return p;
    }
};

} // namespace coin
} // namespace doge
