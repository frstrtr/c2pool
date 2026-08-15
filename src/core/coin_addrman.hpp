// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// core::CoinAddrMan — bucketed new/tried address manager for the embedded
/// coin-P2P arm: a port of the dashd / Bitcoin Core CAddrMan algorithm
/// (addrman.h / addrman.cpp) onto c2pool's core networking types.
///
/// WHY: the per-coin CoinPeerManagers keep a small flat scored map (working
/// set, ~max_peers entries). That is enough to DIAL well but not to REMEMBER
/// well: getaddr harvests beyond the working-set capacity were dropped on the
/// floor, so a daemonless node sat on a handful of seeds instead of growing a
/// large, quality-ranked archival peer DB the way dashd does. This class is
/// the missing DB. The algorithm is MIRRORED from dashd, not reinvented:
///
///   • AddrInfo equivalent (Entry): last_try / last_success / attempts /
///     ref_count / in_tried, wall-clock epoch timestamps (survive restarts).
///   • new table: 1024 buckets x 64 slots (entry may live in up to 8 new
///     buckets, one per distinct source group, ref-counted).
///   • tried table: 256 buckets x 64 slots (an address group maps into at
///     most 8 distinct tried buckets).
///   • Bucket coordinates are keyed by a persistent per-node random SipHash
///     key + the /16 (IPv4) / /32 (IPv6) network group — an attacker cannot
///     aim addresses at chosen buckets, and cannot fill more than a bounded
///     slice of either table from one netgroup.
///   • Add / Good / Attempt / Connected feedback, IsTerrible demotion (never
///     silent deletion of history), GetChance quality bias, stochastic
///     Select() (50/50 tried-vs-new, random bucket walk, acceptance
///     probability chance*factor with factor *= 1.2 per rejection).
///   • Tried-collision protocol: Good() onto an occupied tried slot parks the
///     newcomer in m_collisions; the incumbent is handed out for a re-test
///     (select_tried_collision) and resolve_collisions() applies dashd's
///     eviction rules (recent success protects the incumbent; a recent failed
///     attempt evicts it).
///   • get_addr(): the 23% / 2500-cap random sample used to serve peers to
///     others.
///
/// Constants are dashd's verbatim (ADDRMAN_* family). Persistence is a
/// per-coin JSON file (peers.dat-equivalent): fail-safe — a corrupt or absent
/// DB loads as EMPTY (never throws out of load()), so the seed ladder
/// bootstraps exactly as before.
///
/// Scope fence: this class only remembers and ranks ADDRESSES. It has no
/// influence on block/tx/share validation, serving, or reward paths.
///
/// Header-only over core (NetService/PeerEndpoint, log, nlohmann) to match
/// the sibling core networking headers. SipHash-2-4 is inlined below
/// (public-domain reference algorithm, same primitive as
/// src/btclibs/crypto/siphash.{h,cpp}) so the header stays self-contained
/// and link-free for every consumer target.

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <vector>

#include <boost/asio/ip/address.hpp>
#include <nlohmann/json.hpp>

#include <core/log.hpp>
#include <core/netaddress.hpp>

namespace core {

namespace addrman_detail {

/// SipHash-2-4 over a byte string (reference algorithm; identical primitive
/// to btclibs/crypto/siphash.cpp, restated header-only so core stays
/// link-free). Used ONLY for bucket-coordinate derivation — not consensus.
inline uint64_t rotl64(uint64_t x, int b) { return (x << b) | (x >> (64 - b)); }

inline uint64_t siphash(uint64_t k0, uint64_t k1, const std::string& data)
{
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    auto sipround = [&]() {
        v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
        v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
        v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
        v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
    };

    const auto* in = reinterpret_cast<const unsigned char*>(data.data());
    const size_t len = data.size();
    const size_t left = len & 7;
    uint64_t b = static_cast<uint64_t>(len) << 56;

    size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        uint64_t m = 0;
        for (int j = 7; j >= 0; --j) m = (m << 8) | in[i + j];
        v3 ^= m;
        sipround(); sipround();
        v0 ^= m;
    }
    for (size_t j = 0; j < left; ++j)
        b |= static_cast<uint64_t>(in[i + j]) << (8 * j);

    v3 ^= b;
    sipround(); sipround();
    v0 ^= b;
    v2 ^= 0xff;
    sipround(); sipround(); sipround(); sipround();
    return v0 ^ v1 ^ v2 ^ v3;
}

/// Network group for bucket keying: /16 for IPv4 (and v4-mapped v6), first
/// 32 bits for IPv6, the raw string for anything unparseable. Same group
/// semantics the per-coin peer managers already use for their Sybil caps
/// (dashd-without-asmap: NetGroupManager/asmap is explicitly out of scope).
inline std::string network_group(const std::string& ip)
{
    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(ip, ec);
    if (!ec) {
        if (addr.is_v4()) {
            auto bytes = addr.to_v4().to_bytes();
            return std::to_string(bytes[0]) + "." + std::to_string(bytes[1]);
        }
        if (addr.is_v6()) {
            auto v6 = addr.to_v6();
            if (v6.is_v4_mapped()) {
                auto v4 = boost::asio::ip::make_address_v4(
                    boost::asio::ip::v4_mapped, v6).to_bytes();
                return std::to_string(v4[0]) + "." + std::to_string(v4[1]);
            }
            auto bytes = v6.to_bytes();
            char buf[12];
            std::snprintf(buf, sizeof(buf), "%02x%02x:%02x%02x",
                          bytes[0], bytes[1], bytes[2], bytes[3]);
            return std::string(buf);
        }
    }
    return ip;
}

} // namespace addrman_detail

class CoinAddrMan
{
public:
    // ── dashd ADDRMAN_* constants, verbatim ─────────────────────────────────
    static constexpr int TRIED_BUCKET_COUNT = 1 << 8;   // 256
    static constexpr int NEW_BUCKET_COUNT = 1 << 10;    // 1024
    static constexpr int BUCKET_SIZE = 1 << 6;          // 64
    static constexpr int TRIED_BUCKETS_PER_GROUP = 8;
    static constexpr int NEW_BUCKETS_PER_SOURCE_GROUP = 64;
    static constexpr int NEW_BUCKETS_PER_ADDRESS = 8;
    static constexpr int64_t HORIZON_SECONDS = 30LL * 24 * 3600;   // 30 days
    static constexpr int RETRIES = 3;
    static constexpr int MAX_FAILURES = 10;
    static constexpr int64_t MIN_FAIL_SECONDS = 7LL * 24 * 3600;   // 7 days
    static constexpr int64_t REPLACEMENT_SECONDS = 4LL * 3600;     // 4 hours
    static constexpr int64_t TEST_WINDOW_SECONDS = 40LL * 60;      // 40 minutes
    static constexpr size_t SET_TRIED_COLLISION_SIZE = 10;
    static constexpr int64_t DEFAULT_TIME_PENALTY = 2LL * 3600;    // gossip 2h

    /// AddrInfo equivalent. All timestamps are WALL-CLOCK epoch seconds so
    /// history survives restarts (a steady_clock stamp dies with the process).
    struct Entry
    {
        NetService  addr;
        std::string source_group;       // netgroup of the first source
        int64_t     ntime{0};           // last believed-alive
        int64_t     last_try{0};
        int64_t     last_success{0};
        int64_t     last_count_attempt{0};
        int         attempts{0};
        int         ref_count{0};       // new-table references
        bool        in_tried{false};
        int         random_pos{-1};     // index into m_random

        /// dashd AddrInfo::IsTerrible, verbatim thresholds. Terrible entries
        /// are DEMOTED/overwritten in place, never proactively erased —
        /// history survives until a better candidate needs the slot.
        bool is_terrible(int64_t now) const
        {
            if (last_try && last_try >= now - 60) return false; // tried in the last minute
            if (ntime > now + 10 * 60) return true;             // future timestamp
            if (ntime == 0 || now - ntime > HORIZON_SECONDS) return true;
            if (last_success == 0 && attempts >= RETRIES) return true;
            if (now - last_success > MIN_FAIL_SECONDS && attempts >= MAX_FAILURES)
                return true;
            return false;
        }

        /// dashd AddrInfo::GetChance: 0.66^min(attempts,8), x0.01 if tried
        /// within the last 10 minutes.
        double get_chance(int64_t now) const
        {
            double chance = 1.0;
            const int64_t since_try = std::max<int64_t>(now - last_try, 0);
            if (since_try < 60 * 10) chance *= 0.01;
            chance *= std::pow(0.66, std::min(attempts, 8));
            return chance;
        }
    };

    /// k0/k1 = persistent bucket-key halves. (0,0) => fresh random key (the
    /// production path; load() restores the persisted key). Non-zero keys are
    /// for deterministic KATs and for load().
    explicit CoinAddrMan(uint64_t k0 = 0, uint64_t k1 = 0)
    {
        if (k0 == 0 && k1 == 0) {
            std::random_device rd;
            m_k0 = (static_cast<uint64_t>(rd()) << 32) ^ rd();
            m_k1 = (static_cast<uint64_t>(rd()) << 32) ^ rd();
            // A pathological random_device could still yield (0,0).
            if (m_k0 == 0 && m_k1 == 0) m_k1 = 1;
        } else {
            m_k0 = k0;
            m_k1 = k1;
        }
        m_rng.seed(std::random_device{}());
        clear_tables();
    }

    // ── dashd Add(): bank an address (gossip / seed / manual) ───────────────
    /// source_ip = who told us (empty => self-announced; keyed by own group,
    /// dashd's convention for DNS/fixed/manual sources). Returns true when a
    /// NEW entry landed in a new-table slot.
    bool add(const NetService& addr, const std::string& source_ip = std::string(),
             int64_t time_penalty = DEFAULT_TIME_PENALTY, int64_t now = 0)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (now == 0) now = wall_now();
        if (source_ip.empty()) time_penalty = 0;    // self-announcement

        const std::string key = addr.to_string();
        const std::string src_group = addrman_detail::network_group(
            source_ip.empty() ? addr.address() : source_ip);

        Entry* e = nullptr;
        int id = -1;
        bool created = false;

        auto it = m_index.find(key);
        if (it != m_index.end()) {
            id = it->second;
            e = &m_info[id];
            // Periodic freshness update (dashd's currently-online interval
            // collapses to "seen again now" here because c2pool's addr intake
            // does not carry the gossip nTime field).
            const int64_t update_interval = 24 * 3600;
            if (e->ntime < now - update_interval - time_penalty)
                e->ntime = now - time_penalty;
            if (e->in_tried) return false;
            if (e->ref_count == NEW_BUCKETS_PER_ADDRESS) return false;
            // Stochastic damping: with n references it is 2^n times harder
            // to gain another one (dashd verbatim).
            const int factor = 1 << e->ref_count;
            if (factor > 1 && rand_uint(factor) != 0) return false;
        } else {
            id = m_next_id++;
            Entry fresh;
            fresh.addr = addr;
            fresh.source_group = src_group;
            fresh.ntime = std::max<int64_t>(0, now - time_penalty);
            fresh.random_pos = static_cast<int>(m_random.size());
            m_info[id] = std::move(fresh);
            m_random.push_back(id);
            m_index[key] = id;
            ++m_new_count;
            e = &m_info[id];
            created = true;
        }

        const int bucket = new_bucket_of(*e, src_group);
        const int pos = bucket_position_of(*e, /*is_new=*/true, bucket);
        bool placed = false;
        if (m_new[bucket][pos] != id) {
            placed = (m_new[bucket][pos] == -1);
            if (!placed) {
                Entry& occupant = m_info[m_new[bucket][pos]];
                // Evict a terrible occupant, or one that is redundant while
                // the candidate has no slot at all (dashd verbatim).
                if (occupant.is_terrible(now) ||
                    (occupant.ref_count > 1 && e->ref_count == 0))
                    placed = true;
            }
            if (placed) {
                clear_new_slot(bucket, pos);
                ++e->ref_count;
                m_new[bucket][pos] = id;
            } else if (e->ref_count == 0) {
                erase_new_entry(id);
                return false;
            }
        }
        return created && placed;
    }

    // ── dashd Good(): a full successful handshake ───────────────────────────
    void good(const NetService& addr, int64_t now = 0)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (now == 0) now = wall_now();
        auto it = m_index.find(addr.to_string());
        if (it == m_index.end()) return;
        good_locked(it->second, now);
    }

    // ── dashd Attempt(): a dial happened (typically: and failed) ────────────
    void attempt(const NetService& addr, bool count_failure = true, int64_t now = 0)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (now == 0) now = wall_now();
        auto it = m_index.find(addr.to_string());
        if (it == m_index.end()) return;
        Entry& e = m_info[it->second];
        e.last_try = now;
        // Only count one failure per Good() era (dashd's nLastGood fence:
        // repeated dials while offline don't stack into a permanent ban).
        if (count_failure && e.last_count_attempt < m_last_good) {
            e.last_count_attempt = now;
            ++e.attempts;
        }
    }

    // ── dashd Connected(): peer proved alive; refresh if >20min stale ───────
    void connected(const NetService& addr, int64_t now = 0)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (now == 0) now = wall_now();
        auto it = m_index.find(addr.to_string());
        if (it == m_index.end()) return;
        Entry& e = m_info[it->second];
        if (now - e.ntime > 20 * 60) e.ntime = now;
    }

    // ── dashd Select(): quality-biased stochastic draw ──────────────────────
    /// 50/50 tried-vs-new (when both populated), then a random bucket + slot
    /// walk accepting with probability get_chance()*factor, factor *= 1.2 per
    /// rejection. new_only=true restricts to the new table (feeler-style).
    std::optional<NetService> select(bool new_only = false, int64_t now = 0)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (now == 0) now = wall_now();
        if (m_random.empty()) return std::nullopt;
        if (new_only && m_new_count == 0) return std::nullopt;

        const bool use_tried =
            !new_only && m_tried_count > 0 &&
            (m_new_count == 0 || rand_uint(2) == 0);

        double chance_factor = 1.0;
        // dashd loops unboundedly; a defensive iteration ceiling keeps a
        // (theoretically impossible) empty-walk from wedging the caller.
        for (int iter = 0; iter < (1 << 16); ++iter) {
            const int bucket_count = use_tried ? TRIED_BUCKET_COUNT : NEW_BUCKET_COUNT;
            const int bucket = static_cast<int>(rand_uint(bucket_count));
            const int start = static_cast<int>(rand_uint(BUCKET_SIZE));
            int id = -1;
            for (int i = 0; i < BUCKET_SIZE; ++i) {
                const int pos = (start + i) % BUCKET_SIZE;
                const int candidate =
                    use_tried ? m_tried[bucket][pos] : m_new[bucket][pos];
                if (candidate != -1) { id = candidate; break; }
            }
            if (id == -1) continue;
            const Entry& e = m_info[id];
            const double threshold = chance_factor * e.get_chance(now);
            if (static_cast<double>(rand_uint(1 << 30)) <
                threshold * static_cast<double>(1 << 30))
                return e.addr;
            chance_factor *= 1.2;
        }
        return std::nullopt;
    }

    // ── dashd SelectTriedCollision(): incumbent to re-test (feeler leg) ─────
    /// Returns the TRIED INCUMBENT whose slot a collision newcomer wants.
    /// Dial it: on success its Good() refreshes last_success and
    /// resolve_collisions() keeps it; on dial failure Attempt() ages it and
    /// resolve_collisions() evicts it in favour of the newcomer.
    std::optional<NetService> select_tried_collision()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_collisions.empty()) return std::nullopt;
        auto it = m_collisions.begin();
        std::advance(it, rand_uint(m_collisions.size()));
        const int id_new = *it;
        auto info_it = m_info.find(id_new);
        if (info_it == m_info.end()) { m_collisions.erase(it); return std::nullopt; }
        const Entry& e = info_it->second;
        const int bucket = tried_bucket_of(e);
        const int pos = bucket_position_of(e, /*is_new=*/false, bucket);
        const int id_old = m_tried[bucket][pos];
        if (id_old == -1) { m_collisions.erase(it); return std::nullopt; }
        return m_info[id_old].addr;
    }

    // ── dashd ResolveCollisions() ───────────────────────────────────────────
    void resolve_collisions(int64_t now = 0)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (now == 0) now = wall_now();
        for (auto it = m_collisions.begin(); it != m_collisions.end();) {
            const int id_new = *it;
            bool erase_collision = false;
            auto info_it = m_info.find(id_new);
            if (info_it == m_info.end() || info_it->second.in_tried) {
                erase_collision = true;
            } else {
                Entry& info_new = info_it->second;
                const int bucket = tried_bucket_of(info_new);
                const int pos = bucket_position_of(info_new, false, bucket);
                const int id_old = m_tried[bucket][pos];
                if (id_old == -1) {
                    // Slot freed since the collision was recorded.
                    good_locked(id_new, now, /*test_before_evict=*/false);
                    erase_collision = true;
                } else {
                    const Entry& info_old = m_info[id_old];
                    if (now - info_old.last_success < REPLACEMENT_SECONDS) {
                        // Incumbent recently proved alive — it stays.
                        erase_collision = true;
                    } else if (now - info_old.last_try < REPLACEMENT_SECONDS) {
                        if (now - info_old.last_try > 60) {
                            // Incumbent was re-tested and did NOT succeed —
                            // the newcomer takes the slot.
                            good_locked(id_new, now, /*test_before_evict=*/false);
                            erase_collision = true;
                        }
                    } else if (now - info_new.last_success > TEST_WINDOW_SECONDS) {
                        // Incumbent never got re-tested in a sane window;
                        // don't hold the newcomer hostage forever.
                        good_locked(id_new, now, /*test_before_evict=*/false);
                        erase_collision = true;
                    }
                }
            }
            if (erase_collision) it = m_collisions.erase(it);
            else ++it;
        }
    }

    // ── dashd GetAddr(): random sample for serving to others ────────────────
    std::vector<NetService> get_addr(size_t max_pct = 23, size_t max_count = 2500,
                                     bool tried_only = false, int64_t now = 0)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (now == 0) now = wall_now();
        size_t want = m_random.size() * max_pct / 100;
        if (max_count && want > max_count) want = max_count;

        std::vector<NetService> out;
        for (size_t n = 0; n < m_random.size() && out.size() < want; ++n) {
            swap_random(n, n + rand_uint(m_random.size() - n));
            const Entry& e = m_info[m_random[n]];
            if (e.is_terrible(now)) continue;
            if (tried_only && !e.in_tried) continue;
            out.push_back(e.addr);
        }
        return out;
    }

    // ── introspection ───────────────────────────────────────────────────────
    size_t size() const { std::lock_guard<std::mutex> l(m_mutex); return m_random.size(); }
    size_t tried_count() const { std::lock_guard<std::mutex> l(m_mutex); return m_tried_count; }
    size_t new_count() const { std::lock_guard<std::mutex> l(m_mutex); return m_new_count; }
    size_t collision_count() const { std::lock_guard<std::mutex> l(m_mutex); return m_collisions.size(); }

    bool contains(const NetService& addr) const
    {
        std::lock_guard<std::mutex> l(m_mutex);
        return m_index.count(addr.to_string()) > 0;
    }

    bool is_tried(const NetService& addr) const
    {
        std::lock_guard<std::mutex> l(m_mutex);
        auto it = m_index.find(addr.to_string());
        if (it == m_index.end()) return false;
        return m_info.at(it->second).in_tried;
    }

    /// Soft table capacity (both tables' slot count) — the discovery layer
    /// keeps harvesting getaddr until the DB is of this order, i.e. in
    /// practice: always (dashd never stops listening to addr gossip either).
    static constexpr size_t soft_capacity()
    {
        return static_cast<size_t>(NEW_BUCKET_COUNT + TRIED_BUCKET_COUNT) * BUCKET_SIZE;
    }

    // ── persistence (peers.dat equivalent, per-coin JSON) ───────────────────
    /// Atomic tmp+rename write. Returns false (and logs) on any I/O error.
    bool save(const std::string& path) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        try {
            nlohmann::json j;
            j["version"] = 1;
            // The bucket key MUST persist: bucket coordinates are keyed by it,
            // so a fresh key would reshuffle every persisted tried placement.
            j["k0"] = m_k0;
            j["k1"] = m_k1;
            nlohmann::json peers = nlohmann::json::array();
            for (const auto& [id, e] : m_info) {
                nlohmann::json pj;
                pj["addr"] = e.addr.to_string();
                pj["src"] = e.source_group;
                pj["ntime"] = e.ntime;
                pj["last_try"] = e.last_try;
                pj["last_success"] = e.last_success;
                pj["last_count_attempt"] = e.last_count_attempt;
                pj["attempts"] = e.attempts;
                pj["tried"] = e.in_tried;
                peers.push_back(std::move(pj));
            }
            j["peers"] = std::move(peers);

            const std::string tmp = path + ".tmp";
            {
                std::ofstream ofs(tmp);
                if (!ofs.is_open()) return false;
                ofs << j.dump();
                if (!ofs.good()) return false;
            }
            if (std::rename(tmp.c_str(), path.c_str()) != 0) return false;
            return true;
        } catch (const std::exception& e) {
            LOG_WARNING << "[addrman] save failed: " << e.what();
            return false;
        }
    }

    /// FAIL-SAFE load: any parse/shape error clears the DB and returns false;
    /// the caller's seed ladder then bootstraps exactly as on first run.
    /// Entries are re-inserted through the placement rules (dashd's
    /// incompatible-serialization recovery path): tried entries go straight
    /// to their tried slot when free, and demote to new on collision.
    bool load(const std::string& path)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        try {
            std::ifstream ifs(path);
            if (!ifs.is_open()) return false;   // absent DB: cold start
            auto j = nlohmann::json::parse(ifs);
            if (j.value("version", 0) != 1) { clear_all(); return false; }

            const uint64_t k0 = j.at("k0").get<uint64_t>();
            const uint64_t k1 = j.at("k1").get<uint64_t>();
            clear_all();
            m_k0 = k0;
            m_k1 = k1;

            const int64_t now = wall_now();
            size_t rejected = 0;
            for (const auto& pj : j.at("peers")) {
                NetService addr(pj.at("addr").get<std::string>());
                // Reject stale garbage the same way the managers validate.
                auto ep = PeerEndpoint::from(addr);
                if (!ep || addr.port() == 0) { ++rejected; continue; }
                const std::string key = addr.to_string();
                if (m_index.count(key)) continue;

                const int id = m_next_id++;
                Entry e;
                e.addr = addr;
                e.source_group = pj.value("src", std::string());
                if (e.source_group.empty())
                    e.source_group = addrman_detail::network_group(addr.address());
                e.ntime = pj.value("ntime", int64_t{0});
                e.last_try = pj.value("last_try", int64_t{0});
                e.last_success = pj.value("last_success", int64_t{0});
                e.last_count_attempt = pj.value("last_count_attempt", int64_t{0});
                e.attempts = std::max(0, pj.value("attempts", 0));
                const bool was_tried = pj.value("tried", false);

                e.random_pos = static_cast<int>(m_random.size());
                m_info[id] = e;
                m_random.push_back(id);
                m_index[key] = id;

                Entry& stored = m_info[id];
                if (was_tried) {
                    const int bucket = tried_bucket_of(stored);
                    const int pos = bucket_position_of(stored, false, bucket);
                    if (m_tried[bucket][pos] == -1) {
                        m_tried[bucket][pos] = id;
                        stored.in_tried = true;
                        ++m_tried_count;
                        continue;
                    }
                }
                // New entry, or tried whose slot is already taken: place in
                // the new table under the Add() collision rules.
                ++m_new_count;
                place_in_new(id, stored, now);
            }
            if (rejected > 0)
                LOG_WARNING << "[addrman] rejected " << rejected
                            << " invalid persisted entries";
            return true;
        } catch (const std::exception& e) {
            LOG_WARNING << "[addrman] corrupt DB (" << e.what()
                        << ") — starting empty, seeds will bootstrap";
            clear_all();
            return false;
        }
    }

    // ── test hooks (deterministic KAT surface) ──────────────────────────────
    std::pair<uint64_t, uint64_t> bucket_key() const { return {m_k0, m_k1}; }
    void seed_rng(uint64_t seed) { std::lock_guard<std::mutex> l(m_mutex); m_rng.seed(seed); }

    int test_tried_bucket(const NetService& addr) const
    {
        Entry e; e.addr = addr;
        return tried_bucket_of(e);
    }
    int test_new_bucket(const NetService& addr, const std::string& source_ip) const
    {
        Entry e; e.addr = addr;
        return new_bucket_of(e, addrman_detail::network_group(
            source_ip.empty() ? addr.address() : source_ip));
    }
    int test_bucket_position(const NetService& addr, bool is_new, int bucket) const
    {
        Entry e; e.addr = addr;
        return bucket_position_of(e, is_new, bucket);
    }
    /// Age an entry's timestamps / attempt counter (KATs simulate history
    /// without wall time). attempts < 0 leaves the counter untouched.
    bool test_set_times(const NetService& addr, int64_t ntime, int64_t last_try,
                        int64_t last_success, int attempts = -1)
    {
        std::lock_guard<std::mutex> l(m_mutex);
        auto it = m_index.find(addr.to_string());
        if (it == m_index.end()) return false;
        Entry& e = m_info[it->second];
        e.ntime = ntime;
        e.last_try = last_try;
        e.last_success = last_success;
        if (attempts >= 0) e.attempts = attempts;
        return true;
    }

private:
    static int64_t wall_now()
    {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    uint64_t rand_uint(uint64_t n) const { return n <= 1 ? 0 : m_rng() % n; }

    std::string group_of(const Entry& e) const
    {
        return addrman_detail::network_group(e.addr.address());
    }

    // dashd GetTriedBucket: hash1 = H(key, addr); hash2 = H(key, group,
    // hash1 % TRIED_BUCKETS_PER_GROUP) — an address group can occupy at most
    // 8 distinct tried buckets.
    int tried_bucket_of(const Entry& e) const
    {
        const uint64_t h1 = addrman_detail::siphash(m_k0, m_k1, "T!" + e.addr.to_string());
        const uint64_t h2 = addrman_detail::siphash(
            m_k0, m_k1,
            "TG!" + group_of(e) + "!" + std::to_string(h1 % TRIED_BUCKETS_PER_GROUP));
        return static_cast<int>(h2 % TRIED_BUCKET_COUNT);
    }

    // dashd GetNewBucket: hash1 = H(key, addr_group, src_group); hash2 =
    // H(key, src_group, hash1 % NEW_BUCKETS_PER_SOURCE_GROUP) — one source
    // group can spray into at most 64 new buckets.
    int new_bucket_of(const Entry& e, const std::string& src_group) const
    {
        const uint64_t h1 = addrman_detail::siphash(
            m_k0, m_k1, "N!" + group_of(e) + "!" + src_group);
        const uint64_t h2 = addrman_detail::siphash(
            m_k0, m_k1,
            "NG!" + src_group + "!" + std::to_string(h1 % NEW_BUCKETS_PER_SOURCE_GROUP));
        return static_cast<int>(h2 % NEW_BUCKET_COUNT);
    }

    // dashd GetBucketPosition: H(key, 'N'/'K', bucket, addr) % 64.
    int bucket_position_of(const Entry& e, bool is_new, int bucket) const
    {
        const uint64_t h = addrman_detail::siphash(
            m_k0, m_k1,
            std::string(is_new ? "n!" : "k!") + std::to_string(bucket) + "!" +
                e.addr.to_string());
        return static_cast<int>(h % BUCKET_SIZE);
    }

    void clear_tables()
    {
        for (auto& b : m_new) b.fill(-1);
        for (auto& b : m_tried) b.fill(-1);
    }

    void clear_all()
    {
        m_info.clear();
        m_index.clear();
        m_random.clear();
        m_collisions.clear();
        m_new_count = 0;
        m_tried_count = 0;
        m_next_id = 0;
        clear_tables();
    }

    void swap_random(size_t a, size_t b)
    {
        if (a == b) return;
        const int id_a = m_random[a];
        const int id_b = m_random[b];
        m_info[id_a].random_pos = static_cast<int>(b);
        m_info[id_b].random_pos = static_cast<int>(a);
        std::swap(m_random[a], m_random[b]);
    }

    /// Clear one new-table slot, deleting the occupant when this was its last
    /// reference and it is not tried (dashd ClearNew).
    void clear_new_slot(int bucket, int pos)
    {
        const int id = m_new[bucket][pos];
        if (id == -1) return;
        m_new[bucket][pos] = -1;
        Entry& e = m_info[id];
        if (--e.ref_count <= 0 && !e.in_tried)
            erase_new_entry(id);
    }

    /// Remove an entry that holds no new-table references and is not tried.
    void erase_new_entry(int id)
    {
        auto it = m_info.find(id);
        if (it == m_info.end()) return;
        const Entry& e = it->second;
        // Detach from m_random via swap-with-last.
        if (e.random_pos >= 0) {
            swap_random(static_cast<size_t>(e.random_pos), m_random.size() - 1);
            m_random.pop_back();
        }
        m_index.erase(e.addr.to_string());
        m_collisions.erase(id);
        m_info.erase(it);
        if (m_new_count > 0) --m_new_count;
    }

    /// dashd MakeTried: pull the entry out of every new bucket, then claim the
    /// tried slot, evicting any incumbent back into the new table.
    void make_tried(int id, Entry& e, int64_t now)
    {
        // Remove from all new buckets (dashd scans every bucket's computed
        // position for this entry — positions are hash-derived, so this is
        // NEW_BUCKET_COUNT hash evaluations, exactly like upstream).
        for (int bucket = 0; bucket < NEW_BUCKET_COUNT; ++bucket) {
            const int pos = bucket_position_of(e, true, bucket);
            if (m_new[bucket][pos] == id) {
                m_new[bucket][pos] = -1;
                --e.ref_count;
            }
        }
        e.ref_count = 0;
        if (m_new_count > 0) --m_new_count;

        const int bucket = tried_bucket_of(e);
        const int pos = bucket_position_of(e, false, bucket);
        if (m_tried[bucket][pos] != -1) {
            // Evict the incumbent back into the new table.
            const int id_evict = m_tried[bucket][pos];
            Entry& evicted = m_info[id_evict];
            evicted.in_tried = false;
            m_tried[bucket][pos] = -1;
            if (m_tried_count > 0) --m_tried_count;
            ++m_new_count;
            place_in_new(id_evict, evicted, now);
        }
        m_tried[bucket][pos] = id;
        ++m_tried_count;
        e.in_tried = true;
    }

    /// Insert an entry into its new-table slot under Add()'s collision rules.
    void place_in_new(int id, Entry& e, int64_t now)
    {
        const int bucket = new_bucket_of(e, e.source_group);
        const int pos = bucket_position_of(e, true, bucket);
        if (m_new[bucket][pos] == id) return;
        bool insert = (m_new[bucket][pos] == -1);
        if (!insert) {
            Entry& occupant = m_info[m_new[bucket][pos]];
            if (occupant.is_terrible(now) ||
                (occupant.ref_count > 1 && e.ref_count == 0))
                insert = true;
        }
        if (insert) {
            clear_new_slot(bucket, pos);
            e.ref_count = std::max(1, e.ref_count);
            m_new[bucket][pos] = id;
        } else if (e.ref_count == 0) {
            erase_new_entry(id);
        }
    }

    /// Shared Good() body (assumes m_mutex held). test_before_evict mirrors
    /// dashd's Good_() flag: the normal path parks an occupied-slot newcomer
    /// as a collision (the incumbent gets a feeler re-test first), while the
    /// resolve path — which has already applied the eviction rules — takes
    /// the slot directly via MakeTried.
    void good_locked(int id, int64_t now, bool test_before_evict = true)
    {
        auto it = m_info.find(id);
        if (it == m_info.end()) return;
        Entry& e = it->second;
        e.last_success = now;
        e.last_try = now;
        e.attempts = 0;
        m_last_good = now;
        if (e.in_tried) return;

        const int bucket = tried_bucket_of(e);
        const int pos = bucket_position_of(e, false, bucket);
        if (test_before_evict && m_tried[bucket][pos] != -1) {
            // Occupied: park as a collision; the incumbent gets re-tested
            // (select_tried_collision) before it can be evicted.
            if (m_collisions.size() < SET_TRIED_COLLISION_SIZE)
                m_collisions.insert(id);
        } else {
            make_tried(id, e, now);
        }
    }

    // ── state ───────────────────────────────────────────────────────────────
    mutable std::mutex m_mutex;
    uint64_t m_k0{0};
    uint64_t m_k1{0};
    mutable std::mt19937_64 m_rng;

    std::map<int, Entry> m_info;
    std::map<std::string, int> m_index;        // "host:port" -> id
    std::vector<int> m_random;                  // ids, GetAddr sampling order
    std::set<int> m_collisions;                 // tried-collision newcomers
    std::array<std::array<int, BUCKET_SIZE>, NEW_BUCKET_COUNT> m_new;
    std::array<std::array<int, BUCKET_SIZE>, TRIED_BUCKET_COUNT> m_tried;
    size_t m_new_count{0};
    size_t m_tried_count{0};
    int m_next_id{0};
    int64_t m_last_good{1};
};

} // namespace core
