// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// src/c2pool/v37/xmr/xmr_web_dashboard.cpp   (XMR-WEB) -- see the header.
// The web layer of c2pool-v37-xmr: core::WebServer (the shared dashboard every
// coin binary serves) + a per-coin REST override that answers the
// p2pool-compatible endpoints from the node's published XmrWebState.
#include "xmr_web_dashboard.hpp"

#include <core/web_server.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <set>

namespace c2pool::v37n::xmr::web {

namespace {
double wall_now_s() {
    return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
}
double to_xmr(long double pico) { return static_cast<double>(pico / static_cast<long double>(kPicoPerXmr)); }

struct ShareRec { double t; double diff; std::string address, worker; };
}  // namespace

struct XmrWebDashboard::Impl {
    std::string host, dir;
    std::uint16_t port = 0;
    bool testnet = false;
    std::uint32_t window_s = 300;
    double (*clock)() = &wall_now_s;
    double start_s = 0;

    mutable std::mutex mtx;
    XmrWebState st;
    std::deque<ShareRec> shares;                                  // inside the window
    std::deque<std::pair<double, std::uint64_t>> foreign;         // (t, cumulative foreign receipts)

    boost::asio::io_context ioc;                                  // WebServer's main-loop ctx (never run: no stratum, no coin node)
    std::unique_ptr<core::WebServer> ws;

    // ── the hashrate window (callers hold mtx) ──────────────────────────────
    void prune(double now) {
        const double lo = now - window_s;
        while (!shares.empty() && shares.front().t < lo) shares.pop_front();
        while (foreign.size() > 2 && foreign[1].first < lo) foreign.pop_front();
    }
    double span(double now) const {
        return std::max(1.0, std::min<double>(window_s, now - start_s));
    }
    double local_rate(double now) const {
        double w = 0; for (const auto& s : shares) w += s.diff;
        return w / span(now);
    }
    double foreign_rate() const {
        if (foreign.size() < 2) return 0.0;
        const double dt = foreign.back().first - foreign.front().first;
        if (dt <= 0) return 0.0;
        const double n = static_cast<double>(foreign.back().second - foreign.front().second);
        const double d = static_cast<double>(st.share_difficulty ? st.share_difficulty : st.network_difficulty);
        return n * d / dt;
    }
    std::map<std::string, double> rate_by(bool by_worker, double now) const {
        std::map<std::string, double> m;
        for (const auto& s : shares) m[by_worker ? s.address + "." + s.worker : s.address] += s.diff;
        for (auto& [k, v] : m) { (void)k; v /= span(now); }
        return m;
    }

    nlohmann::json block_value() const {   // the newest found block's R; null if none
        if (!st.found.empty()) return to_xmr(st.found.front().reward_pico);
        return nullptr;
    }
    std::optional<nlohmann::json> answer(const std::string& path) const;
    nlohmann::json local_stats(double now) const;
    nlohmann::json global_stats(double now) const;
    nlohmann::json recent_blocks() const;
    nlohmann::json v37_status(double now) const;
    nlohmann::json pathb_status() const;
    nlohmann::json pathb_view() const;
};

XmrWebDashboard::XmrWebDashboard(std::string host, std::uint16_t port, std::string dashboard_dir,
                                 bool testnet, std::uint32_t window_s)
    : m(std::make_unique<Impl>()) {
    m->host = std::move(host); m->port = port; m->dir = std::move(dashboard_dir);
    m->testnet = testnet; m->window_s = window_s ? window_s : 300;
    m->start_s = m->clock();
}

XmrWebDashboard::~XmrWebDashboard() { stop(); }

void XmrWebDashboard::set_clock_for_test(double (*now_s)()) {
    std::lock_guard<std::mutex> lk(m->mtx);
    m->clock = now_s ? now_s : &wall_now_s;
    m->start_s = m->clock();
}

void XmrWebDashboard::publish(XmrWebState s) {
    std::lock_guard<std::mutex> lk(m->mtx);
    const double now = m->clock();
    if (m->foreign.empty() || m->foreign.back().second != s.relay_foreign_receipts || m->foreign.size() < 2)
        m->foreign.emplace_back(now, s.relay_foreign_receipts);
    else
        m->foreign.back().first = now;   // no new receipts: slide the newest sample's time forward
    m->st = std::move(s);
    m->prune(now);
}

void XmrWebDashboard::on_share(double difficulty, const std::string& address, const std::string& worker) {
    std::lock_guard<std::mutex> lk(m->mtx);
    const double now = m->clock();
    m->shares.push_back(ShareRec{now, difficulty, address, worker.empty() ? std::string("default") : worker});
    m->prune(now);
}

std::string XmrWebDashboard::endpoint_json(const std::string& path) const {
    std::lock_guard<std::mutex> lk(m->mtx);
    const auto j = m->answer(path);
    return j ? j->dump() : std::string();
}

std::uint16_t XmrWebDashboard::bound_port() const { return m->ws ? m->ws->bound_port() : 0; }

bool XmrWebDashboard::start() {
    if (m->ws) return true;
    m->ws = std::make_unique<core::WebServer>(m->ioc, m->host, m->port, m->testnet,
                                              std::shared_ptr<core::IMiningNode>{},
                                              c2pool::address::Blockchain::MONERO);
    auto* mi = m->ws->get_mining_interface();
    mi->set_coin_label("XMR");
    mi->set_payout_scheme_label(kPayoutScheme);          // the served UI never says PPLNS
    mi->set_dashboard_always_ready(true);                // no MiningInterface template: never the loading page
    {
        std::lock_guard<std::mutex> lk(m->mtx);
        if (m->st.stratum_port) mi->set_worker_port(m->st.stratum_port);
    }
    Impl* impl = m.get();
    mi->set_rest_override_fn([impl](const std::string& path) -> std::optional<nlohmann::json> {
        std::lock_guard<std::mutex> lk(impl->mtx);
        return impl->answer(path);
    });
    m->ws->set_dashboard_dir(m->dir);
    m->ws->set_stratum_port(0);                          // the XMR node owns its stratum; never a second acceptor
    if (!m->ws->start()) { m->ws.reset(); return false; }
    return true;
}

void XmrWebDashboard::stop() {
    if (!m || !m->ws) return;
    m->ws->stop();
    m->ws.reset();
}

// ── the endpoints ───────────────────────────────────────────────────────────
std::optional<nlohmann::json> XmrWebDashboard::Impl::answer(const std::string& path) const {
    const double now = clock();
    const double uptime = std::max(0.0, now - start_s);
    if (path == "/local_stats")    return local_stats(now);
    if (path == "/global_stats")   return global_stats(now);
    if (path == "/recent_blocks")  return recent_blocks();
    if (path == "/v37_status")     return v37_status(now);
    if (path == "/xmr/pathb")      return pathb_view();
    if (path == "/local_rate")     return local_rate(now);
    if (path == "/global_rate")    return local_rate(now) + foreign_rate();
    if (path == "/uptime")         return uptime;
    if (path == "/fee")            return st.owner_fee_pct;
    if (path == "/payout_addr")    return st.payout_address;
    if (path == "/payout_addrs")   return nlohmann::json::array({st.payout_address});
    if (path == "/connected_miners") {
        std::set<std::string> a; for (const auto& s : shares) a.insert(s.address);
        return nlohmann::json(std::vector<std::string>(a.begin(), a.end()));
    }
    if (path == "/web/version")    return st.version;
    if (path == "/web/currency_info")
        return nlohmann::json{{"symbol", "XMR"}, {"name", "Monero"}, {"block_period", 120},
                              {"has_treasury", false}, {"payout_scheme", kPayoutScheme},
                              {"payout_scheme_long", kPayoutSchemeLong},
                              {"block_explorer_url_prefix", ""}, {"address_explorer_url_prefix", ""},
                              {"tx_explorer_url_prefix", ""}};
    if (path == "/node_info")
        return nlohmann::json{{"symbol", "XMR"}, {"network", st.network}, {"version", st.version},
                              {"worker_port", st.stratum_port}, {"external_ip", st.stratum_host},
                              {"payout_scheme", kPayoutScheme}, {"blocks", st.found.size()},
                              {"luck_available", false}};
    return std::nullopt;
}

nlohmann::json XmrWebDashboard::Impl::local_stats(double now) const {
    const double local = local_rate(now), pool = local + foreign_rate();
    const double nd = static_cast<double>(st.network_difficulty);
    nlohmann::json miners = nlohmann::json::object(), last_diff = nlohmann::json::object();
    for (const auto& [k, v] : rate_by(true, now)) miners[k] = v;
    for (const auto& s : shares) last_diff[s.address + "." + s.worker] = s.diff;
    return nlohmann::json{
        {"version", st.version}, {"symbol", "XMR"}, {"payout_scheme", kPayoutScheme},
        {"uptime", std::max(0.0, now - start_s)},
        {"peers", {{"incoming", 0}, {"outgoing", 0}, {"relay_ready", st.relay_ready}, {"relay_conns", st.relay_conns}}},
        {"shares", {{"total", shares.size()}, {"orphan", 0}, {"dead", 0}}},
        {"local_shares", st.stratum_shares},
        {"local_hashps", local}, {"pool_hash_rate", pool}, {"pool_nonstale_hash_rate", pool},
        {"pool_stale_prop", 0.0}, {"network_hashrate", nd / 120.0},
        {"network_block_difficulty", st.network_difficulty}, {"min_difficulty", st.share_difficulty},
        {"miner_hash_rates", miners}, {"miner_dead_hash_rates", nlohmann::json::object()},
        {"miner_last_difficulties", last_diff},
        {"attempts_to_block", st.network_difficulty},
        {"attempts_to_share", st.share_difficulty ? st.share_difficulty : st.network_difficulty},
        {"block_value", block_value()},
        {"fee", st.owner_fee_pct}, {"fee_percent", st.owner_fee_pct}, {"donation_percent", 0.0},
        {"efficiency", 1.0}, {"warnings", nlohmann::json::array()}};
}

nlohmann::json XmrWebDashboard::Impl::global_stats(double now) const {
    const double pool = local_rate(now) + foreign_rate();
    std::set<std::string> miners; for (const auto& s : shares) miners.insert(s.address);
    nlohmann::json last_block = nullptr, last_ts = nullptr;
    if (!st.found.empty()) { last_block = st.found.front().height; last_ts = st.found.front().time; }
    return nlohmann::json{
        {"symbol", "XMR"}, {"payout_scheme", kPayoutScheme},
        {"pool_hash_rate", pool}, {"pool_nonstale_hash_rate", pool}, {"pool_stale_prop", 0.0},
        {"network_hashrate", static_cast<double>(st.network_difficulty) / 120.0},
        {"network_block_difficulty", st.network_difficulty},
        {"current_height", st.chain_height}, {"chain_height", st.chain_height},
        {"unique_miners", miners.size()}, {"unique_miners_scope", "local_stratum"},
        {"local_workers", st.stratum_active}, {"found_blocks", st.found.size()},
        {"last_block", last_block}, {"last_block_ts", last_ts},
        {"uptime_seconds", std::max(0.0, now - start_s)}};
}

nlohmann::json XmrWebDashboard::Impl::recent_blocks() const {
    nlohmann::json a = nlohmann::json::array();
    for (const auto& b : st.found)
        a.push_back({{"ts", b.time}, {"hash", b.id_hex}, {"number", b.height}, {"height", b.height},
                     {"found_by", "local"}, {"landed", b.landed}, {"tip", b.tip_hex},
                     {"window_root", b.window_root_hex}, {"n_outputs", b.n_outputs},
                     {"reward_pico", b.reward_pico}, {"reward", to_xmr(b.reward_pico)}});
    return a;
}

nlohmann::json XmrWebDashboard::Impl::pathb_status() const {
    const XmrWebPathb& p = st.pathb;
    return nlohmann::json{
        {"best_tip", {{"pos", p.tip_pos}, {"id", p.tip_id_hex}, {"cum_work", p.cum_work}}},
        {"epoch_cur", p.epoch_cur}, {"h_hold", p.h_hold},
        {"window_root", p.window_root_hex}, {"mmr_root", p.mmr_root_hex}, {"leaf_count", p.leaf_count},
        {"pending", p.pending}, {"pending_ids", p.pending_ids}, {"deferred", p.deferred},
        {"repended_last_switch", p.repended_last_switch}, {"switches", p.switches},
        {"template", p.template_status},
        {"alarms", {{"hold", p.hold}, {"fork_fuse", p.fork_fuse}, {"template_kept", p.template_kept},
                    {"store_poisoned", p.store_poisoned}, {"coinbase_internal", p.coinbase_internal}}}};
}

nlohmann::json XmrWebDashboard::Impl::pathb_view() const {
    nlohmann::json w = nlohmann::json::array();
    for (const auto& e : st.window)
        w.push_back({{"payee", e.payee}, {"share", e.share}, {"amount_pico", e.amount_pico},
                     {"amount", to_xmr(e.amount_pico)}});
    return nlohmann::json{{"payout_scheme", kPayoutScheme}, {"pathb", pathb_status()},
                          {"window", w}, {"found", recent_blocks()}};
}

nlohmann::json XmrWebDashboard::Impl::v37_status(double now) const {
    std::uint64_t peer = 0, own = 0, monerod = 0;
    for (const auto& b : st.found) {
        if (b.landed == "peer") ++peer;
        else if (b.landed == "own-index") ++own;
        else ++monerod;
    }
    return nlohmann::json{
        {"symbol", "XMR"}, {"version", st.version}, {"network", st.network},
        {"payout_scheme", kPayoutScheme}, {"payout_scheme_long", kPayoutSchemeLong},
        {"uptime", std::max(0.0, now - start_s)},
        {"chain", {{"height", st.chain_height}, {"difficulty", st.network_difficulty},
                   {"template_height", st.template_height}}},
        {"lane", {{"suspended", st.lane_suspended}}},
        {"pathb", pathb_status()},
        {"found", {{"listed", st.found.size()}, {"peer", peer}, {"own_index", own}, {"monerod", monerod}}},
        {"relay", {{"enabled", st.relay_enabled}, {"ready", st.relay_ready}, {"conns", st.relay_conns},
                   {"foreign_receipts", st.relay_foreign_receipts}}},
        {"stratum", {{"host", st.stratum_host}, {"port", st.stratum_port},
                     {"share_difficulty", st.share_difficulty}, {"connections", st.stratum_connections},
                     {"active", st.stratum_active}, {"shares", st.stratum_shares},
                     {"rejected", st.stratum_rejected}}},
        {"hashrate", {{"local", local_rate(now)}, {"foreign", foreign_rate()},
                      {"pool", local_rate(now) + foreign_rate()}, {"window_s", window_s},
                      {"shares_in_window", shares.size()}}},
        {"fee", {{"give_author_pct", st.give_author_pct},
                 {"owner_fee_pct", st.owner_fee_pct}, {"owner_address", st.owner_address}}},
        {"payout_address", st.payout_address}};
}

}  // namespace c2pool::v37n::xmr::web
