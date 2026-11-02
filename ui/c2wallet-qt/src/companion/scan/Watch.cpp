// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Watch.hpp"

#include "../sched/Json.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>

#if !defined(_WIN32)
#include <fcntl.h>
#include <unistd.h>
#endif

namespace c2w::companion::scan {

namespace {
using J = sched::json::J;
}

WatchAddress& WatchState::entry(const std::string& address)
{
    for (WatchAddress& a : addresses)
        if (a.address == address) return a;
    addresses.push_back(WatchAddress{address, {}, 0, false});
    return addresses.back();
}

bool load_watch_state(const std::string& path, const std::string& network, WatchState& out, std::string& why)
{
    out = WatchState{};
    out.network = network;
    std::ifstream f(path, std::ios::binary);
    if (!f) return true; // first run
    std::stringstream ss;
    ss << f.rdbuf();
    J j;
    if (!sched::json::parse_bounded(ss.str(), j, why) || !j.is_object()) {
        why = "watch state " + path + ": " + (why.empty() ? std::string("not a JSON object") : why);
        return false;
    }
    sched::json::Reader rd;
    if (rd.str(j, "schema", "watch") != kWatchSchema) {
        why = "watch state " + path + ": schema is not " + std::string(kWatchSchema);
        return false;
    }
    if (rd.str(j, "network", "watch") != network) {
        why = "watch state " + path + " is for another network";
        return false;
    }
    if (const J* arr = rd.arr(j, "addresses", "watch")) {
        for (size_t i = 0; i < arr->size(); ++i) {
            const J& a = (*arr)[i];
            const std::string p = "watch.addresses[" + std::to_string(i) + "]";
            WatchAddress w;
            w.address = rd.req_str(a, "address", p);
            w.last_tip = rd.i64(a, "last_tip", p);
            w.alerted = rd.boolean(a, "alerted", p);
            if (const J* k = rd.arr(a, "known", p))
                for (const J& o : *k)
                    if (o.is_string()) w.known.push_back(o.get<std::string>());
            out.addresses.push_back(std::move(w));
        }
    }
    if (!rd.ok()) {
        why = "watch state " + path + ": " + rd.err;
        return false;
    }
    return true;
}

bool save_watch_state(const std::string& path, const WatchState& st, std::string& why)
{
    J j = J::object();
    j["schema"] = kWatchSchema;
    j["network"] = st.network;
    J arr = J::array();
    for (const WatchAddress& a : st.addresses) {
        J o = J::object();
        o["address"] = a.address;
        o["last_tip"] = a.last_tip;
        o["alerted"] = a.alerted;
        o["known"] = a.known;
        arr.push_back(std::move(o));
    }
    j["addresses"] = std::move(arr);
    const std::string text = sched::json::dump(j);
    const std::string tmp = path + ".tmp";
#if defined(_WIN32)
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    f << text;
    if (!f) {
        why = "cannot write " + tmp;
        return false;
    }
    f.close();
#else
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0) {
        why = "cannot write " + tmp + " (" + std::strerror(errno) + ")";
        return false;
    }
    size_t off = 0;
    while (off < text.size()) {
        const ssize_t n = ::write(fd, text.data() + off, text.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            why = "cannot write " + tmp + " (" + std::strerror(errno) + ")";
            return false;
        }
        off += static_cast<size_t>(n);
    }
    ::fsync(fd);
    ::close(fd);
#endif
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        why = "cannot replace " + path + " (" + std::strerror(errno) + ")";
        return false;
    }
    return true;
}

WatchStep watch_step(WatchAddress& st, const Classification& cls, const WatchPolicy& policy)
{
    WatchStep s;
    s.first_scan = st.last_tip == 0;
    const std::set<std::string> known(st.known.begin(), st.known.end());
    std::vector<std::string> now;
    auto see = [&](const c2w::dash::Utxo& u) {
        const std::string k = u.txid + ":" + std::to_string(u.vout);
        now.push_back(k);
        if (!known.count(k)) s.arrivals.push_back(u);
    };
    for (const c2w::dash::Utxo& u : cls.exportable.utxos) see(u);
    for (const QueuedRow& q : cls.queued) see(q.utxo);
    for (const ImmatureRow& r : cls.immature)
        if (!known.count(r.utxo.txid + ":" + std::to_string(r.utxo.vout))) s.arriving_immature.push_back(r);
    s.mature = cls.mature.size();
    for (const c2w::dash::Utxo& u : cls.mature) s.mature_value += u.satoshis;
    s.policy_holds = s.mature >= policy.min_mature || (policy.min_value > 0 && s.mature_value >= policy.min_value);
    s.alert = s.policy_holds && !st.alerted;
    if (s.alert)
        s.alert_text = cls.address + ": " + std::to_string(s.mature) + " mature UTXOs, " +
                       c2w::dash::format_dash(s.mature_value) + " DASH at target height " +
                       std::to_string(cls.target_height) + " (tip " + std::to_string(cls.tip_height) +
                       "): a batch is ready; run `c2wallet-qt-schedd scan --address " + cls.address +
                       "` and sign the plan offline";
    std::sort(now.begin(), now.end());
    st.known = std::move(now);
    st.last_tip = cls.tip_height;
    st.alerted = s.policy_holds;
    return s;
}

} // namespace c2w::companion::scan
