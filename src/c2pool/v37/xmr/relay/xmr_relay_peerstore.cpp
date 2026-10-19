// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// RELAY-DISCOVERY: the relay PeerBook <-> core::AddrStore (see the header).
#include "xmr_relay_peerstore.hpp"

#include <exception>

#include <core/addr_store.hpp>

namespace c2pool::v37n::xmr::relay {

bool peerstore_load(const std::string& path, std::vector<PeerRecord>& out, std::string* why) {
    out.clear();
    try {
        core::AddrStore st(core::AddrStore::at_file_t{}, path);
        for (const auto& p : st.get_all()) {
            PeerRecord r;
            r.host = p.addr.address();
            r.port = p.addr.port();
            r.first_seen = p.value.m_first_seen;
            r.last_seen = p.value.m_last_seen;
            peer_service_apply(p.value.m_service, r);
            if (!r.host.empty() && r.port) out.push_back(r);
        }
        return true;
    } catch (const std::exception& e) {
        if (why) *why = e.what();
        return false;
    }
}

bool peerstore_save(const std::string& path, const std::vector<PeerRecord>& v, std::string* why) {
    try {
        core::AddrStore st(core::AddrStore::at_file_t{}, path);
        std::vector<core::AddrStorePair> pairs;
        pairs.reserve(v.size());
        for (const auto& r : v) {
            core::AddrStorePair p;
            p.addr = ::NetService(r.host, r.port);
            p.value = core::AddrValue(peer_service_of(r), r.first_seen, r.last_seen);
            pairs.push_back(p);
        }
        st.replace_all(pairs);
        return true;
    } catch (const std::exception& e) {
        if (why) *why = e.what();
        return false;
    }
}

} // namespace c2pool::v37n::xmr::relay
