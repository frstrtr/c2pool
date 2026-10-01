// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_relay_peerstore_kat -- RELAY-DISCOVERY persistent peer storage:
// the relay PeerBook on core::AddrStore (xmr_relay_peerstore.cpp).
//   S1 save -> load round-trip (host, port, first/last seen, good, fails)
//   S2 a SMALLER set saved over a larger one loads exactly (the pre-fix
//      AddrStore::save left the old JSON tail behind: unparsable next start)
//   S3 an absent file is created (and its directory); loads empty
//   S4 a corrupt file loads empty (never throws); the next save repairs it
//   S5 the file name is keyed on network + pool tag
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

#include <c2pool/v37/xmr/relay/xmr_relay_peerstore.hpp>

using namespace c2pool::v37n::xmr::relay;
namespace fs = std::filesystem;

static int g_pass = 0, g_fail = 0;
static void check(bool ok, const std::string& what) {
    (ok ? g_pass : g_fail)++;
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
}
static bool same_set(std::vector<PeerRecord> a, std::vector<PeerRecord> b) {
    auto key = [](const PeerRecord& r) { return peer_key(r.host, r.port); };
    std::sort(a.begin(), a.end(), [&](auto& x, auto& y) { return key(x) < key(y); });
    std::sort(b.begin(), b.end(), [&](auto& x, auto& y) { return key(x) < key(y); });
    return a == b;
}

int main() {
    std::printf("== v37_xmr_relay_peerstore_kat ==\n");
    const char* t = std::getenv("TMPDIR");
    const fs::path dir = fs::path(t && *t ? t : "/tmp") / ("v37_peerstore_kat_" + std::to_string(::getpid())) / "sub";
    fs::remove_all(dir.parent_path());
    const std::string path = (dir / peerstore_file_name(3, "0123456789abcdef0011")).string();

    std::vector<PeerRecord> v, got;
    std::string why;
    check(peerstore_load(path, got, &why) && got.empty(), "S3 absent store: created, loads empty");
    check(fs::exists(path), "S3 the file and its directory now exist");
    for (int i = 0; i < 40; ++i)
        v.push_back(PeerRecord{"10.9." + std::to_string(i / 10) + "." + std::to_string(i), static_cast<std::uint16_t>(59321 + i),
                               1700000000ull + i, 1700001000ull + i, (i % 3) == 0, static_cast<std::uint32_t>(i % 5)});
    v.push_back(PeerRecord{"203.0.113.7", 59321, 1, 2, true, 0});
    check(peerstore_save(path, v, &why), "S1 save 41 records");
    check(peerstore_load(path, got, &why) && same_set(got, v), "S1 load == saved (host, port, seen, good, fails)");
    std::vector<PeerRecord> small(v.begin(), v.begin() + 3);
    check(peerstore_save(path, small, &why), "S2 save 3 records over 41");
    check(peerstore_load(path, got, &why) && same_set(got, small), "S2 load == exactly the 3 (no stale tail)");
    { std::ofstream f(path, std::ios::trunc); f << "{not json"; }
    check(peerstore_load(path, got, &why) && got.empty(), "S4 a corrupt store loads empty, no throw");
    check(peerstore_save(path, small, &why) && peerstore_load(path, got, &why) && same_set(got, small), "S4 the next save repairs it");
    check(peerstore_file_name(0, "aaaaaaaabbbbbbbbcccc") == "relay_peers_0_aaaaaaaabbbbbbbb.json" &&
          peerstore_file_name(3, "aaaaaaaabbbbbbbbcccc") != peerstore_file_name(0, "aaaaaaaabbbbbbbbcccc") &&
          peerstore_file_name(0, "aaaaaaaabbbbbbbc") != peerstore_file_name(0, "aaaaaaaabbbbbbbb"),
          "S5 one store per network + pool tag");
    PeerRecord r{"1.2.3.4", 1, 0, 0, true, 300};
    PeerRecord back; peer_service_apply(peer_service_of(r), back);
    check(back.good && back.fails == 255, "S1 flags ride AddrValue::m_service (good bit, fails capped at 255)");
    fs::remove_all(dir.parent_path());
    std::printf("== v37_xmr_relay_peerstore_kat: %s (%d/%d passed) ==\n", g_fail ? "FAIL" : "OK", g_pass, g_pass + g_fail);
    return g_fail ? 1 : 0;
}
