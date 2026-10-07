// SPDX-License-Identifier: AGPL-3.0-or-later
// D-MINER.7 miner-offline alert relay over the sharechain p2p mesh -- KATs.
//
// Everything here is socket-free: frames cross an in-process fake mesh that
// round-trips every hop through the REAL wire codec (message_alert /
// message_alertack make_raw -> dash::Handler::parse), so the byte format, the
// policy and the multi-node delivery semantics are all pinned by one target.

#include <impl/dash/alert_detector.hpp>
#include <impl/dash/alert_relay.hpp>
#include <impl/dash/alert_service.hpp>
#include <impl/dash/alert_wire.hpp>
#include <impl/dash/messages.hpp>

#include <core/timer.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <variant>
#include <vector>

#include <thread>

#include <sys/stat.h>
#include <unistd.h>

using namespace dash::alert;
namespace fs = std::filesystem;

namespace {

fs::path fresh_dir(const std::string& tag)
{
    static std::atomic<int> n{0};
    fs::path p = fs::temp_directory_path() /
                 ("c2pool_alert_kat_" + std::to_string(::getpid()) + "_" + tag + "_" + std::to_string(n++));
    fs::remove_all(p);
    fs::create_directories(p);
    return p;
}

KeyPair key_from_byte(unsigned char b)
{
    std::array<unsigned char, 32> sec{};
    sec.fill(b);
    auto kp = KeyPair::from_seckey(sec.data());
    EXPECT_TRUE(kp.has_value());
    return *kp;
}

std::vector<std::string> read_lines(const fs::path& p)
{
    std::vector<std::string> out;
    std::ifstream f(p);
    std::string l;
    while (std::getline(f, l))
        if (!l.empty()) out.push_back(l);
    return out;
}

AlertBody sample_body(Kind k = Kind::Offline)
{
    AlertBody b;
    b.kind = static_cast<uint8_t>(k);
    b.event_ts = 1'790'000'000u;
    b.label = "farm-1";
    b.worker = "XdashAddress123.rig1";
    b.detail = "disconnected; down 5m";
    return b;
}

// Serialize through the real wire codec and parse back -- what a peer sees.
AlertFrame wire_alert(const AlertFrame& f)
{
    auto raw = make_raw(f);
    EXPECT_EQ(raw->m_command, "alert");
    dash::Handler h;
    auto res = h.parse(raw);
    return to_frame(*std::get<std::unique_ptr<dash::message_alert>>(res));
}

AckFrame wire_ack(const AckFrame& a)
{
    auto raw = make_raw(a);
    EXPECT_EQ(raw->m_command, "alertack");
    dash::Handler h;
    auto res = h.parse(raw);
    return to_frame(*std::get<std::unique_ptr<dash::message_alertack>>(res));
}

// ── In-process fake mesh ────────────────────────────────────────────────────
struct Mesh {
    struct Msg {
        uint64_t from{0}, to{0};
        std::variant<AlertFrame, AckFrame> frame;
    };
    struct Node {
        std::shared_ptr<AlertRelayService> svc;
        std::map<uint64_t, PeerAlertGuard> guards;   // per-peer guard, keyed by sender
    };

    std::map<uint64_t, Node> nodes;
    std::set<std::pair<uint64_t, uint64_t>> links;
    std::deque<Msg> q;
    std::vector<Msg> delivered_log;
    std::function<bool(const Msg&)> drop;   // return true to lose a frame in flight
    std::vector<Verdict> verdicts;

    bool linked(uint64_t a, uint64_t b) const { return links.count({std::min(a, b), std::max(a, b)}) != 0; }
    void link(uint64_t a, uint64_t b) { links.insert({std::min(a, b), std::max(a, b)}); }

    std::vector<uint64_t> neighbours(uint64_t id) const
    {
        std::vector<uint64_t> v;
        for (const auto& [nid, _] : nodes)
            if (nid != id && linked(id, nid)) v.push_back(nid);
        return v;
    }

    Transport transport_for(uint64_t id)
    {
        Transport t;
        t.send_alert = [this, id](uint64_t peer, const AlertFrame& f) {
            if (!linked(id, peer)) return false;
            q.push_back({id, peer, f});
            return true;
        };
        t.broadcast_alert = [this, id](uint64_t except, const AlertFrame& f) {
            std::size_t n = 0;
            for (auto p : neighbours(id))
                if (p != except) { q.push_back({id, p, f}); ++n; }
            return n;
        };
        t.send_ack = [this, id](uint64_t peer, const AckFrame& a) {
            if (!linked(id, peer)) return false;
            q.push_back({id, peer, a});
            return true;
        };
        t.broadcast_ack = [this, id](uint64_t except, const AckFrame& a) {
            std::size_t n = 0;
            for (auto p : neighbours(id))
                if (p != except) { q.push_back({id, p, a}); ++n; }
            return n;
        };
        return t;
    }

    AlertRelayService& add(uint64_t id, ServiceConfig cfg, std::optional<KeyPair> keys, int64_t now)
    {
        auto svc = std::make_shared<AlertRelayService>(cfg, keys, now);
        std::string err;
        EXPECT_TRUE(svc->init(err)) << err;
        svc->set_transport(transport_for(id));
        nodes[id].svc = svc;
        return *svc;
    }

    void pump(int64_t now)
    {
        int guard = 0;
        while (!q.empty() && ++guard < 100000) {
            Msg m = std::move(q.front());
            q.pop_front();
            if (drop && drop(m)) continue;
            delivered_log.push_back(m);
            auto& n = nodes.at(m.to);
            auto& g = n.guards[m.from];
            if (std::holds_alternative<AlertFrame>(m.frame))
                verdicts.push_back(n.svc->on_alert(wire_alert(std::get<AlertFrame>(m.frame)), m.from, g, now));
            else
                verdicts.push_back(n.svc->on_ack(wire_ack(std::get<AckFrame>(m.frame)), m.from, g, now));
        }
    }

    std::size_t count_alerts_to(uint64_t to) const
    {
        std::size_t n = 0;
        for (const auto& m : delivered_log)
            if (m.to == to && std::holds_alternative<AlertFrame>(m.frame)) ++n;
        return n;
    }
};

ServiceConfig origin_cfg(const fs::path& dir, const Bytes& relay_pub)
{
    ServiceConfig c;
    c.origin = true;
    c.state_dir = dir.string();
    c.label = "farm-1";
    c.relays = {relay_pub};
    c.retry_every = 60;
    c.retry_max = 60;
    c.inline_io = true;
    return c;
}

ServiceConfig relay_cfg(const fs::path& dir, const std::vector<Bytes>& accept)
{
    ServiceConfig c;
    c.telegram = true;
    c.state_dir = dir.string();
    c.accept = accept;
    c.inline_io = true;
    return c;
}

ServiceConfig fwd_cfg(const fs::path& dir)
{
    ServiceConfig c;
    c.forward = true;
    c.state_dir = dir.string();
    c.inline_io = true;
    return c;
}

DetectorEvent offline_event(const std::string& worker, int64_t ts)
{
    DetectorEvent e;
    e.kind = Kind::Offline;
    e.worker = worker;
    e.detail = "disconnected; down 5m";
    e.ts = ts;
    return e;
}

constexpr int64_t T0 = 1'790'000'000;

} // namespace

// ── (1) wire codec ──────────────────────────────────────────────────────────
TEST(DashAlertRelay, WireRoundTripIsByteExact)
{
    auto origin = key_from_byte(0x11), relay = key_from_byte(0x22);
    unsigned char seal_nonce[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    auto f = build_alert(origin, relay.pubkey, sample_body(), T0, 42, 2, seal_nonce);
    ASSERT_TRUE(f);
    auto raw1 = make_raw(*f);
    EXPECT_EQ(raw1->m_command, "alert");
    const auto payload1 = raw1->m_data.get_span();
    std::vector<std::byte> bytes1(payload1.begin(), payload1.end());
    EXPECT_LE(bytes1.size(), 400u) << "alert frame must stay tiny for DPI-bound flows";

    auto back = wire_alert(*f);
    EXPECT_EQ(back, *f);
    auto raw2 = make_raw(back);
    const auto payload2 = raw2->m_data.get_span();
    EXPECT_EQ(std::vector<std::byte>(payload2.begin(), payload2.end()), bytes1);

    auto a = build_ack(relay, origin.pubkey, 42, AckStatus::Queued);
    ASSERT_TRUE(a);
    auto araw = make_raw(*a);
    EXPECT_EQ(araw->m_command, "alertack");
    EXPECT_EQ(wire_ack(*a), *a);
    EXPECT_LE(araw->m_data.size(), 160u);
}

TEST(DashAlertRelay, CommandsFitThePoolFrame)
{
    dash::message_alert m1;
    dash::message_alertack m2;
    EXPECT_EQ(m1.m_command, "alert");
    EXPECT_EQ(m2.m_command, "alertack");
    EXPECT_LE(m1.m_command.size(), 12u);
    EXPECT_LE(m2.m_command.size(), 12u);
}

// ── (2) signatures ──────────────────────────────────────────────────────────
TEST(DashAlertRelay, SignatureCoversEverythingButHops)
{
    auto origin = key_from_byte(0x11), relay = key_from_byte(0x22);
    auto f = build_alert(origin, relay.pubkey, sample_body(), T0, 7);
    ASSERT_TRUE(f);
    EXPECT_TRUE(verify_alert_sig(*f));

    auto hops = *f;
    hops.hops_left = 0;
    EXPECT_TRUE(verify_alert_sig(hops)) << "hops_left is outside the signature";

    auto body = *f;
    body.body.back() ^= 0x01;
    EXPECT_FALSE(verify_alert_sig(body));

    auto ts = *f;
    ts.timestamp += 1;
    EXPECT_FALSE(verify_alert_sig(ts));

    auto nonce = *f;
    nonce.nonce += 1;
    EXPECT_FALSE(verify_alert_sig(nonce));

    auto to = *f;
    to.to_key_id[0] ^= 0xff;
    EXPECT_FALSE(verify_alert_sig(to));

    auto a = build_ack(relay, origin.pubkey, 7, AckStatus::Delivered);
    ASSERT_TRUE(a);
    EXPECT_TRUE(verify_ack_sig(*a));
    auto a2 = *a;
    a2.status = static_cast<uint8_t>(AckStatus::Queued);
    EXPECT_FALSE(verify_ack_sig(a2)) << "an intermediate cannot rewrite the status";
}

// ── (3) ECDH-sealed body ────────────────────────────────────────────────────
TEST(DashAlertRelay, BodyOpensOnlyForTheAddressedRelay)
{
    auto origin = key_from_byte(0x11), relay = key_from_byte(0x22), other = key_from_byte(0x33);
    auto s1 = ecdh_shared(origin.seckey.data(), relay.pubkey);
    auto s2 = ecdh_shared(relay.seckey.data(), origin.pubkey);
    ASSERT_TRUE(s1 && s2);
    EXPECT_EQ(*s1, *s2) << "ECDH must be symmetric";

    auto f = build_alert(origin, relay.pubkey, sample_body(), T0, 9);
    ASSERT_TRUE(f);
    EXPECT_EQ(f->to_key_id, key_id(relay.pubkey));
    auto body = open_alert(relay, *f);
    ASSERT_TRUE(body);
    EXPECT_EQ(*body, sample_body());
    EXPECT_FALSE(open_alert(other, *f)) << "a third key must fail the MAC";
    EXPECT_FALSE(open_alert(origin, *f)) << "the origin key alone does not open it either";

    // The plaintext worker name never appears in the sealed bytes.
    std::string sealed(f->body.begin(), f->body.end());
    EXPECT_EQ(sealed.find("rig1"), std::string::npos);

    // Deterministic given a fixed seal nonce (so the KAT is reproducible).
    unsigned char n16[16] = {};
    auto x = build_alert(origin, relay.pubkey, sample_body(), T0, 9, 2, n16);
    auto y = build_alert(origin, relay.pubkey, sample_body(), T0, 9, 2, n16);
    ASSERT_TRUE(x && y);
    EXPECT_EQ(x->body, y->body);
    // Random seal nonces differ between two production builds.
    auto p = build_alert(origin, relay.pubkey, sample_body(), T0, 9);
    auto q = build_alert(origin, relay.pubkey, sample_body(), T0, 9);
    EXPECT_NE(p->body, q->body);
}

TEST(DashAlertRelay, BodyCodecRejectsGarbageAndClips)
{
    AlertBody b = sample_body();
    b.label = std::string(100, 'L');
    b.worker = std::string(200, 'W');
    b.detail = std::string(300, 'D');
    auto dec = decode_body(encode_body(b));
    ASSERT_TRUE(dec);
    EXPECT_EQ(dec->label.size(), kMaxLabel);
    EXPECT_EQ(dec->worker.size(), kMaxWorker);
    EXPECT_EQ(dec->detail.size(), kMaxDetail);

    Bytes junk = encode_body(sample_body());
    junk.push_back(0);
    EXPECT_FALSE(decode_body(junk)) << "trailing bytes are rejected";
    Bytes bad_kind = encode_body(sample_body());
    bad_kind[0] = 9;
    EXPECT_FALSE(decode_body(bad_kind));
    EXPECT_FALSE(decode_body(Bytes{1, 2}));
}

TEST(DashAlertRelay, ShapeChecks)
{
    auto origin = key_from_byte(0x11), relay = key_from_byte(0x22);
    auto f = *build_alert(origin, relay.pubkey, sample_body(), T0, 1);
    EXPECT_EQ(alert_shape_error(f), nullptr);
    auto v = f; v.version = 2;           EXPECT_STREQ(alert_shape_error(v), "unsupported-version");
    auto h = f; h.hops_left = 5;         EXPECT_STREQ(alert_shape_error(h), "hops-out-of-range");
    auto p = f; p.origin_pubkey.pop_back(); EXPECT_STREQ(alert_shape_error(p), "bad-origin-pubkey");
    auto k = f; k.to_key_id.push_back(0);   EXPECT_STREQ(alert_shape_error(k), "bad-key-id");
    auto b = f; b.body.resize(kMaxBodyBytes + 1); EXPECT_STREQ(alert_shape_error(b), "bad-body-size");
    auto s = f; s.signature.resize(80);  EXPECT_STREQ(alert_shape_error(s), "bad-signature-size");
}

// ── (4) allowlist ───────────────────────────────────────────────────────────
TEST(DashAlertRelay, NonAllowlistedOriginIsRefusedNotQueuedNotForwarded)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto od = fresh_dir("o"), rd = fresh_dir("r"), fd = fresh_dir("f");
    Mesh m;
    m.add(1, origin_cfg(od, rkey.pubkey), okey, T0);
    m.add(2, relay_cfg(rd, {/* empty allowlist */}), rkey, T0);
    m.add(3, fwd_cfg(fd), std::nullopt, T0);
    m.link(1, 2);
    m.link(2, 3);
    m.nodes[1].svc->enqueue_event(offline_event("W.rig1", T0), T0);
    m.pump(T0);
    EXPECT_EQ(m.nodes[2].svc->counters().refused_allowlist, 1u);
    EXPECT_EQ(m.count_alerts_to(3), 0u) << "an alert addressed to the relay is never forwarded on";
    EXPECT_FALSE(fs::exists(rd / "outbox.jsonl"));
    EXPECT_EQ(m.nodes[1].svc->counters().refused, 1u);
    EXPECT_TRUE(m.nodes[1].svc->pending().empty());
    auto ledger = read_lines(od / "ledger.jsonl");
    ASSERT_EQ(ledger.size(), 1u);
    EXPECT_NE(ledger[0].find("refused_not_allowlisted"), std::string::npos);
}

// ── (5) replay / duplicates / restart ───────────────────────────────────────
TEST(DashAlertRelay, StaleTimestampRejected)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto rd = fresh_dir("r");
    auto svc = std::make_shared<AlertRelayService>(relay_cfg(rd, {okey.pubkey}), rkey, T0);
    std::string err;
    ASSERT_TRUE(svc->init(err));
    std::vector<AckFrame> acks;
    Transport t;
    t.send_ack = [&](uint64_t, const AckFrame& a) { acks.push_back(a); return true; };
    t.broadcast_ack = [&](uint64_t, const AckFrame& a) { acks.push_back(a); return std::size_t{1}; };
    t.broadcast_alert = [](uint64_t, const AlertFrame&) { return std::size_t{0}; };
    svc->set_transport(t);
    PeerAlertGuard g;
    auto old = *build_alert(okey, rkey.pubkey, sample_body(), T0 - 901, 1);
    EXPECT_EQ(svc->on_alert(old, 5, g, T0), Verdict::RejectedStale);
    auto future = *build_alert(okey, rkey.pubkey, sample_body(), T0 + 901, 2);
    EXPECT_EQ(svc->on_alert(future, 5, g, T0), Verdict::RejectedStale);
    auto edge = *build_alert(okey, rkey.pubkey, sample_body(), T0 - 900, 3);
    EXPECT_EQ(svc->on_alert(edge, 5, g, T0), Verdict::Queued);
    ASSERT_EQ(acks.size(), 3u);
    EXPECT_EQ(acks[0].status, static_cast<uint8_t>(AckStatus::RefusedInvalid));
    EXPECT_EQ(acks[2].status, static_cast<uint8_t>(AckStatus::Queued));
}

TEST(DashAlertRelay, DuplicateDeliveredOnceAckResentAndRestartSafe)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto rd = fresh_dir("r");
    std::vector<AckFrame> acks;
    Transport t;
    t.send_ack = [&](uint64_t, const AckFrame& a) { acks.push_back(a); return true; };
    t.broadcast_ack = [&](uint64_t, const AckFrame& a) { acks.push_back(a); return std::size_t{1}; };
    t.broadcast_alert = [](uint64_t, const AlertFrame&) { return std::size_t{0}; };
    auto f = *build_alert(okey, rkey.pubkey, sample_body(), T0, 77);
    {
        AlertRelayService svc(relay_cfg(rd, {okey.pubkey}), rkey, T0);
        std::string err;
        ASSERT_TRUE(svc.init(err));
        svc.set_transport(t);
        PeerAlertGuard g1, g2;
        EXPECT_EQ(svc.on_alert(f, 5, g1, T0), Verdict::Queued);
        EXPECT_EQ(svc.on_alert(f, 5, g1, T0 + 1), Verdict::Duplicate);
        EXPECT_EQ(svc.on_alert(f, 6, g2, T0 + 2), Verdict::Duplicate) << "node-level dedupe across peers";
        EXPECT_EQ(acks.size(), 3u) << "every duplicate re-sends the cached ack (lost-ack repair)";
    }
    EXPECT_EQ(read_lines(rd / "outbox.jsonl").size(), 1u);
    {
        // Restart: in-memory seen set is gone, the persisted accepted set is not.
        AlertRelayService svc(relay_cfg(rd, {okey.pubkey}), rkey, T0 + 100);
        std::string err;
        ASSERT_TRUE(svc.init(err));
        svc.set_transport(t);
        PeerAlertGuard g;
        EXPECT_EQ(svc.on_alert(f, 5, g, T0 + 100), Verdict::Duplicate);
        EXPECT_EQ(acks.back().status, static_cast<uint8_t>(AckStatus::Queued));
    }
    EXPECT_EQ(read_lines(rd / "outbox.jsonl").size(), 1u) << "a restart never pages twice";
}

TEST(DashAlertRelay, BadSignatureNeverPoisonsTheSeenSet)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto rd = fresh_dir("r");
    AlertRelayService svc(relay_cfg(rd, {okey.pubkey}), rkey, T0);
    std::string err;
    ASSERT_TRUE(svc.init(err));
    Transport t;
    t.send_ack = [](uint64_t, const AckFrame&) { return true; };
    t.broadcast_ack = [](uint64_t, const AckFrame&) { return std::size_t{1}; };
    svc.set_transport(t);
    PeerAlertGuard g;
    auto good = *build_alert(okey, rkey.pubkey, sample_body(), T0, 5);
    auto forged = good;
    forged.body[20] ^= 0x55;
    EXPECT_EQ(svc.on_alert(forged, 9, g, T0), Verdict::RejectedSig);
    EXPECT_EQ(svc.on_alert(good, 9, g, T0), Verdict::Queued) << "the genuine frame still gets through";
}

// ── (6) per-peer rate limit ─────────────────────────────────────────────────
TEST(DashAlertRelay, PerPeerRateLimitAndRecovery)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto fd = fresh_dir("f");
    AlertRelayService svc(fwd_cfg(fd), std::nullopt, T0);
    std::string err;
    ASSERT_TRUE(svc.init(err));
    Transport t;
    t.broadcast_alert = [](uint64_t, const AlertFrame&) { return std::size_t{1}; };
    svc.set_transport(t);
    PeerAlertGuard g;
    for (uint64_t i = 0; i < PeerAlertGuard::kMaxAlertsPerWindow; ++i) {
        auto f = *build_alert(okey, rkey.pubkey, sample_body(), T0, 1000 + i);
        EXPECT_EQ(svc.on_alert(f, 4, g, T0), Verdict::Forwarded);
    }
    auto extra = *build_alert(okey, rkey.pubkey, sample_body(), T0, 5000);
    EXPECT_EQ(svc.on_alert(extra, 4, g, T0 + 10), Verdict::RateLimited);
    PeerAlertGuard other;
    EXPECT_EQ(svc.on_alert(extra, 8, other, T0 + 10), Verdict::Forwarded) << "the cap is per peer";
    auto later = *build_alert(okey, rkey.pubkey, sample_body(), T0 + 60, 6000);
    EXPECT_EQ(svc.on_alert(later, 4, g, T0 + 60), Verdict::Forwarded) << "window recovers";
}

// ── (7) forwarding ──────────────────────────────────────────────────────────
TEST(DashAlertRelay, ForwardingDecrementsHopsNeverEchoesAndStopsAtZero)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    Mesh m;
    m.add(1, origin_cfg(fresh_dir("o"), rkey.pubkey), okey, T0);
    m.add(2, fwd_cfg(fresh_dir("f2")), std::nullopt, T0);
    m.add(3, fwd_cfg(fresh_dir("f3")), std::nullopt, T0);
    m.add(4, fwd_cfg(fresh_dir("f4")), std::nullopt, T0);
    m.add(5, fwd_cfg(fresh_dir("f5")), std::nullopt, T0);
    m.link(1, 2); m.link(2, 3); m.link(3, 4); m.link(4, 5);
    m.nodes[1].svc->enqueue_event(offline_event("W.rig1", T0), T0);
    const AlertFrame sent = m.nodes[1].svc->pending().begin()->second.frame;
    m.pump(T0);

    std::map<uint64_t, uint8_t> hops_at;
    for (const auto& msg : m.delivered_log) {
        ASSERT_TRUE(std::holds_alternative<AlertFrame>(msg.frame));
        const auto& f = std::get<AlertFrame>(msg.frame);
        EXPECT_NE(msg.to, 1u) << "never sent back toward the origin";
        hops_at[msg.to] = f.hops_left;
        auto same = f;
        same.hops_left = sent.hops_left;
        EXPECT_EQ(same, sent) << "forwarded VERBATIM except hops_left";
    }
    EXPECT_EQ(hops_at[2], 2);
    EXPECT_EQ(hops_at[3], 1);
    EXPECT_EQ(hops_at[4], 0);
    EXPECT_EQ(m.count_alerts_to(5), 0u) << "hops exhausted at node 4";
    EXPECT_EQ(m.nodes[4].svc->counters().forwarded, 0u);
}

TEST(DashAlertRelay, NoRoleMeansNoForward)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    ServiceConfig none;
    none.state_dir = fresh_dir("n").string();
    AlertRelayService svc(none, std::nullopt, T0);
    std::string err;
    ASSERT_TRUE(svc.init(err));
    std::size_t sent = 0;
    Transport t;
    t.broadcast_alert = [&](uint64_t, const AlertFrame&) { ++sent; return std::size_t{1}; };
    svc.set_transport(t);
    PeerAlertGuard g;
    auto f = *build_alert(okey, rkey.pubkey, sample_body(), T0, 3);
    EXPECT_EQ(svc.on_alert(f, 2, g, T0), Verdict::NotForwarded);
    EXPECT_EQ(sent, 0u);
}

// ── (8) ack reverse path + end-to-end ───────────────────────────────────────
TEST(DashAlertRelay, EndToEndQueuedThenDeliveredAcrossAForwarder)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto od = fresh_dir("o"), rd = fresh_dir("r");
    Mesh m;
    m.add(1, origin_cfg(od, rkey.pubkey), okey, T0);
    m.add(2, fwd_cfg(fresh_dir("f")), std::nullopt, T0);
    m.add(3, relay_cfg(rd, {okey.pubkey}), rkey, T0);
    m.link(1, 2);
    m.link(2, 3);

    m.nodes[1].svc->enqueue_event(offline_event("XaddrABC.rig1", T0), T0);
    m.pump(T0);
    auto& o = *m.nodes[1].svc;
    ASSERT_EQ(o.pending().size(), 1u);
    EXPECT_TRUE(o.pending().begin()->second.queued_at_relay) << "status-4 ack travelled back via the forwarder";
    auto rows = read_lines(rd / "outbox.jsonl");
    ASSERT_EQ(rows.size(), 1u);
    auto row = nlohmann::json::parse(rows[0]);
    EXPECT_EQ(row["worker"], "XaddrABC.rig1");
    EXPECT_EQ(row["kind"], "offline");
    EXPECT_EQ(row["label"], "farm-1");

    // queued_at_relay => no retransmits
    for (int64_t t = T0 + 5; t <= T0 + 300; t += 5) {
        o.on_tick({}, t);
        m.pump(t);
    }
    EXPECT_EQ(o.counters().retransmits, 0u);

    // The sidecar reports Telegram ok:true.
    {
        std::ofstream d(rd / "delivered.jsonl", std::ios::app);
        d << nlohmann::json{{"id", row["id"]}}.dump() << "\n";
    }
    m.nodes[3].svc->on_tick({}, T0 + 305);
    m.pump(T0 + 305);
    EXPECT_TRUE(o.pending().empty());
    EXPECT_EQ(o.counters().delivered, 1u);
    EXPECT_EQ(m.nodes[3].svc->counters().delivered_telegram, 1u);
    auto ledger = read_lines(od / "ledger.jsonl");
    ASSERT_EQ(ledger.size(), 2u);
    EXPECT_NE(ledger[0].find("queued_at_relay"), std::string::npos);
    EXPECT_NE(ledger[1].find("\"delivered\""), std::string::npos);

    // Re-reading the same delivered file does not re-ack or double count.
    m.nodes[3].svc->on_tick({}, T0 + 310);
    EXPECT_EQ(m.nodes[3].svc->counters().delivered_telegram, 1u);
}

TEST(DashAlertRelay, AckFromAnUnconfiguredKeyIsIgnored)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22), evil = key_from_byte(0x44);
    auto od = fresh_dir("o");
    AlertRelayService o(origin_cfg(od, rkey.pubkey), okey, T0);
    std::string err;
    ASSERT_TRUE(o.init(err));
    Transport t;
    t.broadcast_alert = [](uint64_t, const AlertFrame&) { return std::size_t{1}; };
    o.set_transport(t);
    o.enqueue_event(offline_event("W.rig1", T0), T0);
    const uint64_t nonce = o.pending().begin()->second.frame.nonce;
    PeerAlertGuard g;
    auto fake = *build_ack(evil, okey.pubkey, nonce, AckStatus::Delivered);
    EXPECT_EQ(o.on_ack(fake, 3, g, T0 + 1), Verdict::AckDropped);
    auto forged = *build_ack(rkey, okey.pubkey, nonce, AckStatus::Delivered);
    forged.signature[10] ^= 1;
    EXPECT_NE(o.on_ack(forged, 3, g, T0 + 1), Verdict::AckConsumed);
    EXPECT_EQ(o.pending().size(), 1u) << "neither silenced the retransmits";
    auto real = *build_ack(rkey, okey.pubkey, nonce, AckStatus::Delivered);
    EXPECT_EQ(o.on_ack(real, 3, g, T0 + 1), Verdict::AckConsumed);
    EXPECT_TRUE(o.pending().empty());
}

TEST(DashAlertRelay, RetransmitCrossesALossyLinkAndLostAckIsRepaired)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto od = fresh_dir("o"), rd = fresh_dir("r");
    Mesh m;
    m.add(1, origin_cfg(od, rkey.pubkey), okey, T0);
    m.add(2, fwd_cfg(fresh_dir("f")), std::nullopt, T0);
    m.add(3, relay_cfg(rd, {okey.pubkey}), rkey, T0);
    m.link(1, 2);
    m.link(2, 3);
    // (a) the first forward 2->3 is lost (a DPI-latched flow)
    int lost_fwd = 0, lost_ack = 0;
    m.drop = [&](const Mesh::Msg& msg) {
        if (msg.from == 2 && msg.to == 3 && std::holds_alternative<AlertFrame>(msg.frame) && lost_fwd == 0) { ++lost_fwd; return true; }
        // (b) the first ack 2->1 is lost as well
        if (msg.from == 2 && msg.to == 1 && std::holds_alternative<AckFrame>(msg.frame) && lost_ack == 0) { ++lost_ack; return true; }
        return false;
    };
    m.nodes[1].svc->enqueue_event(offline_event("W.rig1", T0), T0);
    m.pump(T0);
    EXPECT_FALSE(fs::exists(rd / "outbox.jsonl"));
    for (int64_t t = T0 + 5; t <= T0 + 200; t += 5) {
        for (auto& [id, n] : m.nodes) n.svc->on_tick({}, t);
        m.pump(t);
    }
    EXPECT_EQ(lost_fwd, 1);
    EXPECT_EQ(lost_ack, 1);
    EXPECT_EQ(read_lines(rd / "outbox.jsonl").size(), 1u) << "delivered to the relay exactly once";
    auto& o = *m.nodes[1].svc;
    ASSERT_EQ(o.pending().size(), 1u);
    EXPECT_TRUE(o.pending().begin()->second.queued_at_relay);
    EXPECT_GE(o.counters().retransmits, 2u);
}

TEST(DashAlertRelay, UndeliveredAfterRetryMaxAndReissueBeforeWindowCloses)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto od = fresh_dir("o");
    auto cfg = origin_cfg(od, rkey.pubkey);
    cfg.retry_every = 60;
    cfg.retry_max = 25;
    AlertRelayService o(cfg, okey, T0);
    std::string err;
    ASSERT_TRUE(o.init(err));
    std::vector<AlertFrame> sent;
    Transport t;
    t.broadcast_alert = [&](uint64_t, const AlertFrame& f) { sent.push_back(f); return std::size_t{1}; };
    o.set_transport(t);
    o.enqueue_event(offline_event("W.rig1", T0), T0);
    for (int64_t now = T0 + 5; now <= T0 + 3600; now += 5) o.on_tick({}, now);
    EXPECT_TRUE(o.pending().empty());
    EXPECT_EQ(o.counters().undelivered, 1u);
    EXPECT_EQ(sent.size(), 25u);
    std::set<uint64_t> nonces;
    for (const auto& f : sent) {
        nonces.insert(f.nonce);
        // every frame on the wire is inside the relay's replay window when sent
        EXPECT_TRUE(verify_alert_sig(f));
    }
    EXPECT_GE(nonces.size(), 2u) << "re-issued with a fresh nonce before the +/-900 s window closed";
    EXPECT_GE(o.counters().reissued, 1u);
    auto ledger = read_lines(od / "ledger.jsonl");
    ASSERT_EQ(ledger.size(), 1u);
    EXPECT_NE(ledger[0].find("undelivered"), std::string::npos);
}

TEST(DashAlertRelay, NonceNeverReusedAcrossRestart)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto od = fresh_dir("o");
    uint64_t first = 0, second = 0;
    Transport t;
    t.broadcast_alert = [](uint64_t, const AlertFrame&) { return std::size_t{0}; };
    {
        AlertRelayService o(origin_cfg(od, rkey.pubkey), okey, T0);
        std::string err;
        ASSERT_TRUE(o.init(err));
        o.set_transport(t);
        o.enqueue_event(offline_event("W.a", T0), T0);
        first = o.pending().begin()->second.frame.nonce;
    }
    {
        // Same wall clock (worst case): the persisted counter must still win.
        AlertRelayService o(origin_cfg(od, rkey.pubkey), okey, T0);
        std::string err;
        ASSERT_TRUE(o.init(err));
        o.set_transport(t);
        ASSERT_EQ(o.pending().size(), 1u) << "the first event was restored (pending persists)";
        o.enqueue_event(offline_event("W.a", T0), T0);
        ASSERT_EQ(o.pending().size(), 2u);
        second = o.pending().rbegin()->second.frame.nonce;   // the newly issued event
    }
    EXPECT_GT(second, first);
}

TEST(DashAlertRelay, PendingSurvivesOriginRestartWithTheSameNonce)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto od = fresh_dir("o"), rd = fresh_dir("r");
    uint64_t nonce = 0;
    {
        // Relay unreachable: the event stays awaiting an ack.
        AlertRelayService o(origin_cfg(od, rkey.pubkey), okey, T0);
        std::string err;
        ASSERT_TRUE(o.init(err));
        Transport t;
        t.broadcast_alert = [](uint64_t, const AlertFrame&) { return std::size_t{0}; };
        o.set_transport(t);
        o.enqueue_event(offline_event("W.rig1", T0), T0);
        nonce = o.pending().begin()->second.frame.nonce;
    }   // origin process dies here
    Mesh m;
    m.add(1, origin_cfg(od, rkey.pubkey), okey, T0 + 30);
    m.add(2, relay_cfg(rd, {okey.pubkey}), rkey, T0 + 30);
    m.link(1, 2);
    auto& o = *m.nodes[1].svc;
    ASSERT_EQ(o.pending().size(), 1u) << "pending event restored from state.json";
    EXPECT_EQ(o.pending().begin()->second.frame.nonce, nonce);
    o.on_tick({}, T0 + 35);
    m.pump(T0 + 35);
    auto rows = read_lines(rd / "outbox.jsonl");
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(nlohmann::json::parse(rows[0])["nonce"], nonce) << "retransmitted with the ORIGINAL nonce";
    EXPECT_TRUE(o.pending().begin()->second.queued_at_relay);
}

// ── (9) old-peer tolerance ──────────────────────────────────────────────────
TEST(DashAlertRelay, MasterHandlerListThrowsOutOfRangeOnAlert)
{
    // A handler list WITHOUT the new messages == what a master-built peer runs.
    // MessageHandler::parse throws std::out_of_range for an unknown command,
    // which Legacy/Actual::handle_message catch, LOG_WARNING and drop (no
    // disconnect) -- so sending alert to an old peer is harmless.
    using OldHandler = MessageHandler<dash::message_ping, dash::message_addrme, dash::message_getaddrs,
                                      dash::message_addrs, dash::message_shares, dash::message_sharereq,
                                      dash::message_sharereply, dash::message_bestblock,
                                      dash::message_have_tx, dash::message_losing_tx,
                                      dash::message_forget_tx, dash::message_remember_tx,
                                      dash::message_tx_inject>;
    auto origin = key_from_byte(0x11), relay = key_from_byte(0x22);
    auto raw = make_raw(*build_alert(origin, relay.pubkey, sample_body(), T0, 1));
    OldHandler old;
    EXPECT_THROW(old.parse(raw), std::out_of_range);
    auto araw = make_raw(*build_ack(relay, origin.pubkey, 1, AckStatus::Queued));
    EXPECT_THROW(old.parse(araw), std::out_of_range);
}

// ── (10) detector ───────────────────────────────────────────────────────────
namespace {
DetectorConfig det_cfg()
{
    DetectorConfig c;
    c.offline_after = 300;
    c.online_after = 60;
    c.min_interval = 600;
    c.startup_grace = 600;
    c.stall_after = 900;
    c.max_per_hour = 30;
    return c;
}
std::vector<WorkerSample> one(const std::string& key, const std::string& sid, uint64_t acc)
{
    return {WorkerSample{key, sid, acc}};
}
} // namespace

TEST(DashAlertDetector, OfflineAfterThresholdNotBefore)
{
    auto c = det_cfg();
    c.startup_grace = 0;
    AlertDetector d(c, T0);
    EXPECT_TRUE(d.tick(one("A.rig1", "s1", 0), T0).empty());
    EXPECT_TRUE(d.tick(one("A.rig1", "s1", 5), T0 + 10).empty());
    // disconnect at T0+20
    EXPECT_TRUE(d.tick({}, T0 + 20).empty());
    EXPECT_TRUE(d.tick({}, T0 + 20 + 290).empty()) << "290 s < offline_after";
    auto ev = d.tick({}, T0 + 20 + 300);
    ASSERT_EQ(ev.size(), 1u);
    EXPECT_EQ(ev[0].kind, Kind::Offline);
    EXPECT_EQ(ev[0].worker, "A.rig1");
    EXPECT_NE(ev[0].detail.find("disconnected"), std::string::npos);
    EXPECT_TRUE(d.tick({}, T0 + 20 + 900).empty()) << "fires once";
}

TEST(DashAlertDetector, BackOnlineOnlyAfterEmittedOfflineAndDwell)
{
    auto c = det_cfg();
    c.startup_grace = 0;
    AlertDetector d(c, T0);
    d.tick(one("A.rig1", "s1", 0), T0);
    // short blip: back before offline fired -> no events at all
    d.tick({}, T0 + 10);
    EXPECT_TRUE(d.tick(one("A.rig1", "s2", 0), T0 + 100).empty());
    EXPECT_TRUE(d.tick(one("A.rig1", "s2", 0), T0 + 400).empty()) << "no back_online without an offline";
    // real outage
    d.tick({}, T0 + 410);
    ASSERT_EQ(d.tick({}, T0 + 710).size(), 1u);
    EXPECT_TRUE(d.tick(one("A.rig1", "s3", 0), T0 + 800).empty());
    EXPECT_TRUE(d.tick(one("A.rig1", "s3", 1), T0 + 850).empty()) << "50 s < online_after";
    auto ev = d.tick(one("A.rig1", "s3", 2), T0 + 860);
    ASSERT_EQ(ev.size(), 1u);
    EXPECT_EQ(ev[0].kind, Kind::BackOnline);
}

TEST(DashAlertDetector, StartupGraceAndRestoredWorkers)
{
    auto c = det_cfg();
    AlertDetector d(c, T0);   // grace 600
    d.tick(one("A.rig1", "s1", 0), T0);
    d.tick({}, T0 + 10);
    EXPECT_TRUE(d.tick({}, T0 + 400).empty()) << "inside the startup grace";
    auto ev = d.tick({}, T0 + 600);
    ASSERT_EQ(ev.size(), 1u) << "fires as soon as the grace ends";

    // Persist + restore: a known worker that never comes back after a restart
    // is reported; one already reported is not re-paged.
    auto snap = d.persist();
    snap["B.rig2"] = {{"last_seen", T0}, {"offline_alerted", false}, {"last_offline_alert", 0}};
    AlertDetector d2(c, T0 + 1000);
    d2.restore(snap);
    EXPECT_TRUE(d2.tick({}, T0 + 1000 + 599).empty());
    auto ev2 = d2.tick({}, T0 + 1000 + 600);
    ASSERT_EQ(ev2.size(), 1u);
    EXPECT_EQ(ev2[0].worker, "B.rig2") << "A.rig1 was already alerted before the restart";
    // A.rig1 reconnects after the restart -> its outstanding offline pairs with a back_online
    d2.tick(one("A.rig1", "x", 0), T0 + 1700);
    auto ev3 = d2.tick(one("A.rig1", "x", 0), T0 + 1760);
    ASSERT_EQ(ev3.size(), 1u);
    EXPECT_EQ(ev3[0].kind, Kind::BackOnline);
}

TEST(DashAlertDetector, NeverSeenWorkerNeverFiresAndExpiryForgets)
{
    auto c = det_cfg();
    c.startup_grace = 0;
    AlertDetector d(c, T0);
    for (int64_t t = T0; t < T0 + 3600; t += 60) EXPECT_TRUE(d.tick({}, t).empty());
    EXPECT_TRUE(d.workers().empty());
    d.tick(one("A.rig1", "s1", 0), T0);
    d.tick({}, T0 + 10);
    d.tick({}, T0 + 400);
    d.tick({}, T0 + 10 + c.known_expiry + 1);
    EXPECT_TRUE(d.workers().empty()) << "absent longer than known_expiry -> forgotten";
}

TEST(DashAlertDetector, MinIntervalThrottlesFlaps)
{
    auto c = det_cfg();
    c.startup_grace = 0;
    c.offline_after = 60;
    c.online_after = 10;
    c.min_interval = 600;
    AlertDetector d(c, T0);
    int offlines = 0, backs = 0;
    int sid = 0;
    // flap: 70 s down / 30 s up, for 20 minutes
    for (int64_t t = T0; t < T0 + 1200; t += 10) {
        const bool up = ((t - T0) % 100) >= 70;
        auto ev = d.tick(up ? one("A.rig1", "s" + std::to_string(sid), 0) : std::vector<WorkerSample>{}, t);
        if (!up) ++sid;
        for (auto& e : ev) (e.kind == Kind::Offline ? offlines : backs)++;
    }
    // bootstrap: the worker must be seen up once before it can go offline
    EXPECT_LE(offlines, 2) << "at most one OFFLINE per min_interval";
    EXPECT_GE(offlines, 1);
    EXPECT_LE(backs, offlines);
}

TEST(DashAlertDetector, StalledConnectionCountsAsDown)
{
    auto c = det_cfg();
    c.startup_grace = 0;
    c.stall_after = 120;
    c.offline_after = 60;
    AlertDetector d(c, T0);
    d.tick(one("A.rig1", "s1", 1), T0);
    EXPECT_TRUE(d.tick(one("A.rig1", "s1", 1), T0 + 110).empty());
    d.tick(one("A.rig1", "s1", 1), T0 + 120);   // stalled -> down
    auto ev = d.tick(one("A.rig1", "s1", 1), T0 + 180);
    ASSERT_EQ(ev.size(), 1u);
    EXPECT_NE(ev[0].detail.find("no accepted shares"), std::string::npos);
    d.tick(one("A.rig1", "s1", 2), T0 + 200);   // share accepted -> up
    auto back = d.tick(one("A.rig1", "s1", 3), T0 + 260);
    ASSERT_EQ(back.size(), 1u);
    EXPECT_EQ(back[0].kind, Kind::BackOnline);

    auto c0 = c;
    c0.stall_after = 0;
    AlertDetector d0(c0, T0);
    d0.tick(one("A.rig1", "s1", 1), T0);
    for (int64_t t = T0; t < T0 + 3600; t += 60) EXPECT_TRUE(d0.tick(one("A.rig1", "s1", 1), t).empty());
}

TEST(DashAlertDetector, HourlyCapProducesOneDigestAndHoldsTheRest)
{
    auto c = det_cfg();
    c.startup_grace = 0;
    c.max_per_hour = 30;
    AlertDetector d(c, T0);
    std::vector<WorkerSample> all;
    for (int i = 0; i < 40; ++i) all.push_back({"A.rig" + std::to_string(i), "s" + std::to_string(i), 0});
    d.tick(all, T0);
    d.tick({}, T0 + 10);
    auto ev = d.tick({}, T0 + 310);
    std::size_t off = 0, dig = 0;
    for (auto& e : ev) (e.kind == Kind::Digest ? dig : off)++;
    EXPECT_EQ(off, 30u);
    EXPECT_EQ(dig, 1u);
    EXPECT_EQ(d.suppressed_by_cap(), 10u);
    EXPECT_TRUE(d.tick({}, T0 + 600).empty()) << "no digest storm while saturated";
    auto later = d.tick({}, T0 + 310 + 3600);
    EXPECT_EQ(later.size(), 10u) << "held events fire when the window frees";
}

// ── (11) bounded memory ─────────────────────────────────────────────────────
TEST(DashAlertRelay, SeenSetEvictsFifoAtCap)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    NodeAlertSeen seen;
    auto f = *build_alert(okey, rkey.pubkey, sample_body(), T0, 0);
    for (uint64_t i = 0; i < NodeAlertSeen::kMaxEntries + 10; ++i) {
        f.nonce = i;
        seen.insert(f, 1, T0);
    }
    EXPECT_EQ(seen.size(), NodeAlertSeen::kMaxEntries);
    EXPECT_EQ(seen.evicted, 10u);
    EXPECT_EQ(seen.find(okey.pubkey, 0), nullptr);
    EXPECT_NE(seen.find(okey.pubkey, NodeAlertSeen::kMaxEntries + 9), nullptr);
}

TEST(DashAlertRelay, PendingCapDropsOldestWithACounter)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto od = fresh_dir("o");
    AlertRelayService o(origin_cfg(od, rkey.pubkey), okey, T0);
    std::string err;
    ASSERT_TRUE(o.init(err));
    Transport t;
    t.broadcast_alert = [](uint64_t, const AlertFrame&) { return std::size_t{0}; };
    o.set_transport(t);
    for (std::size_t i = 0; i < AlertRelayService::kMaxPending + 5; ++i)
        o.enqueue_event(offline_event("W." + std::to_string(i), T0), T0);
    EXPECT_EQ(o.pending().size(), AlertRelayService::kMaxPending);
    EXPECT_EQ(o.counters().dropped, 5u);
    EXPECT_EQ(read_lines(od / "ledger.jsonl").size(), 5u) << "every drop is recorded, never silent";
}

// ── keys / status ───────────────────────────────────────────────────────────
TEST(DashAlertRelay, KeyFileCreated0600AndReloadedStable)
{
    auto dir = fresh_dir("k");
    const std::string path = (dir / "alert.key").string();
    bool created = false;
    std::string err, warn;
    auto k1 = load_or_create_key_file(path, created, err, warn);
    ASSERT_TRUE(k1) << err;
    EXPECT_TRUE(created);
    struct stat st{};
    ASSERT_EQ(::stat(path.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600u);
    auto k2 = load_or_create_key_file(path, created, err, warn);
    ASSERT_TRUE(k2);
    EXPECT_FALSE(created);
    EXPECT_EQ(k1->pubkey, k2->pubkey);
    EXPECT_TRUE(warn.empty());

    ::chmod(path.c_str(), 0644);
    warn.clear();
    ASSERT_TRUE(load_or_create_key_file(path, created, err, warn));
    EXPECT_FALSE(warn.empty()) << "a world-readable key file is flagged";

    const std::string bad = (dir / "bad.key").string();
    std::ofstream(bad) << "nothex\n";
    EXPECT_FALSE(load_or_create_key_file(bad, created, err, warn));
    EXPECT_FALSE(err.empty());
    EXPECT_EQ(err.find("nothex"), std::string::npos) << "the key material is never echoed";
}

TEST(DashAlertRelay, StatusSnapshotCarriesNoSecret)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto od = fresh_dir("o");
    AlertRelayService o(origin_cfg(od, rkey.pubkey), okey, T0);
    std::string err;
    ASSERT_TRUE(o.init(err));
    o.publish_status(T0);
    auto s = o.status_json();
    EXPECT_EQ(s["role"]["origin"], true);
    EXPECT_EQ(s["pubkey"], to_hex(okey.pubkey));
    EXPECT_TRUE(s.contains("outbox"));
    EXPECT_TRUE(s.contains("detector"));
    EXPECT_TRUE(s.contains("p2p"));
    const std::string dump = s.dump();
    EXPECT_EQ(dump.find(to_hex(okey.seckey.data(), 32)), std::string::npos);
    std::ifstream state(od / "state.json");
    std::string state_s((std::istreambuf_iterator<char>(state)), std::istreambuf_iterator<char>());
    EXPECT_EQ(state_s.find(to_hex(okey.seckey.data(), 32)), std::string::npos);
}

// ── (11) hardening: bounded memory, IO off the event thread, re-probe ──────
namespace {
// Fresh valid secp256k1 keys (0x30..0xEF filled; all below the group order).
KeyPair junk_key(int i) { return key_from_byte(static_cast<unsigned char>(0x30 + (i % 0xC0))); }

Transport capture_transport(std::vector<AckFrame>& acks, std::vector<AlertFrame>* alerts = nullptr)
{
    Transport t;
    t.send_ack = [&acks](uint64_t, const AckFrame& a) { acks.push_back(a); return true; };
    t.broadcast_ack = [&acks](uint64_t, const AckFrame& a) { acks.push_back(a); return std::size_t{1}; };
    t.broadcast_alert = [alerts](uint64_t, const AlertFrame& f) {
        if (alerts) alerts->push_back(f);
        return std::size_t{1};
    };
    return t;
}

// Holds the writer thread before every job until release() (or destruction).
struct DiskGate {
    std::promise<void> p;
    std::shared_future<void> f{p.get_future().share()};
    bool released{false};
    void install(FileWriter& w) { auto fut = f; w.set_before_job_hook([fut] { fut.wait(); }); }
    void release() { if (!released) { released = true; p.set_value(); } }
    ~DiskGate() { release(); }
};
} // namespace

TEST(DashAlertRelay, RefusedLogThrottleIsGlobalNotPerKey)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto rd = fresh_dir("r");
    AlertRelayService svc(relay_cfg(rd, {okey.pubkey}), rkey, T0);
    std::string err;
    ASSERT_TRUE(svc.init(err));
    std::vector<AckFrame> acks;
    svc.set_transport(capture_transport(acks));
    // 150 distinct self-signed origins, each on its own peer link.
    std::map<uint64_t, PeerAlertGuard> guards;
    for (int i = 0; i < 150; ++i) {
        auto k = junk_key(i);
        auto f = *build_alert(k, rkey.pubkey, sample_body(), T0, 9000 + i);
        EXPECT_EQ(svc.on_alert(f, 100 + i, guards[100 + i], T0 + i % 10), Verdict::RefusedNotAllowed);
    }
    EXPECT_EQ(svc.counters().refused_allowlist, 150u);
    EXPECT_EQ(svc.counters().refused_log_suppressed, 149u) << "one warning, the rest counted -- no per-key table";
    auto k = junk_key(7);
    auto f = *build_alert(k, rkey.pubkey, sample_body(), T0 + 3600, 99999);
    PeerAlertGuard g;
    EXPECT_EQ(svc.on_alert(f, 7, g, T0 + 3600), Verdict::RefusedNotAllowed);
    EXPECT_EQ(svc.counters().refused_log_suppressed, 0u) << "next hour: warns again and resets";
    EXPECT_FALSE(fs::exists(rd / "outbox.jsonl"));
}

TEST(DashAlertRelay, SeenEraseLeavesNoGhostSlot)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    NodeAlertSeen seen;
    auto f = *build_alert(okey, rkey.pubkey, sample_body(), T0, 0);
    f.nonce = 1;
    seen.insert(f, 1, T0);
    ASSERT_TRUE(seen.erase(okey.pubkey, 1));
    EXPECT_FALSE(seen.erase(okey.pubkey, 1));
    EXPECT_EQ(seen.order.size(), 0u);
    SeenEntry& again = seen.insert(f, 2, T0 + 1);   // the origin retransmits the same nonce
    EXPECT_EQ(again.from_peer, 2u);
    EXPECT_EQ(seen.order.size(), seen.entries.size());
    // Fill to the cap: with a ghost slot the live id would be evicted early.
    for (uint64_t i = 0; i < NodeAlertSeen::kMaxEntries - 1; ++i) {
        f.nonce = 100 + i;
        seen.insert(f, 1, T0);
    }
    EXPECT_EQ(seen.size(), NodeAlertSeen::kMaxEntries);
    EXPECT_EQ(seen.evicted, 0u);
    ASSERT_NE(seen.find(okey.pubkey, 1), nullptr) << "re-inserted id survives until it is the oldest";
    f.nonce = 999999;
    SeenEntry& last = seen.insert(f, 3, T0);
    EXPECT_EQ(last.from_peer, 3u);
    EXPECT_EQ(seen.find(okey.pubkey, 1), nullptr) << "now it is the oldest and goes first";
    EXPECT_EQ(seen.order.size(), seen.entries.size());
}

TEST(DashAlertRelay, OutboxWriteFailureDefersWithoutGhostAndRecovers)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto rd = fresh_dir("r");
    fs::create_directories(rd / "outbox.jsonl");   // a directory: every append fails
    AlertRelayService svc(relay_cfg(rd, {okey.pubkey}), rkey, T0);
    std::string err;
    ASSERT_TRUE(svc.init(err));
    std::vector<AckFrame> acks;
    svc.set_transport(capture_transport(acks));
    PeerAlertGuard g;
    auto f = *build_alert(okey, rkey.pubkey, sample_body(), T0, 42);
    EXPECT_EQ(svc.on_alert(f, 5, g, T0), Verdict::Deferred);
    EXPECT_EQ(svc.seen().size(), 0u);
    EXPECT_EQ(svc.seen().order.size(), 0u) << "no ghost FIFO slot";
    EXPECT_TRUE(acks.empty()) << "never ack what is not on disk";
    EXPECT_EQ(svc.on_alert(f, 5, g, T0 + 60), Verdict::Deferred) << "the retransmit is processed afresh";
    EXPECT_EQ(svc.seen().order.size(), svc.seen().entries.size());
    EXPECT_EQ(svc.counters().outbox_errors, 2u);
    fs::remove_all(rd / "outbox.jsonl");
    EXPECT_EQ(svc.on_alert(f, 5, g, T0 + 120), Verdict::Queued);
    ASSERT_EQ(acks.size(), 1u);
    EXPECT_EQ(acks[0].status, static_cast<uint8_t>(AckStatus::Queued));
    EXPECT_EQ(read_lines(rd / "outbox.jsonl").size(), 1u);
}

TEST(DashAlertRelay, IdleTicksWriteNothingAndOneEventIsOneWrite)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto fd = fresh_dir("f"), rd = fresh_dir("r"), od = fresh_dir("o");
    AlertRelayService fwd(fwd_cfg(fd), std::nullopt, T0);
    AlertRelayService rel(relay_cfg(rd, {okey.pubkey}), rkey, T0);
    auto ocfg = origin_cfg(od, rkey.pubkey);
    ocfg.det.startup_grace = 0;
    AlertRelayService org(ocfg, okey, T0);
    std::string err;
    ASSERT_TRUE(fwd.init(err));
    ASSERT_TRUE(rel.init(err));
    ASSERT_TRUE(org.init(err));
    std::vector<AckFrame> acks;
    fwd.set_transport(capture_transport(acks));
    rel.set_transport(capture_transport(acks));
    org.set_transport(capture_transport(acks));
    const uint64_t f0 = fwd.io().submitted(), r0 = rel.io().submitted(), o0 = org.io().submitted();
    for (int64_t t = T0 + 5; t <= T0 + 3600; t += 5) {
        fwd.on_tick({}, t);
        rel.on_tick({}, t);
        org.on_tick({}, t);
    }
    EXPECT_EQ(fwd.io().submitted(), f0) << "an idle forwarder never touches the disk";
    EXPECT_EQ(rel.io().submitted(), r0) << "an idle relay never touches the disk";
    EXPECT_EQ(org.io().submitted(), o0) << "an origin with no workers never touches the disk";

    // A steady worker: one save for its appearance, then a slow last_seen refresh.
    const uint64_t o1 = org.io().submitted();
    for (int64_t t = T0 + 3605; t <= T0 + 7200; t += 5)
        org.on_tick(one("A.rig1", "s1", static_cast<uint64_t>(t - T0)), t);   // submitting shares
    EXPECT_TRUE(org.pending().empty()) << "a healthy worker raises no event";
    EXPECT_LE(org.io().submitted() - o1, 3600 / AlertRelayService::kRefreshSaveSec + 2);

    // One event = one state write (no per-nonce write).
    const uint64_t o2 = org.io().submitted();
    org.enqueue_event(offline_event("W.rig9", T0 + 7200), T0 + 7200);
    EXPECT_EQ(org.io().submitted() - o2, 1u);
    // One accepted alert on the relay = one job (outbox row + state together).
    PeerAlertGuard g;
    const uint64_t r1 = rel.io().submitted();
    auto f = *build_alert(okey, rkey.pubkey, sample_body(), T0 + 7200, 5);
    EXPECT_EQ(rel.on_alert(f, 5, g, T0 + 7200), Verdict::Queued);
    EXPECT_EQ(rel.io().submitted() - r1, 1u);
}

TEST(DashAlertRelay, ThreadedWriterNeverBlocksTheIoThread)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto rd = fresh_dir("r"), od = fresh_dir("o");
    auto rcfg = relay_cfg(rd, {okey.pubkey});
    rcfg.inline_io = false;
    auto ocfg = origin_cfg(od, rkey.pubkey);
    ocfg.inline_io = false;
    AlertRelayService rel(rcfg, rkey, T0);
    AlertRelayService org(ocfg, okey, T0);
    std::string err;
    ASSERT_TRUE(rel.init(err)) << err;
    ASSERT_TRUE(org.init(err)) << err;
    std::vector<AckFrame> acks;
    std::vector<AlertFrame> sent;
    rel.set_transport(capture_transport(acks));
    org.set_transport(capture_transport(acks, &sent));
    DiskGate rgate, ogate;
    rgate.install(rel.io());
    ogate.install(org.io());

    // With the disk stalled, both event paths still return promptly.
    PeerAlertGuard g;
    auto f = *build_alert(okey, rkey.pubkey, sample_body(), T0, 7);
    auto fut = std::async(std::launch::async, [&] {
        const Verdict v = rel.on_alert(f, 5, g, T0);
        org.enqueue_event(offline_event("W.rig1", T0), T0);
        // three retransmits (60/120/180 s), each dirtying the origin state
        for (int64_t t = T0 + 5; t <= T0 + 180; t += 5) { rel.on_tick({}, t); org.on_tick({}, t); }
        return v;
    });
    if (fut.wait_for(std::chrono::seconds(10)) != std::future_status::ready) {
        rgate.release();
        ogate.release();
        FAIL() << "a handler or tick waited for the disk";
    }
    EXPECT_EQ(fut.get(), Verdict::Queued);
    EXPECT_EQ(sent.size(), 4u) << "the origin frame (and its retransmits) left without waiting for the disk";
    EXPECT_TRUE(acks.empty()) << "no queued ack before the outbox row is on disk";
    EXPECT_FALSE(fs::exists(rd / "outbox.jsonl"));
    EXPECT_GE(rel.io().backlog(), 1u);

    rgate.release();
    ogate.release();
    rel.io().flush();
    org.io().flush();
    rel.drain_io();
    ASSERT_EQ(acks.size(), 1u);
    EXPECT_EQ(acks[0].status, static_cast<uint8_t>(AckStatus::Queued));
    EXPECT_EQ(read_lines(rd / "outbox.jsonl").size(), 1u);
    EXPECT_GE(org.io().coalesced(), 1u) << "state saves queued behind a stalled disk were coalesced";
    // The persisted origin state is the LATEST snapshot (pending event present).
    std::ifstream st(od / "state.json");
    auto j = nlohmann::json::parse(st);
    EXPECT_EQ(j["pending"].size(), 1u);
    EXPECT_GT(j["nonce_reserved"].get<uint64_t>(), org.next_nonce());
}

TEST(DashAlertRelay, QueuedEventReprobeRecoversALostDeliveredAck)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto od = fresh_dir("o"), rd = fresh_dir("r");
    Mesh m;
    m.add(1, origin_cfg(od, rkey.pubkey), okey, T0);
    m.add(2, fwd_cfg(fresh_dir("f")), std::nullopt, T0);
    m.add(3, relay_cfg(rd, {okey.pubkey}), rkey, T0);
    m.link(1, 2);
    m.link(2, 3);
    int lost = 0;
    m.drop = [&](const Mesh::Msg& msg) {
        if (std::holds_alternative<AckFrame>(msg.frame) &&
            std::get<AckFrame>(msg.frame).status == static_cast<uint8_t>(AckStatus::Delivered) && lost == 0) {
            ++lost;
            return true;
        }
        return false;
    };
    m.nodes[1].svc->enqueue_event(offline_event("W.rig1", T0), T0);
    m.pump(T0);
    auto& o = *m.nodes[1].svc;
    ASSERT_TRUE(o.pending().begin()->second.queued_at_relay);
    auto row = nlohmann::json::parse(read_lines(rd / "outbox.jsonl").at(0));
    std::ofstream(rd / "delivered.jsonl", std::ios::app) << nlohmann::json{{"id", row["id"]}}.dump() << "\n";
    for (int64_t t = T0 + 5; t <= T0 + 1300 && !o.pending().empty(); t += 5) {
        for (auto& [id, n] : m.nodes) n.svc->on_tick({}, t);
        m.pump(t);
    }
    EXPECT_EQ(lost, 1) << "the first delivered ack was lost";
    EXPECT_TRUE(o.pending().empty()) << "the re-probe recovered it (forwarder held only the queued ack)";
    EXPECT_EQ(o.counters().delivered, 1u);
    EXPECT_GE(o.counters().reprobes, 1u);
    EXPECT_EQ(read_lines(rd / "outbox.jsonl").size(), 1u) << "a re-probe never pages twice";
}

TEST(DashAlertRelay, ReprobeAfterRelayRestartAndOutsideTheWindow)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto od = fresh_dir("o"), rd = fresh_dir("r");
    std::vector<AckFrame> oacks;
    AlertFrame frame;
    {
        // Queue at the relay, sidecar delivers, the delivered ack is lost.
        Mesh m;
        m.add(1, origin_cfg(od, rkey.pubkey), okey, T0);
        m.add(2, relay_cfg(rd, {okey.pubkey}), rkey, T0);
        m.link(1, 2);
        m.nodes[1].svc->enqueue_event(offline_event("W.rig1", T0), T0);
        frame = m.nodes[1].svc->pending().begin()->second.frame;
        m.pump(T0);
        auto row = nlohmann::json::parse(read_lines(rd / "outbox.jsonl").at(0));
        std::ofstream(rd / "delivered.jsonl", std::ios::app) << nlohmann::json{{"id", row["id"]}}.dump() << "\n";
        m.drop = [](const Mesh::Msg&) { return true; };
        m.nodes[2].svc->on_tick({}, T0 + 5);
        m.pump(T0 + 5);
    }
    // Relay restarts (empty seen set); the re-probe arrives 1200 s after the
    // frame was signed -- outside the +/-900 s window.
    AlertRelayService rel(relay_cfg(rd, {okey.pubkey}), rkey, T0 + 1200);
    std::string err;
    ASSERT_TRUE(rel.init(err));
    std::vector<AckFrame> acks;
    rel.set_transport(capture_transport(acks));
    PeerAlertGuard g;
    EXPECT_EQ(rel.on_alert(frame, 1, g, T0 + 1200), Verdict::Duplicate);
    ASSERT_EQ(acks.size(), 1u);
    EXPECT_EQ(acks[0].status, static_cast<uint8_t>(AckStatus::Delivered))
        << "an accepted id is answered with its status whatever its age";
    EXPECT_EQ(rel.counters().rejected_stale, 0u);
    EXPECT_EQ(read_lines(rd / "outbox.jsonl").size(), 1u);
}

TEST(DashAlertRelay, QueuedEventExpiresOrIsLostWithALedgerRow)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    {
        // (a) queued, the sidecar never delivers -> expired_at_relay at max age.
        auto od = fresh_dir("o"), rd = fresh_dir("r");
        Mesh m;
        auto ocfg = origin_cfg(od, rkey.pubkey);
        ocfg.max_event_age = 3600;
        m.add(1, ocfg, okey, T0);
        m.add(2, relay_cfg(rd, {okey.pubkey}), rkey, T0);
        m.link(1, 2);
        m.nodes[1].svc->enqueue_event(offline_event("W.rig1", T0), T0);
        m.pump(T0);
        auto& o = *m.nodes[1].svc;
        for (int64_t t = T0 + 5; t <= T0 + 3700; t += 5) {
            for (auto& [id, n] : m.nodes) n.svc->on_tick({}, t);
            m.pump(t);
        }
        EXPECT_TRUE(o.pending().empty());
        EXPECT_EQ(o.counters().expired_at_relay, 1u);
        EXPECT_GE(o.counters().reprobes, 5u);
        auto ledger = read_lines(od / "ledger.jsonl");
        ASSERT_EQ(ledger.size(), 2u);
        EXPECT_NE(ledger[0].find("queued_at_relay"), std::string::npos);
        EXPECT_NE(ledger[1].find("expired_at_relay"), std::string::npos);
        EXPECT_EQ(read_lines(rd / "outbox.jsonl").size(), 1u) << "re-probes never re-append";
    }
    {
        // (b) queued, then the relay loses its state; the re-probe is outside
        // the window -> the relay answers refused-invalid -> lost_at_relay.
        auto od = fresh_dir("o"), rd = fresh_dir("r"), rd2 = fresh_dir("r2");
        Mesh m;
        m.add(1, origin_cfg(od, rkey.pubkey), okey, T0);
        m.add(2, relay_cfg(rd, {okey.pubkey}), rkey, T0);
        m.link(1, 2);
        m.nodes[1].svc->enqueue_event(offline_event("W.rig1", T0), T0);
        m.pump(T0);
        auto& o = *m.nodes[1].svc;
        ASSERT_TRUE(o.pending().begin()->second.queued_at_relay);
        m.links.clear();                                      // relay unreachable ...
        for (int64_t t = T0 + 5; t <= T0 + 1000; t += 5) o.on_tick({}, t);
        m.q.clear();
        m.add(2, relay_cfg(rd2, {okey.pubkey}), rkey, T0 + 1000);   // ... and back with NO state
        m.link(1, 2);
        for (int64_t t = T0 + 1005; t <= T0 + 1700 && !o.pending().empty(); t += 5) {
            for (auto& [id, n] : m.nodes) n.svc->on_tick({}, t);
            m.pump(t);
        }
        EXPECT_TRUE(o.pending().empty());
        EXPECT_EQ(o.counters().lost_at_relay, 1u);
        EXPECT_EQ(o.counters().refused, 0u) << "not reported as a refusal";
        auto ledger = read_lines(od / "ledger.jsonl");
        ASSERT_EQ(ledger.size(), 2u);
        EXPECT_NE(ledger[1].find("lost_at_relay"), std::string::npos);
    }
}

TEST(DashAlertRelay, JunkFromFreshKeysCannotStarveAnAllowlistedOrigin)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto rd = fresh_dir("r");
    AlertRelayService rel(relay_cfg(rd, {okey.pubkey}), rkey, T0);
    std::string err;
    ASSERT_TRUE(rel.init(err));
    std::vector<AckFrame> acks;
    rel.set_transport(capture_transport(acks));
    PeerAlertGuard g;   // ONE link (a forwarder next to the relay relays everything valid)
    for (std::size_t i = 0; i < PeerAlertGuard::kMaxAlertsPerWindow; ++i) {
        auto f = *build_alert(junk_key(static_cast<int>(i)), rkey.pubkey, sample_body(), T0, 7000 + i);
        EXPECT_EQ(rel.on_alert(f, 4, g, T0), Verdict::RefusedNotAllowed);
    }
    auto more = *build_alert(junk_key(99), rkey.pubkey, sample_body(), T0, 8000);
    EXPECT_EQ(rel.on_alert(more, 4, g, T0 + 1), Verdict::RateLimited) << "the shared window is full";
    auto genuine = *build_alert(okey, rkey.pubkey, sample_body(), T0, 1);
    EXPECT_EQ(rel.on_alert(genuine, 4, g, T0 + 2), Verdict::Queued) << "the allowlisted origin has its own budget";

    // Origin side: junk acks cannot starve the ack from the configured relay.
    auto od = fresh_dir("o");
    AlertRelayService org(origin_cfg(od, rkey.pubkey), okey, T0);
    ASSERT_TRUE(org.init(err));
    org.set_transport(capture_transport(acks));
    org.enqueue_event(offline_event("W.rig1", T0), T0);
    const uint64_t nonce = org.pending().begin()->second.frame.nonce;
    PeerAlertGuard og;
    for (std::size_t i = 0; i < PeerAlertGuard::kMaxAcksPerWindow + 5; ++i) {
        auto k = junk_key(static_cast<int>(i));
        org.on_ack(*build_ack(k, k.pubkey, i, AckStatus::Queued), 4, og, T0);
    }
    EXPECT_EQ(org.on_ack(*build_ack(rkey, okey.pubkey, nonce, AckStatus::Delivered), 4, og, T0 + 1),
              Verdict::AckConsumed);
    EXPECT_TRUE(org.pending().empty());
}

TEST(DashAlertDetector, RestoredWorkerReportsTheRealOutage)
{
    auto c = det_cfg();
    c.startup_grace = 0;
    AlertDetector d(c, T0);
    d.tick(one("A.rig1", "s1", 0), T0);
    d.tick({}, T0 + 100);                                  // A drops at T0+100
    ASSERT_EQ(d.tick({}, T0 + 400).size(), 1u);            // OFFLINE
    d.tick(one("B.rig2", "s2", 0), T0 + 500);              // B up when the node stops
    auto snap = d.persist();
    EXPECT_EQ(snap["A.rig1"]["outage_since"], T0 + 100);
    EXPECT_EQ(snap["B.rig2"]["outage_since"], 0);

    AlertDetector d2(c, T0 + 10000);                       // node restarts much later
    d2.restore(snap);
    const uint64_t g0 = d2.generation();
    d2.tick(one("A.rig1", "x", 0), T0 + 10100);
    auto ev = d2.tick(one("A.rig1", "x", 1), T0 + 10160);
    ASSERT_EQ(ev.size(), 1u);
    EXPECT_EQ(ev[0].kind, Kind::BackOnline);
    EXPECT_NE(ev[0].detail.find("back online after " + fmt_duration(10000)), std::string::npos)
        << ev[0].detail << " -- must count from the real drop, not from the restart";
    EXPECT_GT(d2.generation(), g0);
    // B never reconnects: OFFLINE fires on the restart timer, text counts from last_seen.
    std::vector<DetectorEvent> ev2;
    for (int64_t t = T0 + 10165; t <= T0 + 10400 && ev2.empty(); t += 5) ev2 = d2.tick(one("A.rig1", "x", 1), t);
    ASSERT_EQ(ev2.size(), 1u);
    EXPECT_EQ(ev2[0].worker, "B.rig2");
    EXPECT_NE(ev2[0].detail.find("down " + fmt_duration(10300 - 500)), std::string::npos) << ev2[0].detail;
}

// ── (12) re-verify fixes ────────────────────────────────────────────────────
namespace {
// Blocks the writer thread once it has picked up a job; reports when it did.
struct EnteredGate {
    std::promise<void> go;
    std::shared_future<void> go_f{go.get_future().share()};
    std::atomic<int> entered{0};
    bool released{false};
    void install(FileWriter& w)
    {
        auto f = go_f;
        w.set_before_job_hook([this, f] { ++entered; f.wait(); });
    }
    bool wait_entered(int n)
    {
        for (int i = 0; i < 5000 && entered.load() < n; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return entered.load() >= n;
    }
    void release() { if (!released) { released = true; go.set_value(); } }
    ~EnteredGate() { release(); }
};

std::string repeat_str(const std::string& s, int n)
{
    std::string out;
    for (int i = 0; i < n; ++i) out += s;
    return out;
}
} // namespace

// Fix 1: a final refusal for a SUPERSEDED nonce must not end the event.
// (Before: pending=0, refused=1 after the late refusal of the first nonce.)
TEST(DashAlertRelay, LateRefusalOfASupersededNonceDoesNotEndTheEvent)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto od = fresh_dir("o");
    AlertRelayService org(origin_cfg(od, rkey.pubkey), okey, T0);
    std::string err;
    ASSERT_TRUE(org.init(err));
    std::vector<AckFrame> acks;
    org.set_transport(capture_transport(acks));
    org.enqueue_event(offline_event("W.rig1", T0), T0);
    const uint64_t n1 = org.pending().begin()->second.frame.nonce;
    for (int64_t t = T0 + 5; t <= T0 + 600; t += 5) org.on_tick({}, t);   // re-issue at reissue_after
    ASSERT_EQ(org.pending().size(), 1u);
    const uint64_t n2 = org.pending().begin()->second.frame.nonce;
    ASSERT_NE(n1, n2) << "the event was re-issued under a fresh nonce";
    EXPECT_EQ(org.counters().reissued, 1u);

    PeerAlertGuard g;
    // The first frame reached the relay stale -> a late RefusedInvalid for n1.
    EXPECT_EQ(org.on_ack(*build_ack(rkey, okey.pubkey, n1, AckStatus::RefusedInvalid), 4, g, T0 + 610),
              Verdict::AckDropped);
    EXPECT_EQ(org.on_ack(*build_ack(rkey, okey.pubkey, n1, AckStatus::RefusedNotAllowed), 4, g, T0 + 611),
              Verdict::AckDropped);
    EXPECT_EQ(org.on_ack(*build_ack(rkey, okey.pubkey, n1, AckStatus::Expired), 4, g, T0 + 612),
              Verdict::AckDropped);
    EXPECT_EQ(org.pending().size(), 1u) << "PENDING_AFTER_OLD_NONCE_REFUSAL must stay 1";
    EXPECT_EQ(org.counters().refused, 0u);
    EXPECT_EQ(org.counters().stale_refusal, 3u);
    EXPECT_FALSE(fs::exists(od / "ledger.jsonl")) << "no final ledger row for a superseded refusal";

    // "queued" and "delivered" are honoured for ANY nonce of the event.
    EXPECT_EQ(org.on_ack(*build_ack(rkey, okey.pubkey, n1, AckStatus::Queued), 4, g, T0 + 613),
              Verdict::AckConsumed);
    EXPECT_TRUE(org.pending().begin()->second.queued_at_relay);
    EXPECT_EQ(org.on_ack(*build_ack(rkey, okey.pubkey, n1, AckStatus::Delivered), 4, g, T0 + 614),
              Verdict::AckConsumed);
    EXPECT_TRUE(org.pending().empty());
    EXPECT_EQ(org.counters().delivered, 1u);

    // A refusal of the CURRENT nonce is still final.
    org.enqueue_event(offline_event("W.rig2", T0 + 700), T0 + 700);
    const uint64_t cur = org.pending().begin()->second.frame.nonce;
    EXPECT_EQ(org.on_ack(*build_ack(rkey, okey.pubkey, cur, AckStatus::RefusedInvalid), 4, g, T0 + 701),
              Verdict::AckConsumed);
    EXPECT_TRUE(org.pending().empty());
    EXPECT_EQ(org.counters().refused, 1u);
    org.publish_status(T0 + 702);
    EXPECT_EQ(org.status_json()["outbox"]["stale_refusal"], 3u);
}

// Fix 2: UTF-8 -- clip on a code-point boundary, reject malformed bodies.
TEST(DashAlertRelay, Utf8ClipSanitizeAndValidate)
{
    const std::string zh = "\xd0\xb6";   // U+0436, 2 bytes
    const std::string w = "X" + repeat_str(zh, 40);   // 81 bytes: byte 64 is a continuation byte
    ASSERT_EQ(w.size(), 81u);
    EXPECT_EQ((static_cast<unsigned char>(w[64]) & 0xC0), 0x80) << "a naive 64-byte cut would split a code point";
    const std::string c = clip_utf8(w, kMaxWorker);
    EXPECT_EQ(c, "X" + repeat_str(zh, 31));
    EXPECT_TRUE(is_valid_utf8(c));
    EXPECT_TRUE(is_valid_utf8(w));
    EXPECT_FALSE(is_valid_utf8("a\xd0"));            // truncated
    EXPECT_FALSE(is_valid_utf8("\xc3\x28"));         // bad continuation
    EXPECT_FALSE(is_valid_utf8("\xc0\xaf"));         // overlong
    EXPECT_FALSE(is_valid_utf8("\xed\xa0\x80"));     // surrogate
    EXPECT_FALSE(is_valid_utf8("\xf4\x90\x80\x80")); // > U+10FFFF
    EXPECT_TRUE(is_valid_utf8("\xf0\x9f\x98\x80"));  // 4-byte emoji
    EXPECT_EQ(sanitize_utf8("A.\xff\xferig\xd0"), "A.??rig?");
    // A malformed name is sanitized BEFORE the clip, so the body is always valid.
    AlertBody b = sample_body();
    b.worker = std::string(70, '\xff');
    auto dec = decode_body(encode_body(b));
    ASSERT_TRUE(dec);
    EXPECT_EQ(dec->worker, std::string(kMaxWorker, '?'));
}

TEST(DashAlertRelay, CyrillicWorkerAndLabelRoundTripDeliveredExactlyOnce)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto od = fresh_dir("o"), rd = fresh_dir("r");
    const std::string zh = "\xd0\xb6", yo = "\xd1\x91";
    const std::string worker = "X" + repeat_str(zh, 40);        // 81 bytes > kMaxWorker
    const std::string label = "A" + repeat_str(yo, 20);         // 41 bytes > kMaxLabel, odd-aligned
    Mesh m;
    auto ocfg = origin_cfg(od, rkey.pubkey);
    ocfg.label = label;
    m.add(1, ocfg, okey, T0);
    m.add(2, fwd_cfg(fresh_dir("f")), std::nullopt, T0);
    m.add(3, relay_cfg(rd, {okey.pubkey}), rkey, T0);
    m.link(1, 2);
    m.link(2, 3);
    auto& o = *m.nodes[1].svc;
    o.enqueue_event(offline_event(worker, T0), T0);
    m.pump(T0);
    ASSERT_EQ(o.pending().size(), 1u);
    EXPECT_TRUE(o.pending().begin()->second.queued_at_relay);
    auto rows = read_lines(rd / "outbox.jsonl");
    ASSERT_EQ(rows.size(), 1u);
    auto row = nlohmann::json::parse(rows[0]);
    EXPECT_EQ(row["worker"], "X" + repeat_str(zh, 31)) << "clipped on a code-point boundary";
    EXPECT_EQ(row["label"], "A" + repeat_str(yo, 15));
    // A short Cyrillic label round-trips unchanged.
    AlertBody sb = sample_body();
    sb.label = "\xd0\xa4\xd0\xb5\xd1\x80\xd0\xbc\xd0\xb0-1";   // "Ferma-1" in Cyrillic
    sb.worker = "\xd1\x80\xd0\xb8\xd0\xb3.1";
    auto dec = decode_body(encode_body(sb));
    ASSERT_TRUE(dec);
    EXPECT_EQ(*dec, sb);

    std::ofstream(rd / "delivered.jsonl", std::ios::app) << nlohmann::json{{"id", row["id"]}}.dump() << "\n";
    for (int64_t t = T0 + 5; t <= T0 + 30; t += 5) {
        for (auto& [id, n] : m.nodes) n.svc->on_tick({}, t);
        m.pump(t);
    }
    EXPECT_TRUE(o.pending().empty());
    EXPECT_EQ(o.counters().delivered, 1u);
    EXPECT_EQ(read_lines(rd / "outbox.jsonl").size(), 1u) << "exactly once";
    EXPECT_EQ(m.nodes[3].svc->counters().delivered_telegram, 1u);
    auto ledger = read_lines(od / "ledger.jsonl");
    ASSERT_EQ(ledger.size(), 2u);
    EXPECT_EQ(nlohmann::json::parse(ledger[1])["worker"], worker) << "the origin ledger keeps the full name";
    // Both state files are valid JSON.
    for (const auto& d : {od, rd}) {
        std::ifstream st(d / "state.json");
        EXPECT_TRUE(nlohmann::json::parse(st, nullptr, false).is_object());
    }
}

TEST(DashAlertRelay, MalformedUtf8FromMinersNeverBreaksADump)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto od = fresh_dir("o");
    auto ocfg = origin_cfg(od, rkey.pubkey);
    ocfg.det.startup_grace = 0;
    ocfg.label = "L\xff";
    AlertRelayService org(ocfg, okey, T0);
    std::string err;
    ASSERT_TRUE(org.init(err));
    std::vector<AckFrame> acks;
    std::vector<AlertFrame> sent;
    org.set_transport(capture_transport(acks, &sent));
    const std::string bad = "A.\xff\xfe" "rig";
    for (int64_t t = T0; t <= T0 + 400; t += 5)
        org.run_tick([&] { return t < T0 + 50 ? one(bad, "s1", 0) : std::vector<WorkerSample>{}; }, t);
    EXPECT_EQ(org.counters().tick_errors, 0u) << "no dump threw";
    auto s = org.status_json();
    EXPECT_TRUE(s["detector"]["workers"].contains("A.??rig"));
    EXPECT_NO_THROW((void)s.dump());
    ASSERT_EQ(org.pending().size(), 1u);
    EXPECT_EQ(org.pending().begin()->second.worker, "A.??rig");
    // An event raised with a raw malformed name (not via the detector) is
    // still persisted: the state dump replaces instead of throwing.
    EXPECT_NO_THROW(org.enqueue_event(offline_event("B.\xc3", T0 + 400), T0 + 400));
    std::ifstream st(od / "state.json");
    auto j = nlohmann::json::parse(st, nullptr, false);
    ASSERT_TRUE(j.is_object());
    EXPECT_EQ(j["pending"].size(), 2u);
    EXPECT_FALSE(sent.empty());
}

TEST(DashAlertRelay, InvalidUtf8BodyIsRefusedAndNeverEntersTheSeenSet)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto rd = fresh_dir("r");
    AlertRelayService rel(relay_cfg(rd, {okey.pubkey}), rkey, T0);
    std::string err;
    ASSERT_TRUE(rel.init(err));
    std::vector<AckFrame> acks;
    rel.set_transport(capture_transport(acks));
    // A non-conforming origin: well-formed layout, malformed UTF-8 in the label.
    Bytes pt = {1, 0, 0, 0, 0};
    const std::string lbl = "ok\xd0";   // truncated 2-byte sequence
    pt.push_back(static_cast<unsigned char>(lbl.size()));
    pt.insert(pt.end(), lbl.begin(), lbl.end());
    pt.push_back(0);
    pt.push_back(0);
    EXPECT_FALSE(decode_body(pt));
    auto f = build_alert_plaintext(okey, rkey.pubkey, pt, T0, 77);
    ASSERT_TRUE(f);
    PeerAlertGuard g;
    EXPECT_EQ(rel.on_alert(*f, 5, g, T0), Verdict::RefusedInvalid);
    EXPECT_EQ(rel.seen().size(), 0u);
    EXPECT_EQ(rel.seen().order.size(), 0u);
    EXPECT_EQ(rel.seen().find(okey.pubkey, 77), nullptr);
    ASSERT_EQ(acks.size(), 1u);
    EXPECT_EQ(acks[0].status, static_cast<uint8_t>(AckStatus::RefusedInvalid));
    EXPECT_EQ(rel.counters().refused_invalid, 1u);
    EXPECT_FALSE(fs::exists(rd / "outbox.jsonl"));
    // The retransmit is judged afresh (and refused again), never from a cache.
    EXPECT_EQ(rel.on_alert(*f, 5, g, T0 + 60), Verdict::RefusedInvalid);
    EXPECT_EQ(rel.seen().size(), 0u);
}

// Fix 3: a throwing tick is caught, counted, and later ticks still run.
TEST(DashAlertRelay, ThrowingTickIsCaughtAndLaterTicksRun)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto od = fresh_dir("o");
    AlertRelayService org(origin_cfg(od, rkey.pubkey), okey, T0);
    std::string err;
    ASSERT_TRUE(org.init(err));
    bool transport_throws = false;
    std::size_t sends = 0;
    Transport t;
    t.broadcast_alert = [&](uint64_t, const AlertFrame&) -> std::size_t {
        if (transport_throws) throw std::runtime_error("transport boom");
        ++sends;
        return 1;
    };
    t.broadcast_ack = [](uint64_t, const AckFrame&) { return std::size_t{1}; };
    org.set_transport(t);
    org.enqueue_event(offline_event("W.rig1", T0), T0);
    ASSERT_EQ(sends, 1u);

    // (a) the sampler throws
    org.run_tick([]() -> std::vector<WorkerSample> { throw std::runtime_error("sampler boom"); }, T0 + 5);
    EXPECT_EQ(org.counters().tick_errors, 1u);
    // (b) the tick itself throws (retransmit at +60 s through a throwing transport)
    transport_throws = true;
    org.run_tick({}, T0 + 60);
    EXPECT_EQ(org.counters().tick_errors, 2u);
    auto s = org.status_json();
    EXPECT_EQ(s["tick"]["errors"], 2u);
    EXPECT_NE(s["tick"]["last_error"].get<std::string>().find("transport boom"), std::string::npos);
    // (c) later ticks run normally: the retransmit goes out, status is fresh.
    transport_throws = false;
    for (int64_t now = T0 + 65; now <= T0 + 200; now += 5) org.run_tick({}, now);
    EXPECT_EQ(org.counters().tick_errors, 2u);
    EXPECT_GE(sends, 3u) << "retransmits resumed after the throwing ticks";
    EXPECT_EQ(org.status_json()["now"], T0 + 200);

    // (d) the node's repeating core::Timer: a throwing handler escapes
    // io_context::run() and the timer is NOT re-armed (why the guard exists)...
    {
        boost::asio::io_context ioc;
        core::Timer timer(&ioc, true);
        int calls = 0;
        timer.start(1, [&] { ++calls; throw std::runtime_error("unguarded"); });
        EXPECT_THROW(ioc.run(), std::runtime_error);
        ioc.restart();
        ioc.run_for(std::chrono::milliseconds(1500));
        EXPECT_EQ(calls, 1) << "an unguarded throw stops the repeating timer";
    }
    // ...while the node's handler shape (run_tick around the sampler) keeps it
    // ticking through repeated throws.
    {
        boost::asio::io_context ioc;
        core::Timer timer(&ioc, true);
        int calls = 0;
        const uint64_t e0 = org.counters().tick_errors;
        timer.start(1, [&] {
            org.run_tick([&]() -> std::vector<WorkerSample> {
                ++calls;
                throw std::runtime_error("sampler boom");
            }, T0 + 300 + calls);
            if (calls >= 3) ioc.stop();
        });
        ioc.run_for(std::chrono::seconds(10));
        EXPECT_EQ(calls, 3) << "the guarded timer re-armed after every throw";
        EXPECT_EQ(org.counters().tick_errors, e0 + 3);
    }
}

// Fix 4: a stale but validly signed re-probe crosses a forwarder whose seen set
// was emptied by a restart, so a lost "delivered" ack is recovered multi-hop.
TEST(DashAlertRelay, StaleReprobeCrossesARestartedForwarder)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto od = fresh_dir("o"), rd = fresh_dir("r");
    Mesh m;
    m.add(1, origin_cfg(od, rkey.pubkey), okey, T0);
    m.add(2, fwd_cfg(fresh_dir("f")), std::nullopt, T0);
    m.add(3, relay_cfg(rd, {okey.pubkey}), rkey, T0);
    m.link(1, 2);
    m.link(2, 3);
    int64_t cur = T0;
    int lost = 0;
    m.drop = [&](const Mesh::Msg& msg) {
        const bool delivered = std::holds_alternative<AckFrame>(msg.frame) &&
                               std::get<AckFrame>(msg.frame).status == static_cast<uint8_t>(AckStatus::Delivered);
        if (delivered && cur < T0 + 1000) { ++lost; return true; }
        return false;
    };
    auto& o = *m.nodes[1].svc;
    o.enqueue_event(offline_event("W.rig1", T0), T0);
    const AlertFrame frame = o.pending().begin()->second.frame;
    m.pump(T0);
    ASSERT_TRUE(o.pending().begin()->second.queued_at_relay);
    auto row = nlohmann::json::parse(read_lines(rd / "outbox.jsonl").at(0));
    std::ofstream(rd / "delivered.jsonl", std::ios::app) << nlohmann::json{{"id", row["id"]}}.dump() << "\n";
    for (cur = T0 + 5; cur < T0 + 1000; cur += 5) {
        for (auto& [id, n] : m.nodes) n.svc->on_tick({}, cur);
        m.pump(cur);
    }
    ASSERT_GE(lost, 2) << "the delivered ack and the answer to the first re-probe were both lost";
    ASSERT_EQ(o.pending().size(), 1u);

    // The forwarder restarts: empty seen set. The next re-probe (T0+1200) is
    // outside the +/-900 s window.
    m.add(2, fwd_cfg(fresh_dir("f2")), std::nullopt, cur);
    for (; cur <= T0 + 1400 && !o.pending().empty(); cur += 5) {
        for (auto& [id, n] : m.nodes) n.svc->on_tick({}, cur);
        m.pump(cur);
    }
    EXPECT_GT(cur - static_cast<int64_t>(frame.timestamp), kReplayWindowSec);
    EXPECT_TRUE(o.pending().empty()) << "the stale re-probe crossed the restarted forwarder";
    EXPECT_EQ(o.counters().delivered, 1u);
    auto& f2 = *m.nodes[2].svc;
    EXPECT_EQ(f2.counters().stale_forwarded, 1u);
    EXPECT_EQ(f2.counters().rejected_stale, 0u);
    EXPECT_EQ(f2.counters().ack_forwarded, 1u) << "the relay's cached delivered ack came back through it";
    EXPECT_EQ(read_lines(rd / "outbox.jsonl").size(), 1u) << "a stale re-probe never pages";

    // A repeat of the stale frame is throttled like any duplicate.
    PeerAlertGuard g;
    AlertFrame again = frame;
    again.hops_left = 1;
    EXPECT_EQ(f2.on_alert(again, 1, g, cur), Verdict::Duplicate);
    // A stale frame with a bad signature is still rejected, never forwarded.
    AlertRelayService f3(fwd_cfg(fresh_dir("f3")), std::nullopt, cur);
    std::string e3;
    ASSERT_TRUE(f3.init(e3));
    std::vector<AckFrame> acks;
    std::vector<AlertFrame> fwded;
    f3.set_transport(capture_transport(acks, &fwded));
    AlertFrame forged = frame;
    forged.body.back() ^= 1;
    PeerAlertGuard g3;
    EXPECT_EQ(f3.on_alert(forged, 1, g3, cur), Verdict::RejectedStale);
    EXPECT_TRUE(fwded.empty());
    AlertFrame spent = frame;
    spent.hops_left = 0;
    EXPECT_EQ(f3.on_alert(spent, 1, g3, cur), Verdict::RejectedStale) << "hops exhausted";
    EXPECT_EQ(f3.seen().size(), 0u);
}

// Fix 5: bounded writer queue + trailing-Replace coalescing.
TEST(DashAlertRelay, WriterQueueCapAndTrailingReplaceCoalescing)
{
    auto dir = fresh_dir("w");
    const std::string st = (dir / "state.json").string(), log = (dir / "rows.jsonl").string();
    FileWriter w(false, 3);
    EnteredGate gate;
    gate.install(w);
    EXPECT_TRUE(w.submit(0, {FileOp{FileOp::Type::Append, log, "r0"}}, true));
    ASSERT_TRUE(gate.wait_entered(1)) << "the worker holds job 0";
    EXPECT_TRUE(w.submit(0, {FileOp{FileOp::Type::Append, log, "r1"}}, true));
    EXPECT_TRUE(w.submit(0, {FileOp{FileOp::Type::Append, log, "r2"}}, true));
    // [append r3, replace state "s1"] (tagged, like an accepted alert)
    EXPECT_TRUE(w.submit(7, {FileOp{FileOp::Type::Append, log, "r3"}, FileOp{FileOp::Type::Replace, st, "s1"}}, true));
    EXPECT_EQ(w.queued(), 3u);
    EXPECT_FALSE(w.submit(0, {FileOp{FileOp::Type::Append, log, "r4"}}, true)) << "cap reached: deferred";
    EXPECT_EQ(w.deferred(), 1u);
    // An untagged state save folds into the trailing Replace of the last job.
    EXPECT_TRUE(w.submit(0, {FileOp{FileOp::Type::Replace, st, "s2"}}, true));
    EXPECT_EQ(w.coalesced(), 1u);
    EXPECT_EQ(w.queued(), 3u);
    // Two tagged jobs never fold; a non-deferrable job is accepted above the cap.
    EXPECT_TRUE(w.submit(8, {FileOp{FileOp::Type::Replace, st, "s3"}}));
    EXPECT_EQ(w.queued(), 4u);
    EXPECT_EQ(w.coalesced(), 1u);
    // ...and a later untagged save folds into that one.
    EXPECT_TRUE(w.submit(0, {FileOp{FileOp::Type::Replace, st, "s4"}}, true));
    EXPECT_EQ(w.coalesced(), 2u);
    gate.release();
    w.flush();
    std::ifstream sf(st);
    std::string content((std::istreambuf_iterator<char>(sf)), std::istreambuf_iterator<char>());
    EXPECT_EQ(content, "s4") << "the newest snapshot is on disk";
    EXPECT_EQ(read_lines(log), (std::vector<std::string>{"r0", "r1", "r2", "r3"}));
    auto res = w.take_results();
    ASSERT_EQ(res.size(), 2u);
    EXPECT_EQ(res[0].tag, 7u);
    EXPECT_EQ(res[1].tag, 8u);
    EXPECT_TRUE(res[0].ok && res[1].ok);
}

TEST(DashAlertRelay, RelayDefersAlertsWhenTheWriterQueueIsFull)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto rd = fresh_dir("r");
    auto rcfg = relay_cfg(rd, {okey.pubkey});
    rcfg.inline_io = false;
    rcfg.io_max_jobs = 4;
    AlertRelayService rel(rcfg, rkey, T0);
    std::string err;
    ASSERT_TRUE(rel.init(err)) << err;
    std::vector<AckFrame> acks;
    rel.set_transport(capture_transport(acks));
    EnteredGate gate;
    gate.install(rel.io());
    PeerAlertGuard g;
    std::vector<AlertFrame> frames;
    for (uint64_t i = 0; i < 7; ++i) frames.push_back(*build_alert(okey, rkey.pubkey, sample_body(), T0, 100 + i));
    EXPECT_EQ(rel.on_alert(frames[0], 5, g, T0), Verdict::Queued);
    ASSERT_TRUE(gate.wait_entered(1));
    std::vector<Verdict> v;
    for (std::size_t i = 1; i < frames.size(); ++i) v.push_back(rel.on_alert(frames[i], 5, g, T0));
    EXPECT_EQ(v, (std::vector<Verdict>{Verdict::Queued, Verdict::Queued, Verdict::Queued, Verdict::Queued,
                                       Verdict::Deferred, Verdict::Deferred}));
    EXPECT_EQ(rel.counters().io_deferred, 2u);
    EXPECT_EQ(rel.io().queued(), 4u);
    EXPECT_EQ(rel.seen().find(okey.pubkey, 105), nullptr) << "a deferred id is forgotten";
    EXPECT_EQ(rel.seen().find(okey.pubkey, 106), nullptr);
    EXPECT_TRUE(acks.empty());
    rel.publish_status(T0);
    EXPECT_EQ(rel.status_json()["io"]["deferred"], 2u);
    gate.release();
    rel.io().flush();
    rel.drain_io();
    EXPECT_EQ(acks.size(), 5u);
    // The origin's retransmits of the deferred ids are processed afresh.
    EXPECT_EQ(rel.on_alert(frames[5], 5, g, T0 + 60), Verdict::Queued);
    EXPECT_EQ(rel.on_alert(frames[6], 5, g, T0 + 60), Verdict::Queued);
    rel.io().flush();
    rel.drain_io();
    EXPECT_EQ(acks.size(), 7u);
    auto rows = read_lines(rd / "outbox.jsonl");
    EXPECT_EQ(rows.size(), 7u);
    std::set<std::string> ids;
    for (const auto& r : rows) ids.insert(nlohmann::json::parse(r)["id"].get<std::string>());
    EXPECT_EQ(ids.size(), 7u) << "no duplicate outbox row";
    std::ifstream st(rd / "state.json");
    auto j = nlohmann::json::parse(st);
    EXPECT_EQ(j["accepted"].size(), 7u) << "the latest state (all ids) is on disk";
}

// Fix 6: the sidecar's expired.jsonl is fed back: the relay acks "expired" at
// once and the origin records expired_at_relay without waiting out max age.
TEST(DashAlertRelay, SidecarExpiredRowIsAckedExpiredPromptly)
{
    auto okey = key_from_byte(0x11), rkey = key_from_byte(0x22);
    auto od = fresh_dir("o"), rd = fresh_dir("r");
    Mesh m;
    m.add(1, origin_cfg(od, rkey.pubkey), okey, T0);
    m.add(2, fwd_cfg(fresh_dir("f")), std::nullopt, T0);
    m.add(3, relay_cfg(rd, {okey.pubkey}), rkey, T0);
    m.link(1, 2);
    m.link(2, 3);
    auto& o = *m.nodes[1].svc;
    o.enqueue_event(offline_event("W.rig1", T0), T0);
    const AlertFrame frame = o.pending().begin()->second.frame;
    m.pump(T0);
    ASSERT_TRUE(o.pending().begin()->second.queued_at_relay);
    auto row = nlohmann::json::parse(read_lines(rd / "outbox.jsonl").at(0));
    // Exactly the row shape the sidecar writes.
    std::ofstream(rd / "expired.jsonl", std::ios::app)
        << nlohmann::json{{"id", row["id"]}, {"event_ts", T0 - 7 * 3600}, {"ts", T0 + 5}}.dump() << "\n";
    for (int64_t t = T0 + 5; t <= T0 + 10; t += 5) {
        for (auto& [id, n] : m.nodes) n.svc->on_tick({}, t);
        m.pump(t);
    }
    EXPECT_TRUE(o.pending().empty()) << "finalized within one tick, not after max_event_age";
    EXPECT_EQ(o.counters().expired_at_relay, 1u);
    EXPECT_EQ(o.counters().refused, 0u);
    EXPECT_EQ(o.counters().lost_at_relay, 0u);
    auto ledger = read_lines(od / "ledger.jsonl");
    ASSERT_EQ(ledger.size(), 2u);
    EXPECT_EQ(nlohmann::json::parse(ledger[1])["status"], "expired_at_relay");
    auto& r = *m.nodes[3].svc;
    EXPECT_EQ(r.counters().expired_sidecar, 1u);
    EXPECT_EQ(r.counters().delivered_telegram, 0u);
    r.publish_status(T0 + 10);
    EXPECT_EQ(r.status_json()["relay"]["pending_sidecar"], 0u);

    // Persisted: a restarted relay answers a re-probe "expired" and does not
    // re-read (re-ack) the expired file.
    std::vector<AckFrame> acks;
    {
        AlertRelayService rel(relay_cfg(rd, {okey.pubkey}), rkey, T0 + 20);
        std::string err;
        ASSERT_TRUE(rel.init(err));
        rel.set_transport(capture_transport(acks));
        rel.on_tick({}, T0 + 25);
        EXPECT_TRUE(acks.empty()) << "expired_offset persisted: no second ack from the file";
        PeerAlertGuard g;
        EXPECT_EQ(rel.on_alert(frame, 9, g, T0 + 30), Verdict::Duplicate);
        ASSERT_EQ(acks.size(), 1u);
        EXPECT_EQ(acks[0].status, static_cast<uint8_t>(AckStatus::Expired));
    }
    EXPECT_EQ(read_lines(rd / "outbox.jsonl").size(), 1u);
    EXPECT_EQ(ack_shape_error(acks[0]), nullptr) << "status 5 is a valid wire status";
    EXPECT_EQ(wire_ack(acks[0]), acks[0]);
}
