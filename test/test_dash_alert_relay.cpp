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

#include <gtest/gtest.h>

#include <atomic>
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
    b.label = "hotel";
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
    c.label = "hotel";
    c.relays = {relay_pub};
    c.retry_every = 60;
    c.retry_max = 60;
    return c;
}

ServiceConfig relay_cfg(const fs::path& dir, const std::vector<Bytes>& accept)
{
    ServiceConfig c;
    c.telegram = true;
    c.state_dir = dir.string();
    c.accept = accept;
    return c;
}

ServiceConfig fwd_cfg(const fs::path& dir)
{
    ServiceConfig c;
    c.forward = true;
    c.state_dir = dir.string();
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
    EXPECT_EQ(row["label"], "hotel");

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
