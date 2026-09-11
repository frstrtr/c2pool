// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_native_block_relay_kat.cpp   --  C5 KATs
//
// The C5 dual-arm found-block relay: the 2008 frame it puts on the wire, the
// two arms and their orders, the RandomX gate that is the only door into the
// whole path, the never-silent-drop rule, the 2009 responder, and the
// c2pool-side redundant-broadcast carrier with its cheap-to-heavy admission
// ladder.
//
// THE BYTES ARE REAL. Every block and every transaction body below is a real
// stagenet capture with the identity monerod itself reported:
//
//   golden_c2a::BLOCKS   whole block blobs with monerod's block ids
//   golden::FULL_TXS     complete transaction blobs with monerod's tx ids
//
// Suite Z re-derives both identities with this repository's own code before any
// other suite uses them, so a fixture that had quietly stopped being a Monero
// block could not make the rest of the file pass.
//
// The one synthetic step is deliberate and is spelled out where it happens: a
// real 0-transaction block blob has its trailing varint(0) replaced by
// varint(3) plus three real transaction ids, producing a block that commits to
// three real transactions whose real bodies we hold. That is the only shape in
// which a self-contained fluffy frame can be checked end to end -- the capture
// format carries block blobs and transaction blobs, but no block whose
// transactions were also captured in full.
//
// WHAT THIS FILE IS FOR. A relay is the one component whose bugs are paid for
// by somebody else: an invalid or incomplete block does not bounce, it bans our
// P2P identity at every peer that received it, and a block that silently fails
// to go out is a found block thrown away with the share that paid for it. So
// the assertions here are mostly about REFUSING: what must never reach the
// wire, and what must be shouted about when it does not.
//
// SCOPE FENCE: src/impl/xmr/ only; no consensus digest; src/sharechain/v37 is
// not touched.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <string>
#include <vector>

#include "impl/xmr/native/contracts/fakes/fakes.hpp"
#include "impl/xmr/native/relay/xmr_block_relay.hpp"
#include "impl/xmr/native/relay/xmr_block_relay_submit_bridge.hpp"
#include "impl/xmr/native/relay/xmr_found_block_carrier.hpp"

#include "xmr_c2a_golden.hpp"
#include "xmr_tx_weight_golden.hpp"

using namespace c2pool::xmr::native;
namespace R  = c2pool::xmr::native::relay;
namespace G2 = c2pool::xmr::native::golden_c2a;
namespace GT = c2pool::xmr::native::golden;

namespace {

int g_fail   = 0;
int g_checks = 0;

#define CHECK(cond, ...)                                       \
    do {                                                       \
        const bool _ok = (cond);                               \
        ++g_checks;                                            \
        if (!_ok) ++g_fail;                                    \
        std::printf("  [%s] ", _ok ? "PASS" : "FAIL");         \
        std::printf(__VA_ARGS__);                              \
        std::printf("\n");                                     \
    } while (0)

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> bytes_from_hex(const char* hex) {
    std::vector<std::uint8_t> out;
    const std::size_t n = std::strlen(hex);
    out.reserve(n / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < n; i += 2) {
        const int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

Hash hash_from_hex(const char* hex) {
    Hash h{};
    const std::vector<std::uint8_t> b = bytes_from_hex(hex);
    if (b.size() == 32) std::memcpy(h.data(), b.data(), 32);
    return h;
}

std::string hex_of(const Hash& h) {
    static const char* kD = "0123456789abcdef";
    std::string s;
    for (const std::uint8_t b : h) { s.push_back(kD[b >> 4]); s.push_back(kD[b & 0x0f]); }
    return s;
}

std::string body_key(const Hash& h) {
    return std::string(reinterpret_cast<const char*>(h.data()), h.size());
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------
struct TxFixture {
    Hash                      id{};
    std::vector<std::uint8_t> blob;
};

// One real block, parsed, with everything the relay will be asked about.
struct BlockFixture {
    std::vector<std::uint8_t> blob;
    Hash                      id{};
    std::uint64_t             height = 0;
    std::uint32_t             nonce  = 0;
    Hash                      prev_id{};
    std::vector<Hash>         tx_hashes;
    std::vector<TxFixture>    bodies;      // parallel to tx_hashes
};

BlockFixture parse_fixture(std::vector<std::uint8_t> blob) {
    BlockFixture f;
    f.blob = std::move(blob);
    ParsedBlock   pb;
    BlockIdentity ident;
    if (parse_and_identify(f.blob, pb, ident) != BlockParseStatus::Ok) return f;
    f.id        = ident.id;
    f.nonce     = pb.header.nonce;
    f.prev_id   = pb.header.prev_id;
    f.tx_hashes = pb.tx_hashes;
    CoinbaseFields cb;
    if (parse_coinbase_fields(f.blob.data(), pb, cb)) f.height = cb.height;
    return f;
}

// The real 0-tx block, untouched.
BlockFixture empty_block_fixture() {
    return parse_fixture(bytes_from_hex(G2::BLOCKS[0].blob_hex));
}

// THE ONE SYNTHETIC STEP. A real 0-tx block blob ends with the varint tx count,
// which for zero transactions is the single byte 0x00. Replace that byte with
// varint(k) followed by k real transaction ids and the result is a structurally
// valid Monero block committing to transactions whose full bodies the tx-weight
// golden carries. Its block id changes (the tx list is inside the hashing blob,
// which is the point) and is recomputed, not assumed.
BlockFixture block_with_real_txs(std::size_t k) {
    std::vector<std::uint8_t> blob = bytes_from_hex(G2::BLOCKS[0].blob_hex);
    if (!blob.empty() && blob.back() == 0x00) blob.pop_back();

    std::vector<TxFixture> bodies;
    std::vector<std::uint8_t> tail;
    blob_write_varint(tail, static_cast<std::uint64_t>(k));
    for (std::size_t i = 0; i < k && i < GT::FULL_TX_COUNT; ++i) {
        TxFixture t;
        t.id   = hash_from_hex(GT::FULL_TXS[i].id_hex);
        t.blob = bytes_from_hex(GT::FULL_TXS[i].full_hex);
        tail.insert(tail.end(), t.id.begin(), t.id.end());
        bodies.push_back(std::move(t));
    }
    blob.insert(blob.end(), tail.begin(), tail.end());

    BlockFixture f = parse_fixture(std::move(blob));
    f.bodies       = std::move(bodies);
    return f;
}

// ---------------------------------------------------------------------------
// test doubles
// ---------------------------------------------------------------------------
struct Daemon {
    int  calls    = 0;
    bool armed    = true;
    bool accepts  = true;

    R::DaemonSubmitSink sink() {
        return [this](const BlockRelayRequest&) {
            ++calls;
            R::DaemonArmResult r;
            r.armed    = armed;
            r.accepted = armed && accepts;
            r.rejected = armed && !accepts;
            r.status   = r.accepted ? "OK" : "Block not accepted";
            return r;
        };
    }
};

struct LogSpy {
    std::vector<std::pair<bool, std::string>> lines;

    R::RelayLog sink() {
        return [this](bool err, const std::string& s) { lines.push_back({err, s}); };
    }
    bool has_error() const {
        for (const auto& l : lines) if (l.first) return true;
        return false;
    }
    bool error_mentions(const std::string& needle) const {
        for (const auto& l : lines)
            if (l.first && l.second.find(needle) != std::string::npos) return true;
        return false;
    }
    void clear() { lines.clear(); }
};

// A gate that records what it was shown.
struct GateSpy {
    int                       calls = 0;
    R::PowVerdict             verdict = R::PowVerdict::Accept;
    std::vector<std::uint8_t> last_hashing_blob;
    Hash                      last_id{};

    R::PowGate gate() {
        return [this](const BlockRelayRequest& req,
                      const std::vector<std::uint8_t>& hb) {
            ++calls;
            last_hashing_blob = hb;
            last_id           = req.block_id;
            return verdict;
        };
    }
};

void load_bodies(fakes::FakeMinerDataSource& src, const BlockFixture& f) {
    for (const TxFixture& t : f.bodies) src.bodies[body_key(t.id)] = t.blob;
}

BlockRelayRequest request_for(const BlockFixture& f) {
    BlockRelayRequest r;
    r.block_id   = f.id;
    r.height     = f.height;
    r.block_blob = f.blob;
    r.tx_hashes  = f.tx_hashes;
    r.nonce      = f.nonce;
    return r;
}

// Read back what this component produced, the way a peer would.
//
// C5 hands the transport a message BODY and the transport frames it
// (LevinLink::send_notify -> make_notify). So this helper frames the body the
// way C1 would and then parses the result. That order is deliberate: it is what
// catches a body that was ALREADY framed, because the re-framed buffer then
// carries a levin header where the epee storage signature should be and the
// parse fails. C5 shipped exactly that bug -- broadcast_notify was handed a
// complete frame -- and every Monero peer answered "portable_storage: wrong
// binary format - signature mismatch" while the peers-written count read
// perfectly. A fake port frames nothing, so nothing here could see it.
bool decode_frame(const std::vector<std::uint8_t>& body,
                  levin::BucketHead&               head,
                  levin::NewBlock&                 msg) {
    const std::vector<std::uint8_t> frame =
        levin::make_notify(levin::CMD_NEW_FLUFFY_BLOCK, body);
    levin::HeaderPolicy pol;
    pol.handshaked = true;
    levin::HeaderError herr = levin::HeaderError::None;
    if (!levin::read_header(frame.data(), frame.size(), pol, head, herr)) return false;
    if (frame.size() != levin::HEADER_SIZE + head.cb) return false;
    levin::MessageError merr = levin::MessageError::None;
    return levin::decode_new_fluffy_block(frame.data() + levin::HEADER_SIZE,
                                          static_cast<std::size_t>(head.cb), msg, merr);
}

// The body C5 produced must START with the epee portable_storage signature
// (01 11 01 01 | 01 01 02 01 | version), never with a levin bucket header
// (01 21 01 01 ...). One byte comparison, and it is the whole of the bug.
bool is_bare_epee_body(const std::vector<std::uint8_t>& body) {
    if (body.size() < 9) return false;
    const std::uint8_t want[9] = {0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01};
    for (int i = 0; i < 9; ++i)
        if (body[static_cast<std::size_t>(i)] != want[i]) return false;
    return true;
}

// ===========================================================================
// Z -- the fixtures are what they claim to be
// ===========================================================================
void suite_z() {
    std::printf("\n== Z: the fixtures ==\n");

    const BlockFixture empty = empty_block_fixture();
    CHECK(!empty.blob.empty(), "Z1  golden block blob decodes from hex (%zu bytes)",
          empty.blob.size());
    CHECK(empty.id == hash_from_hex(G2::BLOCKS[0].id_hex),
          "Z2  our block-id path reproduces monerod's id for height %llu",
          static_cast<unsigned long long>(G2::BLOCKS[0].height));
    CHECK(empty.height == G2::BLOCKS[0].height,
          "Z3  coinbase height %llu == the captured height",
          static_cast<unsigned long long>(empty.height));
    CHECK(empty.tx_hashes.empty(), "Z4  the base fixture carries no transactions");

    int matched = 0;
    for (std::size_t i = 0; i < GT::FULL_TX_COUNT; ++i) {
        const std::vector<std::uint8_t> blob = bytes_from_hex(GT::FULL_TXS[i].full_hex);
        TxWeightInfo info;
        if (parse_tx_full(blob, info) != TxParseStatus::Ok) continue;
        if (tx_hash_full(blob.data(), blob.size(), info) == hash_from_hex(GT::FULL_TXS[i].id_hex))
            ++matched;
    }
    CHECK(matched == static_cast<int>(GT::FULL_TX_COUNT),
          "Z5  all %zu full transaction bodies hash to monerod's ids (%d matched)",
          GT::FULL_TX_COUNT, matched);

    const BlockFixture three = block_with_real_txs(3);
    CHECK(three.tx_hashes.size() == 3, "Z6  the 3-tx fixture parses as a 3-tx block");
    CHECK(three.tx_hashes.size() == three.bodies.size() &&
              three.tx_hashes[0] == three.bodies[0].id &&
              three.tx_hashes[2] == three.bodies[2].id,
          "Z7  its tx list is exactly the three real transaction ids");
    CHECK(three.id != empty.id,
          "Z8  changing the tx list changed the block id (the list is inside the hash)");
    CHECK(three.height == empty.height && three.prev_id == empty.prev_id,
          "Z9  header, coinbase and parent are the real block's");
}

// ===========================================================================
// A -- the 2008 frame
// ===========================================================================
void suite_a() {
    std::printf("\n== A: the NOTIFY_NEW_FLUFFY_BLOCK frame ==\n");

    const BlockFixture f = empty_block_fixture();
    fakes::FakeBroadcastPort port;
    port.state_normal_peers = 4;
    fakes::FakeMinerDataSource bodies;
    Daemon daemon;
    GateSpy gate;

    R::LevinBlockRelay relay(port, daemon.sink(), &bodies, nullptr);
    relay.set_pow_gate(gate.gate());
    const BlockRelayVerdict v = relay.relay(request_for(f));

    CHECK(v.reached_network() && port.broadcasts.size() == 1,
          "A1  one frame was broadcast, verdict reached the network");
    CHECK(port.broadcasts[0].cmd == levin::CMD_NEW_FLUFFY_BLOCK,
          "A2  the broadcast command is 2008 (got %u)", port.broadcasts[0].cmd);

    levin::BucketHead head;
    levin::NewBlock   msg;
    const bool ok = decode_frame(port.broadcasts[0].bytes, head, msg);
    CHECK(ok, "A3  a peer can read the frame back with the C1a decoder");
    CHECK(is_bare_epee_body(port.broadcasts[0].bytes),
          "A3b the port was handed a BARE epee body, not an already-framed 2008 "
          "(the transport adds the levin header; a doubly-framed notify is a "
          "signature mismatch at every Monero peer)");
    CHECK(head.command == 2008 && levin::classify(head) == levin::FrameClass::Notify,
          "A4  the levin header says command 2008, class Notify (no answer owed)");
    CHECK(head.return_code == 0 && head.protocol_version == levin::PROTOCOL_VER_1,
          "A5  return_code 0, protocol version 1");
    CHECK(msg.b.block_blob == f.blob, "A6  the block blob round-trips byte for byte");
    CHECK(!msg.b.pruned && msg.b.txs.empty(),
          "A7  a 0-tx block carries no bodies and is not marked pruned");
    CHECK(msg.current_blockchain_height == f.height + 1,
          "A8  current_blockchain_height is H+1 = %llu (rule 6: we are ahead)",
          static_cast<unsigned long long>(f.height + 1));

    // Self-contained: bodies included, so the peer never needs the 2009 trip.
    const BlockFixture t = block_with_real_txs(3);
    fakes::FakeBroadcastPort port2;
    port2.state_normal_peers = 7;
    fakes::FakeMinerDataSource bodies2;
    load_bodies(bodies2, t);
    R::LevinBlockRelay relay2(port2, daemon.sink(), &bodies2, nullptr);
    relay2.set_pow_gate(gate.gate());
    const BlockRelayVerdict v2 = relay2.relay(request_for(t));

    CHECK(v2.p2p_peers_sent == 7, "A9  the verdict reports the peers written to (7)");
    levin::NewBlock msg2;
    levin::BucketHead head2;
    CHECK(decode_frame(port2.broadcasts.at(0).bytes, head2, msg2) && msg2.b.txs.size() == 3,
          "A10 the self-contained frame carries all three bodies");
    bool bodies_exact = msg2.b.txs.size() == 3;
    for (std::size_t i = 0; bodies_exact && i < 3; ++i)
        bodies_exact = (msg2.b.txs[i].blob == t.bodies[i].blob) && !msg2.b.txs[i].pruned;
    CHECK(bodies_exact, "A11 each body is the real blob, full (not pruned), in block order");
    CHECK(t.bodies[0].blob != t.bodies[1].blob,
          "A12 (non-vacuity) the three bodies are not the same bytes");

    // monerod's own shape, for the parity run.
    R::RelayConfig cfg;
    cfg.policy.include_all_tx_bodies = false;
    fakes::FakeBroadcastPort port3;
    port3.state_normal_peers = 2;
    fakes::FakeMinerDataSource bodies3;
    load_bodies(bodies3, t);
    R::LevinBlockRelay relay3(port3, daemon.sink(), &bodies3, nullptr, cfg);
    relay3.set_pow_gate(gate.gate());
    relay3.relay(request_for(t));
    levin::NewBlock msg3;
    levin::BucketHead head3;
    CHECK(decode_frame(port3.broadcasts.at(0).bytes, head3, msg3) &&
              msg3.b.txs.empty() && msg3.b.block_blob == t.blob,
          "A13 include_all_tx_bodies=false mirrors monerod: block only, txs empty");
}

// ===========================================================================
// B -- the two arms
// ===========================================================================
void suite_b() {
    std::printf("\n== B: dual-arm order ==\n");

    const BlockFixture f = empty_block_fixture();
    GateSpy gate;

    {   // Parallel (the default): P2P first, daemon behind it.
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 5;
        fakes::FakeMinerDataSource bodies;
        Daemon d;
        R::LevinBlockRelay relay(port, d.sink(), &bodies, nullptr);
        relay.set_pow_gate(gate.gate());
        const BlockRelayVerdict v = relay.relay(request_for(f));
        CHECK(v.p2p_peers_sent == 5 && v.daemon_accepted && d.calls == 1,
              "B1  Parallel: both arms fired");
        CHECK(v.landed_first == "p2p",
              "B2  Parallel: the P2P arm is first (daemonless-primary), got '%s'",
              v.landed_first.c_str());
    }
    {   // Parallel with a rejecting daemon: P2P is NOT suppressed.
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 3;
        fakes::FakeMinerDataSource bodies;
        Daemon d; d.accepts = false;
        R::LevinBlockRelay relay(port, d.sink(), &bodies, nullptr);
        relay.set_pow_gate(gate.gate());
        const BlockRelayVerdict v = relay.relay(request_for(f));
        CHECK(v.p2p_peers_sent == 3 && v.daemon_rejected && v.reached_network(),
              "B3  Parallel: a rejecting daemon does not gate the P2P arm");
    }
    {   // DaemonFirst + reject: the block never touches P2P.
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 9;
        fakes::FakeMinerDataSource bodies;
        Daemon d; d.accepts = false;
        LogSpy log;
        R::RelayConfig cfg; cfg.policy.order = ArmOrder::DaemonFirst;
        R::LevinBlockRelay relay(port, d.sink(), &bodies, nullptr, cfg, log.sink());
        relay.set_pow_gate(gate.gate());
        const BlockRelayVerdict v = relay.relay(request_for(f));
        CHECK(port.broadcasts.empty() && v.p2p_peers_sent == 0,
              "B4  DaemonFirst: a daemon rejection suppresses the P2P arm entirely");
        CHECK(!v.reached_network() && !v.why.empty() && log.has_error(),
              "B5  DaemonFirst: and that is reported as a loud failure");
    }
    {   // DaemonFirst + accept: P2P follows.
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 6;
        fakes::FakeMinerDataSource bodies;
        Daemon d;
        R::RelayConfig cfg; cfg.policy.order = ArmOrder::DaemonFirst;
        R::LevinBlockRelay relay(port, d.sink(), &bodies, nullptr, cfg);
        relay.set_pow_gate(gate.gate());
        const BlockRelayVerdict v = relay.relay(request_for(f));
        CHECK(v.p2p_peers_sent == 6 && v.landed_first == "daemon",
              "B6  DaemonFirst: acceptance lets the P2P arm add its own peers");
    }
    {   // P2pOnly: the daemon is never asked.
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 2;
        fakes::FakeMinerDataSource bodies;
        Daemon d;
        R::RelayConfig cfg; cfg.policy.order = ArmOrder::P2pOnly;
        R::LevinBlockRelay relay(port, d.sink(), &bodies, nullptr, cfg);
        relay.set_pow_gate(gate.gate());
        const BlockRelayVerdict v = relay.relay(request_for(f));
        CHECK(d.calls == 0 && v.p2p_peers_sent == 2 && !v.daemon_armed,
              "B7  P2pOnly: the daemon arm is not called and not claimed");
    }
    {   // Daemonless: no sink at all is 'not armed', never 'rejected'.
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 4;
        fakes::FakeMinerDataSource bodies;
        R::LevinBlockRelay relay(port, R::DaemonSubmitSink{}, &bodies, nullptr);
        relay.set_pow_gate(gate.gate());
        const BlockRelayVerdict v = relay.relay(request_for(f));
        CHECK(!v.daemon_armed && !v.daemon_rejected && v.p2p_peers_sent == 4,
              "B8  no daemon configured: armed=false, rejected=false, P2P carries it");
    }
}

// ===========================================================================
// C -- never a silent drop
// ===========================================================================
void suite_c() {
    std::printf("\n== C: never a silent drop ==\n");

    const BlockFixture f = empty_block_fixture();
    GateSpy gate;
    {
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 0;   // nobody
        fakes::FakeMinerDataSource bodies;
        LogSpy log;
        R::LevinBlockRelay relay(port, R::DaemonSubmitSink{}, &bodies, nullptr,
                                 R::RelayConfig{}, log.sink());
        relay.set_pow_gate(gate.gate());
        const BlockRelayVerdict v = relay.relay(request_for(f));
        CHECK(!v.reached_network(), "C1  zero peers and no daemon: reached_network() is false");
        CHECK(v.why.find(hex_of(f.id)) != std::string::npos,
              "C2  the verdict names the block that was lost");
        CHECK(log.error_mentions("RELAY FAILED"),
              "C3  and it is logged at error level, not shrugged off");
        CHECK(relay.stats().reached_nobody == 1, "C4  the loud-failure counter moved");
    }
    {
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 0;
        fakes::FakeMinerDataSource bodies;
        Daemon d; d.accepts = false;
        R::LevinBlockRelay relay(port, d.sink(), &bodies, nullptr);
        relay.set_pow_gate(gate.gate());
        const BlockRelayVerdict v = relay.relay(request_for(f));
        CHECK(!v.reached_network() && !v.why.empty(),
              "C5  zero peers and a rejecting daemon is also a failure with a reason");
    }
    {
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 1;
        fakes::FakeMinerDataSource bodies;
        Daemon d;
        R::LevinBlockRelay relay(port, d.sink(), &bodies, nullptr);
        relay.set_pow_gate(gate.gate());
        const BlockRelayVerdict v = relay.relay(request_for(f));
        CHECK(v.reached_network() && v.why.empty(),
              "C6  (non-vacuity) a relay that worked leaves `why` empty");
    }
}

// ===========================================================================
// D -- the RandomX gate is the only door
// ===========================================================================
void suite_d() {
    std::printf("\n== D: the 128-bit RandomX gate ==\n");

    const BlockFixture f = empty_block_fixture();
    {   // No gate at all.
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 8;
        fakes::FakeMinerDataSource bodies;
        Daemon d;
        R::LevinBlockRelay relay(port, d.sink(), &bodies, nullptr);
        const BlockRelayVerdict v = relay.relay(request_for(f));
        CHECK(port.broadcasts.empty() && d.calls == 0 && !v.reached_network(),
              "D1  no gate installed: NEITHER arm fires (fail-closed)");
        CHECK(relay.last_reject() == R::RelayReject::PowNotAccepted &&
                  v.why.find("randomx") != std::string::npos,
              "D2  and the refusal names the gate");
    }
    for (const R::PowVerdict bad : {R::PowVerdict::BelowTarget,
                                    R::PowVerdict::SeedNotResident,
                                    R::PowVerdict::Malformed,
                                    R::PowVerdict::Unavailable}) {
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 8;
        fakes::FakeMinerDataSource bodies;
        Daemon d;
        GateSpy gate; gate.verdict = bad;
        R::LevinBlockRelay relay(port, d.sink(), &bodies, nullptr);
        relay.set_pow_gate(gate.gate());
        relay.relay(request_for(f));
        CHECK(port.broadcasts.empty() && d.calls == 0,
              "D3  gate verdict %s: nothing goes out", R::to_string(bad));
    }
    {   // The gate sees the hashing blob of the bytes actually being sent.
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 1;
        fakes::FakeMinerDataSource bodies;
        GateSpy gate;
        R::LevinBlockRelay relay(port, R::DaemonSubmitSink{}, &bodies, nullptr);
        relay.set_pow_gate(gate.gate());
        relay.relay(request_for(f));
        ParsedBlock pb; BlockIdentity ident;
        parse_and_identify(f.blob, pb, ident);
        CHECK(gate.calls == 1 && gate.last_hashing_blob == ident.hashing_blob,
              "D4  the gate is shown the hashing blob recomputed from those exact bytes");
    }
    {   // The attestation form.
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 3;
        fakes::FakeMinerDataSource bodies;
        R::LevinBlockRelay relay(port, R::DaemonSubmitSink{}, &bodies, nullptr);
        const BlockRelayVerdict good =
            relay.relay_with_gate(request_for(f), R::pow_attestation(f.id));
        CHECK(good.reached_network(), "D5  an attestation for THIS block relays it");

        Hash other = f.id;
        other[0] ^= 0xff;
        fakes::FakeBroadcastPort port2;  port2.state_normal_peers = 3;
        R::LevinBlockRelay relay2(port2, R::DaemonSubmitSink{}, &bodies, nullptr);
        const BlockRelayVerdict bad =
            relay2.relay_with_gate(request_for(f), R::pow_attestation(other));
        CHECK(!bad.reached_network() && port2.broadcasts.empty(),
              "D6  an attestation for a DIFFERENT block relays nothing");
    }
}

// ===========================================================================
// E -- structural refusals
// ===========================================================================
void suite_e() {
    std::printf("\n== E: structural refusals ==\n");

    const BlockFixture f = empty_block_fixture();
    GateSpy gate;

    auto run = [&](BlockRelayRequest req, const char* what, R::RelayReject want) {
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 8;
        fakes::FakeMinerDataSource bodies;
        Daemon d;
        R::LevinBlockRelay relay(port, d.sink(), &bodies, nullptr);
        relay.set_pow_gate(gate.gate());
        const BlockRelayVerdict v = relay.relay(req);
        CHECK(port.broadcasts.empty() && d.calls == 0 && !v.reached_network() &&
                  relay.last_reject() == want,
              "E   %s -> %s, no arm fired", what, R::to_string(want));
    };

    { BlockRelayRequest r = request_for(f); r.block_blob.clear();
      run(r, "empty blob", R::RelayReject::EmptyBlob); }
    { BlockRelayRequest r = request_for(f); r.block_blob.assign(40, 0xab);
      run(r, "garbage blob", R::RelayReject::Unparseable); }
    { BlockRelayRequest r = request_for(f); r.block_id[7] ^= 0x01;
      run(r, "id the blob does not hash to", R::RelayReject::IdMismatch); }
    { BlockRelayRequest r = request_for(f); r.tx_hashes.push_back(Hash{});
      run(r, "tx list the blob does not commit to", R::RelayReject::TxListMismatch); }
    { BlockRelayRequest r = request_for(f); r.nonce = f.nonce + 1;
      run(r, "winning nonce not patched into the blob", R::RelayReject::NonceMismatch); }
    { BlockRelayRequest r = request_for(f); r.height = f.height + 5;
      run(r, "height the coinbase does not claim", R::RelayReject::HeightMismatch); }

    // The gate never even runs for a structurally broken block.
    fakes::FakeBroadcastPort port;
    fakes::FakeMinerDataSource bodies;
    GateSpy g2;
    R::LevinBlockRelay relay(port, R::DaemonSubmitSink{}, &bodies, nullptr);
    relay.set_pow_gate(g2.gate());
    BlockRelayRequest r = request_for(f);
    r.block_blob.assign(9, 0x00);
    relay.relay(r);
    CHECK(g2.calls == 0, "E7  RandomX is not spent on a blob that is not a block");
}

// ===========================================================================
// F -- fail loud on a partial block (DASH rule 5)
// ===========================================================================
void suite_f() {
    std::printf("\n== F: never emit a partial block ==\n");

    const BlockFixture t = block_with_real_txs(3);
    GateSpy gate;
    {   // One body missing, daemon armed.
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 5;
        fakes::FakeMinerDataSource bodies;
        load_bodies(bodies, t);
        bodies.bodies.erase(body_key(t.bodies[1].id));      // the hole
        Daemon d;
        LogSpy log;
        R::LevinBlockRelay relay(port, d.sink(), &bodies, nullptr, R::RelayConfig{}, log.sink());
        relay.set_pow_gate(gate.gate());
        const BlockRelayVerdict v = relay.relay(request_for(t));
        CHECK(port.broadcasts.empty() && v.p2p_peers_sent == 0,
              "F1  a missing body suppresses the P2P arm entirely");
        CHECK(v.daemon_accepted && v.reached_network(),
              "F2  the daemon arm still fires (monerod has its own pool)");
        CHECK(relay.stats().partial_block == 1 && log.error_mentions("incomplete block"),
              "F3  it is counted and logged, not silently degraded");
    }
    {   // Same, daemonless: now it is a lost block and must be loud.
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 5;
        fakes::FakeMinerDataSource bodies;
        load_bodies(bodies, t);
        bodies.bodies.erase(body_key(t.bodies[0].id));
        R::LevinBlockRelay relay(port, R::DaemonSubmitSink{}, &bodies, nullptr);
        relay.set_pow_gate(gate.gate());
        const BlockRelayVerdict v = relay.relay(request_for(t));
        CHECK(!v.reached_network() && v.why.find("incomplete") != std::string::npos,
              "F4  daemonless + missing body = a loud failure naming the cause");
    }
    {   // A body filed under the wrong id: the re-hash is what catches it.
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 5;
        fakes::FakeMinerDataSource bodies;
        load_bodies(bodies, t);
        bodies.bodies[body_key(t.bodies[2].id)] = t.bodies[0].blob;   // right shape, wrong tx
        R::LevinBlockRelay relay(port, R::DaemonSubmitSink{}, &bodies, nullptr);
        relay.set_pow_gate(gate.gate());
        const BlockRelayVerdict v = relay.relay(request_for(t));
        CHECK(port.broadcasts.empty() && !v.reached_network(),
              "F5  a body that does not hash to its id is caught before the wire");

        R::RelayConfig off; off.verify_tx_bodies = false;
        fakes::FakeBroadcastPort port2;  port2.state_normal_peers = 5;
        R::LevinBlockRelay relay2(port2, R::DaemonSubmitSink{}, &bodies, nullptr, off);
        relay2.set_pow_gate(gate.gate());
        const BlockRelayVerdict v2 = relay2.relay(request_for(t));
        CHECK(v2.reached_network() && port2.broadcasts.size() == 1,
              "F6  (non-vacuity) with verify_tx_bodies off the same block goes out --"
              " the re-hash is what caught it");
    }
    {   // No body source wired at all, for a block that needs bodies.
        fakes::FakeBroadcastPort port;  port.state_normal_peers = 5;
        R::LevinBlockRelay relay(port, R::DaemonSubmitSink{}, nullptr, nullptr);
        relay.set_pow_gate(gate.gate());
        const BlockRelayVerdict v = relay.relay(request_for(t));
        CHECK(port.broadcasts.empty() && !v.reached_network(),
              "F7  no body source and a block with transactions: nothing goes out");
    }
}

// ===========================================================================
// G -- answering 2009
// ===========================================================================
void suite_g() {
    std::printf("\n== G: REQUEST_FLUFFY_MISSING_TX (2009) ==\n");

    const BlockFixture t = block_with_real_txs(3);
    GateSpy gate;
    std::uint64_t clock = 1000;

    fakes::FakeBroadcastPort port;  port.state_normal_peers = 3;
    fakes::FakeMinerDataSource bodies;
    load_bodies(bodies, t);
    R::LevinBlockRelay relay(port, R::DaemonSubmitSink{}, &bodies, nullptr);
    relay.set_pow_gate(gate.gate());
    relay.set_clock([&clock] { return clock; });

    CHECK(static_cast<bool>(port.fluffy_handler),
          "G1  the 2009 handler is installed on the broadcast port at construction");

    relay.relay(request_for(t));
    CHECK(relay.knows(t.id) && relay.retained_count() == 1,
          "G2  the announced block is retained for serving");

    std::vector<std::uint8_t> reply;
    const bool served = port.fluffy_handler(PeerRef{7, "10.0.0.7:18080", 0}, t.id,
                                            t.height + 1, {0, 2}, reply);
    levin::BucketHead head;
    levin::NewBlock   msg;
    CHECK(served && decode_frame(reply, head, msg) && head.command == 2008,
          "G3  the reply is another 2008 frame");
    CHECK(msg.b.txs.size() == 2 && msg.b.txs[0].blob == t.bodies[0].blob &&
              msg.b.txs[1].blob == t.bodies[2].blob,
          "G4  it carries exactly the requested bodies, in the requested order");
    CHECK(msg.b.block_blob == t.blob && msg.current_blockchain_height == t.height + 1,
          "G5  with the block itself and our height");

    std::vector<std::uint8_t> junk;
    CHECK(!relay.on_request_fluffy_missing_tx(t.id, {0, 99}, junk) && junk.empty(),
          "G6  an out-of-range index is declined, not clamped");
    Hash unknown{}; unknown[0] = 0xaa;
    CHECK(!relay.on_request_fluffy_missing_tx(unknown, {0}, junk),
          "G7  a block we never announced is declined");
    CHECK(!relay.on_request_fluffy_missing_tx(t.id, {}, junk),
          "G8  an empty index list is declined");

    clock += 3600;   // exactly the retention window
    CHECK(relay.on_request_fluffy_missing_tx(t.id, {1}, junk),
          "G9  (non-vacuity) still served at the retention boundary");
    clock += 1;
    CHECK(!relay.on_request_fluffy_missing_tx(t.id, {1}, junk) && !relay.knows(t.id),
          "G10 past the retention window the book has forgotten it");

    R::RelayConfig off; off.policy.serve_missing_tx = false;
    fakes::FakeBroadcastPort port2;
    R::LevinBlockRelay relay2(port2, R::DaemonSubmitSink{}, &bodies, nullptr, off);
    CHECK(!static_cast<bool>(port2.fluffy_handler) &&
              !relay2.on_request_fluffy_missing_tx(t.id, {0}, junk),
          "G11 serve_missing_tx=false installs no handler and answers nothing");
}

// ===========================================================================
// H -- the c2pool redundant-broadcast carrier
// ===========================================================================
void suite_h() {
    std::printf("\n== H: the xmr_found_block carrier ==\n");

    const BlockFixture t = block_with_real_txs(3);

    R::FoundBlockCarrier c;
    c.height                 = t.height;
    c.block_id               = t.id;
    c.full_blob              = t.blob;
    c.nonce                  = t.nonce;
    c.extra_nonce            = 0x1234abcd;
    c.inputs.chain_id        = hash_from_hex(G2::BLOCKS[1].id_hex);
    c.inputs.lane_commitment = hash_from_hex(G2::BLOCKS[2].id_hex);
    c.inputs.reward          = 600030400000ull;
    c.inputs.ledger_seq      = 42;
    c.origin_node_id         = hash_from_hex(G2::BLOCKS[3].id_hex);

    const std::vector<std::uint8_t> wire = R::encode_found_block(c);
    R::FoundBlockCarrier back;
    R::CarrierWireError werr = R::CarrierWireError::None;
    CHECK(R::decode_found_block(wire, back, werr) && werr == R::CarrierWireError::None,
          "H1  the carrier decodes (%zu bytes on the wire)", wire.size());
    CHECK(back.height == c.height && back.block_id == c.block_id &&
              back.full_blob == c.full_blob && back.nonce == c.nonce &&
              back.extra_nonce == c.extra_nonce &&
              back.inputs.chain_id == c.inputs.chain_id &&
              back.inputs.lane_commitment == c.inputs.lane_commitment &&
              back.inputs.reward == c.inputs.reward &&
              back.inputs.ledger_seq == c.inputs.ledger_seq &&
              back.origin_node_id == c.origin_node_id,
          "H2  every field round-trips");

    std::vector<std::uint8_t> cut(wire.begin(), wire.end() - 1);
    CHECK(!R::decode_found_block(cut, back, werr) && werr == R::CarrierWireError::Truncated,
          "H3  a truncated carrier is Truncated, not a short read");
    std::vector<std::uint8_t> ver = wire;  ver[0] = 9;
    CHECK(!R::decode_found_block(ver, back, werr) && werr == R::CarrierWireError::BadVersion,
          "H4  an unknown wire version is refused");
    std::vector<std::uint8_t> big = wire;
    for (int i = 0; i < 4; ++i) big[1 + 8 + 32 + static_cast<std::size_t>(i)] = 0xff;
    CHECK(!R::decode_found_block(big, back, werr) && werr == R::CarrierWireError::Oversize,
          "H5  an oversize length claim is refused before anything is allocated");

    // --- the admission ladder ---------------------------------------------
    fakes::FakeChain chain;
    {
        node::ChainMainBlock tip;
        tip.height = t.height - 1;
        tip.id     = t.prev_id;
        chain.rows.push_back(tip);
    }

    fakes::FakeBroadcastPort port;  port.state_normal_peers = 4;
    fakes::FakeMinerDataSource bodies;
    load_bodies(bodies, t);
    GateSpy relay_gate;
    R::LevinBlockRelay core(port, R::DaemonSubmitSink{}, &bodies, nullptr);
    core.set_pow_gate(relay_gate.gate());

    // `wire_dedup` is opt-in: only the duplicate case asks the relay's own book,
    // because every later case deliberately re-sends the block the first case
    // already relayed and must be judged on its own merits, not deduplicated.
    auto make_ingress = [&](GateSpy& g, bool coinbase_ok, bool wire_dedup = false) {
        R::FoundBlockIngress in(core, &chain);
        in.set_pow_gate(g.gate());
        in.set_coinbase_check([coinbase_ok](const R::FoundBlockCarrier&, const ParsedBlock&,
                                            const std::uint8_t*, std::string& why) {
            if (!coinbase_ok) why = "coinbase is not the canonical settlement";
            return coinbase_ok;
        });
        if (wire_dedup) in.set_already_relayed([&](const Hash& id) { return core.knows(id); });
        return in;
    };

    const PeerRef peer{11, "203.0.113.9:18080", 64512};
    {
        GateSpy g;
        R::FoundBlockIngress in = make_ingress(g, true, /*wire_dedup=*/true);
        const R::CarrierOutcome o = in.on_carrier(peer, c);
        CHECK(o.verdict == R::CarrierVerdict::Relayed && o.relay.p2p_peers_sent == 4,
              "H6  a good carrier is relayed under OUR arms (%s)", R::to_string(o.verdict));
        CHECK(g.calls == 1, "H7  RandomX was spent exactly once");

        const R::CarrierOutcome dup = in.on_carrier(peer, c);
        CHECK(dup.verdict == R::CarrierVerdict::Duplicate && g.calls == 1,
              "H8  the same block again is a Duplicate and costs no RandomX");
    }
    {   // Every cheap rejection must happen BEFORE RandomX.
        GateSpy g;
        R::FoundBlockIngress in = make_ingress(g, true);
        R::FoundBlockCarrier bad = c;  bad.block_id[3] ^= 0x40;
        const R::CarrierOutcome o = in.on_carrier(peer, bad);
        CHECK(o.verdict == R::CarrierVerdict::IdMismatch && o.ban && g.calls == 0,
              "H9  a forged id: ban, and RandomX never runs");
    }
    {
        GateSpy g;
        R::FoundBlockIngress in = make_ingress(g, true);
        R::FoundBlockCarrier bad = c;  bad.height += 1;
        const R::CarrierOutcome o = in.on_carrier(peer, bad);
        CHECK(o.verdict == R::CarrierVerdict::HeightMismatch && o.ban && g.calls == 0,
              "H10 a height the coinbase does not claim: ban, no RandomX");
    }
    {
        GateSpy g;
        fakes::FakeChain other;
        node::ChainMainBlock tip;  tip.height = 99; tip.id = hash_from_hex(G2::BLOCKS[4].id_hex);
        other.rows.push_back(tip);
        R::FoundBlockIngress foreign(core, &other);
        foreign.set_pow_gate(g.gate());
        foreign.set_coinbase_check([](const R::FoundBlockCarrier&, const ParsedBlock&,
                                      const std::uint8_t*, std::string&) { return true; });
        const R::CarrierOutcome o = foreign.on_carrier(peer, c);
        CHECK(o.verdict == R::CarrierVerdict::ForeignBranch && !o.ban && o.defer &&
                  foreign.pow_calls() == 0,
              "H11 a block off our tip is DEFERRED, never banned, and costs no RandomX");
    }
    {
        GateSpy g;
        R::FoundBlockIngress in = make_ingress(g, false);
        const R::CarrierOutcome o = in.on_carrier(peer, c);
        CHECK(o.verdict == R::CarrierVerdict::CoinbaseMismatch && o.ban && g.calls == 0,
              "H12 a non-canonical coinbase: ban, and still no RandomX");
    }
    {   // No coinbase check wired: refuse to relay blind, but do not blame the peer.
        GateSpy g;
        R::FoundBlockIngress blind(core, &chain);
        blind.set_pow_gate(g.gate());
        const R::CarrierOutcome o = blind.on_carrier(peer, c);
        CHECK(o.verdict == R::CarrierVerdict::CoinbaseMismatch && !o.ban && o.defer &&
                  g.calls == 0,
              "H13 no canonical-coinbase check wired: we refuse, and it is OUR gap");
    }
    {
        GateSpy g;  g.verdict = R::PowVerdict::BelowTarget;
        R::FoundBlockIngress in = make_ingress(g, true);
        const R::CarrierOutcome o = in.on_carrier(peer, c);
        CHECK(o.verdict == R::CarrierVerdict::PowRejected && o.ban && g.calls == 1,
              "H14 RandomX below target: forged, ban");
    }
    for (const R::PowVerdict ours : {R::PowVerdict::SeedNotResident, R::PowVerdict::Unavailable}) {
        GateSpy g;  g.verdict = ours;
        R::FoundBlockIngress in = make_ingress(g, true);
        const R::CarrierOutcome o = in.on_carrier(peer, c);
        CHECK(o.verdict == R::CarrierVerdict::PowDeferred && !o.ban && o.defer,
              "H15 RandomX %s is OUR fault: defer, never ban", R::to_string(ours));
    }
    {   // The per-peer budget.
        GateSpy g;
        R::CarrierConfig cfg;  cfg.max_per_peer_per_window = 2;
        R::FoundBlockIngress in(core, &chain, cfg);
        in.set_pow_gate(g.gate());
        in.set_coinbase_check([](const R::FoundBlockCarrier&, const ParsedBlock&,
                                 const std::uint8_t*, std::string&) { return false; });
        in.on_carrier(peer, c);
        in.on_carrier(peer, c);
        const R::CarrierOutcome third = in.on_carrier(peer, c);
        CHECK(third.verdict == R::CarrierVerdict::BudgetExceeded,
              "H16 a peer over its carrier budget is cut off before the bytes are read");
        const R::CarrierOutcome other = in.on_carrier(PeerRef{12, "198.51.100.4:18080", 0}, c);
        CHECK(other.verdict != R::CarrierVerdict::BudgetExceeded,
              "H17 (non-vacuity) the budget is per peer, not global");
    }
}

// ===========================================================================
// I -- our own tip (PREFER-OWN)
// ===========================================================================
void suite_i() {
    std::printf("\n== I: our own index ==\n");

    const BlockFixture t = block_with_real_txs(3);
    fakes::FakeBroadcastPort port;  port.state_normal_peers = 2;
    fakes::FakeMinerDataSource bodies;
    load_bodies(bodies, t);
    fakes::FakeChain chain;
    GateSpy gate;

    R::LevinBlockRelay relay(port, R::DaemonSubmitSink{}, &bodies, &chain);
    relay.set_pow_gate(gate.gate());
    relay.relay(request_for(t));

    CHECK(chain.own_blocks.size() == 1 && chain.own_blocks[0].block_blob == t.blob,
          "I1  the block we relayed was handed to our own index");
    CHECK(chain.own_blocks[0].txs.size() == 3 && !chain.own_blocks[0].pruned,
          "I2  with its full bodies attached");

    // A refusing index must not make the relay lie about the network.
    fakes::FakeChain grumpy;  grumpy.accept_own_block = false;
    fakes::FakeBroadcastPort port2;  port2.state_normal_peers = 2;
    LogSpy log;
    R::LevinBlockRelay relay2(port2, R::DaemonSubmitSink{}, &bodies, &grumpy,
                              R::RelayConfig{}, log.sink());
    relay2.set_pow_gate(gate.gate());
    const BlockRelayVerdict v = relay2.relay(request_for(t));
    CHECK(v.reached_network() && grumpy.own_blocks.empty(),
          "I3  an index that refuses our block does not un-relay it");
}

// ===========================================================================
// J -- the BlockCandidate bridge (the plan's relay(candidate, nonce, extra))
// ===========================================================================
void suite_j() {
    std::printf("\n== J: the BlockCandidate bridge ==\n");

    const BlockFixture t = block_with_real_txs(3);
    ParsedBlock pb; BlockIdentity ident;
    parse_and_identify(t.blob, pb, ident);

    // Rebuild the candidate the template layer would have produced: the same
    // blobs with the nonce field zeroed, exactly as they are served.
    submit::BlockCandidate cand;
    cand.height       = t.height;
    cand.nonce_offset = pb.header_size - 4;
    cand.full_blob    = t.blob;
    cand.hashing_blob = ident.hashing_blob;
    for (int i = 0; i < 4; ++i) {
        cand.full_blob[cand.nonce_offset + static_cast<std::size_t>(i)]    = 0;
        cand.hashing_blob[cand.nonce_offset + static_cast<std::size_t>(i)] = 0;
    }

    const BlockRelayRequest req = R::to_relay_request(cand, t.nonce, 0);
    CHECK(req.block_blob == t.blob,
          "J1  the bridge patches the winning nonce back into the exact block bytes");
    CHECK(req.block_id == t.id,
          "J2  and derives the block id the native path derives (%s)",
          hex_of(t.id).substr(0, 16).c_str());
    CHECK(req.height == t.height && req.nonce == t.nonce,
          "J3  height and nonce carry through");

    fakes::FakeBroadcastPort port;  port.state_normal_peers = 6;
    fakes::FakeMinerDataSource bodies;
    load_bodies(bodies, t);
    R::LevinBlockRelay core(port, R::DaemonSubmitSink{}, &bodies, nullptr);
    R::CandidateBlockRelay bridge(core);

    const BlockRelayVerdict refused = bridge.relay(cand, t.nonce, 0, /*pow_accepted=*/false);
    CHECK(!refused.reached_network() && port.broadcasts.empty(),
          "J4  pow_accepted=false relays nothing");

    const BlockRelayVerdict ok = bridge.relay(cand, t.nonce, 0, /*pow_accepted=*/true);
    CHECK(ok.reached_network() && ok.p2p_peers_sent == 6 && ok.block_id == t.id,
          "J5  pow_accepted=true relays it under an attestation for that id");

    // A candidate with no hashing blob cannot be attested, so it cannot go out.
    submit::BlockCandidate blind = cand;
    blind.hashing_blob.clear();
    fakes::FakeBroadcastPort port2;  port2.state_normal_peers = 6;
    R::LevinBlockRelay core2(port2, R::DaemonSubmitSink{}, &bodies, nullptr);
    R::CandidateBlockRelay bridge2(core2);
    const BlockRelayVerdict nb = bridge2.relay(blind, t.nonce, 0, true);
    CHECK(!nb.reached_network() && port2.broadcasts.empty(),
          "J6  a candidate with no served hashing blob has nothing to attest: refused");
}

} // namespace

int main() {
    std::printf("xmr_native_block_relay_kat -- C5 dual-arm found-block relay\n");
    std::printf("fixtures: monerod %s %s, blocks at %llu.., full txs from tip %llu\n",
                G2::MONEROD_VERSION, G2::NETWORK,
                static_cast<unsigned long long>(G2::BLOCKS[0].height),
                static_cast<unsigned long long>(GT::CAPTURE_TIP));

    suite_z();
    suite_a();
    suite_b();
    suite_c();
    suite_d();
    suite_e();
    suite_f();
    suite_g();
    suite_h();
    suite_i();
    suite_j();

    std::printf("\n%d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
