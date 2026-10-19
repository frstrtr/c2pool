// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_relay_pool_id_kat -- the C23 pool identity in the Path B HELLO head (impl/xmr/pathb/pathb_hello.hpp)
// and the Path B relay node's refusal of another pool:
//   P1  wire: the head carries pool_id = pool_id_of(network, chain_id, pool_genesis) at bytes [11, 43) and the
//       frame round-trips; the pool_id moves with the network, the chain_id, the derived genesis (block hash,
//       headline) and the raw genesis; pathb_hello_check refuses another network / chain_id / pool_id as
//       TAG_MISMATCH naming the field with both values, and accepts the same identity
//   P2  live: three loopback Path B relay nodes; A and B of one pool, X of another (B dials A, X dials A and B):
//       A and B link, X ends with no ready link; the refusal "TAG_MISMATCH field=pool_id" is logged by A, B and X
//       and counted (hello_tag_mismatch) on each
//   P3  nothing crosses: a carrier mined at X never reaches A or B; a carrier mined at A reaches B
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

#include "xmr_pathb_relay_test_util.hpp"
#include "impl/xmr/pathb/pathb_pool_identity.hpp"

using namespace pathb_relay_test;
using namespace std::chrono_literals;

static void p1_wire(Checker& C) {
    std::printf("-- P1 the C23 pool identity in the Path B HELLO head\n");
    pb::GenesisSpec g;
    g.height = 3000000;
    g.block_hash = pk::seq32(0x21);
    g.headline = "pool one";
    const pb::PoolIdentity id = pb::identity_derived(pb::LaneNet::Stagenet, 0, g);
    C(id.pool_id == pb::pool_id_of(pb::LaneNet::Stagenet, 0, pb::pool_genesis_derived(g.block_hash, g.headline)),
      "P1 the derived identity's pool_id = pool_id_of(network, chain_id, pool_genesis_derived(hash, headline))");

    Rig rig;
    std::unique_ptr<RNode> a = rig.make("A", Rig::opts(false));
    pb::PathbHello h = a->r().with_node([](pb::PathbNode& n) { return n.our_hello(0x1111, 4242); });
    h.network = static_cast<std::uint8_t>(id.network);
    h.chain_id = id.chain_id;
    h.pool_id = id.pool_id;
    const std::optional<std::vector<u8>> f = pb::encode_pathb_hello(h);
    C(f && f->size() >= 43 && std::equal(id.pool_id.begin(), id.pool_id.end(), f->begin() + 11),
      "P1 the head carries the pool_id at bytes [11, 43)");
    const pb::PathbHelloDecode d = f ? pb::decode_pathb_hello(*f) : pb::PathbHelloDecode{};
    C(f && d.error == pb::HelloError::None && d.hello == h, "P1 the frame round-trips");
    const pb::Hash32 node_pool = a->r().with_node([](pb::PathbNode& n) { return n.our_hello(1, 0).pool_id; });
    C(node_pool == rig.net.pool_id, "P1 a node's HELLO carries its configured pool identity");

    pb::GenesisSpec g2 = g;
    g2.headline = "pool two";
    pb::GenesisSpec g3 = g;
    g3.block_hash[0] ^= 1;
    const pb::Hash32 raw = pb::identity_raw(pb::LaneNet::Stagenet, 0, pb::default_pool_genesis(pb::LaneNet::Stagenet), 1).pool_id;
    C(pb::identity_derived(pb::LaneNet::Testnet, 0, g).pool_id != id.pool_id &&
              pb::identity_derived(pb::LaneNet::Stagenet, 1, g).pool_id != id.pool_id &&
              pb::identity_derived(pb::LaneNet::Stagenet, 0, g2).pool_id != id.pool_id &&
              pb::identity_derived(pb::LaneNet::Stagenet, 0, g3).pool_id != id.pool_id && raw != id.pool_id,
      "P1 the pool_id moves with the network, the chain_id, the headline, the block hash and the raw genesis");

    const auto chk = [&](const pb::PathbHello& theirs) { return pb::pathb_hello_check(h, theirs, std::nullopt, 0, 0); };
    pb::PathbHello other = h;
    other.node_nonce = 0x2222;
    const pb::HelloCheck same = chk(other);
    C(same.verdict == pb::HelloVerdict::Accept, "P1 the same identity is accepted");
    other.pool_id = pb::identity_derived(pb::LaneNet::Stagenet, 0, g2).pool_id;
    const pb::HelloCheck cp = chk(other);
    C(cp.verdict == pb::HelloVerdict::Refuse && cp.reason == pb::HelloReason::PoolId &&
              cp.text == "TAG_MISMATCH field=pool_id ours=" + hex(h.pool_id) + " theirs=" + hex(other.pool_id),
      "P1 another pool_id: " + cp.text.substr(0, 40));
    other = h;
    other.node_nonce = 0x2222;
    other.chain_id = 9;
    const pb::HelloCheck cc = chk(other);
    C(cc.verdict == pb::HelloVerdict::Refuse && cc.reason == pb::HelloReason::ChainId &&
              cc.text == "TAG_MISMATCH field=chain_id ours=0 theirs=9",
      "P1 another chain_id: " + cc.text);
    other = h;
    other.node_nonce = 0x2222;
    other.network = static_cast<std::uint8_t>(pb::LaneNet::Testnet);
    const pb::HelloCheck cn = chk(other);
    C(cn.verdict == pb::HelloVerdict::Refuse && cn.reason == pb::HelloReason::Network &&
              cn.text == "TAG_MISMATCH field=network ours=2 theirs=1",
      "P1 another network: " + cn.text);
}

static void p2_p3_live(Checker& C) {
    std::printf("-- P2 live: another pool's node is refused at HELLO in both directions\n");
    Rig rig;
    std::unique_ptr<RNode> A = rig.make("A", Rig::opts(true), /*launch=*/true);
    C(A->start(), "P2 A starts");
    std::unique_ptr<RNode> B = rig.make("B", Rig::opts(true, {A->port()}));
    C(B->start(), "P2 B starts, dials A");
    std::unique_ptr<RNode> X = rig.make("X", Rig::opts(false, {A->port(), B->port()}), /*launch=*/true,
                                        /*another_pool=*/true);
    C(X->start(), "P2 X (another pool identity) starts, dials A and B");
    C(wait_until([&] { return A->r().ready_links().size() == 1 && B->r().ready_links().size() == 1; }, 15000ms),
      "P2 A and B link");
    const std::string tag = "TAG_MISMATCH field=pool_id";
    C(wait_until([&] { return A->count_logs(tag) >= 1 && B->count_logs(tag) >= 1 && X->count_logs(tag) >= 2; }, 15000ms),
      "P2 the refusal is logged by A, B and X (X: once per dial)");
    std::this_thread::sleep_for(300ms);
    C(X->r().ready_links().empty(), "P2 X has no ready link");
    C(A->st().hello_tag_mismatch.load() >= 1 && B->st().hello_tag_mismatch.load() >= 1 &&
              X->st().hello_tag_mismatch.load() >= 2,
      "P2 hello_tag_mismatch counted on A, B and X");
    std::printf("    %s\n", A->first_log(tag).substr(0, 140).c_str());
    std::printf("    %s\n", X->first_log(tag).substr(0, 140).c_str());

    std::printf("-- P3 nothing crosses\n");
    const pb::Hash32 a0 = A->best(), b0 = B->best();
    C(rig.mine(*X, 0, 0x9100).action == pb::NodeAction::Placed, "P3 X mines a carrier on its own pool");
    std::this_thread::sleep_for(500ms);
    C(A->best() == a0 && B->best() == b0 && A->best() != X->best(), "P3 X's carrier reaches neither A nor B");
    C(rig.mine(*A, 1, 0x9200).action == pb::NodeAction::Placed, "P3 A mines a carrier");
    C(wait_until([&] { return B->best() == A->best(); }, 10000ms), "P3 A's carrier reaches B");
    C(X->best() != A->best(), "P3 ... and not X");
}

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_pool_id_kat ==\n");
    p1_wire(C);
    p2_p3_live(C);
    return C.done("v37_xmr_relay_pool_id_kat");
}
