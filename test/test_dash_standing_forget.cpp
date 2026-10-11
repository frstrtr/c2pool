// SPDX-License-Identifier: AGPL-3.0-or-later
//
// DASH standing-remember vs sendShares transient bracket — issue #950.
//
// Canonical p2pool seeds every freshly-connected peer with its mining-tx set as
// a STANDING remembered set (p2p.py:269-283) and keeps it standing: sendShares
// builds its transient remember_tx/forget_tx bracket from
//
//     hashes_to_send = [x for x in tx_hashes
//                       if x not in self.node.mining_txs_var.value and x in known_txs]
//
// (p2p.py:377), so a tx the peer already holds as standing is NEVER forgotten by
// a share broadcast. c2pool gained the standing seed in #1167
// (send_standing_remember, node.cpp) but send_shares' needed_txs gate
// (node.cpp:1526) excluded only m_remote_txs and the INBOUND m_remembered_txs —
// it had no record of what WE standing-seeded. A locally minted share references
// the current template's txs, which are exactly the ones the standing seed drew
// from m_known_txs, so every local broadcast re-sent those bodies and then
// forget_tx'd them. Two canonical consequences, both on the RECEIVING peer:
//
//  - handle_remember_tx DISCONNECTS on a tx already in remembered_txs
//    ("Peer referenced transaction twice", p2p.py:474-477). Any standing tx the
//    peer had not advertised via have_tx was re-sent as a body by the bracket.
//    Our own Legacy handler only logs and continues on the same condition
//    (protocol_legacy.cpp), so c2pool-to-c2pool links never show it.
//  - handle_forget_tx erases unconditionally (p2p.py:493-497), so the standing
//    set drains back to zero after the first share: the peer-visible txpool
//    (web.py:673 remembered_txs_size) that #950 is about.
//
// `ShareBroadcastDoesNotForgetStandingSeededTx` drives the REAL
// NodeImpl::handle_version (which emits the standing seed) and the REAL
// NodeImpl::send_shares over a REAL loopback socket, and reads the frames the
// node actually wrote. Before the fix the forget_tx frame carries the standing
// tx's hash and the EXPECT_FALSE fires. The non-standing tx in the same share is
// the control: it must still get the full transient bracket, so the fix cannot
// pass by suppressing the bracket wholesale.
//
// Real types throughout (NodeImpl, dash::Peer, core::Socket, message codecs);
// the only stub is the ICommunicator error sink the harness hands core::Socket.
// The share is hand-built (not mined): send_shares packs it and reads only
// m_new_transaction_hashes, so its PoW is irrelevant to what is asserted here.
//
// FOLDED into the EXISTING allowlisted `test_dash_node` target — a standalone
// add_executable is absent from build.yml's --target list and CTest reports its
// cases "Not Run" (the #769 trap).

#include "dash_socket_harness.hpp"

#include <impl/dash/node.hpp>
#include <impl/dash/config.hpp>
#include <impl/dash/share.hpp>
#include <impl/dash/coin/transaction.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

using namespace dash_socket_harness;

dash::coin::MutableTransaction make_tx(std::uint32_t salt)
{
    dash::coin::MutableTransaction tx;
    tx.version = 1;
    tx.type = 0;
    tx.locktime = salt;
    dash::coin::TxIn in;
    in.prevout.hash = uint256(salt);
    in.prevout.index = 0;
    in.sequence = 0xffffffffu;
    tx.vin.push_back(in);
    dash::coin::TxOut out;
    out.value = 1000 + salt;
    tx.vout.push_back(out);
    return tx;
}

std::vector<std::byte> tx_bytes(const dash::coin::MutableTransaction& tx)
{
    auto ps = ::pack(tx);
    auto sp = ps.get_span();
    return {sp.begin(), sp.end()};
}

uint256 txid(const dash::coin::MutableTransaction& tx)
{
    auto ps = ::pack(tx);
    return ::Hash(ps.get_span());
}

bool payload_contains(const Frame& f, const std::byte* needle, std::size_t len)
{
    return std::search(f.payload.begin(), f.payload.end(), needle, needle + len)
           != f.payload.end();
}

bool payload_contains(const Frame& f, const std::vector<std::byte>& needle)
{
    return payload_contains(f, needle.data(), needle.size());
}

bool payload_contains(const Frame& f, const uint256& h)
{
    return payload_contains(f, reinterpret_cast<const std::byte*>(h.data()), 32);
}

} // namespace

TEST(DashStandingForget, ShareBroadcastDoesNotForgetStandingSeededTx)
{
    LoopbackPair pair;
    StubCommunicator stub;

    dash::Config cfg{"dash-standing-forget-kat"};
    cfg.pool()->m_prefix = test_prefix();

    dash::NodeImpl node(&pair.ioc_node, &cfg);

    // Template 1 is current when the peer connects: its tx becomes the standing
    // seed.
    const auto standing = make_tx(0x51);
    const uint256 h_standing = txid(standing);
    node.register_template_txs({dash::coin::Transaction(standing)}, {h_standing});

    auto peer = make_socket_peer(pair, stub);
    IoThread io(pair.ioc_node);

    const auto type = node.handle_version(
        make_version(0x950F'0A6E'7000'0001ull, "c2pool-dash-standing-forget-kat"), peer);
    ASSERT_TRUE(type.has_value()) << "handshake must be accepted at the cold floor";

    const auto handshake = read_frames(*pair.theirs, std::chrono::milliseconds(400));
    const Frame* seed = find_frame(handshake, "remember_tx");
    ASSERT_NE(seed, nullptr)
        << "harness sanity: handle_version must emit the #1167 standing seed";
    ASSERT_TRUE(payload_contains(*seed, tx_bytes(standing)))
        << "harness sanity: the standing seed must carry the template tx body";

    // Template 2 adds a tx the peer was NOT seeded with. A share referencing
    // both is what a local mint on the current tip looks like.
    const auto fresh = make_tx(0x52);
    const uint256 h_fresh = txid(fresh);
    node.register_template_txs(
        {dash::coin::Transaction(standing), dash::coin::Transaction(fresh)},
        {h_standing, h_fresh});

    auto* share = new dash::DashShare();
    share->m_hash = uint256(0x950950u);
    share->m_new_transaction_hashes = {h_standing, h_fresh};
    dash::ShareType st;
    st = share;
    node.tracker().add(st);

    const auto sent = node.send_shares(peer, {uint256(0x950950u)});
    ASSERT_EQ(sent.size(), 1u) << "both referenced txs are held, so the share must go out";

    const auto bracket = read_frames(*pair.theirs, std::chrono::milliseconds(400));
    io.stop(pair.ioc_node);

    ASSERT_NE(find_frame(bracket, "shares"), nullptr)
        << "harness sanity: send_shares must put the share on the wire";

    // Control: the non-standing tx still gets canonical's full transient
    // bracket (p2p.py:384 remember, :388 forget).
    const Frame* remember = find_frame(bracket, "remember_tx");
    ASSERT_NE(remember, nullptr)
        << "control: the non-standing tx must still be remembered before the share";
    EXPECT_TRUE(payload_contains(*remember, tx_bytes(fresh)));
    const Frame* forget = find_frame(bracket, "forget_tx");
    ASSERT_NE(forget, nullptr)
        << "control: the non-standing tx must still be forgotten after the share";
    EXPECT_TRUE(payload_contains(*forget, h_fresh));

    // The #950 defect: the standing-seeded tx must be outside the bracket.
    EXPECT_FALSE(payload_contains(*forget, h_standing))
        << "#950: send_shares forget_tx'd a STANDING-seeded tx — the peer erases it "
           "from its remembered set, draining the standing seed to zero "
           "(canonical excludes mining_txs from the bracket, p2p.py:377)";
    EXPECT_FALSE(payload_contains(*remember, tx_bytes(standing)))
        << "#950: send_shares re-sent the body of a tx the peer already holds as "
           "standing — a canonical peer disconnects on that (p2p.py:474-477)";
}
