// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH v36 flip KATs: the private/isolated DASH v36 sharechain (a custom
// --network-id) MINTS v36 — CoinParams::current_share_version is the profile's
// target share version (36), the mint path builds DashV36Share with
// desired_version 36 and the P2PKH donation, the node's runtime accept floor is
// seeded at 3600, the producer retarget carries the v36 emergency time-decay,
// and the operator message blob is embedded into minted shares when it
// validates against the chain's (maintainer-only) authority. The public network
// (no --network-id) is byte-identical to master: it mints v16 exactly as
// before, its ratchet starts at 1700 and its retarget has no decay.
//
// What is pinned:
//   A. CoinParams: isolated current_share_version 36 (P2PKH donation for v36),
//      public 16 with every master field unchanged.
//   B. Mint: an isolated node mints a v36 share (genesis, then a child whose
//      coinbase pays the parent's window) that its own tracker and a second
//      node accept; the public mint path is byte-identical to mint_from_inputs.
//   C. The flipped isolated chain drops a v16 peer share at node receive.
//   D. Ratchet seed 3600 on isolated (the ratchet is a no-op there), 1700 on
//      public; the REAL handle_version refuses a 1700 peer on isolated and
//      admits 3600; public still admits 1700.
//   E. Emergency decay: exact max_bits/bits after a stall on isolated, none on
//      public; the shift saturates instead of wrapping; a producer job commits
//      the eased bits and the mined share passes the peer checks.
//   F. Operator blob: embedded when keyed to the chain authority, not embedded
//      (and the share still verifies) when mis-keyed; never on public.
//   G. The pre-flip v16 store of the same identity is never opened by the v36
//      chain (data subdir keyed on the share version).
//   H. Web label DashV36Share for DASH type 36; the per-share payout view sums
//      v36 shares.
//
// Folded into test_dash_node (needs dash::NodeImpl + c2pool_storage + the dash
// OBJECT lib). The profile is keyed on the process-global SharechainConfig
// identity; IdentityGuard resets it around every test.

#include <gtest/gtest.h>

#include "dash_v36_live_fixture.hpp"   // IdentityGuard, DataDirGuard, LiveNode, mine_v36, ...

#include <impl/dash/crypto/hash_x11.hpp>
#include <impl/dash/emergency_decay.hpp>
#include <impl/dash/messages.hpp>
#include <impl/dash/mint_runloop.hpp>
#include <impl/dash/pplns.hpp>
#include <impl/dash/share_messages.hpp>
#include <impl/bitcoin_family/coin/base_block.hpp>

#include <c2pool/storage/sharechain_storage.hpp>
#include <core/socket.hpp>
#include <core/web_server.hpp>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

#include <secp256k1.h>

#include <atomic>
#include <optional>
#include <thread>
#include <variant>

namespace {

using dash::mint::build_producer_job;
using dash::mint::mint_from_inputs;
using dash::mint::mint_from_inputs_any;
using dash::mint::select_embed_blob;
using dash::producer::BuiltShare;
using dash::producer::BuiltV36Share;
using MintShareInputs = dash::stratum::DASHWorkSource::MintShareInputs;
using KeySpan = std::span<const dash::AuthorityPubkey* const>;

// Private/isolated identity with the PRODUCTION CoinParams (no
// current_share_version override — the flip is what sets 36), easy PoW.
core::CoinParams iso_prod_params() {
    SharechainConfig::reset_network_id();
    SharechainConfig::set_network_id(ISO_ID, ISO_PFX);
    return easy(dash::make_coin_params(false));
}

dash::coin::DashWorkData make_wd() {
    dash::coin::DashWorkData wd;
    wd.m_version        = 536870912;
    wd.m_previous_block = tag_hash(0x77);
    wd.m_height         = 1000;
    wd.m_coinbase_value = SUBSIDY;
    wd.m_bits           = 0x1b00ffffu;   // block target far harder than shares
    wd.m_curtime        = PAST_TS + 5;
    return wd;
}

uint256 sha256d_bytes(const Bytes& b) {
    return dash::coinbase::sha256d(std::span<const unsigned char>(b.data(), b.size()));
}

// The miner + mining_submit side of one producer job (the test_dash_mint_runloop
// solve_job idiom): coinb1/coinb2 split around the nonce64 slot, coinbase
// reassembly with en1||en2, coinbase-only merkle root, a REAL X11 nonce search
// against the job's committed share target, MintShareInputs as mining_submit
// fills them (ref_hash recovered from the coinb1 tail).
struct SolvedJob {
    dash::mint::ProducerJobBuild build;
    MintShareInputs in;
    bool built{false};
    bool solved{false};
};

template <typename ChainT>
SolvedJob solve_job(ChainT& chain, const core::CoinParams& p, const uint256& prev,
                    const uint160& miner, const dash::coin::DashWorkData& wd,
                    uint32_t share_nonce, uint32_t desired_ts,
                    const Bytes& message_data = {}) {
    SolvedJob out;
    const auto payout_script = dash::pubkey_hash_to_script2(miner);
    auto b = build_producer_job(chain, p, prev, payout_script, wd, desired_ts,
                                share_nonce, /*donation=*/0, "c2pool", 0.0, message_data);
    if (!b) return out;
    out.built = true;
    out.build = *b;
    const auto& job = b->job;

    const Bytes coinb1(job.gentx_bytes.begin(), job.gentx_bytes.begin() + job.nonce64_offset);
    const Bytes coinb2(job.gentx_bytes.begin() + job.nonce64_offset + 8, job.gentx_bytes.end());
    const Bytes en1 = {0x01, 0x02, 0x03, 0x04};
    const Bytes en2 = {0x05, 0x06, 0x07, 0x08};
    Bytes coinbase = coinb1;
    coinbase.insert(coinbase.end(), en1.begin(), en1.end());
    coinbase.insert(coinbase.end(), en2.begin(), en2.end());
    coinbase.insert(coinbase.end(), coinb2.begin(), coinb2.end());

    const uint256 target = chain::bits_to_target(job.share_bits);
    bitcoin_family::coin::BlockHeaderType hdr;
    hdr.m_version        = wd.m_version;
    hdr.m_previous_block = wd.m_previous_block;
    hdr.m_merkle_root    = sha256d_bytes(coinbase);   // coinbase-only template
    hdr.m_timestamp      = wd.m_curtime;
    hdr.m_bits           = wd.m_bits;
    Bytes header_bytes;
    uint256 pow;
    for (uint32_t n = 0; n < 4000000; ++n) {
        hdr.m_nonce = n;
        PackStream ps;
        ps << hdr;
        header_bytes = to_bytes(ps);
        pow = dash::crypto::hash_x11(header_bytes.data(), header_bytes.size());
        if (pow <= target) { out.solved = true; break; }
    }
    if (!out.solved) return out;

    out.in.header_bytes    = header_bytes;
    out.in.coinbase_bytes  = coinbase;
    out.in.subsidy         = wd.m_coinbase_value;
    out.in.prev_share_hash = prev;
    out.in.payout_script   = payout_script;
    out.in.pow_hash        = pow;
    std::memcpy(out.in.ref_hash.begin(), coinb1.data() + coinb1.size() - 32, 32);
    uint64_t n64 = 0;
    for (int i = 7; i >= 0; --i)
        n64 = (n64 << 8) | (i < 4 ? en1[i] : en2[i - 4]);
    out.in.last_txout_nonce = n64;
    return out;
}

// Coinbase outputs (value, scriptPubKey) of a serialized DASH coinbase.
std::vector<std::pair<uint64_t, Bytes>> coinbase_outputs(const Bytes& tx) {
    size_t o = 4;   // version int16 + type int16
    auto varint = [&]() -> uint64_t {
        const uint8_t c = tx.at(o++);
        if (c < 0xfd) return c;
        const int n = c == 0xfd ? 2 : c == 0xfe ? 4 : 8;
        uint64_t v = 0;
        for (int i = 0; i < n; ++i) v |= static_cast<uint64_t>(tx.at(o++)) << (8 * i);
        return v;
    };
    EXPECT_EQ(varint(), 1u);   // one coinbase input
    o += 36;
    o += varint();             // scriptSig
    o += 4;                    // sequence
    std::vector<std::pair<uint64_t, Bytes>> outs;
    const uint64_t n = varint();
    for (uint64_t k = 0; k < n; ++k) {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(tx.at(o++)) << (8 * i);
        const uint64_t len = varint();
        outs.emplace_back(v, Bytes(tx.begin() + o, tx.begin() + o + len));
        o += len;
    }
    return outs;
}

const BuiltV36Share& v36_of(const dash::stratum::MintedShare& m) {
    return std::get<BuiltV36Share>(m.built);
}

// ── message key material (test keypair; no authority seckey is in-tree) ─────
struct TestKey { unsigned char sk[32]; dash::AuthorityPubkey pk; };

TestKey make_test_key(unsigned char fill) {
    TestKey k;
    std::fill(std::begin(k.sk), std::end(k.sk), fill);
    const auto* ctx = dash::get_secp256k1_context();
    secp256k1_pubkey pub;
    EXPECT_EQ(secp256k1_ec_pubkey_create(ctx, &pub, k.sk), 1);
    size_t len = k.pk.size();
    secp256k1_ec_pubkey_serialize(ctx, k.pk.data(), &len, &pub, SECP256K1_EC_COMPRESSED);
    return k;
}

// One signed message, signed by `signer`, envelope encrypted under `envelope`.
Bytes signed_blob(const TestKey& signer, const dash::AuthorityPubkey& envelope) {
    dash::ShareMessage m;
    m.msg_type = dash::MSG_NODE_STATUS;
    m.wire_flags = dash::FLAG_HAS_SIGNATURE;
    m.timestamp = 1710000000;
    m.payload = {0x01, 0x02, 0x03, 0x04};
    std::vector<dash::ShareMessage> msgs{m};
    return dash::create_message_data(signer.sk, envelope, msgs);
}

// ── loopback handshake harness (the test_dash_addrme idiom) ─────────────────
const std::vector<std::byte>& test_prefix() {
    static const std::vector<std::byte> prefix{
        std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdc}};
    return prefix;
}

struct StubCommunicator : public core::ICommunicator {
    void error(const message_error_type&, const NetService&,
               const std::source_location = std::source_location::current()) override {}
    void error(const boost::system::error_code&, const NetService&,
               const std::source_location = std::source_location::current()) override {}
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}
    const std::vector<std::byte>& get_prefix() const override { return test_prefix(); }
};

struct LoopbackPair {
    boost::asio::io_context ioc_peer, ioc_node;
    std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor;
    std::unique_ptr<boost::asio::ip::tcp::socket> theirs, ours;
    LoopbackPair() {
        using boost::asio::ip::tcp;
        acceptor = std::make_unique<tcp::acceptor>(
            ioc_peer, tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
        acceptor->listen();
        ours = std::make_unique<tcp::socket>(ioc_node);
        ours->connect(acceptor->local_endpoint());
        theirs = std::make_unique<tcp::socket>(acceptor->accept());
    }
};

struct IoThread {
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> guard;
    std::thread thread;
    explicit IoThread(boost::asio::io_context& ioc)
        : guard(boost::asio::make_work_guard(ioc)), thread([&ioc] { ioc.run(); }) {}
    void stop(boost::asio::io_context& ioc) {
        guard.reset();
        ioc.stop();
        if (thread.joinable()) thread.join();
    }
};

dash::NodeImpl::peer_ptr make_socket_peer(LoopbackPair& pair, StubCommunicator& stub) {
    auto sock = std::make_shared<core::Socket>(
        std::move(pair.ours), core::outgoing, &stub,
        std::weak_ptr<core::INetwork>{}, /*was_managed=*/false);
    sock->init();
    return std::make_shared<dash::NodeImpl::peer_t>(sock);
}

std::unique_ptr<RawMessage> make_version(uint32_t proto, uint64_t nonce) {
    return dash::message_version::make_raw(
        proto, uint64_t{0},
        addr_t(1u, NetService("203.0.113.1", 9999)),
        addr_t(1u, NetService("203.0.113.2", 8888)),
        nonce, std::string("c2pool-dash-v36-flip-kat"), 1u, uint256());
}

// Outcome of the REAL NodeImpl::handle_version for one peer protocol version:
// "" = admitted (returns a peer type), else the exception text.
std::string handshake(uint32_t proto, uint64_t nonce) {
    LoopbackPair pair;
    StubCommunicator stub;
    dash::NodeImpl node;   // rig-free; its ratchet seed is read from the live profile
    auto peer = make_socket_peer(pair, stub);
    IoThread io(pair.ioc_node);
    std::string result;
    try {
        auto t = node.handle_version(make_version(proto, nonce), peer);
        result = t.has_value() ? "" : "<no peer type>";
    } catch (const std::exception& e) {
        result = e.what();
    }
    io.stop(pair.ioc_node);
    return result;
}

// ── synthetic chains for the retarget / payout-view KATs ────────────────────
// `n` back-linked DashV36Shares: fixed bits == max_bits, timestamps t0 + i*spacing,
// absheight 1..n, abswork accumulated, pubkey_hash cycling over `miners`.
uint256 build_v36_chain(dash::ShareChain& chain, int n, uint32_t bits, uint32_t t0,
                        uint32_t spacing, int miners = 1) {
    uint256 prev;
    uint128 abswork;
    for (int i = 0; i < n; ++i) {
        auto* s = new dash::DashV36Share();
        Bytes hv(32, 0x00);
        hv[0] = static_cast<uint8_t>(i & 0xff);
        hv[1] = static_cast<uint8_t>(i >> 8);
        hv[30] = 0xf1; hv[31] = 0x36;
        s->m_hash = uint256(hv);
        s->m_prev_hash = prev;
        s->m_bits = bits;
        s->m_max_bits = bits;
        s->m_timestamp = t0 + static_cast<uint32_t>(i) * spacing;
        s->m_absheight = static_cast<uint32_t>(i + 1);
        abswork = abswork + dash::producer::low128(
            chain::target_to_average_attempts(chain::bits_to_target(bits)));
        s->m_abswork = abswork;
        s->m_pubkey_hash = h160(static_cast<uint8_t>(0x10 + (i % miners)));
        s->m_desired_version = 36;
        s->m_coinbase = BaseScript(Bytes{0x03, 0x01, 0x02, 0x03});
        prev = s->m_hash;
        chain.add(s);
    }
    return prev;
}

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// A. CoinParams
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36Flip, IsolatedParamsMintVersionIs36PublicStays16)
{
    IdentityGuard guard;
    for (bool testnet : {false, true}) {
        SCOPED_TRACE(testnet ? "testnet" : "mainnet");
        SharechainConfig::reset_network_id();
        const auto pub = dash::make_coin_params(testnet);
        EXPECT_EQ(pub.current_share_version, 16u);
        EXPECT_EQ(pub.donation_script_func(16), dash::DONATION_SCRIPT);
        EXPECT_EQ(pub.donation_script_func(36), dash::COMBINED_DONATION_SCRIPT);
        EXPECT_EQ(pub.minimum_protocol_version, 1700u);

        SharechainConfig::set_network_id(ISO_ID, ISO_PFX);
        const auto iso = dash::make_coin_params(testnet);
        EXPECT_EQ(iso.current_share_version, 36u) << "the flip: the isolated chain mints v36";
        EXPECT_EQ(iso.current_share_version, SharechainConfig::share_profile().target_share_version);
        EXPECT_EQ(iso.donation_script_func(36), dash::DONATION_SCRIPT) << "v36 pays the P2PKH donation";
        EXPECT_EQ(iso.minimum_protocol_version, 1700u) << "the cold floor is not the ratchet seed";
        EXPECT_NO_THROW(dash::check_share_type_admitted(36, iso));
        EXPECT_EQ(invalid_arg_text([&] { dash::check_share_type_admitted(16, iso); }),
                  "share type v16 not admitted: this sharechain speaks v36");
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// B. Mint
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36Flip, IsolatedNodeMintsV36ThatSelfAndPeerAccept)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_v36_flip_mint");
    const auto p = iso_prod_params();
    ASSERT_EQ(p.current_share_version, 36u);
    const std::string sub = SharechainConfig::data_subdir(false);
    const auto wd = make_wd();
    const uint160 miner_a = h160(0xa1), miner_b = h160(0xb2);
    const Bytes donation(dash::DONATION_SCRIPT.begin(), dash::DONATION_SCRIPT.end());

    // ── genesis ──
    dash::ShareChain scratch;
    const auto j1 = solve_job(scratch, p, uint256(), miner_a, wd, 7, wd.m_curtime);
    ASSERT_TRUE(j1.built) << "the isolated node must serve a producer job";
    EXPECT_EQ(j1.build.frozen.desired_version, 36u);
    ASSERT_TRUE(j1.solved);
    const auto m1 = mint_from_inputs_any(scratch, p, j1.in, j1.build.frozen);
    ASSERT_TRUE(m1.has_value());
    ASSERT_TRUE(m1->is_v36()) << "the isolated chain mints DashV36Share";
    const auto& g = v36_of(*m1);
    EXPECT_EQ(dash::DashV36Share::version, 36);
    EXPECT_EQ(g.share.m_desired_version, 36u);
    EXPECT_EQ(g.share.m_hash, j1.in.pow_hash) << "X11 identity gate";
    EXPECT_EQ(g.ref_hash, j1.in.ref_hash);
    EXPECT_EQ(g.gentx_hash, sha256d_bytes(j1.in.coinbase_bytes))
        << "the served coinbase IS the share's gentx";
    {   // genesis window is empty: the worker payout goes to the P2PKH donation
        const auto outs = coinbase_outputs(j1.in.coinbase_bytes);
        ASSERT_EQ(outs.size(), 2u) << "donation + OP_RETURN; no finder output";
        EXPECT_EQ(outs[0].second, donation);
        EXPECT_EQ(outs[0].first, SUBSIDY);
        EXPECT_EQ(outs[1].second.at(0), 0x6a);
    }

    // ── a child on top of it: its coinbase pays the parent's window ──
    scratch.add(new dash::DashV36Share(g.share));
    const auto j2 = solve_job(scratch, p, g.share.m_hash, miner_b, wd, 8, wd.m_curtime + 20);
    ASSERT_TRUE(j2.built);
    ASSERT_TRUE(j2.solved);
    const auto m2 = mint_from_inputs_any(scratch, p, j2.in, j2.build.frozen);
    ASSERT_TRUE(m2.has_value());
    ASSERT_TRUE(m2->is_v36());
    const auto& c = v36_of(*m2);
    EXPECT_EQ(c.share.m_prev_hash, g.share.m_hash);
    EXPECT_EQ(c.share.m_desired_version, 36u);
    {
        const auto outs = coinbase_outputs(j2.in.coinbase_bytes);
        bool pays_a = false, pays_b = false, pays_donation = false;
        for (const auto& [v, script] : outs) {
            if (script == dash::pubkey_hash_to_script2(miner_a)) { pays_a = true; EXPECT_GT(v, 0u); }
            if (script == dash::pubkey_hash_to_script2(miner_b)) pays_b = true;
            if (script == donation) { pays_donation = true; EXPECT_GE(v, 1u); }
        }
        EXPECT_TRUE(pays_a) << "the parent's miner is paid by the child";
        EXPECT_FALSE(pays_b) << "no block-finder fee on v36";
        EXPECT_TRUE(pays_donation) << "donation output >= 1 sat";
    }

    const Bytes wg = wire_of(g.share), wc = wire_of(c.share);

    // ── node A: its own tracker takes both minted shares ──
    {
        LiveNode a(p, sub + "_a");
        EXPECT_FALSE(a.node->add_local_share(m1->to_share_type()).IsNull());
        EXPECT_FALSE(a.node->add_local_share(m2->to_share_type()).IsNull());
        ASSERT_TRUE(a.pump_until([&](dash::ShareTracker& t) {
            return t.chain.contains(g.share.m_hash) && t.chain.contains(c.share.m_hash);
        }));
        auto& t = a.quiesce();
        EXPECT_EQ(t.chain.get_share(c.share.m_hash).version(), 36);
        EXPECT_TRUE(t.attempt_verify(g.share.m_hash));
        EXPECT_TRUE(t.attempt_verify(c.share.m_hash));
    }
    // ── node B: a second node receives the wire bytes and verifies them ──
    {
        LiveNode b(p, sub + "_b");
        b.receive({{36, wg}, {36, wc}});
        ASSERT_TRUE(b.pump_until([&](dash::ShareTracker& t) {
            return t.chain.contains(g.share.m_hash) && t.chain.contains(c.share.m_hash);
        })) << "a second isolated node admits the minted v36 shares";
        auto& t = b.quiesce();
        EXPECT_TRUE(t.attempt_verify(g.share.m_hash));
        EXPECT_TRUE(t.attempt_verify(c.share.m_hash));
        EXPECT_TRUE(t.verified.contains(c.share.m_hash));
        EXPECT_EQ(dash::generate_share_transaction(c.share, t, p), c.gentx_hash);
    }
}

TEST(DashV36Flip, PublicNodeStillMintsV16ByteIdentical)
{
    IdentityGuard guard;
    const auto p = public_params();
    ASSERT_EQ(p.current_share_version, 16u);
    const auto wd = make_wd();
    dash::ShareChain chain;

    const auto j = solve_job(chain, p, uint256(), h160(0x22), wd, 7, wd.m_curtime);
    ASSERT_TRUE(j.solved);
    EXPECT_EQ(j.build.frozen.desired_version, 16u);

    const auto v16 = mint_from_inputs(chain, p, j.in, j.build.frozen);
    const auto any = mint_from_inputs_any(chain, p, j.in, j.build.frozen);
    ASSERT_TRUE(v16.has_value());
    ASSERT_TRUE(any.has_value());
    ASSERT_TRUE(std::holds_alternative<BuiltShare>(any->built)) << "public mints DashShare";
    const auto& b = std::get<BuiltShare>(any->built);
    EXPECT_EQ(wire_of(b.share), wire_of(v16->share)) << "byte-identical to mint_from_inputs";
    EXPECT_EQ(b.share.m_hash, v16->share.m_hash);
    EXPECT_EQ(b.gentx_hash, v16->gentx_hash);
    EXPECT_EQ(b.share.m_desired_version, 16u);

    // A message blob handed to the public mint path is ignored: v16 has no
    // message_data field, the job bytes and the frozen context are unchanged.
    const Bytes blob(64, 0x5a);
    const auto jb = build_producer_job(chain, p, uint256(), dash::pubkey_hash_to_script2(h160(0x22)),
                                       wd, wd.m_curtime, 7, 0, "c2pool", 0.0, blob);
    ASSERT_TRUE(jb.has_value());
    EXPECT_EQ(jb->job.gentx_bytes, j.build.job.gentx_bytes);
    EXPECT_EQ(jb->job.ref_hash, j.build.job.ref_hash);
    EXPECT_TRUE(jb->frozen.message_data.empty());
}

// ═════════════════════════════════════════════════════════════════════════════
// C. The flipped isolated chain drops a v16 peer share
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36Flip, IsolatedRejectsV16PeerShareAfterFlip)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_v36_flip_rx");
    const auto p16 = iso_params(16);
    dash::ShareChain s16c;
    const auto s16 = mine_v16(s16c, p16, info(uint256(), 1, 0xaa, 16)).share;
    const auto p = iso_prod_params();   // production: no override
    dash::ShareChain s36c;
    const auto s36 = mine_v36(s36c, p, info(uint256(), 1, 0xbb, 36)).share;

    LiveNode n(p, SharechainConfig::data_subdir(false));
    n.node->hold_think_slot(true);
    n.receive({{16, wire_of(s16)}, {36, wire_of(s36)}});
    ASSERT_TRUE(n.pump_until([&](dash::ShareTracker& t) { return t.chain.contains(s36.m_hash); }))
        << "the v36 share is admitted";
    auto& t = n.quiesce();
    EXPECT_FALSE(t.chain.contains(s16.m_hash)) << "the v16 share is dropped at receive";
    EXPECT_EQ(t.chain.size(), 1u);
    EXPECT_FALSE(n.node->stored(s16.m_hash));
}

// ═════════════════════════════════════════════════════════════════════════════
// D. Ratchet seed + live handshake
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36Flip, RatchetSeedIs3600OnIsolated1700OnPublic)
{
    IdentityGuard guard;
    {
        dash::NodeImpl pub;
        EXPECT_EQ(pub.runtime_min_protocol_version(), 1700u);
        pub.apply_min_protocol_ratchet();   // no best share: stays at the cold floor
        EXPECT_EQ(pub.runtime_min_protocol_version(), 1700u);
    }
    SharechainConfig::set_network_id(ISO_ID, ISO_PFX);
    {
        dash::NodeImpl iso;
        EXPECT_EQ(iso.runtime_min_protocol_version(), 3600u)
            << "the v36-from-genesis chain starts ratcheted";
        iso.apply_min_protocol_ratchet();   // latched: no-op
        EXPECT_EQ(iso.runtime_min_protocol_version(), 3600u);
    }
}

TEST(DashV36Flip, IsolatedHandshakeRefuses1700Admits3600)
{
    IdentityGuard guard;
    const std::string refused = "peer protocol below min-protocol floor";
    // Public: the cold floor admits the p2pool-dash 1700 peer (master behaviour).
    EXPECT_EQ(handshake(1700, 0x1111'2222'3333'4401ull), "");
    EXPECT_EQ(handshake(3600, 0x1111'2222'3333'4402ull), "");

    SharechainConfig::set_network_id(ISO_ID, ISO_PFX);
    EXPECT_EQ(handshake(1700, 0x1111'2222'3333'4403ull), refused);
    EXPECT_EQ(handshake(3599, 0x1111'2222'3333'4404ull), refused);
    EXPECT_EQ(handshake(3600, 0x1111'2222'3333'4405ull), "");
}

// ═════════════════════════════════════════════════════════════════════════════
// E. Emergency time-decay retarget (operator Q4)
// ═════════════════════════════════════════════════════════════════════════════
//
// Chain: 100 v36 shares, bits = max_bits = 0x1c00ffff (pm = 0xffff * 2^200),
// 20 s spacing -> aps = 99*ata(pm)//1980, pre_target = 2^256//(20*aps)-1 is a
// hair above pm, inside the band. desired_target = max_target, so bits ==
// max_bits == compact(pre_target3). Threshold = 20*20 = 400 s, half-life
// 10*20 = 200 s. Expected values: exact integer trace (same ops, python ints):
//   gap   400 (== threshold, not >)  -> ref = pm             -> 0x1c00ffff
//   gap   401 (0 halvings, r=1)      -> ref = pm*201//200; lo = 0.9045 pm < pre -> 0x1c00ffff
//   gap   700 (1 halving,  r=100)    -> ref = 3 pm;   lo = 27 pm/10          -> 0x1c02b330
//   gap  1200 (4 halvings, r=0)      -> ref = 16 pm;  lo = 14.4 pm           -> 0x1c0e6658
//   gap 100000 (saturates)           -> ref = MAX;    lo = 0.9 MAX           -> 0x1d00e665
// "Lowers the target" (Q4) in the difficulty sense: the numeric target rises.
TEST(DashShareProducerRetarget, EmergencyDecayEasesBandOnIsolatedOnly)
{
    IdentityGuard guard;
    constexpr uint32_t T0 = 1000000, SPACING = 20;
    dash::ShareChain chain;
    const uint256 tip = build_v36_chain(chain, 100, 0x1c00ffffu, T0, SPACING);
    ASSERT_EQ(chain.get_acc_height(tip), 100);
    const uint32_t tip_ts = T0 + 99 * SPACING;

    struct Case { uint32_t gap; uint32_t isolated_bits; };
    const Case cases[] = {
        {0, 0x1c00ffffu}, {100, 0x1c00ffffu}, {400, 0x1c00ffffu}, {401, 0x1c00ffffu},
        {700, 0x1c02b330u}, {1200, 0x1c0e6658u}, {100000, 0x1d00e665u},
    };

    SharechainConfig::set_network_id(ISO_ID, ISO_PFX);
    ASSERT_TRUE(SharechainConfig::share_profile().emergency_decay);
    const auto iso = dash::make_coin_params(false);
    for (const auto& c : cases) {
        SCOPED_TRACE("isolated gap=" + std::to_string(c.gap));
        const auto st = dash::producer::compute_share_target(
            chain, tip, iso.max_target, iso, tip_ts + c.gap);
        EXPECT_EQ(st.max_bits, c.isolated_bits);
        EXPECT_EQ(st.bits, c.isolated_bits);
    }

    SharechainConfig::reset_network_id();
    ASSERT_FALSE(SharechainConfig::share_profile().emergency_decay);
    const auto pub = dash::make_coin_params(false);
    for (const auto& c : cases) {
        SCOPED_TRACE("public gap=" + std::to_string(c.gap));
        const auto st = dash::producer::compute_share_target(
            chain, tip, pub.max_target, pub, tip_ts + c.gap);
        EXPECT_EQ(st.max_bits, 0x1c00ffffu) << "the public retarget has no decay";
        EXPECT_EQ(st.bits, 0x1c00ffffu);
        // and it equals the oracle-only 4-arg form (no timestamp) exactly
        const auto st4 = dash::producer::compute_share_target(chain, tip, pub.max_target, pub);
        EXPECT_EQ(st.max_bits, st4.max_bits);
        EXPECT_EQ(st.bits, st4.bits);
    }
}

TEST(DashShareProducerRetarget, EmergencyDecayShiftSaturatesNotWraps)
{
    uint256 max_target;
    max_target.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
    uint256 pm;
    pm.SetHex("0000000000ffff00000000000000000000000000000000000000000000000000");   // 0xffff * 2^200
    constexpr uint32_t SP = 20, PREV = 1000000;
    auto at = [&](uint32_t halvings, uint32_t rem) {
        return dash::emergency_decay_clamp_ref(pm, PREV, PREV + SP * 20 + halvings * SP * 10 + rem,
                                               SP, max_target);
    };
    // No decay at / below the threshold, or without a usable timestamp pair.
    EXPECT_EQ(dash::emergency_decay_clamp_ref(pm, PREV, PREV + 400, SP, max_target), pm);
    EXPECT_EQ(dash::emergency_decay_clamp_ref(pm, 0, PREV + 5000, SP, max_target), pm);
    EXPECT_EQ(dash::emergency_decay_clamp_ref(pm, PREV, PREV - 1, SP, max_target), pm);
    // One halving, no remainder: exactly 2 pm.
    uint256 two_pm = pm; two_pm <<= 1;
    EXPECT_EQ(at(1, 0), two_pm);
    // 8 halvings reach max_target exactly (pm << 8 == max_target).
    EXPECT_EQ(at(8, 0), max_target);
    // Far past it: saturated at max_target for every halving count, including
    // the counts where a bare 256-bit shift drops every bit (>= 56 here).
    for (uint32_t h : {9u, 30u, 55u, 56u, 60u, 200u, 255u, 256u, 1000u})
        EXPECT_EQ(at(h, 0), max_target) << "halvings=" << h;
    // The wrap the saturating form avoids (the previous tracker Step 3 shape):
    uint256 bare = pm;
    bare <<= 60;
    EXPECT_TRUE(bare < pm) << "a bare shift wraps below prev_max_target";
}

TEST(DashV36Flip, ProducerJobCommitsEmergencyEasedBitsAndPeerAccepts)
{
    IdentityGuard guard;
    const auto p = iso_prod_params();
    constexpr uint32_t T0 = PAST_TS, SPACING = 20;
    // Easy chain (pm = 0x1fffff * 2^224) so the eased share target is X11-mineable.
    dash::ShareTracker t;
    t.m_coin_params = p;
    const uint256 tip = build_v36_chain(t.chain, 100, 0x1f1fffffu, T0, SPACING, 4);
    const uint32_t tip_ts = T0 + 99 * SPACING;
    auto wd = make_wd();
    wd.m_curtime = tip_ts + 700;

    // No stall: the band holds the chain's own target (trace: 0x1f202020).
    {
        const auto j0 = build_producer_job(t.chain, p, tip, dash::pubkey_hash_to_script2(h160(0xc3)),
                                           wd, tip_ts + 20, 3, 0, "c2pool");
        ASSERT_TRUE(j0.has_value());
        EXPECT_EQ(j0->job.share_max_bits, 0x1f202020u);
        EXPECT_EQ(j0->job.share_bits, 0x1f202020u);
    }
    // 700 s stall: ref = 3 pm, lo = 27 pm / 10 -> 0x1f566663.
    const auto j = solve_job(t.chain, p, tip, h160(0xc3), wd, 3, tip_ts + 700);
    ASSERT_TRUE(j.built);
    EXPECT_EQ(j.build.job.share_max_bits, 0x1f566663u);
    EXPECT_EQ(j.build.job.share_bits, 0x1f566663u);
    ASSERT_TRUE(j.solved);
    const auto m = mint_from_inputs_any(t.chain, p, j.in, j.build.frozen);
    ASSERT_TRUE(m.has_value()) << "the mint-time rebuild reproduces the eased job";
    const auto& s = v36_of(*m).share;
    EXPECT_EQ(s.m_max_bits, 0x1f566663u);
    EXPECT_EQ(s.m_bits, 0x1f566663u);
    EXPECT_EQ(s.m_timestamp, tip_ts + 2 * SPACING - 1) << "committed timestamp is still clipped";

    // What a peer checks on receipt (no retarget recompute, v16 and v36 alike):
    // the full share verifier with PoW against the committed bits, the target
    // validity guard, the version transition and the payout commitment over
    // the same chain.
    EXPECT_EQ(dash::share_init_verify(s, p, /*check_pow=*/true), s.m_hash);
    EXPECT_NO_THROW(dash::check_share_target_valid(chain::bits_to_target(s.m_bits), p));
    EXPECT_NO_THROW(dash::verify_version_transition(s, t.chain, SharechainConfig::chain_length()));
    EXPECT_EQ(dash::generate_share_transaction(s, t, p), v36_of(*m).gentx_hash);
    EXPECT_NO_THROW(dash::verify_payout_commitment(s, t, p, v36_of(*m).gentx_hash));
}

// ═════════════════════════════════════════════════════════════════════════════
// F. Operator message blob embed
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36Flip, OperatorBlobEmbeddedWhenKeyedToTheChainAuthority)
{
    IdentityGuard guard;
    const auto p = iso_prod_params();
    const auto key = make_test_key(0x66);
    const dash::AuthorityPubkey* set[] = {&key.pk};
    const Bytes blob = signed_blob(key, key.pk);
    ASSERT_FALSE(blob.empty());

    std::string why = "unset";
    EXPECT_EQ(select_embed_blob(blob, SharechainConfig::ISOLATED_V36_PROFILE, KeySpan(set), &why), blob);
    EXPECT_EQ(why, "");

    const auto wd = make_wd();
    dash::ShareChain chain;
    const auto j = solve_job(chain, p, uint256(), h160(0x31), wd, 5, wd.m_curtime, blob);
    ASSERT_TRUE(j.solved);
    EXPECT_EQ(j.build.frozen.message_data, blob) << "the job freezes the committed blob";
    const auto m = mint_from_inputs_any(chain, p, j.in, j.build.frozen, KeySpan(set));
    ASSERT_TRUE(m.has_value());
    const auto& s = v36_of(*m).share;
    EXPECT_EQ(s.m_message_data.m_data, blob) << "embedded into the minted share";
    EXPECT_EQ(dash::share_init_verify(s, p, true, KeySpan(set)), s.m_hash);

    // The blob is committed: the same job without it has a different ref_hash.
    const auto j0 = solve_job(chain, p, uint256(), h160(0x31), wd, 5, wd.m_curtime);
    ASSERT_TRUE(j0.built);
    EXPECT_NE(j0.build.job.ref_hash, j.build.job.ref_hash);
    EXPECT_NE(dash::compute_v36_ref_hash(p, s), j0.build.job.ref_hash);
}

TEST(DashV36Flip, MisKeyedBlobIsNotEmbeddedAndTheShareStillVerifies)
{
    IdentityGuard guard;
    const auto p = iso_prod_params();
    const auto key_a = make_test_key(0x44), key_b = make_test_key(0x45);

    // A blob opened by a WIDER set (the public-style 2-key check at startup)
    // but not by the chain's authority set is not embedded.
    const Bytes blob = signed_blob(key_a, key_a.pk);
    const dash::AuthorityPubkey* wide[] = {&key_b.pk, &key_a.pk};
    const dash::AuthorityPubkey* chain_set[] = {&key_b.pk};
    ASSERT_EQ(dash::validate_message_data(blob, KeySpan(wide)), "");
    std::string why;
    EXPECT_TRUE(select_embed_blob(blob, SharechainConfig::ISOLATED_V36_PROFILE,
                                  KeySpan(chain_set), &why).empty());
    EXPECT_NE(why.find("does not validate against this sharechain's message authority"),
              std::string::npos) << why;

    // Production authority on the isolated chain (maintainer key only): a blob
    // enveloped to the other public authority key is not embedded.
    const Bytes forrestv_blob = signed_blob(key_a, dash::DONATION_PUBKEY_FORRESTV());
    ASSERT_FALSE(forrestv_blob.empty());
    why.clear();
    const Bytes embed = select_embed_blob(forrestv_blob, SharechainConfig::share_profile(),
                                          dash::active_message_authority(), &why);
    EXPECT_TRUE(embed.empty());
    EXPECT_FALSE(why.empty());

    // The node mints with the (empty) selection: the share verifies under the
    // production verifier, so the node does not orphan its own shares ...
    const auto wd = make_wd();
    dash::ShareChain chain;
    const auto j = solve_job(chain, p, uint256(), h160(0x32), wd, 6, wd.m_curtime, embed);
    ASSERT_TRUE(j.solved);
    const auto m = mint_from_inputs_any(chain, p, j.in, j.build.frozen);
    ASSERT_TRUE(m.has_value());
    EXPECT_TRUE(v36_of(*m).share.m_message_data.m_data.empty());
    EXPECT_EQ(dash::share_init_verify(v36_of(*m).share, p), v36_of(*m).share.m_hash);
    // ... whereas embedding the raw blob would make its own verifier reject it.
    const auto jr = solve_job(chain, p, uint256(), h160(0x32), wd, 6, wd.m_curtime, forrestv_blob);
    ASSERT_TRUE(jr.solved);
    EXPECT_THROW((void)mint_from_inputs_any(chain, p, jr.in, jr.build.frozen), std::invalid_argument);

    // Public profile: never embedded, even a blob valid for its key set.
    const dash::AuthorityPubkey* aset[] = {&key_a.pk};
    why.clear();
    EXPECT_TRUE(select_embed_blob(blob, SharechainConfig::PUBLIC_PROFILE, KeySpan(aset), &why).empty());
    EXPECT_NE(why.find("carry no message_data"), std::string::npos) << why;
    EXPECT_TRUE(select_embed_blob({}, SharechainConfig::ISOLATED_V36_PROFILE, KeySpan(aset)).empty());
}

// ═════════════════════════════════════════════════════════════════════════════
// G. Store separation
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36Flip, PreFlipV16StoreIsNeverOpenedByTheV36Chain)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_v36_flip_store");
    const auto p16 = iso_params(16);
    dash::ShareChain scratch;
    const auto s16 = mine_v16(scratch, p16, info(uint256(), 1, 0xaa, 16)).share;
    const auto p = iso_prod_params();

    // What a build before the flip persisted for this identity: a v16 row in
    // "dash_<id>" (the pre-flip subdir literal).
    const std::string pre_flip = "dash_" + SharechainConfig::identifier_hex();
    {
        fs::create_directories(core::filesystem::config_path() / pre_flip);
        c2pool::storage::SharechainStorage st(pre_flip);
        ASSERT_TRUE(st.is_available());
        std::vector<uint8_t> row(8, 0);
        const uint64_t ver = 16;
        std::memcpy(row.data(), &ver, 8);
        const Bytes w = wire_of(s16);
        row.insert(row.end(), w.begin(), w.end());
        ASSERT_TRUE(st.store_share(s16.m_hash, row, s16.m_prev_hash, 1, s16.m_timestamp,
                                   uint256::ZERO, chain::bits_to_target(s16.m_bits)));
    }

    const std::string sub = SharechainConfig::data_subdir(false);
    ASSERT_EQ(sub, pre_flip + "_v36");
    {
        LiveNode n(p, sub);
        auto& t = n.quiesce();
        EXPECT_EQ(t.chain.size(), 0u) << "the v36 chain opens its own, empty store";
        EXPECT_FALSE(n.node->stored(s16.m_hash));
    }
    {   // the pre-flip store is untouched
        c2pool::storage::SharechainStorage st(pre_flip);
        ASSERT_TRUE(st.is_available());
        EXPECT_TRUE(st.has_share(s16.m_hash));
        EXPECT_EQ(st.get_shares_by_height_range(0, UINT64_MAX).size(), 1u);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// H. Dashboard: type-36 label, per-share payout view
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36Flip, WebShareTypeLabelIsDashV36ShareOnDash)
{
    auto stats = [] {
        nlohmann::json sc = nlohmann::json::object();
        sc["total_shares"] = 100;
        sc["chain_height"] = 100;
        sc["chain_length"] = 4320;
        sc["shares_by_version"] = {{"36", 100}};
        sc["shares_by_desired_version"] = {{"36", 100}};
        sc["sampling_desired_version"] = {{"36", 1.0}};
        return sc;
    };
    {
        core::MiningInterface mi(/*testnet=*/false, nullptr, Blockchain::DASH);
        mi.set_sharechain_stats_fn(stats);
        const auto r = mi.rest_version_signaling();
        ASSERT_TRUE(r.contains("share_types")) << r.dump();
        EXPECT_EQ(r["share_types"]["36"]["name"], "DashV36Share");
        EXPECT_EQ(r["current_share_name"], "DashV36Share");
    }
    {
        core::MiningInterface mi(/*testnet=*/true, nullptr, Blockchain::LITECOIN);
        mi.set_sharechain_stats_fn(stats);
        const auto r = mi.rest_version_signaling();
        ASSERT_TRUE(r.contains("share_types")) << r.dump();
        EXPECT_EQ(r["share_types"]["36"]["name"], "MergedMiningShare");
    }
}

TEST(DashV36Flip, PerSharePayoutViewSumsDashV36Shares)
{
    dash::ShareChain chain;
    const uint256 tip = build_v36_chain(chain, 25, 0x1d00ffffu, PAST_TS, 20, /*miners=*/5);
    const Bytes fallback = dash::pubkey_hash_to_script2(h160(0xfe));
    const auto r = dash::pplns::compute_payouts(chain, tip, 100, SUBSIDY, fallback, 20);
    EXPECT_FALSE(r.used_fallback) << "v36 shares carry the weight fields";
    EXPECT_EQ(r.shares_used, 25u);
    uint64_t sum = 0;
    size_t miners = 0;
    for (const auto& po : r.payouts) {
        sum += po.amount;
        for (uint8_t m = 0; m < 5; ++m)
            if (po.script == dash::pubkey_hash_to_script2(h160(0x10 + m))) ++miners;
    }
    EXPECT_EQ(miners, 5u);
    EXPECT_EQ(sum, SUBSIDY);
}
