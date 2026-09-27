// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH v36 live-variant KATs: the private/isolated DASH v36 sharechain holds
// DashV36Share in the LIVE share type (dash::ShareType), end to end — wire load,
// node receive, tracker verify (share_init_verify / verify_version_transition /
// verify_payout_commitment dispatched by type), LevelDB persist and reload,
// won-block reconstruction — while the public network keeps master's exact
// behaviour.
//
// What is pinned:
//   A. Public network: a wire-type-36 share throws the SAME std::invalid_argument
//      with the SAME text from the SAME loader as master
//      (chain::ShareVariants<DashFormatter, DashShare>::load,
//      src/sharechain/share.hpp). The isolated identity loads it.
//   B. Isolated, chain speaking v36: two v36 shares go node receive
//      (processing_shares) -> tracker verify -> LevelDB -> a second node reloads
//      them verified, byte-identical.
//   C. Storage row of a v36 share: [LE64 36][v36 wire]; reload round-trips; the
//      public identity refuses the row with master's text.
//   D. A chain admits exactly the type it speaks (CoinParams::current_share_version):
//      v16 is rejected on the v36 chain at the tracker / admit_share / verify_share
//      and at node receive; v36 is rejected on a chain still speaking v16
//      (today's isolated chain until the flip slice); persisted rows of the other
//      type are skipped on reload.
//   E. No mixed-type chain on either profile; genesis v36 and 36-on-36 are
//      admitted without a vote; v36 votes are tallied.
//   F. The v36 PPLNS window over the LIVE tracker reads the key think() primes,
//      and the producer's coinbase == the verifier's coinbase over it; a child
//      whose coinbase mis-pays the window is rejected by attempt_verify.
//   G. A won v36 share reconstructs to its coinbase-only block.
//
// Folded into test_dash_node (needs dash::NodeImpl + c2pool_storage). The
// private/isolated profile is keyed on the process-global SharechainConfig
// identity; IdentityGuard resets it around every test.

#include <gtest/gtest.h>

#include <impl/dash/chain_admit.hpp>
#include <impl/dash/coin/reconstruct_won_block.hpp>
#include <impl/dash/config.hpp>
#include <impl/dash/config_pool.hpp>
#include <impl/dash/node.hpp>
#include <impl/dash/params.hpp>
#include <impl/dash/pplns_v36.hpp>
#include <impl/dash/share.hpp>
#include <impl/dash/share_chain.hpp>
#include <impl/dash/share_check.hpp>
#include <impl/dash/share_producer.hpp>
#include <impl/dash/share_tracker.hpp>
#include <impl/dash/version_negotiation.hpp>
#include "dash_v36_share_fixture.hpp"   // make_canonical_v36

#include <c2pool/storage/sharechain_storage.hpp>
#include <core/coin_params.hpp>
#include <core/filesystem.hpp>
#include <core/hash.hpp>
#include <core/netaddress.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <sharechain/share.hpp>

#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

namespace fs = std::filesystem;
using dash::SharechainConfig;
using Bytes = std::vector<unsigned char>;

constexpr const char* ISO_ID  = "d3a5c0920263617";   // any custom id => isolated v36
constexpr const char* ISO_PFX = "0badc0ffee11";
constexpr uint32_t PAST_TS   = 1700000000u;
constexpr uint64_t NONCE64   = 0x0807060504030201ull;
constexpr uint64_t SUBSIDY   = 500000000ull;
constexpr uint32_t EASY_BITS = 0x2000ffffu;   // target 0x00ffff00.. (~1/256 X11 hashes)

// The unknown-wire-type text, frozen from master src/sharechain/share.hpp
// (ShareVariants::load). The public network must keep throwing exactly this.
constexpr const char* MASTER_UNKNOWN_TYPE_TEXT = "ShareVariants::unpack -- version unsupported!";

struct IdentityGuard {
    IdentityGuard()  { SharechainConfig::reset_network_id(); SharechainConfig::is_testnet = false; }
    ~IdentityGuard() { SharechainConfig::reset_network_id(); SharechainConfig::is_testnet = false; }
};

// Per-test data dir (the process-wide --data-dir seam), restored afterwards.
struct DataDirGuard {
    fs::path prev;
    fs::path root;
    explicit DataDirGuard(const std::string& tag)
        : prev(core::filesystem::data_dir_override())
    {
        root = fs::temp_directory_path()
            / (tag + "_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::error_code ec;
        fs::remove_all(root, ec);
        fs::create_directories(root);
        core::filesystem::set_data_dir(root);
    }
    ~DataDirGuard()
    {
        core::filesystem::set_data_dir(prev);
        std::error_code ec;
        fs::remove_all(root, ec);
    }
};

core::CoinParams easy(core::CoinParams p) {
    p.max_target.SetHex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    return p;
}

core::CoinParams public_params() {
    SharechainConfig::reset_network_id();
    return easy(dash::make_coin_params(false));
}

// Private/isolated identity. `speaks` = the share version the chain mints and
// admits (current_share_version): 16 = the isolated chain today (before the
// flip slice), 36 = after it.
core::CoinParams iso_params(uint32_t speaks) {
    SharechainConfig::reset_network_id();
    SharechainConfig::set_network_id(ISO_ID, ISO_PFX);
    auto p = easy(dash::make_coin_params(false));
    p.current_share_version = speaks;
    return p;
}

uint160 h160(uint8_t b) { return uint160(Bytes(20, b)); }

uint256 tag_hash(uint8_t tag) {
    Bytes v(32, 0x00);
    v[0] = tag; v[30] = 0x5e; v[31] = 0x36;
    return uint256(v);
}

bitcoin_family::coin::SmallBlockHeaderType header(uint32_t nonce) {
    bitcoin_family::coin::SmallBlockHeaderType h;
    h.m_version = 536870912;
    h.m_previous_block.SetHex("00000000000000000000000000000000000000000000000000000000000000aa");
    h.m_timestamp = PAST_TS + 5;
    h.m_bits = 0x1b00ffffu;   // block target far harder than the share target: not a block
    h.m_nonce = nonce;
    return h;
}

dash::producer::ProspectiveShareInfo info(const uint256& prev, uint32_t absheight,
                                          uint8_t pkh, uint64_t desired) {
    dash::producer::ProspectiveShareInfo i;
    i.prev_hash = prev;
    i.coinbase = {0x03, 0x01, 0x02, 0x03};
    i.nonce = 7;
    i.pubkey_hash = h160(pkh);
    i.subsidy = SUBSIDY;
    i.donation = 0;
    i.desired_version = desired;
    i.max_bits = EASY_BITS;
    i.bits = EASY_BITS;
    i.timestamp = PAST_TS + absheight;
    i.absheight = absheight;
    i.abswork = uint128(0x10001ull * absheight);
    return i;
}

// Grind the header nonce until the X11 share hash meets the share target, then
// build once more with the full verifier (check_pow=true) — the producer's
// mandatory self-verify is the share_init_verify of the share's own type.
template <typename Build>
auto grind(Build&& build) {
    for (uint32_t n = 0; n < 1000000; ++n) {
        const auto hdr = header(n);
        auto b = build(hdr, false);
        if (!(b.share.m_hash > chain::bits_to_target(b.share.m_bits)))
            return build(hdr, true);
    }
    throw std::runtime_error("grind: no header nonce met the share target");
}

dash::producer::BuiltV36Share mine_v36(dash::ShareChain& chain, const core::CoinParams& p,
                                       const dash::producer::ProspectiveShareInfo& i) {
    return grind([&](const auto& h, bool pow) {
        return dash::producer::build_share_v36(chain, p, i, h, NONCE64, pow);
    });
}

dash::producer::BuiltShare mine_v16(dash::ShareChain& chain, const core::CoinParams& p,
                                    const dash::producer::ProspectiveShareInfo& i) {
    return grind([&](const auto& h, bool pow) {
        return dash::producer::build_share(chain, p, i, h, NONCE64, pow);
    });
}

Bytes to_bytes(PackStream& ps) {
    const auto* b = reinterpret_cast<const unsigned char*>(ps.data());
    return Bytes(b, b + ps.size());
}

template <typename S>
Bytes wire_of(S s) {   // by value: DashFormatter::Write takes a mutable pointer
    PackStream ps;
    dash::DashFormatter::Write(ps, &s);
    return to_bytes(ps);
}

Bytes wire_of_variant(dash::ShareType& v) {
    PackStream ps;
    v.Serialize(ps);
    return to_bytes(ps);
}

dash::ShareType load(uint64_t type, const Bytes& b) {
    chain::RawShare r(type, PackStream(b));
    return dash::load_share(r, NetService{"test", 0});
}

template <typename F>
std::string invalid_arg_text(F&& fn) {
    try { fn(); }
    catch (const std::invalid_argument& e) { return e.what(); }
    catch (const std::exception& e) { return std::string("<other exception: ") + e.what() + ">"; }
    return "<no exception>";
}

template <typename S>
dash::ShareType var_of(const S& s) {
    dash::ShareType v;
    v = new S(s);
    return v;
}

// NodeImpl with two test probes: hold the think slot (so no think() cycle runs
// and the receive path's own admission is observed alone — think() would
// otherwise drop an unverifiable share from the chain afterwards), and read the
// node's LevelDB store.
struct ProbeNode : dash::NodeImpl {
    using dash::NodeImpl::NodeImpl;
    void hold_think_slot(bool hold) { m_think_running.store(hold); if (!hold) m_rethink_pending.store(false); }
    bool think_slot_held() const { return m_think_running.load(); }
    bool stored(const uint256& h) { return m_storage && m_storage->has_share(h); }
};

// A real ctx-bound dash::NodeImpl over an identity-scoped LevelDB: the node
// receive path (processing_shares -> verify pool -> add_verified_shares on the
// io_context) and the persisted-share load (init_storage).
struct LiveNode {
    boost::asio::io_context ioc;
    dash::Config cfg;
    std::unique_ptr<ProbeNode> node;

    LiveNode(const core::CoinParams& p, const std::string& sub)
        : cfg("dash-v36-live-kat")
    {
        node = std::make_unique<ProbeNode>(&ioc, &cfg);
        node->tracker().m_coin_params = p;   // before init_storage, as main_dash does
        fs::create_directories(core::filesystem::config_path() / sub);
        node->init_storage(sub);
    }

    ~LiveNode()
    {
        if (node) {
            node->join_compute_pools();
            node->hold_think_slot(false);
            node->shutdown_persistence();
        }
        node.reset();
    }

    // Wire bytes -> load_share (the peer message path) -> processing_shares.
    void receive(const std::vector<std::pair<uint64_t, Bytes>>& wires)
    {
        const NetService from{"127.0.0.1", 18999};
        dash::HandleSharesData data;
        for (const auto& [type, bytes] : wires) {
            chain::RawShare r(type, PackStream(bytes));
            data.add(dash::load_share(r, from), {});
        }
        node->processing_shares(data, from);
    }

    template <typename Pred>
    bool pump_until(Pred&& pred)
    {
        for (int i = 0; i < 400; ++i) {
            ioc.restart();
            ioc.run_for(std::chrono::milliseconds(20));
            auto g = node->read_tracker();
            if (g && pred(*g))
                return true;
        }
        return false;
    }

    // Stop the verify/think pools: the tracker is quiescent afterwards.
    dash::ShareTracker& quiesce()
    {
        node->join_compute_pools();
        return node->tracker();
    }
};

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// A. The load gate
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36LiveVariant, PublicTypeThirtySixThrowsExactlyAsMasterAndIsolatedLoadsIt)
{
    IdentityGuard guard;
    static_assert(std::is_same_v<dash::PublicShareType,
                                 chain::ShareVariants<dash::DashFormatter, dash::DashShare>>,
                  "the public loader must be master's variant, unchanged");
    static_assert(std::is_same_v<dash::ShareType,
                                 chain::ShareVariants<dash::DashFormatter, dash::DashShare,
                                                      dash::DashV36Share>>,
                  "the live variant holds both DASH share types, DashShare first");

    const Bytes w36 = wire_of(make_canonical_v36());
    dash::DashShare v16;
    v16.m_coinbase = BaseScript(Bytes{0xab, 0xcd});
    v16.m_desired_version = 16;
    v16.m_bits = 0x1d00ffffu;
    v16.m_hash_link.m_state.m_data.assign(32, 0x00);
    const Bytes w16 = wire_of(v16);

    // ── public network ──
    ASSERT_FALSE(SharechainConfig::isolated_v36());
    EXPECT_EQ(invalid_arg_text([&] { auto s = load(36, w36); s.destroy(); }), MASTER_UNKNOWN_TYPE_TEXT);
    // The same text an arbitrary unknown type gets: the generic load-map miss,
    // not a new DASH-specific message.
    EXPECT_EQ(invalid_arg_text([&] { auto s = load(17, w36); s.destroy(); }), MASTER_UNKNOWN_TYPE_TEXT);
    // Same site: master's loader called directly throws the identical text.
    EXPECT_EQ(invalid_arg_text([&] {
                  chain::RawShare r(uint64_t{36}, PackStream(w36));
                  auto st = r.contents.as_stream();
                  auto s = chain::ShareVariants<dash::DashFormatter, dash::DashShare>::load(36, st);
                  s.destroy();
              }),
              MASTER_UNKNOWN_TYPE_TEXT);
    {
        auto s = load(16, w16);   // v16 unchanged
        EXPECT_EQ(s.version(), 16);
        EXPECT_EQ(wire_of_variant(s), w16);
        s.destroy();
    }

    // ── private/isolated v36 sharechain ──
    SharechainConfig::set_network_id(ISO_ID, ISO_PFX);
    ASSERT_TRUE(SharechainConfig::isolated_v36());
    {
        auto s = load(36, w36);
        EXPECT_EQ(s.version(), 36);
        EXPECT_EQ(wire_of_variant(s), w36) << "v36 re-serialization must round-trip";
        s.invoke([](auto* obj) {
            using T = std::remove_pointer_t<decltype(obj)>;
            EXPECT_TRUE((std::is_same_v<T, dash::DashV36Share>));
            EXPECT_EQ(obj->peer_addr.to_string(), NetService("test", 0).to_string());
        });
        s.destroy();
    }
    {
        auto s = load(16, w16);   // the pre-flip isolated chain still parses v16
        EXPECT_EQ(s.version(), 16);
        s.destroy();
    }
    EXPECT_EQ(invalid_arg_text([&] { auto s = load(17, w36); s.destroy(); }), MASTER_UNKNOWN_TYPE_TEXT);
}

// ═════════════════════════════════════════════════════════════════════════════
// B. End to end on the isolated chain speaking v36
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36LiveVariant, IsolatedEndToEndReceiveVerifyPersistReload)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_v36_live_e2e");
    const auto p = iso_params(36);
    const std::string sub = SharechainConfig::data_subdir(false);

    dash::ShareChain scratch;
    const auto gen = mine_v36(scratch, p, info(uint256(), 1, 0xaa, 36));
    scratch.add(new dash::DashV36Share(gen.share));
    const auto child = mine_v36(scratch, p, info(gen.share.m_hash, 2, 0xbb, 36));
    const uint256 hg = gen.share.m_hash, hc = child.share.m_hash;
    const Bytes wg = wire_of(gen.share), wc = wire_of(child.share);

    {
        LiveNode n(p, sub);
        n.receive({{36, wg}, {36, wc}});
        ASSERT_TRUE(n.pump_until([&](dash::ShareTracker& t) {
            return t.chain.contains(hg) && t.chain.contains(hc);
        })) << "both v36 shares must be admitted by the node receive path";

        auto& t = n.quiesce();
        EXPECT_EQ(t.chain.get_share(hg).version(), 36);
        EXPECT_EQ(t.chain.get_share(hc).version(), 36);
        // Tracker verify: phase 0 type, phase 1 share_init_verify(DashV36Share),
        // phase 2 verify_version_transition(DashV36Share), phase 3 the v36
        // payout commitment over the live tracker.
        EXPECT_TRUE(t.attempt_verify(hg));
        EXPECT_TRUE(t.attempt_verify(hc));
        EXPECT_TRUE(t.verified.contains(hg));
        EXPECT_TRUE(t.verified.contains(hc));
        EXPECT_EQ(t.verified.size(), 2u);
        EXPECT_EQ(dash::generate_share_transaction(child.share, t, p), child.gentx_hash);
        n.node->shutdown_persistence();
    }   // LevelDB closed

    {
        LiveNode n2(p, sub);   // init_storage -> load_persisted_shares
        auto& t = n2.quiesce();
        ASSERT_TRUE(t.chain.contains(hg));
        ASSERT_TRUE(t.chain.contains(hc));
        EXPECT_TRUE(t.verified.contains(hg)) << "is_verified flag persisted";
        EXPECT_TRUE(t.verified.contains(hc)) << "is_verified flag persisted";
        EXPECT_EQ(t.chain.get_share(hg).version(), 36);
        EXPECT_EQ(t.chain.get_share(hc).version(), 36);
        EXPECT_EQ(wire_of_variant(t.chain.get_share(hg)), wg);
        EXPECT_EQ(wire_of_variant(t.chain.get_share(hc)), wc);
        EXPECT_EQ(t.chain.get_share(hc).prev_hash(), hg);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// C. Storage row of a v36 share
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36LiveVariant, StorageBatchEntryAndReloadPreserveV36Bytes)
{
    IdentityGuard guard;
    (void)iso_params(36);
    auto v = make_canonical_v36();
    v.m_hash = tag_hash(0x42);
    const Bytes wire = wire_of(v);

    dash::NodeImpl node;   // rig-free
    auto var = var_of(v);
    std::vector<c2pool::storage::SharechainStorage::ShareBatchEntry> out;
    node.collect_share_batch_entry(var, out);
    var.destroy();
    ASSERT_EQ(out.size(), 1u);

    std::vector<uint8_t> expect(8, 0);
    const uint64_t ver = 36;
    std::memcpy(expect.data(), &ver, 8);
    expect.insert(expect.end(), wire.begin(), wire.end());
    EXPECT_EQ(out[0].serialized_data, expect) << "row = [LE64 36][v36 wire]";
    EXPECT_EQ(out[0].hash, v.m_hash);
    EXPECT_EQ(out[0].prev_hash, v.m_prev_hash);
    EXPECT_EQ(out[0].height, v.m_absheight);
    EXPECT_EQ(out[0].timestamp, v.m_timestamp);
    EXPECT_EQ(out[0].target, chain::bits_to_target(v.m_bits));

    // Reload exactly as load_persisted_shares does.
    uint64_t row_ver = 0;
    std::memcpy(&row_ver, out[0].serialized_data.data(), 8);
    EXPECT_EQ(row_ver, 36u);
    const Bytes tail(out[0].serialized_data.begin() + 8, out[0].serialized_data.end());
    {
        auto s = load(row_ver, tail);
        EXPECT_EQ(s.version(), 36);
        EXPECT_EQ(wire_of_variant(s), wire);
        s.destroy();
    }
    // The public identity refuses the same row with master's text.
    SharechainConfig::reset_network_id();
    EXPECT_EQ(invalid_arg_text([&] { auto s = load(row_ver, tail); s.destroy(); }), MASTER_UNKNOWN_TYPE_TEXT);
}

// ═════════════════════════════════════════════════════════════════════════════
// D. A chain admits exactly the type it speaks
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36LiveVariant, ChainSpeakingV36RejectsV16AtEveryGate)
{
    IdentityGuard guard;
    const auto p16 = iso_params(16);
    dash::ShareChain scratch;
    const auto s16 = mine_v16(scratch, p16, info(uint256(), 1, 0xaa, 16)).share;
    const auto p36 = iso_params(36);
    const uint64_t CL = SharechainConfig::chain_length();
    const std::string not16 = "share type v16 not admitted: this sharechain speaks v36";
    const std::string not36 = "share type v36 not admitted: this sharechain speaks v16";

    EXPECT_EQ(invalid_arg_text([&] { dash::check_share_type_admitted(16, p36); }), not16);
    EXPECT_NO_THROW(dash::check_share_type_admitted(36, p36));

    {   // tracker verify
        dash::ShareTracker t;
        t.m_coin_params = p36;
        t.add(var_of(s16));
        EXPECT_FALSE(t.attempt_verify(s16.m_hash));
        EXPECT_FALSE(t.verified.contains(s16.m_hash));
        EXPECT_EQ(t.verified.size(), 0u);
    }
    {   // single-call admission seams
        dash::ShareChain ch;
        EXPECT_EQ(invalid_arg_text([&] { dash::admit_share(s16, ch, p36, CL); }), not16);
        EXPECT_EQ(invalid_arg_text([&] { dash::verify_share(s16, ch, CL, p36); }), not16);
    }

    // Mirror: the SAME valid v16 share on a chain speaking v16 (the isolated
    // chain today, and the public network) is admitted — it is rejected above
    // only for its type.
    {
        dash::ShareTracker t;
        t.m_coin_params = p16;
        t.add(var_of(s16));
        EXPECT_TRUE(t.attempt_verify(s16.m_hash));
        dash::ShareChain ch;
        EXPECT_EQ(dash::admit_share(s16, ch, p16, CL), s16.m_hash);
    }
    EXPECT_EQ(invalid_arg_text([&] { dash::check_share_type_admitted(36, p16); }), not36);

    const auto pp = public_params();
    EXPECT_EQ(pp.current_share_version, 16u);
    EXPECT_NO_THROW(dash::check_share_type_admitted(16, pp));
    EXPECT_EQ(invalid_arg_text([&] { dash::check_share_type_admitted(36, pp); }), not36);

    // A default-constructed CoinParams (unconfigured) admits the v16 baseline only.
    const core::CoinParams unset;
    EXPECT_NO_THROW(dash::check_share_type_admitted(16, unset));
    EXPECT_EQ(invalid_arg_text([&] { dash::check_share_type_admitted(36, unset); }), not36);
}

TEST(DashV36LiveVariant, NodeReceiveAdmitsOnlyTheTypeTheChainSpeaks)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_v36_live_rx");
    const auto p16 = iso_params(16);
    dash::ShareChain scratch16;
    const auto s16 = mine_v16(scratch16, p16, info(uint256(), 1, 0xaa, 16)).share;
    const auto p36 = iso_params(36);
    dash::ShareChain scratch36;
    const auto s36 = mine_v36(scratch36, p36, info(uint256(), 1, 0xbb, 36)).share;
    const std::string sub = SharechainConfig::data_subdir(false);

    // think() is held off so the receive path's admission is observed alone:
    // the other-type share is never added to the chain nor written to LevelDB.
    {   // chain speaking v36: the v36 share lands, the v16 share of the same batch does not
        LiveNode n(p36, sub + "_36");
        n.node->hold_think_slot(true);
        n.receive({{36, wire_of(s36)}, {16, wire_of(s16)}});
        ASSERT_TRUE(n.pump_until([&](dash::ShareTracker& t) { return t.chain.contains(s36.m_hash); }));
        EXPECT_TRUE(n.node->think_slot_held());
        auto& t = n.quiesce();
        EXPECT_FALSE(t.chain.contains(s16.m_hash));
        EXPECT_EQ(t.chain.size(), 1u);
        EXPECT_TRUE(n.node->stored(s36.m_hash));
        EXPECT_FALSE(n.node->stored(s16.m_hash));
    }
    {   // chain speaking v16 (the isolated chain before the flip): the reverse
        LiveNode n(p16, sub + "_16");
        n.node->hold_think_slot(true);
        n.receive({{16, wire_of(s16)}, {36, wire_of(s36)}});
        ASSERT_TRUE(n.pump_until([&](dash::ShareTracker& t) { return t.chain.contains(s16.m_hash); }));
        auto& t = n.quiesce();
        EXPECT_FALSE(t.chain.contains(s36.m_hash));
        EXPECT_EQ(t.chain.size(), 1u);
        EXPECT_TRUE(n.node->stored(s16.m_hash));
        EXPECT_FALSE(n.node->stored(s36.m_hash));
    }
}

TEST(DashV36LiveVariant, PersistedRowsOfAnotherTypeAreSkippedOnReload)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_v36_live_reload");
    const auto p16 = iso_params(16);
    dash::ShareChain scratch;
    const auto s16 = mine_v16(scratch, p16, info(uint256(), 1, 0xaa, 16)).share;
    const auto p36 = iso_params(36);
    const std::string sub = SharechainConfig::data_subdir(false);

    {   // the isolated chain before the flip persists a v16 share
        LiveNode n(p16, sub);
        n.receive({{16, wire_of(s16)}});
        ASSERT_TRUE(n.pump_until([&](dash::ShareTracker& t) { return t.chain.contains(s16.m_hash); }));
        n.quiesce();
    }
    {   // after the flip the same identity-scoped DB is opened speaking v36: skipped
        LiveNode n(p36, sub);
        auto& t = n.quiesce();
        EXPECT_FALSE(t.chain.contains(s16.m_hash));
        EXPECT_EQ(t.chain.size(), 0u);
    }
    {   // the row is really there: speaking v16 loads it
        LiveNode n(p16, sub);
        auto& t = n.quiesce();
        EXPECT_TRUE(t.chain.contains(s16.m_hash));
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// E. One sharechain, one share type; the v36 chain needs no vote
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36LiveVariant, MixedTypeChainImpossibleOnBothProfiles)
{
    IdentityGuard guard;
    const uint64_t CL = SharechainConfig::chain_length();
    dash::ShareChain ch;
    {
        auto* g36 = new dash::DashV36Share();
        g36->m_hash = tag_hash(1);
        g36->m_bits = g36->m_max_bits = 0x1d00ffffu;
        g36->m_desired_version = 36;
        ch.add(g36);
        auto* g16 = new dash::DashShare();
        g16->m_hash = tag_hash(2);
        g16->m_bits = g16->m_max_bits = 0x1d00ffffu;
        g16->m_desired_version = 16;
        ch.add(g16);
    }

    dash::DashShare c16;             // v16 on a v36 parent
    c16.m_prev_hash = tag_hash(1);
    c16.m_desired_version = 16;
    EXPECT_EQ(invalid_arg_text([&] { dash::verify_version_transition(c16, ch, CL); }),
              "mixed share types on one sharechain: v16 share on a v36 parent");
    EXPECT_EQ(invalid_arg_text([&] { dash::admit_chain_relative(c16, ch, CL); }),
              "mixed share types on one sharechain: v16 share on a v36 parent");

    dash::DashV36Share c36;          // v36 on a v16 parent
    c36.m_prev_hash = tag_hash(2);
    c36.m_desired_version = 36;
    EXPECT_EQ(invalid_arg_text([&] { dash::verify_version_transition(c36, ch, CL); }),
              "mixed share types on one sharechain: v36 share on a v16 parent");

    // Genesis v36 and 36 on 36: admitted with no history and no vote.
    dash::DashV36Share gen;
    gen.m_desired_version = 36;
    EXPECT_NO_THROW(dash::verify_version_transition(gen, ch, CL));
    dash::DashV36Share c36ok;
    c36ok.m_prev_hash = tag_hash(1);
    c36ok.m_desired_version = 36;
    EXPECT_NO_THROW(dash::verify_version_transition(c36ok, ch, CL));
    EXPECT_NO_THROW(dash::admit_chain_relative(c36ok, ch, CL));
    // ...while the v16 overload gates the SAME vote shape (a 36 vote on a 16
    // parent) behind the successor-history rule: the public path is unchanged.
    dash::DashShare up;
    up.m_prev_hash = tag_hash(2);
    up.m_desired_version = 36;
    EXPECT_EQ(invalid_arg_text([&] { dash::verify_version_transition(up, ch, CL); }),
              "version switch without enough history");
    // v16 on v16 (the public chain): admitted.
    dash::DashShare c16ok;
    c16ok.m_prev_hash = tag_hash(2);
    c16ok.m_desired_version = 16;
    EXPECT_NO_THROW(dash::verify_version_transition(c16ok, ch, CL));
}

TEST(DashV36LiveVariant, VersionTallyCountsV36Votes)
{
    dash::ShareChain ch;
    uint256 prev;
    for (uint8_t i = 1; i <= 3; ++i) {
        auto* s = new dash::DashV36Share();
        s->m_hash = tag_hash(i);
        s->m_prev_hash = prev;
        s->m_bits = s->m_max_bits = 0x1d00ffffu;
        s->m_desired_version = 36;
        ch.add(s);
        prev = s->m_hash;
    }
    namespace vn = dash::version_negotiation;
    const auto counts = vn::get_desired_version_counts(ch, prev, 3);
    ASSERT_EQ(counts.size(), 1u);
    EXPECT_EQ(counts.at(36), 3u);
    const auto weights = vn::get_desired_version_weights(ch, prev, 3);
    ASSERT_EQ(weights.size(), 1u);
    EXPECT_TRUE(vn::v36_active(weights));
}

// ═════════════════════════════════════════════════════════════════════════════
// F. v36 PPLNS window + payout commitment over the LIVE tracker
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36LiveVariant, V36WindowOverLiveTrackerUsesPrimedCacheKey)
{
    IdentityGuard guard;
    const auto p = iso_params(36);
    const int32_t CL = static_cast<int32_t>(SharechainConfig::chain_length());

    dash::ShareTracker t;
    t.m_coin_params = p;
    auto add = [&](uint8_t tag, const uint256& prev, uint32_t bits, uint8_t pkh, uint16_t don) {
        auto* s = new dash::DashV36Share();
        s->m_hash = tag_hash(tag);
        s->m_prev_hash = prev;
        s->m_bits = bits;
        s->m_max_bits = 0x1d00ffffu;
        s->m_pubkey_hash = h160(pkh);
        s->m_donation = don;
        s->m_desired_version = 36;
        const uint256 h = s->m_hash;
        t.chain.add(s);
        return h;
    };
    const auto g  = add(1, uint256(), 0x1d00ffffu, 0xaa, 0);
    const auto s1 = add(2, g,         0x1c00ffffu, 0xbb, 0x0100);
    const auto s2 = add(3, s1,        0x1b00ffffu, 0xcc, 0);

    // think() Phase 2 primes the cache for a v36 share from the HeadPPLNS ring
    // under (prev_hash, CHAIN_LENGTH, unlimited) (share_tracker.hpp
    // prime_pplns_cache). Fill the cache under exactly that key, and pin the
    // premise that the ring equals the walk.
    dash::HeadPPLNS hp;
    hp.rebuild(t.chain, s2, CL);
    const dash::CumulativeWeights ring = hp.weights();
    const dash::CumulativeWeights w =
        t.get_v36_decayed_cumulative_weights(s2, CL, dash::v36_pplns::unlimited_weight());

    const auto free_walk = dash::v36_pplns_window(t.chain, s2);
    EXPECT_EQ(ring.weights, free_walk.weights) << "ring == walk (the cache-priming premise)";
    EXPECT_EQ(ring.total_weight, free_walk.total_weight);
    EXPECT_EQ(ring.total_donation_weight, free_walk.total_donation_weight);
    EXPECT_EQ(w.weights, ring.weights);
    EXPECT_EQ(w.weights.size(), 3u);

    // Producer (free walk over the chain) == verifier (live tracker).
    const auto built = dash::producer::build_share_v36(t.chain, p, info(s2, 4, 0xdd, 36),
                                                       header(0), NONCE64, /*check_pow=*/false);
    dash::coin::GentxCoinbase gc;
    EXPECT_EQ(dash::generate_share_transaction(built.share, t, p, &gc), built.gentx_hash);
    EXPECT_EQ(Hash(std::span<const unsigned char>(gc.bytes.data(), gc.bytes.size())), built.gentx_hash);
    EXPECT_NO_THROW(dash::verify_payout_commitment(built.share, t, p, built.gentx_hash));
    EXPECT_NE(invalid_arg_text([&] { dash::verify_payout_commitment(built.share, t, p, tag_hash(9)); })
                  .find("GENTX-MISMATCH"),
              std::string::npos);

    // The tracker form reads the primed key: change a window share WITHOUT
    // invalidating the cache -> the tracker still answers the primed value.
    t.chain.get_share(s1).invoke([](auto* obj) { obj->m_donation = 0x4000; });
    EXPECT_EQ(t.v36_pplns_window(s2).total_donation_weight, w.total_donation_weight);
    EXPECT_NE(dash::v36_pplns_window(t.chain, s2).total_donation_weight, w.total_donation_weight);
}

TEST(DashV36LiveVariant, LiveTrackerRejectsV36ChildWhoseCoinbaseMisPaysTheWindow)
{
    IdentityGuard guard;
    const auto p = iso_params(36);
    const uint64_t CL = SharechainConfig::chain_length();

    dash::ShareChain honest;
    const auto gen = mine_v36(honest, p, info(uint256(), 1, 0xaa, 36));
    honest.add(new dash::DashV36Share(gen.share));
    const auto good = mine_v36(honest, p, info(gen.share.m_hash, 2, 0xbb, 36));

    // A child built over a forged view of the same parent (miner 0xee instead of
    // 0xaa): valid PoW and hash_link, but its coinbase pays the wrong window.
    dash::ShareChain forged;
    {
        auto* fg = new dash::DashV36Share(gen.share);
        fg->m_pubkey_hash = h160(0xee);
        forged.add(fg);
    }
    const auto bad = mine_v36(forged, p, info(gen.share.m_hash, 2, 0xbb, 36));
    ASSERT_NE(bad.gentx_hash, good.gentx_hash);

    dash::ShareTracker t;
    t.m_coin_params = p;
    t.add(var_of(gen.share));
    t.add(var_of(bad.share));
    t.add(var_of(good.share));
    EXPECT_EQ(dash::admit_share(gen.share, t.chain, p, CL), gen.share.m_hash);
    EXPECT_TRUE(t.attempt_verify(gen.share.m_hash));
    EXPECT_FALSE(t.attempt_verify(bad.share.m_hash)) << "GENTX-MISMATCH on the live tracker";
    EXPECT_TRUE(t.attempt_verify(good.share.m_hash));
}

// ═════════════════════════════════════════════════════════════════════════════
// G. Won-block reconstruction from a v36 share
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36LiveVariant, WonBlockReconstructsFromV36Share)
{
    IdentityGuard guard;
    const auto p = iso_params(36);

    dash::ShareChain scratch;
    const auto gen = mine_v36(scratch, p, info(uint256(), 1, 0xaa, 36));
    scratch.add(new dash::DashV36Share(gen.share));
    const auto child = mine_v36(scratch, p, info(gen.share.m_hash, 2, 0xbb, 36));

    dash::ShareTracker t;
    t.m_coin_params = p;
    t.add(var_of(gen.share));
    t.add(var_of(child.share));

    const auto r = dash::coin::reconstruct_won_block(child.share.m_hash, child.share, t, p);
    ASSERT_TRUE(r.has_value());
    dash::coin::GentxCoinbase gc;
    ASSERT_EQ(dash::generate_share_transaction(child.share, t, p, &gc), child.gentx_hash);

    const Bytes& b = r->bytes;
    ASSERT_EQ(b.size(), 80u + 1u + gc.bytes.size()) << "coinbase-only block";
    EXPECT_EQ(b[80], 1u) << "one transaction";
    EXPECT_TRUE(std::equal(gc.bytes.begin(), gc.bytes.end(), b.begin() + 81));
    PackStream txid_ps;
    txid_ps << gc.txid;
    const Bytes txid_wire = to_bytes(txid_ps);
    ASSERT_EQ(txid_wire.size(), 32u);
    EXPECT_EQ(Bytes(b.begin() + 36, b.begin() + 68), txid_wire)
        << "merkle_root == gentx txid (empty merkle link)";
    EXPECT_EQ(p.pow_func(std::span<const unsigned char>(b.data(), 80)), child.share.m_hash)
        << "the reconstructed header is the one the share solved";
}
