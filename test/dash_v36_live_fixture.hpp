// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// Shared harness for the private/isolated DASH v36 sharechain node KATs
// (test_dash_v36_live_variant.cpp, test_dash_v36_flip.cpp; both folded into
// test_dash_node): identity / data-dir guards, easy-PoW params, a real X11
// grind over the v16 and v36 producers, wire helpers and a ctx-bound
// dash::NodeImpl over an identity-scoped LevelDB (LiveNode). Everything is in
// an anonymous namespace: each including TU gets its own copy.

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
