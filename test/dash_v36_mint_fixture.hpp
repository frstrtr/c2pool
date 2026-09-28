// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// Mint + handshake harness for the private/isolated DASH v36 sharechain node
// KATs (test_dash_v36_flip.cpp, test_dash_v36_e2e.cpp; both folded into
// test_dash_node), on top of dash_v36_live_fixture.hpp: production isolated
// params with easy PoW, a coinbase-only work template, the miner +
// mining_submit side of one producer job (solve_job: a REAL X11 nonce search
// against the job's committed share target), coinbase output parsing, and the
// loopback version-handshake harness that drives the REAL
// NodeImpl::handle_version (and reads the REAL send_version frame).
// Everything is in an anonymous namespace: each including TU gets its own
// copy.

#include "dash_v36_live_fixture.hpp"

#include <impl/dash/crypto/hash_x11.hpp>
#include <impl/dash/messages.hpp>
#include <impl/dash/mint_runloop.hpp>
#include <impl/bitcoin_family/coin/base_block.hpp>

#include <core/socket.hpp>

#include <boost/asio.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <variant>
#include <vector>

namespace {

using dash::mint::build_producer_job;
using dash::mint::mint_from_inputs;
using dash::mint::mint_from_inputs_any;
using dash::producer::BuiltShare;
using dash::producer::BuiltV36Share;
using MintShareInputs = dash::stratum::DASHWorkSource::MintShareInputs;

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
                    const Bytes& message_data = {},
                    uint32_t max_nonce = 4000000, unsigned threads = 1) {
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
    if (threads <= 1) {
        for (uint32_t n = 0; n < max_nonce; ++n) {
            hdr.m_nonce = n;
            PackStream ps;
            ps << hdr;
            header_bytes = to_bytes(ps);
            pow = dash::crypto::hash_x11(header_bytes.data(), header_bytes.size());
            if (pow <= target) { out.solved = true; break; }
        }
    } else {
        // Same answer as the sequential loop (the LOWEST nonce that meets the
        // target), found by `threads` strided workers: a worker stops once its
        // next nonce is not below the best found so far, so every nonce below
        // the result was checked by some worker.
        std::atomic<uint32_t> best{UINT32_MAX};
        std::vector<std::thread> pool;
        for (unsigned t = 0; t < threads; ++t) {
            pool.emplace_back([&, t] {
                auto h = hdr;
                for (uint32_t n = t; n < max_nonce && n < best.load(); n += threads) {
                    h.m_nonce = n;
                    PackStream ps;
                    ps << h;
                    const Bytes hb = to_bytes(ps);
                    if (dash::crypto::hash_x11(hb.data(), hb.size()) <= target) {
                        uint32_t cur = best.load();
                        while (n < cur && !best.compare_exchange_weak(cur, n)) {}
                        break;
                    }
                }
            });
        }
        for (auto& th : pool) th.join();
        if (best.load() != UINT32_MAX) {
            hdr.m_nonce = best.load();
            PackStream ps;
            ps << hdr;
            header_bytes = to_bytes(ps);
            pow = dash::crypto::hash_x11(header_bytes.data(), header_bytes.size());
            out.solved = true;
        }
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
// "" = admitted (returns a peer type), else the exception text. Runs against a
// caller-owned node and loopback pair: the caller keeps `pair` and `stub`
// alive for as long as `node` (an admitted peer stays in the node's peer table
// with a socket on pair.ioc_node). `peer_addr` (optional) receives the address
// the node saw the peer at.
std::string handshake_on(dash::NodeImpl& node, LoopbackPair& pair, StubCommunicator& stub,
                         uint32_t proto, uint64_t nonce, NetService* peer_addr = nullptr) {
    auto peer = make_socket_peer(pair, stub);
    if (peer_addr) *peer_addr = peer->addr();
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

// Handshake results are exception texts; assert on a substring (no gmock in
// this target).
::testing::AssertionResult has_substr(const std::string& s, const std::string& sub) {
    if (s.find(sub) != std::string::npos) return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure() << "\"" << s << "\" does not contain \"" << sub << "\"";
}

// Reads exactly one wire frame (prefix | command[12] | length u32 LE |
// checksum[4] | payload) off the far end of a loopback pair. Bounded by a
// deadline so a missing write fails the assertion instead of hanging CI;
// returns what arrived (possibly short) on timeout.
Bytes read_one_frame(boost::asio::ip::tcp::socket& s,
                     std::chrono::milliseconds budget = std::chrono::milliseconds(3000)) {
    constexpr std::size_t HDR = 4 + 12 + 4 + 4;
    Bytes buf;
    std::size_t want = HDR;
    const auto deadline = std::chrono::steady_clock::now() + budget;
    s.non_blocking(true);
    while (buf.size() < want && std::chrono::steady_clock::now() < deadline) {
        std::array<unsigned char, 4096> chunk{};
        boost::system::error_code ec;
        const std::size_t n = s.read_some(
            boost::asio::buffer(chunk.data(), std::min(chunk.size(), want - buf.size())), ec);
        if (n > 0) {
            buf.insert(buf.end(), chunk.begin(), chunk.begin() + n);
            if (buf.size() == HDR && want == HDR) {
                uint32_t len = 0;
                std::memcpy(&len, buf.data() + 4 + 12, 4);
                want = HDR + len;
            }
        } else if (ec == boost::asio::error::would_block) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        } else if (ec) {
            break;
        }
    }
    return buf;
}

// The same on a fresh rig-free node, destroyed before its loopback pair.
std::string handshake(uint32_t proto, uint64_t nonce) {
    LoopbackPair pair;
    StubCommunicator stub;
    dash::NodeImpl node;   // rig-free; its ratchet seed is read from the live profile
    return handshake_on(node, pair, stub, proto, nonce);
}

} // namespace
