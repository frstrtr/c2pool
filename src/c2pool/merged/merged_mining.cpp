// SPDX-License-Identifier: AGPL-3.0-or-later
#include "merged_mining.hpp"
#include "aux_chain_params.hpp"
#include <core/coin/mweb_shape.hpp>
#include <core/coin/sigop_cost.hpp>
#include <impl/nmc/coin/aux_expected_index.hpp>  // CAuxPow::getExpectedIndex; leveldb-free

#include <core/log.hpp>
#include <core/hash.hpp>
#include <core/target_utils.hpp>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <set>
#include <thread>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <chrono>

namespace io = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;

namespace c2pool {
namespace merged {

// ─── Hex utilities ───────────────────────────────────────────────────────────

static std::string to_hex(const uint8_t* data, size_t len)
{
    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += H[data[i] >> 4];
        out += H[data[i] & 0x0f];
    }
    return out;
}

static std::string to_hex(const std::vector<uint8_t>& v)
{
    return to_hex(v.data(), v.size());
}

static std::vector<uint8_t> from_hex(const std::string& hex)
{
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(
            std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

static std::string encode_le32(uint32_t v)
{
    uint8_t buf[4];
    buf[0] = v & 0xFF; buf[1] = (v >> 8) & 0xFF;
    buf[2] = (v >> 16) & 0xFF; buf[3] = (v >> 24) & 0xFF;
    return to_hex(buf, 4);
}

// Write uint256 as 32 bytes big-endian hex (MSB first)
static std::string uint256_to_be_hex(const uint256& v)
{
    // uint256 internal bytes are little-endian; reverse for big-endian
    const uint8_t* p = reinterpret_cast<const uint8_t*>(v.pn);
    std::string out;
    out.reserve(64);
    static const char* H = "0123456789abcdef";
    for (int i = 31; i >= 0; --i) {
        out += H[p[i] >> 4];
        out += H[p[i] & 0x0f];
    }
    return out;
}

// Write uint256 as 32 bytes little-endian hex
static std::string uint256_to_le_hex(const uint256& v)
{
    return to_hex(reinterpret_cast<const uint8_t*>(v.pn), 32);
}

// ─── AuxPowTree ──────────────────────────────────────────────────────────────

AuxPowTree AuxPowTree::build(const std::vector<uint32_t>& chain_ids)
{
    AuxPowTree tree;
    if (chain_ids.empty()) {
        tree.size = 0;
        return tree;
    }

    // One slot per distinct chain id: a repeated id would collide with itself
    // at every size and the doubling below would never end.
    const std::set<uint32_t> distinct_ids(chain_ids.begin(), chain_ids.end());

    // Tree size = smallest power of 2 >= chain count
    uint32_t n = static_cast<uint32_t>(distinct_ids.size());
    tree.size = 1;
    while (tree.size < n) tree.size <<= 1;

    // Slots as the aux daemons check them: CAuxPow::getExpectedIndex(nonce,
    // chain_id, h) with h = log2(size) (dogecoin/namecoin auxpow.cpp;
    // "Aux POW wrong index" otherwise), ported in
    // nmc::coin::aux_expected_index. The commitment carries nonce 0
    // (build_auxpow_commitment's default).
    //
    // A collision is resolved by doubling the tree, never by another nonce:
    // for a fixed nonce the slot is an odd-multiplier affine map of
    // chain_id mod 2^h, so two chains share a slot exactly when their ids
    // agree mod 2^h, whatever the nonce.
    for (;;) {
        unsigned height = 0;
        while ((1u << height) < tree.size)
            ++height;
        tree.slot_map.clear();
        bool collision = false;
        std::vector<bool> used(tree.size, false);
        for (uint32_t cid : distinct_ids) {
            const uint32_t slot =
                nmc::coin::aux_expected_index(0, static_cast<int32_t>(cid), height);
            if (used[slot]) {
                collision = true;
                break;
            }
            used[slot] = true;
            tree.slot_map[cid] = slot;
        }
        if (!collision) break;
        // CAuxPow::check refuses a branch longer than 30, and compute_root
        // materializes every leaf: no tree above kMaxHeight.
        if (height >= kMaxHeight) {
            tree.size = 0;
            tree.slot_map.clear();
            return tree;
        }
        tree.size <<= 1;
    }

    return tree;
}

AuxPowTree::MerkleProof AuxPowTree::compute_root(
    const std::map<uint32_t, uint256>& slot_hashes,
    uint32_t target_slot) const
{
    MerkleProof proof;
    proof.index = target_slot;

    if (size == 0) {
        proof.root = uint256();
        return proof;
    }

    // Build leaf layer
    std::vector<uint256> layer(size);
    for (const auto& [slot, hash] : slot_hashes) {
        if (slot < size) layer[slot] = hash;
    }

    // Build merkle tree bottom-up, collecting branch for target_slot
    uint32_t idx = target_slot;
    uint32_t n = size;
    while (n > 1) {
        std::vector<uint256> next_layer(n / 2);
        uint32_t sibling = idx ^ 1;
        if (sibling < n)
            proof.branch.push_back(layer[sibling]);
        for (uint32_t i = 0; i < n; i += 2) {
            next_layer[i / 2] = Hash(layer[i], layer[i + 1]);
        }
        idx >>= 1;
        n >>= 1;
        layer = std::move(next_layer);
    }
    proof.root = layer[0];
    return proof;
}

// ─── AuxPoW commitment ──────────────────────────────────────────────────────

std::vector<uint8_t> build_auxpow_commitment(const uint256& mm_root,
                                              uint32_t tree_size,
                                              uint32_t nonce)
{
    // \xfa\xbe\x6d\x6d + mm_root(32 bytes big-endian) + tree_size(4 LE) + nonce(4 LE)
    std::vector<uint8_t> out;
    out.reserve(44);

    // Magic bytes
    out.push_back(0xfa);
    out.push_back(0xbe);
    out.push_back(0x6d);
    out.push_back(0x6d);

    // MM merkle root — 32 bytes big-endian
    const uint8_t* p = reinterpret_cast<const uint8_t*>(mm_root.pn);
    for (int i = 31; i >= 0; --i)
        out.push_back(p[i]);

    // Tree size — 4 bytes LE
    out.push_back(tree_size & 0xFF);
    out.push_back((tree_size >> 8) & 0xFF);
    out.push_back((tree_size >> 16) & 0xFF);
    out.push_back((tree_size >> 24) & 0xFF);

    // Nonce — 4 bytes LE
    out.push_back(nonce & 0xFF);
    out.push_back((nonce >> 8) & 0xFF);
    out.push_back((nonce >> 16) & 0xFF);
    out.push_back((nonce >> 24) & 0xFF);

    return out;
}

// ─── AuxPoW proof serialization ─────────────────────────────────────────────

// Serialize a Bitcoin-style varint
static std::string varint_hex(uint64_t n)
{
    if (n < 0xfd) {
        uint8_t buf[1] = { static_cast<uint8_t>(n) };
        return to_hex(buf, 1);
    } else if (n <= 0xffff) {
        uint8_t buf[3] = { 0xfd, static_cast<uint8_t>(n & 0xff), static_cast<uint8_t>((n >> 8) & 0xff) };
        return to_hex(buf, 3);
    } else if (n <= 0xffffffff) {
        uint8_t buf[5];
        buf[0] = 0xfe;
        for (int i = 0; i < 4; ++i) buf[1+i] = (n >> (8*i)) & 0xff;
        return to_hex(buf, 5);
    } else {
        uint8_t buf[9];
        buf[0] = 0xff;
        for (int i = 0; i < 8; ++i) buf[1+i] = (n >> (8*i)) & 0xff;
        return to_hex(buf, 9);
    }
}

std::string build_auxpow_proof(
    const std::string& parent_coinbase_hex,
    const uint256& parent_block_hash,
    const std::vector<std::string>& parent_merkle_branch,
    uint32_t parent_merkle_index,
    const std::vector<uint256>& aux_merkle_branch,
    uint32_t aux_merkle_index,
    const std::string& parent_header_hex)
{
    std::ostringstream out;

    // 1. Parent coinbase TX (as a raw tx, no witness)
    out << parent_coinbase_hex;

    // 2. Parent block hash (uint256 LE)
    out << uint256_to_le_hex(parent_block_hash);

    // 3. Parent coinbase merkle branch (count + hashes) + index
    out << varint_hex(parent_merkle_branch.size());
    for (const auto& h : parent_merkle_branch)
        out << h;  // each is 64-char hex (32 bytes)
    out << encode_le32(parent_merkle_index);

    // 4. Aux merkle branch (count + hashes) + index
    out << varint_hex(aux_merkle_branch.size());
    for (const auto& h : aux_merkle_branch)
        out << uint256_to_le_hex(h);
    out << encode_le32(aux_merkle_index);

    // 5. Parent block header (80 bytes)
    out << parent_header_hex;

    return out.str();
}

// ─── Submit verdicts / block size limits ─────────────────────────────────────

std::string SubmitVerdict::label() const
{
    switch (kind) {
    case Kind::accepted:     return "accepted";
    case Kind::duplicate:    return "duplicate";
    case Kind::inconclusive: return "inconclusive";
    case Kind::rejected:     return "rejected: " + reason;
    case Kind::error:        return "error: " + reason;
    case Kind::unknown:      return "unknown: " + reason;
    }
    return "error: " + reason;
}

SubmitVerdict classify_submitblock_result(const nlohmann::json& result)
{
    using K = SubmitVerdict::Kind;
    if (result.is_null())
        return SubmitVerdict::of(K::accepted);
    if (!result.is_string())
        return SubmitVerdict::of(K::rejected, result.dump());
    const std::string r = result.get<std::string>();
    if (r == "duplicate")
        return SubmitVerdict::of(K::duplicate, r);
    // Stored but not connected: not on the best chain (yet). "valid?" is
    // BIP22ValidationResult's answer for a state neither valid nor invalid.
    if (r == "inconclusive" || r == "duplicate-inconclusive" || r == "valid?")
        return SubmitVerdict::of(K::inconclusive, r);
    return SubmitVerdict::of(K::rejected, r.empty() ? std::string("rejected") : r);
}

std::string AuxBlockLimit::check(uint64_t stripped_bytes, uint64_t full_bytes) const
{
    if (max_stripped && stripped_bytes > max_stripped)
        return "stripped size " + std::to_string(stripped_bytes) + " > " + std::to_string(max_stripped);
    if (max_weight && stripped_bytes * 3 + full_bytes > max_weight)
        return "weight " + std::to_string(stripped_bytes * 3 + full_bytes) + " > " + std::to_string(max_weight);
    return {};
}

AuxBlockLimit aux_block_limit(uint32_t chain_id)
{
    if (chain_id == 8225)   // Junkcoin testnet / regtest
        chain_id = 8224;
    for (const auto& p : aux_chain_params_table())
        if (p.chain_id == chain_id)
            return {p.max_stripped_bytes, p.max_weight};
    return {};
}

namespace {
bool read_compact(const std::vector<uint8_t>& b, size_t& p, uint64_t& out)
{
    if (p >= b.size()) return false;
    const uint8_t c = b[p++];
    size_t n = c < 0xfd ? 0 : c == 0xfd ? 2 : c == 0xfe ? 4 : 8;
    if (n == 0) { out = c; return true; }
    if (p + n > b.size()) return false;
    out = 0;
    for (size_t i = 0; i < n; ++i)
        out |= uint64_t(b[p + i]) << (8 * i);
    p += n;
    return true;
}
bool skip(const std::vector<uint8_t>& b, size_t& p, uint64_t n)
{
    if (n > b.size() || p + n > b.size()) return false;
    p += n;
    return true;
}
} // namespace

std::optional<size_t> tx_stripped_size(const std::vector<uint8_t>& b)
{
    // version | [00 01 marker/flag] | vin | vout | [witness] | locktime
    size_t p = 4;
    if (b.size() < 10)
        return std::nullopt;
    const bool witness = b[4] == 0x00 && b[5] == 0x01;
    if (witness)
        p = 6;
    uint64_t n = 0, len = 0;
    if (!read_compact(b, p, n)) return std::nullopt;
    const uint64_t n_in = n;
    for (uint64_t i = 0; i < n_in; ++i)
        if (!skip(b, p, 36) || !read_compact(b, p, len) || !skip(b, p, len) || !skip(b, p, 4))
            return std::nullopt;
    if (!read_compact(b, p, n)) return std::nullopt;
    for (uint64_t i = 0; i < n; ++i)
        if (!skip(b, p, 8) || !read_compact(b, p, len) || !skip(b, p, len))
            return std::nullopt;
    const size_t witness_start = p;
    if (witness)
        for (uint64_t i = 0; i < n_in; ++i) {
            uint64_t items = 0;
            if (!read_compact(b, p, items)) return std::nullopt;
            for (uint64_t k = 0; k < items; ++k)
                if (!read_compact(b, p, len) || !skip(b, p, len))
                    return std::nullopt;
        }
    const size_t witness_bytes = p - witness_start;
    if (!skip(b, p, 4) || p != b.size())
        return std::nullopt;
    return witness ? b.size() - 2 - witness_bytes : b.size();
}

// ─── AuxChainRPC ─────────────────────────────────────────────────────────────

namespace {
using SteadyClock = std::chrono::steady_clock;
constexpr size_t kRpcBodyLimit = 64u * 1024 * 1024;   // a 4 MB-block getblocktemplate fits

bool is_closed_by_peer(const boost::system::error_code& ec)
{
    return ec == http::error::end_of_stream || ec == io::error::eof
        || ec == io::error::connection_reset || ec == io::error::broken_pipe
        || ec == io::error::connection_aborted;
}

// One asynchronous step's outcome. Held by the handler too, so a step that is
// abandoned never writes into a finished call's stack.
struct StepState {
    boost::system::error_code                   ec;
    bool                                        done{false};
    io::ip::tcp::resolver::results_type         endpoints;
    beast::flat_buffer                          buffer;
    http::response_parser<http::string_body>    parser;
};

// Runs `ioc` (owned by the calling thread) until the step is done, the call
// is cancelled or `limit` passes. The step's own deadline (tcp_stream expiry)
// normally ends it first, with beast::error::timeout.
void run_until(io::io_context& ioc, const StepState& st, std::chrono::milliseconds limit,
               const std::atomic<bool>& cancelled)
{
    ioc.restart();
    const auto end = SteadyClock::now() + limit;
    while (!st.done && !cancelled && !ioc.stopped() && SteadyClock::now() < end)
        ioc.run_one_until(end);
}

// A step not done (cancelled, or no handler by the limit): abort it and run
// its handler, so nothing is left pending on the io_context.
void abort_step(io::io_context& ioc, const StepState& st, const std::function<void()>& abort)
{
    abort();
    ioc.restart();
    const auto end = SteadyClock::now() + std::chrono::seconds(2);
    while (!st.done && SteadyClock::now() < end)
        ioc.run_one_until(end);
}

void prepare_request(http::request<http::string_body>& r, const AuxChainConfig& cfg)
{
    r = {http::verb::post, "/", 11};
    r.set(http::field::host, cfg.rpc_host + ":" + std::to_string(cfg.rpc_port));
    r.set(http::field::user_agent, "c2pool-mm/1.0");
    r.set(http::field::content_type, "application/json");
    r.keep_alive(true);
    const auto& up = cfg.rpc_userpass;
    std::string encoded;
    encoded.resize(beast::detail::base64::encoded_size(up.size()));
    auto n = beast::detail::base64::encode(&encoded[0], up.data(), up.size());
    encoded.resize(n);
    r.set(http::field::authorization, "Basic " + encoded);
}
} // namespace

AuxChainRPC::AuxChainRPC(boost::asio::io_context& /*ioc*/, const AuxChainConfig& config)
    : m_config(config), m_client(*this, jsonrpccxx::version::v2)
{
    prepare_request(m_poll.request, m_config);
    prepare_request(m_submit.request, m_config);
}

AuxChainRPC::~AuxChainRPC()
{
    {
        std::lock_guard<std::mutex> lock(m_io_mutex);
        close(m_poll);
    }
    std::lock_guard<std::mutex> lock(m_submit_mutex);
    close(m_submit);
}

bool AuxChainRPC::connected() const { return m_connected.load(); }

void AuxChainRPC::cancel_io()
{
    m_cancelled = true;
    m_poll.io.stop();
    m_submit.io.stop();
}

void AuxChainRPC::close(Conn& c)
{
    if (c.stream) {
        beast::error_code ec;
        c.stream->socket().shutdown(io::ip::tcp::socket::shutdown_both, ec);
        c.stream->socket().close(ec);
        c.stream.reset();
    }
    c.used = false;
    if (&c == &m_poll)
        m_connected = false;
}

void AuxChainRPC::note_failure_locked()
{
    const auto max = std::chrono::milliseconds(std::max<uint32_t>(m_config.rpc_reconnect_max_ms, 1'000));
    m_backoff = m_backoff.count() == 0 ? std::chrono::milliseconds(1'000)
                                       : std::min<std::chrono::milliseconds>(m_backoff * 2, max);
    m_next_connect = SteadyClock::now() + m_backoff;
}

void AuxChainRPC::open(Conn& c, const char* what)
{
    if (m_cancelled)
        throw std::runtime_error("RPC client stopped");
    close(c);
    const auto connect_timeout = std::chrono::milliseconds(std::max<uint32_t>(m_config.rpc_connect_timeout_ms, 1));
    const auto margin = std::chrono::milliseconds(1'000);

    auto st = std::make_shared<StepState>();
    c.resolver.async_resolve(m_config.rpc_host, std::to_string(m_config.rpc_port),
        [st](const boost::system::error_code& e, io::ip::tcp::resolver::results_type r) {
            st->ec = e;
            st->endpoints = std::move(r);
            st->done = true;
        });
    run_until(c.io, *st, connect_timeout, m_cancelled);
    if (!st->done) {
        abort_step(c.io, *st, [&c] { c.resolver.cancel(); });
        st->ec = io::error::timed_out;
    }
    if (m_cancelled)
        throw std::runtime_error("RPC client stopped");
    if (st->ec)
        throw std::runtime_error("resolve " + m_config.rpc_host + ": " + st->ec.message());

    c.stream = std::make_unique<beast::tcp_stream>(c.io);
    c.stream->expires_after(connect_timeout);
    auto cst = std::make_shared<StepState>();
    c.stream->async_connect(st->endpoints,
        [cst](const boost::system::error_code& e, const io::ip::tcp::endpoint&) {
            cst->ec = e;
            cst->done = true;
        });
    run_until(c.io, *cst, connect_timeout + margin, m_cancelled);
    if (!cst->done) {
        abort_step(c.io, *cst, [&c] { boost::system::error_code ig; c.stream->socket().close(ig); });
        cst->ec = beast::error::timeout;
    }
    if (m_cancelled) {
        close(c);
        throw std::runtime_error("RPC client stopped");
    }
    if (cst->ec) {
        close(c);
        throw std::runtime_error("connect " + m_config.rpc_host + ":" + std::to_string(m_config.rpc_port)
                                 + ": " + (cst->ec == beast::error::timeout ? std::string("timed out") : cst->ec.message()));
    }
    c.used = false;
    if (&c == &m_poll) {
        m_connected = true;
        const uint64_t n = ++m_connects;
        if (n == 1 || m_backoff.count() > 0)
            LOG_INFO << "[MM:" << m_config.symbol << "] " << (n == 1 ? "Connected" : "Reconnected")
                     << " to aux daemon at " << m_config.rpc_host << ":" << m_config.rpc_port;
        else
            LOG_DEBUG_DIAG << "[MM:" << m_config.symbol << "] new RPC connection (the last one was closed)";
    } else {
        LOG_DEBUG_DIAG << "[MM:" << m_config.symbol << "] new " << what << " connection";
    }
}

bool AuxChainRPC::connect()
{
    std::lock_guard<std::mutex> lock(m_io_mutex);
    if (m_connected)
        return true;
    try {
        open(m_poll, "RPC");
        return true;
    } catch (const std::exception& e) {
        note_failure_locked();
        LOG_WARNING << "[MM:" << m_config.symbol << "] Failed to connect: " << e.what();
        return false;
    }
}

std::string AuxChainRPC::exchange(Conn& c, const std::string& request, std::chrono::milliseconds timeout,
                                  bool& stale_connection)
{
    const auto margin = std::chrono::milliseconds(1'000);
    const auto close_socket = [&c] { boost::system::error_code ig; c.stream->socket().close(ig); };
    c.request.body() = request;
    c.request.prepare_payload();

    auto wst = std::make_shared<StepState>();
    c.stream->expires_after(timeout);
    http::async_write(*c.stream, c.request,
        [wst](const boost::system::error_code& e, std::size_t) { wst->ec = e; wst->done = true; });
    run_until(c.io, *wst, timeout + margin, m_cancelled);
    if (!wst->done) {
        abort_step(c.io, *wst, close_socket);
        wst->ec = beast::error::timeout;
    }
    if (m_cancelled)
        throw std::runtime_error("RPC client stopped");
    if (wst->ec) {
        stale_connection = c.used && is_closed_by_peer(wst->ec);
        throw std::runtime_error("RPC write: " + (wst->ec == beast::error::timeout ? std::string("timed out")
                                                                                   : wst->ec.message()));
    }

    auto rst = std::make_shared<StepState>();
    rst->parser.body_limit(kRpcBodyLimit);
    c.stream->expires_after(timeout);
    http::async_read(*c.stream, rst->buffer, rst->parser,
        [rst](const boost::system::error_code& e, std::size_t) { rst->ec = e; rst->done = true; });
    run_until(c.io, *rst, timeout + margin, m_cancelled);
    if (!rst->done) {
        abort_step(c.io, *rst, close_socket);
        rst->ec = beast::error::timeout;
    }
    if (m_cancelled)
        throw std::runtime_error("RPC client stopped");
    if (rst->ec) {
        // A keep-alive connection the daemon closed while idle answers the
        // next request with end-of-stream: the request was never read.
        stale_connection = c.used && is_closed_by_peer(rst->ec);
        throw std::runtime_error("RPC read: " + (rst->ec == beast::error::timeout
                                                     ? "no answer within " + std::to_string(timeout.count()) + " ms"
                                                     : rst->ec.message()));
    }
    c.used = true;
    auto res = rst->parser.release();
    if (!res.keep_alive())
        close(c);   // the daemon closes it: the next call opens another
    return std::move(res.body());
}

// Called by m_client from call(), m_io_mutex held. A JSON-RPC error comes
// back as a body (HTTP 500 with an "error" object) like any other answer.
std::string AuxChainRPC::Send(const std::string& request)
{
    const auto timeout = std::chrono::milliseconds(std::max<uint32_t>(m_config.rpc_timeout_ms, 1));
    for (int attempt = 0;; ++attempt) {
        if (m_cancelled)
            throw std::runtime_error("RPC client stopped");
        if (!m_connected) {
            const auto now = SteadyClock::now();
            if (now < m_next_connect)
                throw std::runtime_error("not connected (next connect in "
                    + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(m_next_connect - now).count())
                    + " ms)");
            try {
                open(m_poll, "RPC");
            } catch (const std::exception& e) {
                note_failure_locked();
                LOG_WARNING << "[MM:" << m_config.symbol << "] " << e.what() << " (next try in "
                            << m_backoff.count() << " ms)";
                throw;
            }
        }
        bool stale = false;
        try {
            std::string body = exchange(m_poll, request, timeout, stale);
            m_backoff = std::chrono::milliseconds(0);
            return body;
        } catch (const std::exception& e) {
            close(m_poll);
            if (stale && attempt == 0) {
                LOG_DEBUG_DIAG << "[MM:" << m_config.symbol << "] the daemon closed the connection ("
                               << e.what() << "): sending again on a new one";
                continue;
            }
            note_failure_locked();
            LOG_WARNING << "[MM:" << m_config.symbol << "] " << e.what() << " (connection closed; next connect in "
                        << m_backoff.count() << " ms)";
            throw;
        }
    }
}

nlohmann::json AuxChainRPC::call(const std::string& method, const nlohmann::json& params)
{
    jsonrpccxx::positional_parameter pos_params;
    if (params.is_array()) {
        for (const auto& p : params) pos_params.push_back(p);
    } else {
        pos_params.push_back(params);
    }
    std::lock_guard<std::mutex> lock(m_io_mutex);
    return m_client.CallMethod<nlohmann::json>("c2pool", method, pos_params);
}

AuxWork AuxChainRPC::get_work_template()
{
    AuxWork work;
    work.chain_id = m_config.chain_id;

    // Request template with auxpow capability
    nlohmann::json params = nlohmann::json::array();
    params.push_back(nlohmann::json::object({
        {"capabilities", nlohmann::json::array({"auxpow"})},
        {"rules", nlohmann::json::array({"segwit"})}
    }));
    auto tmpl = call("getblocktemplate", params);

    work.block_template = tmpl;
    work.height = tmpl.value("height", 0);
    work.coinbase_value = tmpl.value("coinbasevalue", uint64_t(0));
    work.prev_block_hash = tmpl.value("previousblockhash", "");

    // Target: prefer "target" field directly, fall back to SetCompact(bits)
    bool target_set = false;
    if (tmpl.contains("target") && tmpl["target"].is_string()) {
        std::string target_hex = tmpl["target"].get<std::string>();
        if (!target_hex.empty() && target_hex.size() <= 64) {
            work.target.SetHex(target_hex);
            target_set = !work.target.IsNull();
        }
    }
    if (!target_set) {
        std::string bits_hex = tmpl.value("bits", "");
        if (!bits_hex.empty()) {
            uint32_t nbits = std::stoul(bits_hex, nullptr, 16);
            work.target.SetCompact(nbits);
        } else {
            LOG_WARNING << "[MM:" << m_config.symbol
                        << "] getblocktemplate: no target/bits field — target will be null!";
        }
    }

    // Block hash for aux work identification:
    // - createauxblock mode: daemon returns "hash" directly
    // - getblocktemplate mode: no "hash" field; use previousblockhash as
    //   work identifier so the refresh-skip logic works correctly.
    //   The actual aux block hash is computed at submission time.
    if (tmpl.contains("hash")) {
        work.block_hash.SetHex(tmpl["hash"].get<std::string>());
    } else if (!work.prev_block_hash.empty()) {
        work.block_hash.SetHex(work.prev_block_hash);
    }

    return work;
}

bool aux_target_from_le_hex(const std::string& le_hex, uint256& out)
{
    if (le_hex.size() != 64)
        return false;
    for (char c : le_hex)
        if (!std::isxdigit(static_cast<unsigned char>(c)))
            return false;
    // Reverse the byte order: byte 0 (least significant) goes last, so
    // SetHex sees the big-endian display form it expects.
    std::string be;
    be.reserve(64);
    for (int i = 62; i >= 0; i -= 2)
        be.append(le_hex, static_cast<size_t>(i), 2);
    out.SetHex(be);
    return true;
}

AuxWork aux_work_from_createauxblock(const nlohmann::json& result,
                                     uint32_t default_chain_id,
                                     const std::string& symbol)
{
    AuxWork work;
    work.block_hash.SetHex(result.value("hash", ""));
    work.chain_id = result.value("chainid", default_chain_id);
    work.height = result.value("height", 0);
    work.coinbase_value = result.value("coinbasevalue", uint64_t(0));

    // Target: prefer the "target" field (like p2pool), then the legacy
    // "_target", then "bits". createauxblock / getauxblock give both target
    // fields as the raw little-endian bytes of the uint256 (HexStr(BEGIN,
    // END)), NOT the big-endian display form GBT uses: regtest bits 207fffff
    // comes back as "...00ffff7f". p2pool unpacks the decoded bytes as a
    // little-endian integer; aux_target_from_le_hex does the same.
    bool target_set = false;
    for (const char* field : {"target", "_target"}) {
        if (target_set || !result.contains(field) || !result[field].is_string())
            continue;
        uint256 t;
        if (aux_target_from_le_hex(result[field].get<std::string>(), t) && !t.IsNull()) {
            work.target = t;
            target_set = true;
        }
    }
    if (!target_set) {
        std::string bits_hex = result.value("bits", "");
        if (!bits_hex.empty()) {
            uint32_t nbits = std::stoul(bits_hex, nullptr, 16);
            work.target.SetCompact(nbits);
        } else {
            LOG_WARNING << "[MM:" << symbol
                        << "] createauxblock: no target/bits field — target will be null!";
        }
    }
    return work;
}

AuxWork AuxChainRPC::create_aux_block(const std::string& address)
{
    nlohmann::json result;
    try {
        result = call("createauxblock", nlohmann::json::array({address}));
    } catch (const jsonrpccxx::JsonRpcException& e) {
        // Dogecoin-family -8, Bellscoin -5: no work until the address is fixed.
        if (std::string(e.what()).find("Invalid coinbase payout address") != std::string::npos)
            throw std::runtime_error("the daemon refuses the createauxblock payout address \"" + address
                                     + "\" (" + e.what() + "): set --merged-payout-address "
                                     + m_config.symbol + ":<" + m_config.symbol + " address>");
        throw;
    }
    LOG_TRACE << "[MM:" << m_config.symbol << "] createauxblock raw hash: \"" << result.value("hash", "")
              << "\" height=" << result.value("height", 0);
    return aux_work_from_createauxblock(result, m_config.chain_id, m_config.symbol);
}

SubmitVerdict AuxChainRPC::submit_block_verdict(const std::string& block_hex)
{
    // Its own connection (a find never queues behind a poll), no backoff (a
    // block is always tried), a longer deadline (validation). BIP22
    // (classify_submitblock_result): a rejection is a non-null string result,
    // not a JSON-RPC error. No answer is unknown: the daemon may have taken
    // the block, and the P2P relay sent it too; the found-block check follows
    // the chain. A JSON-RPC error object is the daemon's refusal.
    using K = SubmitVerdict::Kind;
    SubmitVerdict v;
    const auto timeout = std::chrono::milliseconds(std::max<uint32_t>(m_config.rpc_submit_timeout_ms, 1));
    const std::string request = nlohmann::json{{"jsonrpc", "1.0"}, {"id", "c2pool-submit"},
                                               {"method", "submitblock"},
                                               {"params", nlohmann::json::array({block_hex})}}.dump();
    {
        std::lock_guard<std::mutex> lock(m_submit_mutex);
        for (int attempt = 0;; ++attempt) {
            bool stale = false;
            try {
                if (!m_submit.stream)
                    open(m_submit, "submit");
                const std::string body = exchange(m_submit, request, timeout, stale);
                const auto j = nlohmann::json::parse(body, nullptr, false);
                if (j.is_discarded() || !j.is_object())
                    v = SubmitVerdict::of(K::unknown, "unparsable answer: " + body.substr(0, 120));
                else if (j.contains("error") && j["error"].is_object()) {
                    // -22 (RPC_DESERIALIZATION_ERROR, "Block decode failed"):
                    // the bytes are no block, on any path. Any other error
                    // (-28 warming up, a verify error) says nothing about the
                    // block the P2P relay also sent: the chain decides.
                    const int code = j["error"].value("code", 0);
                    v = SubmitVerdict::of(code == -22 ? K::error : K::unknown,
                                          std::to_string(code) + ": " + j["error"].value("message", std::string()));
                }
                else if (j.contains("error") && j["error"].is_string())
                    v = SubmitVerdict::of(K::error, j["error"].get<std::string>());
                else
                    v = classify_submitblock_result(j.contains("result") ? j["result"] : nlohmann::json());
                break;
            } catch (const std::exception& e) {
                close(m_submit);
                if (stale && attempt == 0)
                    continue;   // the daemon had closed the idle connection
                v = SubmitVerdict::of(K::unknown, e.what());
                break;
            }
        }
    }
    switch (v.kind) {
    case K::accepted:
        LOG_INFO << "[MM:" << m_config.symbol << "] submitblock ACCEPTED";
        break;
    case K::duplicate:
        LOG_INFO << "[MM:" << m_config.symbol << "] submitblock: duplicate (the daemon already has this block, valid)";
        break;
    case K::inconclusive:
        LOG_WARNING << "[MM:" << m_config.symbol << "] submitblock INCONCLUSIVE (" << v.reason
                    << "): stored, not on the daemon's best chain";
        break;
    case K::rejected:
        LOG_ERROR << "[MM:" << m_config.symbol << "] submitblock REJECTED by daemon: " << v.reason;
        break;
    case K::error:
        LOG_ERROR << "[MM:" << m_config.symbol << "] submitblock refused: " << v.reason;
        break;
    case K::unknown:
        LOG_WARNING << "[MM:" << m_config.symbol << "] submitblock: no answer (" << v.reason
                    << "): the chain decides (P2P relay sent it too)";
        break;
    }
    return v;
}

bool AuxChainRPC::submit_block(const std::string& block_hex)
{
    return submit_block_verdict(block_hex).accepted();
}

std::optional<std::string> AuxChainRPC::get_chain_name()
{
    try {
        const auto r = call("getblockchaininfo");
        if (r.is_object() && r.contains("chain") && r["chain"].is_string())
            return r["chain"].get<std::string>();
    } catch (const std::exception&) {}
    return std::nullopt;
}

std::optional<uint32_t> AuxChainRPC::get_block_count()
{
    try {
        const auto r = call("getblockcount");
        if (r.is_number_integer() && r.get<int64_t>() >= 0)
            return static_cast<uint32_t>(r.get<int64_t>());
    } catch (const std::exception&) {}
    return std::nullopt;
}

std::optional<uint256> AuxChainRPC::get_block_hash_at(uint32_t height)
{
    try {
        const auto r = call("getblockhash", nlohmann::json::array({height}));
        if (r.is_string()) {
            uint256 h;
            h.SetHex(r.get<std::string>());
            return h;
        }
    } catch (const std::exception&) {}   // e.g. -8 "Block height out of range"
    return std::nullopt;
}

std::optional<uint32_t> AuxChainRPC::get_block_height(const uint256& hash)
{
    try {
        const auto r = call("getblockheader", nlohmann::json::array({hash.GetHex(), true}));
        if (r.is_object() && r.contains("height") && r["height"].is_number_integer())
            return static_cast<uint32_t>(r["height"].get<int64_t>());
    } catch (const std::exception&) {}   // -5 "Block not found"
    return std::nullopt;
}

bool AuxChainRPC::submit_aux_block(const uint256& block_hash, const std::string& auxpow_hex)
{
    try {
        auto result = call("submitauxblock",
                           nlohmann::json::array({block_hash.GetHex(), auxpow_hex}));
        // submitauxblock returns a BOOLEAN result: true = accepted, false =
        // rejected (e.g. "block hash unknown" for a hash the daemon never minted
        // via createauxblock). Honor it -- the previous code discarded the result
        // and returned true unless call() threw, so a false-result rejection was
        // mis-recorded as a won block. (No run-path caller today: the DOGE
        // PPLNS-committed hash is structurally not createauxblock-minted, so this
        // path is not wired as a fallback -- corrected here for latent safety.)
        const bool accepted = result.is_boolean() ? result.get<bool>() : false;
        if (accepted)
            LOG_INFO << "[MM:" << m_config.symbol << "] submitauxblock ACCEPTED by daemon";
        else
            LOG_ERROR << "[MM:" << m_config.symbol
                      << "] submitauxblock REJECTED by daemon: " << result.dump();
        return accepted;
    } catch (const std::exception& e) {
        LOG_WARNING << "[MM:" << m_config.symbol << "] submitauxblock failed: " << e.what();
        return false;
    }
}

std::string AuxChainRPC::get_best_block_hash()
{
    try {
        auto result = call("getbestblockhash");
        return result.get<std::string>();
    } catch (const std::exception& e) {
        LOG_WARNING << "[MM:" << m_config.symbol << "] getbestblockhash failed: " << e.what();
        return "";
    }
}

std::string AuxChainRPC::get_block_hex(const std::string& block_hash)
{
    try {
        // verbosity 0 → raw hex serialization of the full block
        auto result = call("getblock", nlohmann::json::array({block_hash, 0}));
        return result.get<std::string>();
    } catch (const std::exception& e) {
        LOG_WARNING << "[MM:" << m_config.symbol << "] getblock(hex) failed: " << e.what();
        return "";
    }
}

std::vector<NetService> AuxChainRPC::getpeerinfo()
{
    std::vector<NetService> result;
    try {
        auto peers = call("getpeerinfo");
        if (!peers.is_array()) return result;
        for (auto& peer : peers) {
            if (!peer.contains("addr")) continue;
            std::string addr_str = peer["addr"].get<std::string>();
            // Parse "host:port" — handle IPv6 [::]:port
            auto colon = addr_str.rfind(':');
            if (colon == std::string::npos) continue;
            std::string host = addr_str.substr(0, colon);
            uint16_t port = static_cast<uint16_t>(
                std::stoul(addr_str.substr(colon + 1)));
            // Strip brackets from IPv6
            if (!host.empty() && host.front() == '[' && host.back() == ']') {
                host = host.substr(1, host.size() - 2);
            }
            result.emplace_back(host, port);
        }
    } catch (const std::exception& e) {
        LOG_WARNING << "[MM:" << m_config.symbol << "] getpeerinfo failed: " << e.what();
    }
    return result;
}

// ─── MergedMiningManager ────────────────────────────────────────────────────

namespace {
thread_local bool t_mm_rpc_thread = false;
thread_local std::string t_payout_miss;
thread_local uint256 t_payout_basis;
} // namespace

MergedMiningManager::MergedMiningManager(boost::asio::io_context& ioc)
    : m_ioc(ioc), m_poll_timer(ioc)
{
    // The RPC pool's one thread may wait for a busy tracker lock in a payout
    // provider (on_rpc_thread); the network thread may not.
    boost::asio::post(m_rpc_pool, []() { t_mm_rpc_thread = true; });
}

MergedMiningManager::~MergedMiningManager()
{
    stop();
}

void MergedMiningManager::add_chain(const AuxChainConfig& config)
{
    // Default: create RPC backend
    add_chain(config, std::make_unique<AuxChainRPC>(m_ioc, config));
}

void MergedMiningManager::add_chain(const AuxChainConfig& config, std::unique_ptr<IAuxChainBackend> backend)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    // Two chains cannot share a chain id: a daemon finds its chain's slot
    // from the id alone (CAuxPow::getExpectedIndex). The first one stays.
    for (const auto& c : m_chains)
        if (c.config.chain_id == config.chain_id) {
            LOG_ERROR << "[MM] Refusing aux chain " << config.symbol << ": chain_id "
                      << config.chain_id << " is already registered as " << c.config.symbol;
            return;
        }

    // The tree with every chain committed at once must exist: chain ids
    // that collide at every size up to AuxPowTree::kMaxHeight are a
    // configuration error. The chains registered so far stay.
    std::vector<uint32_t> ids;
    for (const auto& c : m_chains)
        ids.push_back(c.config.chain_id);
    ids.push_back(config.chain_id);
    AuxPowTree tree = AuxPowTree::build(ids);
    if (tree.size == 0) {
        std::string list;
        for (auto id : ids)
            list += (list.empty() ? "" : ", ") + std::to_string(id);
        LOG_ERROR << "[MM] Configuration error: refusing aux chain " << config.symbol << " (chain_id "
                  << config.chain_id << "): chain ids {" << list << "} cannot be given distinct slots in a "
                  << "chain merkle tree of height <= " << AuxPowTree::kMaxHeight << " ("
                  << (1u << AuxPowTree::kMaxHeight) << " slots); remove one of the colliding chains";
        return;
    }

    ChainState state;
    state.config = config;
    state.rpc = std::move(backend);
    m_chains.push_back(std::move(state));
    m_tree = std::move(tree);

    // The slots are logged once all chains are in (start()): with each
    // registration the tree can still grow and move them.
    LOG_INFO << "[MM] Registered aux chain: " << config.symbol << " (chain_id=" << config.chain_id << ")";
}

void MergedMiningManager::set_fallback_backend(uint32_t chain_id, std::unique_ptr<IAuxChainBackend> fallback)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    for (auto& chain : m_chains) {
        if (chain.config.chain_id == chain_id) {
            chain.fallback = std::move(fallback);
            LOG_INFO << "[MM:" << chain.config.symbol << "] Fallback backend set (auto-switch on primary failure)";
            return;
        }
    }
}

IAuxChainBackend* MergedMiningManager::get_chain_rpc(uint32_t chain_id)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    for (auto& chain : m_chains) {
        if (chain.config.chain_id == chain_id)
            return chain.rpc.get();
    }
    return nullptr;
}

bool MergedMiningManager::has_chain(uint32_t chain_id) const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    for (const auto& chain : m_chains) {
        if (chain.config.chain_id == chain_id)
            return true;
    }
    return false;
}

void MergedMiningManager::start()
{
    if (m_running) return;

    {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        std::string slots;
        for (const auto& c : m_chains) {
            const auto it = m_tree.slot_map.find(c.config.chain_id);
            slots += " " + c.config.symbol + "(" + std::to_string(c.config.chain_id) + ")=slot "
                   + (it != m_tree.slot_map.end() ? std::to_string(it->second) : std::string("none"));
        }
        LOG_INFO << "[MM] Chain merkle tree with every chain: size " << m_tree.size << ":" << slots
                 << (m_chains.size() > 1 ? " (a round without some chain commits to the smallest tree of the rest)"
                                         : "");
    }

    // Connect all RPC clients (a failed one connects again on its first call)
    for (auto& chain : m_chains) {
        chain.rpc->connect();
    }

    m_running = true;
    poll_loop();
    LOG_INFO << "[MM] Merged mining manager started with " << m_chains.size() << " chain(s)";
}

void MergedMiningManager::stop()
{
    m_running = false;
    m_poll_timer.cancel();
    // A call blocked on a daemon returns now (and later ones fail at once).
    {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        for (auto& chain : m_chains) {
            if (chain.rpc) chain.rpc->cancel_io();
            if (chain.fallback) chain.fallback->cancel_io();
        }
    }
    // Queued refreshes are dropped (their backends may be the embedded
    // chains, which close after this); the one running finishes.
    m_rpc_pool.stop();
    m_rpc_pool.join();
    std::lock_guard<std::mutex> lock(m_io_pool_mutex);
    if (m_io_pool) {
        m_io_pool->stop();
        m_io_pool->join();
    }
}

void MergedMiningManager::set_refresh_round_deadline(std::chrono::milliseconds d)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_refresh_deadline = d;
}

void MergedMiningManager::set_unresponsive_after(std::chrono::milliseconds d)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_unresponsive_after = d;
}

boost::asio::thread_pool& MergedMiningManager::io_pool()
{
    std::lock_guard<std::mutex> lock(m_io_pool_mutex);
    if (!m_io_pool)
        m_io_pool = std::make_unique<boost::asio::thread_pool>(std::max<size_t>(4, m_chains.size() + 1));
    return *m_io_pool;
}

void MergedMiningManager::request_refresh()
{
    if (m_refresh_in_progress.exchange(true))
        return;
    boost::asio::post(m_rpc_pool, [this]() {
        try {
            refresh_aux_work();
        } catch (const std::exception& e) {
            LOG_WARNING << "[MM] refresh_aux_work exception: " << e.what();
        }
        m_refresh_in_progress.store(false);
    });
}

void MergedMiningManager::note_payout_miss(const std::string& reason) { t_payout_miss = reason; }

void MergedMiningManager::note_payout_basis(const uint256& best) { t_payout_basis = best; }

bool MergedMiningManager::on_rpc_thread() { return t_mm_rpc_thread; }

namespace {
nlohmann::json payout_source_json(const MergedPayoutSource::Stats& st)
{
    return {{"published", st.published},
            {"from_weights", st.from_weights},
            {"computed", st.computed},
            {"busy", st.busy}};
}
} // namespace

nlohmann::json MergedMiningManager::get_rebuild_stats_json() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    nlohmann::json no_payouts = nlohmann::json::object();
    for (const auto& [reason, n] : m_rebuild_no_payouts)
        no_payouts[reason] = n;
    // Seconds without payouts (no block built, so no commitment unless the
    // last block on the same parent was kept): closed episodes plus the open one.
    const int64_t now = now_sec();
    int64_t no_payout_seconds = 0;
    nlohmann::json no_payout_now = nlohmann::json::array();
    for (const auto& chain : m_chains) {
        no_payout_seconds += chain.no_payout_seconds;
        if (chain.no_payout_episode) {
            no_payout_seconds += now - chain.no_payout_since;
            no_payout_now.push_back(chain.config.symbol);
        }
    }
    return {{"no_payouts", std::move(no_payouts)},
            {"kept_last_block", m_rebuild_kept_last_block},
            {"dropped_commitment", m_rebuild_dropped_commitment},
            {"dropped_best_moved", m_rebuild_dropped_best_moved},
            {"stale_results", m_rebuild_stale_results},
            {"work_changed", m_rebuild_work_changed},
            {"work_unchanged", m_rebuild_work_unchanged},
            {"snapshot_target_refusals", m_snapshot_target_refusals},
            {"no_payout_seconds", no_payout_seconds},
            {"no_payout_now", std::move(no_payout_now)},
            {"payout_source", payout_source_json(m_payout_source->stats())}};
}

void MergedMiningManager::set_clock_for_test(ClockFn fn) { m_clock = std::move(fn); }

int64_t MergedMiningManager::now_sec() const
{
    if (m_clock)
        return m_clock();
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void MergedMiningManager::poll_loop()
{
    if (!m_running) return;

    // Offload refresh_aux_work to dedicated RPC thread — prevents blocking
    // the ioc event loop during ~1s RPC round-trips (createauxblock, etc.).
    // Skip if previous refresh is still in progress (RPC latency spike).
    if (!m_refresh_in_progress.exchange(true)) {
        boost::asio::post(m_rpc_pool, [this]() {
            t_mm_rpc_thread = true;
            try {
                refresh_aux_work();
            } catch (const std::exception& e) {
                LOG_WARNING << "[MM] refresh_aux_work exception: " << e.what();
            }
            m_refresh_in_progress.store(false);
        });
    }

    m_poll_timer.expires_after(std::chrono::seconds(1));
    m_poll_timer.async_wait([this](const boost::system::error_code& ec) {
        if (!ec && m_running) {
            poll_loop();
        }
    });
}

// ─── Poll: fetch each chain outside m_mutex ─────────────────────────────────

struct MergedMiningManager::FetchInput
{
    size_t                              index{0};
    AuxChainConfig                      config;
    IAuxChainBackend*                   primary{nullptr};
    IAuxChainBackend*                   fallback{nullptr};
    bool                                using_fallback{false};
    std::string                         last_tip;
    bool                                has_work{false};
    bool                                template_degraded{false};
    uint32_t                            size_reserve{0};
    uint32_t                            sigop_reserve{0};
    std::shared_ptr<ChainState::ChainIo> io;
};

struct MergedMiningManager::FetchResult
{
    // unchanged: same tip, nothing to fetch; waiting_sync: the embedded
    // chain has no work yet (nor the fallback); still_degraded: the template
    // on the same tip is still degraded; new_work; failed: no backend answered.
    enum class Kind { unchanged, waiting_sync, still_degraded, new_work, failed };
    Kind        kind{Kind::failed};
    std::string error;
    std::string config_error;            // set: the chain is disabled (chain id / address)
    bool        swapped{false};          // primary and fallback exchanged
    bool        using_fallback{false};
    bool        tip_set{false};
    std::string last_tip;
    AuxWork     work;
    bool        via_failover{false};     // work from the backend switched to on a failure
};

// The poll of one chain, as the poll under m_mutex did it: the tip, then
// createauxblock (and the template in multiaddress mode) when it moved or the
// template came back degraded, the embedded/RPC jumpstart and failover, the
// daemon's authoritative target, the promotion back to the embedded backend.
// Runs without m_mutex, each backend call under that backend's own lock (a
// find's submit waits for at most one call): it only reads its input and
// writes its result (apply_fetch_locked applies it). Work whose chain id is
// not the configured one, or a payout address that is not of the daemon's
// network, is a configuration error: the chain is disabled.
MergedMiningManager::FetchResult MergedMiningManager::fetch_chain(const FetchInput& in)
{
    using Kind = FetchResult::Kind;
    FetchResult r;
    r.using_fallback = in.using_fallback;
    IAuxChainBackend* rpc = in.primary;
    IAuxChainBackend* fb = in.fallback;
    const auto swap = [&] { std::swap(rpc, fb); r.swapped = !r.swapped; };
    const auto& sym = in.config.symbol;
    const auto& address = in.config.aux_payout_address;
    const auto now_ns = [] { return std::chrono::steady_clock::now().time_since_epoch().count(); };
    auto& io = *in.io;
    // One backend call under that backend's lock.
    const auto locked = [&io](IAuxChainBackend* b, auto&& f) {
        const auto m = io.lock_for(b);
        std::lock_guard<std::mutex> g(*m);
        return f(b);
    };
    const auto best_hash = [&](IAuxChainBackend* b) {
        return locked(b, [](IAuxChainBackend* x) { return x->get_best_block_hash(); });
    };
    const auto aux_block = [&](IAuxChainBackend* b) {
        return locked(b, [&address](IAuxChainBackend* x) { return x->create_aux_block(address); });
    };
    const auto work_template = [&](IAuxChainBackend* b) {
        return locked(b, [](IAuxChainBackend* x) { return x->get_work_template(); });
    };
    // createauxblock's chain id is the daemon's: another than the configured
    // one puts the block at a slot its daemon does not check ("Aux POW wrong
    // index") with a version of another chain.
    const auto chain_id_error = [&](const AuxWork& w) -> std::string {
        if (w.chain_id == 0 || w.chain_id == in.config.chain_id)
            return {};
        return "the daemon's chain id is " + std::to_string(w.chain_id) + ", configured "
               + std::to_string(in.config.chain_id) + ": fix --merged " + sym + ":<CHAIN_ID>:...";
    };

    // Size budget for the template about to be built: the backends that
    // build their own (embedded) keep header + AuxPoW + coinbase room.
    for (IAuxChainBackend* b : {rpc, fb}) {
        if (!b)
            continue;
        locked(b, [&](IAuxChainBackend* x) {
            x->set_block_size_reserve(in.size_reserve);
            x->set_block_sigop_reserve(in.sigop_reserve);
            return 0;
        });
    }

    try {
        // The payout address against the daemon's own network, once.
        if (in.config.check_payout_address && !io.network_checked.load()) {
            const auto chain = locked(rpc, [](IAuxChainBackend* x) { return x->get_chain_name(); });
            if (chain) {
                const std::string why = in.config.check_payout_address(*chain);
                if (!why.empty()) {
                    r.config_error = why;
                    r.error = why;
                    return r;
                }
                io.network_checked = true;
            }
        }
        // A degraded template (built before the tip's body cleaned the
        // mempool: coinbase only) is fetched again on every poll until a
        // clean one comes back.
        const auto tip = best_hash(rpc);
        const bool same_tip = tip == in.last_tip && in.has_work;
        if (same_tip && !in.template_degraded) {
            r.kind = Kind::unchanged;
        } else {
            // Always createauxblock: the canonical hash and target; in
            // multiaddress mode the template too (PPLNS coinbase).
            auto new_work = aux_block(rpc);

            // Primary returned empty work (embedded chain not synced yet):
            // the fallback (daemon RPC) keeps the commitment present.
            if (new_work.block_hash.IsNull() && new_work.height == 0) {
                if (fb && !r.using_fallback) {
                    try {
                        new_work = aux_block(fb);
                        if (!new_work.block_hash.IsNull()) {
                            swap();
                            r.using_fallback = true;
                            r.last_tip = best_hash(rpc);
                            r.tip_set = true;
                            LOG_INFO << "[MM:" << sym << "] Embedded not synced — using RPC (jumpstart)"
                                     << " height=" << new_work.height;
                        }
                    } catch (const std::exception&) {
                        // Fallback also unavailable
                    }
                }
                if (new_work.block_hash.IsNull() && new_work.height == 0) {
                    if (now_ns() - io.last_sync_log_ns.load() > 30'000'000'000LL) {
                        io.last_sync_log_ns = now_ns();
                        LOG_INFO << "[MM:" << sym << "] Waiting for embedded chain sync (fallback also unavailable)...";
                    }
                    if (!r.tip_set) {
                        r.last_tip = tip;
                        r.tip_set = true;
                    }
                    r.kind = Kind::waiting_sync;
                    return r;
                }
            }
            if (auto why = chain_id_error(new_work); !why.empty()) {
                r.config_error = r.error = why;
                return r;
            }
            if (!r.tip_set) {
                r.last_tip = tip;
                r.tip_set = true;
            }
            if (in.config.multiaddress) {
                auto tmpl_work = work_template(rpc);
                // Keep the template data but preserve the createauxblock hash
                new_work.block_template = std::move(tmpl_work.block_template);
                new_work.prev_block_hash = std::move(tmpl_work.prev_block_hash);
                new_work.coinbase_value = tmpl_work.coinbase_value;
            }
            // Still degraded on the same tip: keep the block already being
            // mined. A new one would differ only in its time, and each rebuild
            // would push new work to every miner and fill frozen_history.
            if (same_tip && in.template_degraded
                && core::coin::template_degraded_code(new_work.block_template)) {
                r.kind = Kind::still_degraded;
                return r;
            }
            // Like p2pool: the authoritative target from the daemon via
            // createauxblock when the RPC fallback is there. The embedded
            // backend computes its own, which can diverge from the chain.
            if (fb && !r.using_fallback) {
                try {
                    auto daemon_work = aux_block(fb);
                    if (auto why = chain_id_error(daemon_work); !why.empty()) {
                        r.config_error = r.error = why;
                        return r;
                    }
                    if (!daemon_work.target.IsNull()) {
                        if (new_work.target != daemon_work.target) {
                            LOG_INFO << "[MM:" << sym << "] Target from daemon differs from embedded:"
                                     << " embedded=" << new_work.target.GetHex().substr(0, 16)
                                     << " daemon=" << daemon_work.target.GetHex().substr(0, 16)
                                     << " — using daemon (authoritative)";
                        }
                        new_work.target = daemon_work.target;
                    }
                } catch (...) {
                    // RPC unavailable — keep embedded target (best effort)
                }
            }
            r.work = std::move(new_work);
            r.kind = Kind::new_work;
        }
    } catch (const std::exception& e) {
        r.error = e.what();
        if (now_ns() - io.last_warn_ns.load() > 30'000'000'000LL) {   // 30 s rate limit
            io.last_warn_ns = now_ns();
            LOG_WARNING << "[MM:" << sym << "] Failed to refresh: " << e.what();
        }
        r.kind = Kind::failed;
        // The other backend: RPC is the jumpstart while embedded syncs
        // headers; once embedded has a tip it is preferred again.
        if (fb) {
            swap();
            r.using_fallback = !r.using_fallback;
            try {
                const auto tip = best_hash(rpc);
                AuxWork w = aux_block(rpc);
                if (auto why = chain_id_error(w); !why.empty()) {
                    swap();
                    r.using_fallback = !r.using_fallback;
                    r.config_error = r.error = why;
                    return r;
                }
                if (in.config.multiaddress) {
                    auto tmpl_work = work_template(rpc);
                    w.block_template = std::move(tmpl_work.block_template);
                    w.prev_block_hash = std::move(tmpl_work.prev_block_hash);
                    w.coinbase_value = tmpl_work.coinbase_value;
                }
                r.last_tip = tip;
                r.tip_set = true;
                r.work = std::move(w);
                r.via_failover = true;
                r.kind = Kind::new_work;
                LOG_INFO << "[MM:" << sym << "] Using "
                         << (r.using_fallback ? "RPC (jumpstart)" : "embedded (preferred)")
                         << " — height " << r.work.height;
            } catch (const std::exception&) {
                // Both failed — swap back, wait for next cycle
                swap();
                r.using_fallback = !r.using_fallback;
            }
        }
    } catch (...) {
        r.error = "unknown exception";
        r.kind = Kind::failed;
    }

    // Auto-promote: if using RPC fallback but embedded (primary) now has a
    // tip, switch back to embedded (preferred backend).
    if (r.using_fallback && fb) {
        try {
            auto embedded_tip = best_hash(fb);
            if (!embedded_tip.empty()) {
                swap();
                r.using_fallback = false;
                LOG_INFO << "[MM:" << sym << "] Embedded node synced — promoting to primary";
            }
        } catch (...) {
            // Embedded not ready yet — keep using RPC
        }
    }
    return r;
}

bool MergedMiningManager::apply_fetch_locked(size_t index, FetchResult& r)
{
    using Kind = FetchResult::Kind;
    auto& chain = m_chains[index];
    if (r.swapped)
        chain.rpc.swap(chain.fallback);
    chain.using_fallback = r.using_fallback;
    if (r.tip_set)
        chain.last_tip = r.last_tip;

    if (!r.config_error.empty()) {
        if (chain.config_error.empty()) {
            chain.config_error = r.config_error;
            LOG_ERROR << "[MM:" << chain.config.symbol << "] merged chain DISABLED: " << r.config_error;
        }
        return true;
    }

    bool changed = false;
    switch (r.kind) {
    case Kind::unchanged:
    case Kind::waiting_sync:
        break;
    case Kind::still_degraded:
        ++chain.templates_still_degraded;
        break;
    case Kind::new_work:
        chain.current_work = std::move(r.work);
        changed = true;
        if (r.via_failover)
            break;
        {
            const bool was_degraded = chain.template_degraded;
            const auto why = core::coin::template_degraded_code(chain.current_work.block_template);
            chain.template_degraded = why.has_value();
            if (chain.template_degraded) {
                ++chain.templates_degraded;
                LOG_INFO << "[MM:" << chain.config.symbol << "] Template at height "
                         << chain.current_work.height << " degraded (" << *why
                         << "): coinbase only, fetching again next poll";
            } else if (was_degraded) {
                ++chain.templates_refetched_clean;
                LOG_INFO << "[MM:" << chain.config.symbol << "] Template at height "
                         << chain.current_work.height << " fetched again, clean";
            }
        }
        chain.last_update_time = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        LOG_INFO << "[MM:" << chain.config.symbol << "] New aux work at height "
                 << chain.current_work.height
                 << " hash=" << chain.current_work.block_hash.GetHex()
                 << " target=" << chain.current_work.target.GetHex()
                 << (chain.current_work.target.IsNull() ? " [NULL — NO BLOCKS POSSIBLE]" : "");
        break;
    case Kind::failed:
        break;
    }

    const bool answered = r.kind != Kind::failed;
    if (answered != chain.responsive) {
        chain.responsive = answered;
        if (answered) {
            chain.unresponsive_why.clear();
            LOG_INFO << "[MM:" << chain.config.symbol << "] answering again"
                     << (m_chains.size() > 1 ? ": back in the merged-mining commitment" : "");
        } else {
            chain.unresponsive_why = r.error;
            ++chain.dropouts;
            LOG_WARNING << "[MM:" << chain.config.symbol << "] no work from the daemon (" << r.error << ")"
                        << (m_chains.size() > 1 ? ": out of the merged-mining commitment until it answers"
                                                : ": keeping its last work");
        }
        changed = changed || m_chains.size() > 1;
    } else if (!answered) {
        chain.unresponsive_why = r.error;
    }
    return changed;
}

void MergedMiningManager::refresh_aux_work()
{
    const bool pplns_was_dirty = m_pplns_dirty.load(std::memory_order_relaxed);

    // One round: every chain not already being fetched is fetched in
    // parallel. The round waits (at most m_refresh_deadline) for the chains
    // that answered last time, and kOutChainWait from its start for the ones
    // already out (one that is back rejoins in this round); then it builds
    // the commitment without waiting any longer. A slower answer is applied
    // when it comes (then a refresh is asked for): a slow chain keeps its
    // last work committed meanwhile. A chain whose fetch fails, or is still
    // running m_unresponsive_after after it started (a hung daemon), drops
    // out of the commitment until it answers.
    static constexpr auto kOutChainWait = std::chrono::milliseconds(200);
    struct Round {
        std::mutex              mu;
        std::condition_variable cv;
        size_t                  pending{0};       // fetches of chains that answered last time
        size_t                  pending_all{0};   // every fetch started this round
        bool                    closed{false};
    };
    const auto round_start = std::chrono::steady_clock::now();
    auto round = std::make_shared<Round>();
    std::chrono::milliseconds deadline, hang_after;
    {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        deadline = m_refresh_deadline;
        hang_after = m_unresponsive_after;
        auto& pool = io_pool();
        for (size_t i = 0; i < m_chains.size(); ++i) {
            auto& chain = m_chains[i];
            if (!chain.config_error.empty())
                continue;   // disabled (configuration error): not polled
            if (chain.io->in_flight.exchange(true))
                continue;   // still fetching (a slow or hung daemon): not waited for again
            FetchInput in;
            in.index = i;
            in.config = chain.config;
            in.primary = chain.rpc.get();
            in.fallback = chain.fallback.get();
            in.using_fallback = chain.using_fallback;
            in.last_tip = chain.last_tip;
            in.has_work = !chain.current_work.block_hash.IsNull();
            in.template_degraded = chain.template_degraded;
            in.size_reserve = block_size_reserve_locked(chain);
            in.sigop_reserve = block_sigop_reserve_locked(chain);
            in.io = chain.io;
            chain.io->fetch_started_ns = std::chrono::steady_clock::now().time_since_epoch().count();
            const bool wait_for = chain.responsive;
            {
                std::lock_guard<std::mutex> rl(round->mu);
                ++round->pending_all;
                if (wait_for)
                    ++round->pending;
            }
            boost::asio::post(pool, [this, in = std::move(in), round, wait_for]() {
                FetchResult r;
                try {
                    r = fetch_chain(in);
                } catch (const std::exception& e) {
                    r = FetchResult{};
                    r.using_fallback = in.using_fallback;
                    r.error = e.what();
                } catch (...) {
                    r = FetchResult{};
                    r.using_fallback = in.using_fallback;
                    r.error = "unknown exception";
                }
                bool changed = false;
                try {
                    std::lock_guard<std::recursive_mutex> lock(m_mutex);
                    if (in.index < m_chains.size())
                        changed = apply_fetch_locked(in.index, r);
                } catch (const std::exception& e) {
                    LOG_WARNING << "[MM:" << in.config.symbol << "] applying its work failed: " << e.what();
                }
                if (changed)
                    m_work_dirty.store(true);
                in.io->in_flight.store(false);
                bool late;
                {
                    std::lock_guard<std::mutex> rl(round->mu);
                    late = round->closed;
                    if (!late) {
                        --round->pending_all;
                        if (wait_for)
                            --round->pending;
                    }
                }
                round->cv.notify_all();
                // An answer after its round: the commitment is rebuilt now,
                // not at the next tip change.
                if (late && changed && m_running)
                    request_refresh();
            });
        }
    }

    {
        std::unique_lock<std::mutex> rl(round->mu);
        round->cv.wait_for(rl, deadline, [&] { return round->pending == 0; });
        round->cv.wait_until(rl, round_start + std::min(deadline, kOutChainWait),
                             [&] { return round->pending_all == 0; });
        round->closed = true;
    }

    // Chains whose fetch has been running longer than hang_after: hung.
    {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        const int64_t now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
        for (auto& chain : m_chains) {
            if (!chain.io->in_flight.load() || !chain.responsive)
                continue;
            if (now_ns - chain.io->fetch_started_ns.load()
                < std::chrono::duration_cast<std::chrono::nanoseconds>(hang_after).count())
                continue;
            chain.responsive = false;
            chain.unresponsive_why = "no answer within " + std::to_string(hang_after.count()) + " ms";
            ++chain.dropouts;
            LOG_WARNING << "[MM:" << chain.config.symbol << "] " << chain.unresponsive_why
                        << (m_chains.size() > 1 ? ": out of the merged-mining commitment until it answers"
                                                : ": keeping its last work");
            if (m_chains.size() > 1)
                m_work_dirty.store(true);
        }
    }

    // ── Rebuild the aux blocks if the work changed or PPLNS is dirty ──
    // rebuild_cached_blocks() manages its own lock acquisition/release to
    // safely call payout_fn (which calls into tracker) without deadlock.
    const bool work_dirty = m_work_dirty.exchange(false);
    if (work_dirty || pplns_was_dirty) {
        const bool work_changed = rebuild_cached_blocks();

        // Notify stratum to push new work with the fresh MM commitment.
        // Without this, miners keep working on old coinbases that commit to
        // the previous DOGE block hash — any found DOGE blocks are stale.
        // Only when the commitment (or the header infos) changed: a chain
        // left without a block is fetched again on every poll to retry, and
        // each retry would otherwise push the same work to every miner.
        if (work_changed && m_on_work_changed) {
            boost::asio::post(m_ioc, m_on_work_changed);
        }
    }
}

std::vector<uint8_t> MergedMiningManager::get_auxpow_commitment()
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_cached_commitment;
}



// ─── Finds: assemble under m_mutex, submit outside it ───────────────────────

struct MergedMiningManager::SubmitJob
{
    uint32_t                             chain_id{0};
    std::string                          symbol;
    IAuxChainBackend*                    backend{nullptr};   // owned by the chain (never freed while running)
    // The backend's call lock (null: its submit has its own connection).
    std::shared_ptr<std::mutex>          backend_lock;
    std::string                          block_hex;
    uint256                              block_hash;
    int                                  height{0};
    uint64_t                             coinbase_value{0};
    SubmitVerdict                        verdict;
};

void MergedMiningManager::try_submit_merged_blocks(
    const std::string& parent_header_hex,
    const std::string& parent_coinbase_hex,
    const std::vector<std::string>& parent_merkle_branch,
    uint32_t parent_merkle_index,
    const uint256& parent_hash)
{
    std::vector<SubmitJob> jobs;
    {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    // For each aux chain, check if the parent PoW meets the aux target
    for (auto& chain : m_chains) {
      // A chain whose template or snapshot cannot be turned into a block
      // (malformed field, ...) does not stop the others.
      try {
        // No current block (e.g. no payouts for the new parent yet): a share
        // from an older job may still commit to a frozen one.
        if (chain.current_work.block_hash.IsNull() && chain.frozen_history.empty()) continue;

        auto it = m_tree.slot_map.find(chain.config.chain_id);
        if (it == m_tree.slot_map.end()) continue;

        uint32_t slot = it->second;

        // Check if parent hash meets aux target
        // Parent hash (scrypt for LTC) must be ≤ aux target
        static int mm_check_count = 0;
        ++mm_check_count;

        if (chain.current_work.target.IsNull()) {
            if (mm_check_count <= 5 || mm_check_count % 100 == 0) {
                LOG_WARNING << "[MM:" << chain.config.symbol << "] Check #" << mm_check_count
                            << " — target is NULL, no merged blocks can be found!"
                            << " (chain synced? work height=" << chain.current_work.height << ")";
            }
            continue;
        }
        bool meets = parent_hash <= chain.current_work.target;
        if (mm_check_count <= 5 || mm_check_count % 20 == 0 || meets) {
            LOG_INFO << "[MM:" << chain.config.symbol << "] Check #" << mm_check_count
                     << " parent_hash=" << parent_hash.GetHex().substr(0, 16) << "..."
                     << " aux_target=" << chain.current_work.target.GetHex().substr(0, 16) << "..."
                     << " meets=" << (meets ? "YES" : "no")
                     << " height=" << chain.current_work.height;
        }
        if (!meets) {
            continue;
        }

        LOG_WARNING << "\n"
                 << "######################################################################\n"
                 << "###  MERGED BLOCK FOUND! " << chain.config.symbol
                 << std::string(std::max(0, 39 - (int)chain.config.symbol.size()), ' ') << "###\n"
                 << "######################################################################\n"
                 << "  Chain:       " << chain.config.symbol << " (chain_id=" << chain.config.chain_id << ")\n"
                 << "  Height:      " << chain.current_work.height << "\n"
                 << "  Block hash:  " << chain.current_work.block_hash.GetHex() << "\n"
                 << "  Aux target:  " << chain.current_work.target.GetHex() << "\n"
                 << "  Parent PoW:  " << parent_hash.GetHex() << "\n"
                 << "######################################################################";

        // ── Extract committed root from parent coinbase ──
        // The LTC coinbase was built at stratum job time and may contain an OLDER
        // DOGE block hash than the current chain.frozen_* fields (which get
        // updated on each rebuild_cached_blocks cycle).
        // We must use the snapshot that matches the committed root, not the latest.
        auto parent_cb_bytes = from_hex(parent_coinbase_hex);
        static const uint8_t MAGIC[] = {0xfa, 0xbe, 0x6d, 0x6d};
        auto magic_pos = std::search(parent_cb_bytes.begin(), parent_cb_bytes.end(),
                                      std::begin(MAGIC), std::end(MAGIC));

        if (magic_pos == parent_cb_bytes.end()) {
            LOG_WARNING << "[MM:" << chain.config.symbol
                        << "] fabe6d6d NOT FOUND in parent coinbase — cannot submit";
            continue;
        }

        size_t magic_offset = std::distance(parent_cb_bytes.begin(), magic_pos);
        if (magic_offset + 4 + 32 > parent_cb_bytes.size()) {
            LOG_WARNING << "[MM:" << chain.config.symbol
                        << "] fabe6d6d found but insufficient bytes after magic";
            continue;
        }

        // Extract the committed root (32 bytes BE after magic → convert to uint256 LE)
        uint256 committed_root;
        {
            uint8_t* dst = reinterpret_cast<uint8_t*>(committed_root.data());
            for (int i = 0; i < 32; ++i)
                dst[i] = parent_cb_bytes[magic_offset + 4 + 31 - i];
        }

        // What this chain's block hash in the commitment is, and the leaves of
        // the chain merkle tree the root was built from (the proof's branch must
        // be taken from THESE, not from the chains' current hashes: the job's
        // coinbase may be older than the current commitment).
        // With one chain registered the committed root IS the chain's block
        // hash. With several, the root commits to the chains that were in that
        // round, in the smallest tree that holds them (a round without some
        // chain commits to the rest only): its tree and leaves were recorded
        // when the root was built, keyed by the root
        // (remember_committed_root_locked); a root not recorded cannot be
        // submitted, nor can a chain missing from it.
        uint256 committed_block_hash = committed_root;
        std::map<uint32_t, uint256> committed_leaves{{slot, committed_root}};
        AuxPowTree proof_tree = m_tree;
        if (m_chains.size() > 1) {
            const auto refuse = [&](const char* code, const std::string& why) {
                ++m_block_refusals_by_code[chain.config.symbol + ":" + code];
                LOG_WARNING << "[MM:" << chain.config.symbol << "] Merged block refused: " << why
                            << " — committed root " << committed_root.GetHex().substr(0, 16)
                            << ", not submitted";
            };
            if (magic_offset + 4 + 32 + 8 > parent_cb_bytes.size()) {
                refuse("no_commitment", "no tree size and nonce after the merged-mining root");
                continue;
            }
            uint32_t committed_tree_size = 0, committed_nonce = 0;
            std::memcpy(&committed_tree_size, &parent_cb_bytes[magic_offset + 4 + 32], 4);
            std::memcpy(&committed_nonce, &parent_cb_bytes[magic_offset + 4 + 32 + 4], 4);
            const auto committed = m_committed_roots.find(committed_root);
            if (committed == m_committed_roots.end()
                || committed_tree_size != committed->second.tree_size
                || committed_nonce != 0) {
                refuse("no_commitment",
                       "the parent coinbase does not carry a commitment this node built (tree size "
                           + std::to_string(committed_tree_size) + ", nonce "
                           + std::to_string(committed_nonce) + ")");
                continue;
            }
            const auto in_tree = committed->second.slots.find(chain.config.chain_id);
            const auto leaf = in_tree == committed->second.slots.end()
                ? committed->second.slot_hashes.end()
                : committed->second.slot_hashes.find(in_tree->second);
            if (leaf == committed->second.slot_hashes.end() || leaf->second.IsNull()) {
                refuse("not_committed", "this chain has no block in that commitment");
                continue;
            }
            slot = in_tree->second;
            committed_block_hash = leaf->second;
            committed_leaves = committed->second.slot_hashes;
            proof_tree.size = committed->second.tree_size;
            proof_tree.slot_map = committed->second.slots;
        }

        LOG_INFO << "[MM:" << chain.config.symbol
                 << "] committed_root=" << committed_root.GetHex().substr(0, 16)
                 << " frozen_block_hash=" << chain.frozen_block_hash.GetHex().substr(0, 16)
                 << " match=" << (committed_block_hash == chain.frozen_block_hash ? "yes" : "NO");

        // Look up the frozen snapshot matching the committed hash.
        // If it matches the current frozen_* fields, use those (common case).
        // Otherwise search the history ring buffer (stale job case).
        const nlohmann::json* use_tmpl = nullptr;
        const std::string*    use_coinbase = nullptr;

        if (committed_block_hash == chain.frozen_block_hash
            && !chain.frozen_coinbase_hex.empty()
            && !chain.frozen_template.is_null()) {
            // Fast path: latest freeze matches
            use_tmpl = &chain.frozen_template;
            use_coinbase = &chain.frozen_coinbase_hex;
        } else {
            // Stale job: look up in history
            auto it = chain.frozen_history.find(committed_block_hash);
            if (it != chain.frozen_history.end()) {
                use_tmpl = &it->second.tmpl;
                use_coinbase = &it->second.coinbase_hex;
                LOG_INFO << "[MM:" << chain.config.symbol
                         << "] Using historical snapshot for committed hash "
                         << committed_block_hash.GetHex().substr(0, 16)
                         << " (age=" << (std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::steady_clock::now().time_since_epoch()).count()
                                - it->second.timestamp) << "s)";
            }
        }

        if (!use_tmpl || !use_coinbase || use_coinbase->empty() || use_tmpl->is_null()) {
            ++m_block_refusals_by_code[chain.config.symbol + ":no_snapshot"];
            LOG_WARNING << "[MM:" << chain.config.symbol
                        << "] No matching snapshot for committed hash "
                        << committed_block_hash.GetHex().substr(0, 16)
                        << " — history_size=" << chain.frozen_history.size()
                        << ", skipping submission to avoid ban";
            continue;
        }

        // The chain merkle proof for this chain's slot, over the leaves the
        // committed root was built from.
        auto proof = proof_tree.compute_root(committed_leaves, slot);
        if (proof.root != committed_root) {
            ++m_block_refusals_by_code[chain.config.symbol + ":root_mismatch"];
            LOG_ERROR << "[MM:" << chain.config.symbol
                      << "] BUG: recomputed chain merkle root " << proof.root.GetHex().substr(0, 16)
                      << " != committed " << committed_root.GetHex().substr(0, 16)
                      << " — skipping to avoid ban";
            continue;
        }

        // Build auxpow proof
        std::string auxpow = build_auxpow_proof(
            parent_coinbase_hex,
            parent_hash,
            parent_merkle_branch,
            parent_merkle_index,
            proof.branch,
            proof.index,
            parent_header_hex);

        // Build the aux block from the matching snapshot
        auto& tmpl = *use_tmpl;
        uint32_t version = tmpl.value("version", 0x20000002u) | 0x100;
        std::string prev_hash_hex = tmpl.value("previousblockhash", "");
        uint32_t curtime = tmpl.value("curtime", 0u);
        std::string bits_hex = tmpl.value("bits", "1d00ffff");
        const int snapshot_height = tmpl.value("height", chain.current_work.height);

        auto coinbase_bytes = from_hex(*use_coinbase);
        uint256 cb_hash = Hash(coinbase_bytes);
        auto tx_hashes = collect_tx_hashes(cb_hash, tmpl);
        uint256 merkle_root = compute_tx_merkle_root(tx_hashes);

        // Build 80-byte header
        uint256 prev_hash; prev_hash.SetHex(prev_hash_hex);
        uint32_t nbits = std::stoul(bits_hex, nullptr, 16);

        // The block carries the snapshot's bits, so the parent PoW must
        // meet THEIR target. A snapshot of an older job can be on
        // another parent than the current work (DOGE retargets every
        // block): the check against the current target above does not
        // cover it, and a PoW-invalid block is never submitted or
        // relayed (peers ban for it).
        if (!(parent_hash <= chain::bits_to_target(nbits))) {
            ++m_snapshot_target_refusals;
            LOG_WARNING << "[MM:" << chain.config.symbol
                        << "] Parent PoW " << parent_hash.GetHex().substr(0, 16)
                        << " does not meet the snapshot's bits " << bits_hex
                        << " (block " << committed_block_hash.GetHex().substr(0, 16)
                        << " on " << prev_hash_hex.substr(0, 16) << ") — not submitted";
            continue;
        }
        std::vector<unsigned char> header_bytes(80);
        auto* p = header_bytes.data();
        std::memcpy(p, &version, 4); p += 4;
        std::memcpy(p, prev_hash.data(), 32); p += 32;
        std::memcpy(p, merkle_root.data(), 32); p += 32;
        std::memcpy(p, &curtime, 4); p += 4;
        std::memcpy(p, &nbits, 4); p += 4;
        uint32_t nonce = 0;
        std::memcpy(p, &nonce, 4);

        // Verify: the header we just built must hash to the committed root
        uint256 verify_hash = Hash(header_bytes);
        if (verify_hash != committed_block_hash) {
            LOG_ERROR << "[MM:" << chain.config.symbol
                      << "] BUG: rebuilt header hash " << verify_hash.GetHex().substr(0, 16)
                      << " != committed " << committed_block_hash.GetHex().substr(0, 16)
                      << " — skipping to avoid ban";
            continue;
        }

        // Assemble: header + auxpow + coinbase + template txs
        std::ostringstream blk;
        blk << to_hex(header_bytes.data(), 80);
        blk << auxpow;
        size_t n_tx = 1;
        if (tmpl.contains("transactions")) n_tx += tmpl["transactions"].size();
        blk << varint_hex(n_tx);
        blk << *use_coinbase;
        if (tmpl.contains("transactions")) {
            for (auto& tx : tmpl["transactions"])
                blk << tx.value("data", std::string(""));
        }

        auto block_hex = blk.str();
        // The chain's CheckBlock refuses a block over its limits (aux_block_limit:
        // the stripped size, AuxPoW included, and on a segwit chain the
        // weight): such a block can never be accepted, so it is refused here
        // and counted, neither submitted nor relayed (peers ban for it).
        const AuxBlockLimit limit = aux_block_limit(chain.config);
        if (limit.known()) {
            uint64_t stripped = 80 + auxpow.size() / 2 + varint_hex(n_tx).size() / 2 + use_coinbase->size() / 2;
            if (tmpl.contains("transactions"))
                for (auto& tx : tmpl["transactions"]) {
                    const auto raw = from_hex(tx.value("data", std::string("")));
                    // A transaction that does not parse counts whole (no witness to remove).
                    stripped += tx_stripped_size(raw).value_or(raw.size());
                }
            const std::string why = limit.check(stripped, block_hex.size() / 2);
            if (!why.empty()) {
                ++m_block_refusals_by_code[chain.config.symbol + ":oversize"];
                LOG_ERROR << "[MM:" << chain.config.symbol << "] Merged block REFUSED: " << why
                          << " (" << block_hex.size() / 2 << " bytes; auxpow " << auxpow.size() / 2
                          << " B, coinbase " << use_coinbase->size() / 2 << " B, " << n_tx - 1
                          << " txs) — not submitted, not relayed";
                continue;
            }
        }
        if (block_hex.empty())
            continue;
        LOG_INFO << "[MM:" << chain.config.symbol
                 << "] Merged block submitted (" << block_hex.size()/2 << " bytes"
                 << ", snapshot hash=" << committed_block_hash.GetHex().substr(0, 16) << ")";
        {
            // Transient manual-submit artifact kept at a fixed /tmp
            // path (NOT re-rooted under --data-dir): routing an
            // env/CLI-derived path into a file sink trips CodeQL
            // cpp/path-injection, and the state that matters for
            // co-located isolation (LevelDB, addrs, logs) is already
            // re-rooted via config_path(). See #722.
            // Chain id in the name for any chain but DOGE: two aux
            // chains can solve at the same height. The height is the
            // block's (the snapshot's), not the current work's.
            std::string path = (chain.config.chain_id == 98
                                    ? std::string("/tmp/c2pool_doge_block_")
                                    : "/tmp/c2pool_aux" + std::to_string(chain.config.chain_id) + "_block_")
                               + std::to_string(snapshot_height) + ".hex";
            std::ofstream f(path);
            if (f.is_open()) { f << block_hex; f.close(); }
        }
        // DOGE dual-path broadcast (the viable pair for a PPLNS merged
        // block): ARM B = full-block submitblock to a local daemon; ARM A =
        // the INDEPENDENT embedded P2P relay (m_block_relay_fn, bound in
        // main_ltc). The P2P relay fires UNCONDITIONALLY -- including when
        // the local submitblock is REJECTED for a transient/local reason --
        // because it is an independent arm that can still land the block on
        // the network; gating it on `ok` would drop a working reward-safety
        // arm. #744 note: submitauxblock is NOT a viable fallback here.
        // DOGE ships multiaddress=true and rebuild_cached_blocks commits
        // current_work.block_hash to c2pool's self-built PPLNS block hash,
        // which the daemon's AuxpowMiner never minted via createauxblock, so
        // submitauxblock of it is always rejected ("block hash unknown") --
        // and the daemon's own template would pay its aux address, violating
        // the trustless merged-payout invariant. So the canonical aux path
        // is deliberately NOT wired as a fallback.
        SubmitJob job;
        job.chain_id = chain.config.chain_id;
        job.symbol = chain.config.symbol;
        job.backend = chain.rpc.get();
        // A backend whose submit has its own connection is not waited for at
        // all; any other waits for at most the one call it is in.
        if (!job.backend->submit_independent())
            job.backend_lock = chain.io->lock_for(job.backend);
        job.block_hex = std::move(block_hex);
        // The block found is the snapshot's (a share on a stale job
        // commits to an older block than the current work).
        job.block_hash = committed_block_hash;
        job.height = snapshot_height;
        job.coinbase_value = tmpl.value("coinbasevalue", chain.current_work.coinbase_value);
        jobs.push_back(std::move(job));
      } catch (const std::exception& e) {
        ++m_block_refusals_by_code[chain.config.symbol + ":assembly_error"];
        LOG_ERROR << "[MM:" << chain.config.symbol << "] Merged block assembly failed: " << e.what()
                  << " — not submitted";
      }
    }
    } // m_mutex

    if (!jobs.empty())
        run_submit_jobs(jobs, parent_hash.GetHex());
    LOG_INFO << "[MM] try_submit_merged_blocks finished";
}

// The P2P relay first, for every block, on the calling thread (ARM A: it
// fires whatever the daemon will say). Then each block goes to its daemon
// on its own thread (none waits for another, one that throws stops nothing);
// as each answers, on the calling thread (the found-block callback reads its
// thread's submit context), its record. A backend that throws, or a daemon
// that does not answer, is unknown: the found-block check follows the chain.
// One block: submitted right here.
void MergedMiningManager::run_submit_jobs(std::vector<SubmitJob>& jobs, const std::string& parent_hash_hex)
{
    using K = SubmitVerdict::Kind;
    const auto submit_one = [](SubmitJob& j) {
        try {
            std::unique_lock<std::mutex> lock;
            if (j.backend_lock)
                lock = std::unique_lock<std::mutex>(*j.backend_lock);
            j.verdict = j.backend->submit_block_verdict(j.block_hex);
        } catch (const std::exception& e) {
            j.verdict = SubmitVerdict::of(K::unknown, std::string("the backend threw: ") + e.what());
            LOG_ERROR << "[MM:" << j.symbol << "] submit threw: " << e.what();
        } catch (...) {
            j.verdict = SubmitVerdict::of(K::unknown, "the backend threw an unknown exception");
            LOG_ERROR << "[MM:" << j.symbol << "] submit threw an unknown exception";
        }
    };
    BlockRelayFn relay;
    {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        relay = m_block_relay_fn;
    }
    if (relay)
        for (auto& j : jobs) {
            try { relay(j.chain_id, j.block_hex); }
            catch (...) {}
        }
    const auto finish = [&](SubmitJob& j) {
        try {
            std::lock_guard<std::recursive_mutex> lock(m_mutex);
            for (const auto& chain : m_chains)
                if (chain.config.chain_id == j.chain_id) {
                    record_discovered_block(chain, j.verdict, parent_hash_hex, j.block_hash, j.height,
                                            j.coinbase_value);
                    break;
                }
        } catch (const std::exception& e) {
            LOG_ERROR << "[MM:" << j.symbol << "] recording the found block failed: " << e.what();
        }
        LOG_INFO << "[MM:" << j.symbol << "] Post-submission processing complete";
    };

    if (jobs.size() == 1) {
        submit_one(jobs[0]);
        finish(jobs[0]);
        return;
    }

    std::mutex mu;
    std::condition_variable cv;
    std::deque<size_t> done;
    std::vector<std::thread> threads;
    threads.reserve(jobs.size());
    for (size_t i = 0; i < jobs.size(); ++i) {
        auto work = [&, i]() {
            submit_one(jobs[i]);
            {
                std::lock_guard<std::mutex> l(mu);
                done.push_back(i);
            }
            cv.notify_one();
        };
        try {
            threads.emplace_back(work);
        } catch (const std::exception& e) {
            LOG_WARNING << "[MM:" << jobs[i].symbol << "] no thread for the submit (" << e.what()
                        << "): submitting here";
            work();
        }
    }
    for (size_t n = 0; n < jobs.size(); ++n) {
        size_t i;
        {
            std::unique_lock<std::mutex> l(mu);
            cv.wait(l, [&] { return !done.empty(); });
            i = done.front();
            done.pop_front();
        }
        finish(jobs[i]);
    }
    for (auto& t : threads)
        t.join();
}

void MergedMiningManager::submit_aux_and_relay(ChainState& chain, const std::string& auxpow,
                                                const std::string& parent_hash_hex)
{
    bool ok = chain.rpc->submit_aux_block(chain.current_work.block_hash, auxpow);
    // Force aux work refresh — tip has changed
    chain.last_tip.clear();
    record_discovered_block(chain, ok, parent_hash_hex);
    if (ok) {
        // Fetch the accepted block and relay via P2P for fast propagation
        if (m_block_relay_fn) {
            auto best = chain.rpc->get_best_block_hash();
            if (!best.empty()) {
                auto block_hex = chain.rpc->get_block_hex(best);
                if (!block_hex.empty())
                    m_block_relay_fn(chain.config.chain_id, block_hex);
            }
        }
    }
}

nlohmann::json MergedMiningManager::aux_template_json(const std::string& symbol) const
{
    auto upper = [](std::string v) {
        for (auto& ch : v)
            if (ch >= 'a' && ch <= 'z')
                ch = static_cast<char>(ch - 32);
        return v;
    };
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    for (const auto& chain : m_chains) {
        if (upper(chain.config.symbol) != upper(symbol))
            continue;
        const auto& w = chain.current_work;
        const auto& t = w.block_template;
        nlohmann::json j = nlohmann::json::object();
        j["chain"] = chain.config.symbol;
        j["chain_id"] = chain.config.chain_id;
        j["height"] = w.height;
        j["previousblockhash"] = t.is_object() ? t.value("previousblockhash", w.prev_block_hash)
                                               : w.prev_block_hash;
        j["bits"] = t.is_object() ? t.value("bits", std::string()) : std::string();
        j["version"] = t.is_object() ? t.value("version", 0) : 0;
        j["curtime"] = t.is_object() ? t.value("curtime", int64_t{0}) : int64_t{0};
        j["mintime"] = t.is_object() ? t.value("mintime", int64_t{0}) : int64_t{0};
        j["coinbasevalue"] = w.coinbase_value;
        j["target"] = w.target.GetHex();
        j["block_hash"] = w.block_hash.GetHex();
        j["coinbase_hex"] = chain.frozen_coinbase_hex;
        j["using_fallback"] = chain.using_fallback;
        const auto why = core::coin::template_degraded_code(t);
        j["degraded"] = why ? nlohmann::json(*why) : nlohmann::json(nullptr);
        nlohmann::json txs = nlohmann::json::array();
        uint64_t tx_bytes = 0;
        if (t.is_object() && t.contains("transactions") && t["transactions"].is_array()) {
            for (const auto& e : t["transactions"]) {
                if (!e.is_object())
                    continue;
                const std::string data = e.value("data", std::string());
                tx_bytes += data.size() / 2;
                txs.push_back({{"txid", e.value("txid", std::string())},
                               {"data", data},
                               {"fee", e.contains("fee") ? e["fee"] : nlohmann::json(nullptr)}});
            }
        }
        j["tx_count"] = txs.size();
        j["tx_bytes"] = tx_bytes;
        j["transactions"] = std::move(txs);
        return j;
    }
    return nullptr;
}

nlohmann::json MergedMiningManager::get_template_gate_json() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    nlohmann::json j = nlohmann::json::object();
    for (const auto& chain : m_chains)
        j[chain.config.symbol] = {{"degraded", chain.templates_degraded},
                                  {"refetched_clean", chain.templates_refetched_clean},
                                  {"still_degraded", chain.templates_still_degraded},
                                  {"degraded_now", chain.template_degraded}};
    return j;
}

bool MergedMiningManager::has_frozen_snapshot(uint32_t chain_id, const uint256& block_hash) const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    for (const auto& chain : m_chains)
        if (chain.config.chain_id == chain_id)
            return chain.frozen_history.count(block_hash) > 0;
    return false;
}

uint32_t MergedMiningManager::block_size_reserve_locked(const ChainState& chain) const
{
    uint32_t aux_branch_len = 0;
    for (uint32_t n = 1; n < m_tree.size; n <<= 1)
        ++aux_branch_len;
    return aux_block_reserve_bytes(m_parent_coinbase_bytes.load(std::memory_order_relaxed),
                                   m_parent_branch_len.load(std::memory_order_relaxed),
                                   aux_branch_len,
                                   static_cast<uint32_t>(chain.frozen_coinbase_hex.size() / 2));
}

uint32_t MergedMiningManager::block_sigop_reserve_locked(const ChainState& chain) const
{
    if (chain.frozen_coinbase_hex.empty())
        return kAuxCoinbaseSigopsUnknown;
    const auto ops = core::coin::sigops::tx_hex_legacy_sigops(chain.frozen_coinbase_hex);
    if (!ops)
        return kAuxCoinbaseSigopsUnknown;
    return *ops + kAuxCoinbaseSigopMargin;
}

uint32_t MergedMiningManager::block_size_reserve(uint32_t chain_id) const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    for (const auto& chain : m_chains)
        if (chain.config.chain_id == chain_id)
            return block_size_reserve_locked(chain);
    return 0;
}

nlohmann::json MergedMiningManager::get_block_refusals_json() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    nlohmann::json j = nlohmann::json::object();
    for (const auto& [code, n] : m_block_refusals_by_code)
        j[code] = n;
    return j;
}

std::map<uint32_t, AuxWork> MergedMiningManager::get_current_work() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    std::map<uint32_t, AuxWork> result;
    for (const auto& c : m_chains) {
        result[c.config.chain_id] = c.current_work;
    }
    return result;
}

// ─── Committed roots ─────────────────────────────────────────────────────────
// With a chain merkle tree of more than one slot a parent coinbase carries the
// root over all the chains' block hashes: a find has to recover which block
// of its chain the root commits to and the chain merkle branch for it from
// the leaves the root was built from, even when the job is older than the
// current commitment (the frozen snapshots live per chain, a job's root
// commits to one of each at once). Aged and capped like frozen_history.
void MergedMiningManager::remember_committed_root_locked(const uint256& root, const AuxPowTree& tree,
                                                         const std::map<uint32_t, uint256>& slot_hashes,
                                                         int64_t now)
{
    auto& rec = m_committed_roots[root];
    rec.slots = tree.slot_map;
    rec.slot_hashes = slot_hashes;
    rec.tree_size = tree.size;
    // Jobs may keep committing to the same root: it ages from now.
    rec.timestamp = now;
    rec.seq = ++m_frozen_seq;
    for (auto it = m_committed_roots.begin(); it != m_committed_roots.end(); ) {
        if (now - it->second.timestamp > ChainState::FROZEN_EXPIRY_SEC)
            it = m_committed_roots.erase(it);
        else
            ++it;
    }
    while (m_committed_roots.size() > kMaxCommittedRoots) {
        auto oldest = m_committed_roots.begin();
        for (auto it = m_committed_roots.begin(); it != m_committed_roots.end(); ++it)
            if (it->second.seq < oldest->second.seq)
                oldest = it;
        m_committed_roots.erase(oldest);
    }
}

// ─── rebuild_cached_blocks ──────────────────────────────────────────────────
// p2pool equivalent: set_merged_work() Phase A.
// Builds the full DOGE block (PPLNS coinbase + merkle + header) ONCE,
// freezes the snapshot, computes the commitment, and caches everything.
// Stratum sessions read the cache via get_cached_header_infos_and_commitment().
//
// Lock strategy: snapshot chain data under m_mutex, release, call payout_fn
// (which calls back into tracker), then re-acquire to store results + freeze.
bool MergedMiningManager::rebuild_cached_blocks()
{
    m_pplns_dirty.store(false, std::memory_order_relaxed);

    // ── Step 1: Snapshot chain data under lock ──
    struct ChainSnapshot {
        uint32_t chain_id; uint64_t coinbase_value; int height;
        nlohmann::json block_template;
    };
    std::vector<ChainSnapshot> snapshots;
    PayoutProvider payout_fn;
    {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        payout_fn = m_payout_provider;
        for (const auto& chain : m_chains) {
            // With several chains, one that did not answer its last poll is
            // out of the commitment: no block is built for it. A chain with a
            // configuration error never is.
            if (m_chains.size() > 1 && !chain.responsive) continue;
            if (!chain.config_error.empty()) continue;
            if (chain.current_work.coinbase_value == 0) continue;
            if (chain.current_work.block_template.is_null()) continue;
            snapshots.push_back({chain.config.chain_id,
                chain.current_work.coinbase_value,
                chain.current_work.height,
                chain.current_work.block_template});
        }
    }
    // ── Lock released — safe to call payout_fn ──

    std::vector<MergedHeaderInfo> header_infos;
    std::vector<nlohmann::json> built_templates;   // the template each header_infos entry was built from
    // Chains whose block could not be built this time (no payouts): chain id -> why.
    std::map<uint32_t, std::string> no_payouts;
    // The best share each chain's payouts are (or would have been) split at.
    std::map<uint32_t, uint256> payout_basis;

    for (auto& snap : snapshots)
    {
        const auto& tmpl = snap.block_template;
        MergedHeaderInfo info;
        info.chain_id = snap.chain_id;
        info.coinbase_value = snap.coinbase_value;
        info.block_height = static_cast<uint32_t>(snap.height);

        // Build PPLNS coinbase for this chain (NO lock held — safe)
        payout_basis[snap.chain_id] = uint256();
        if (!payout_fn) {
            no_payouts[snap.chain_id] = "no_provider";
            continue;
        }
        t_payout_miss.clear();
        t_payout_basis.SetNull();
        auto payouts = payout_fn(snap.chain_id, snap.coinbase_value);
        payout_basis[snap.chain_id] = t_payout_basis;
        info.payout_basis = t_payout_basis;
        if (payouts.empty()) {
            no_payouts[snap.chain_id] = t_payout_miss.empty() ? "empty" : t_payout_miss;
            continue;
        }

        uint32_t version = tmpl.value("version", 1u);
        if ((version >> 16) > 0)  // has chain_id → AuxPoW chain
            version |= (1 << 8);
        std::string prev_hash_hex = tmpl.value("previousblockhash", std::string("0000000000000000000000000000000000000000000000000000000000000000"));
        uint32_t curtime = tmpl.value("curtime", 0u);
        std::string bits_hex = tmpl.value("bits", std::string("1d00ffff"));

        try {
            uint256 state_root; // zero — avoid deadlock
            std::string coinbase_hex = build_pplns_coinbase_hex(
                info.block_height, payouts, state_root);
            if (coinbase_hex.empty()) continue;

            auto coinbase_bytes = from_hex(coinbase_hex);
            uint256 cb_hash = Hash(coinbase_bytes);
            auto tx_hashes = collect_tx_hashes(cb_hash, tmpl);
            uint256 merkle_root = compute_tx_merkle_root(tx_hashes);
            info.coinbase_merkle_branches = compute_merkle_link(tx_hashes, 0);
            info.coinbase_hex = coinbase_hex;

            // Extract scriptSig
            // Layout: version(4) + vin_count(1) + prev_hash(32) + prev_idx(4) = 41 bytes
            if (coinbase_bytes.size() > 42) {
                size_t pos = 41;
                uint64_t sslen = coinbase_bytes[pos++];
                if (sslen < 0xfd && pos + sslen <= coinbase_bytes.size()) {
                    info.coinbase_script.assign(
                        coinbase_bytes.begin() + pos,
                        coinbase_bytes.begin() + pos + sslen);
                }
            }

            // 80-byte header
            uint256 prev_hash;
            prev_hash.SetHex(prev_hash_hex);
            uint32_t nbits = std::stoul(bits_hex, nullptr, 16);

            info.block_header.resize(80);
            auto* p = info.block_header.data();
            std::memcpy(p, &version, 4); p += 4;
            std::memcpy(p, prev_hash.data(), 32); p += 32;
            std::memcpy(p, merkle_root.data(), 32); p += 32;
            std::memcpy(p, &curtime, 4); p += 4;
            std::memcpy(p, &nbits, 4); p += 4;
            uint32_t nonce = 0;
            std::memcpy(p, &nonce, 4);

            uint256 frozen_hdr_hash = Hash(info.block_header);
            LOG_INFO << "[MM-cache:" << snap.chain_id << "] built DOGE block hash="
                     << frozen_hdr_hash.GetHex().substr(0, 16)
                     << " payouts=" << payouts.size()
                     << " cb_len=" << coinbase_hex.size()/2;

            header_infos.push_back(std::move(info));
            built_templates.push_back(tmpl);
        } catch (const std::exception& e) {
            LOG_WARNING << "[MM:chain_" << snap.chain_id
                        << "] rebuild_cached_blocks failed: " << e.what();
        }
    }

    // ── Step 2: Re-acquire lock, freeze snapshots, compute commitment, cache ──
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    const auto now_sec = this->now_sec();

    std::vector<MergedHeaderInfo> adopted;   // the header infos stratum sessions will read
    for (size_t k = 0; k < header_infos.size(); ++k) {
        const auto& hi = header_infos[k];
        for (auto& chain : m_chains) {
            if (chain.config.chain_id != hi.chain_id) continue;
            // The work moved on while the payouts were computed (a refresh
            // replaced the template): this block is of the old template and
            // nobody commits to it. Freezing it under the new template would
            // leave a snapshot whose header does not hash to its key.
            if (chain.current_work.block_template != built_templates[k]) {
                ++m_rebuild_stale_results;
                break;
            }
            adopted.push_back(hi);
            if (chain.no_payout_episode) {
                const int64_t secs = now_sec - chain.no_payout_since;
                LOG_INFO << "[MM:" << chain.config.symbol << "] payouts back: " << chain.no_payout_rebuilds
                         << " rebuild(s) without payouts over " << secs << "s";
                chain.no_payout_seconds += secs;
                chain.no_payout_episode = false;
                chain.no_payout_rebuilds = 0;
            }
            if (hi.block_header.size() == 80) {
                chain.current_work.block_hash = Hash(hi.block_header);
                chain.frozen_block_hash = chain.current_work.block_hash;
            }
            chain.frozen_coinbase_hex = hi.coinbase_hex;
            chain.frozen_template = built_templates[k];
            chain.frozen_payout_basis = hi.payout_basis;

            if (!chain.frozen_block_hash.IsNull()) {
                chain.frozen_history[chain.frozen_block_hash] = {
                    chain.frozen_template,
                    chain.frozen_coinbase_hex,
                    now_sec,
                    ++m_frozen_seq
                };
                // Expire old snapshots, then keep at most MAX_FROZEN_HISTORY,
                // dropping the oldest first. (The map is keyed by block hash:
                // trimming in key order could drop the snapshot just frozen,
                // and a find committing to it would be skipped at submit.)
                for (auto it = chain.frozen_history.begin(); it != chain.frozen_history.end(); ) {
                    if (now_sec - it->second.timestamp > ChainState::FROZEN_EXPIRY_SEC)
                        it = chain.frozen_history.erase(it);
                    else
                        ++it;
                }
                while (chain.frozen_history.size() > ChainState::MAX_FROZEN_HISTORY) {
                    auto oldest = chain.frozen_history.begin();
                    for (auto it = chain.frozen_history.begin(); it != chain.frozen_history.end(); ++it)
                        if (it->second.seq < oldest->second.seq)
                            oldest = it;
                    chain.frozen_history.erase(oldest);
                }
                LOG_INFO << "[MM-cache] chain " << hi.chain_id
                         << " frozen hash=" << chain.frozen_block_hash.GetHex().substr(0, 16)
                         << " history_size=" << chain.frozen_history.size();
            }
            break;
        }
    }

    // A chain whose block the merged manager builds itself (multiaddress)
    // can only be committed to with a block it froze: try_submit rebuilds
    // the found block from that snapshot. After a refresh its current work
    // carries the backend's hash instead (for the embedded DOGE backend the
    // PARENT's hash) until a rebuild freezes a block; when this rebuild
    // could not (no payouts, or the work moved on meanwhile), a share
    // committing to that hash would find a DOGE block that cannot be built.
    // Keep the last block frozen on the same parent (valid, submittable),
    // else take the chain out of the commitment until a block is built.
    const auto prev_of = [](const nlohmann::json& t) {
        return t.is_object() ? t.value("previousblockhash", std::string()) : std::string();
    };
    // The last block's payouts must also still be for the current best share:
    // a job's LTC share carries that best as its prev share, and a V36 peer
    // re-derives the merged payouts from it (p2pool data.py
    // verify_merged_coinbase_commitment) and rejects the share otherwise.
    for (auto& chain : m_chains) {
        const auto np = no_payouts.find(chain.config.chain_id);
        const auto basis = payout_basis.find(chain.config.chain_id);
        const bool same_best = basis == payout_basis.end()
            || basis->second == chain.frozen_payout_basis;
        const char* action = "its last block stays committed";
        if (chain.config.multiaddress && !chain.current_work.block_hash.IsNull()
            && (chain.current_work.block_hash != chain.frozen_block_hash || !same_best)) {
            const std::string parent = prev_of(chain.current_work.block_template);
            const bool keep = same_best && !chain.frozen_block_hash.IsNull() && !parent.empty()
                && prev_of(chain.frozen_template) == parent
                && chain.frozen_history.count(chain.frozen_block_hash) > 0;
            if (!same_best)
                ++m_rebuild_dropped_best_moved;
            if (keep) {
                chain.current_work.block_hash = chain.frozen_block_hash;
                // Jobs keep committing to it: it ages from now, not from when
                // it was frozen (else the next freeze expires it under them),
                // and it is the newest for the oldest-first size trim too.
                auto& kept = chain.frozen_history[chain.frozen_block_hash];
                kept.timestamp = now_sec;
                kept.seq = ++m_frozen_seq;
                ++m_rebuild_kept_last_block;
                action = "keeping the last block built on this parent";
            } else {
                chain.current_work.block_hash.SetNull();
                ++m_rebuild_dropped_commitment;
                action = same_best ? "no commitment to this chain until a block is built"
                                   : "the last block pays another best share: no commitment until a block is built";
            }
        }
        if (np == no_payouts.end())
            continue;
        ++m_rebuild_no_payouts[np->second];
        ++chain.no_payout_rebuilds;
        if (!chain.no_payout_episode) {
            chain.no_payout_episode = true;
            chain.no_payout_since = now_sec;
            LOG_INFO << "[MM:" << chain.config.symbol << "] rebuild without payouts (" << np->second
                     << "): " << action;
        }
    }

    // A chain committed to a block this rebuild did not build (kept, or a
    // stale result, or no payouts on a block already frozen) keeps the
    // header info stratum sessions put in their shares for that block.
    for (const auto& chain : m_chains) {
        if (chain.current_work.block_hash.IsNull())
            continue;
        if ((m_chains.size() > 1 && !chain.responsive) || !chain.config_error.empty())
            continue;
        bool have = false;
        for (const auto& a : adopted)
            have = have || a.chain_id == chain.config.chain_id;
        if (have)
            continue;
        for (const auto& old : m_cached_header_infos)
            if (old.chain_id == chain.config.chain_id && old.block_header.size() == 80
                && Hash(old.block_header) == chain.current_work.block_hash) {
                adopted.push_back(old);
                break;
            }
    }

    // Rebuild commitment from PPLNS-derived block hashes
    std::vector<uint8_t> commitment;
    if (m_chains.size() <= 1) {
        std::map<uint32_t, uint256> slot_hashes;
        for (const auto& chain : m_chains) {
            if (!chain.current_work.block_hash.IsNull() && chain.config_error.empty()) {
                auto it = m_tree.slot_map.find(chain.config.chain_id);
                if (it != m_tree.slot_map.end())
                    slot_hashes[it->second] = chain.current_work.block_hash;
            }
        }
        if (!slot_hashes.empty()) {
            auto proof = m_tree.compute_root(slot_hashes, 0);
            commitment = build_auxpow_commitment(proof.root, m_tree.size);
        }   // else nothing buildable to commit to
    } else {
        // Several chains: the round commits to the chains that have a block
        // now, answered their poll and, when the block is c2pool's own
        // (multiaddress), whose header info the shares carry — in the
        // smallest tree that holds exactly them (AuxPowTree::build, the
        // daemons' getExpectedIndex slots). A V36 peer checks the tree size
        // against the chains in the share's merged_coinbase_info the same way
        // (p2pool data.py make_auxpow_tree), so a chain out this round must
        // not leave an empty slot behind.
        // A chain whose block c2pool does not build (createauxblock mode)
        // has no header info: it is committed only while no chain is carried
        // (a share without merged_coinbase_info is not checked); once one is,
        // the tree holds the carried chains alone (the peers' rule:
        // check_merged_aux_commitment).
        std::vector<uint32_t> ids;
        std::map<uint32_t, uint256> by_chain;
        std::vector<std::pair<uint32_t, uint256>> uncarried;   // createauxblock-mode chains
        for (const auto& chain : m_chains) {
            if (chain.current_work.block_hash.IsNull() || !chain.responsive || !chain.config_error.empty())
                continue;
            if (!chain.config.multiaddress) {
                uncarried.emplace_back(chain.config.chain_id, chain.current_work.block_hash);
                continue;
            }
            bool carried = false;
            for (const auto& a : adopted)
                carried = carried || (a.chain_id == chain.config.chain_id && a.block_header.size() == 80
                                      && Hash(a.block_header) == chain.current_work.block_hash);
            if (!carried)
                continue;
            ids.push_back(chain.config.chain_id);
            by_chain[chain.config.chain_id] = chain.current_work.block_hash;
        }
        if (ids.empty())
            for (const auto& [cid, hash] : uncarried) {
                ids.push_back(cid);
                by_chain[cid] = hash;
            }
        // The shares carry the header infos of the committed chains only.
        adopted.erase(std::remove_if(adopted.begin(), adopted.end(),
                                     [&](const MergedHeaderInfo& a) { return !by_chain.count(a.chain_id); }),
                      adopted.end());
        const AuxPowTree round_tree = AuxPowTree::build(ids);
        if (!ids.empty() && round_tree.size > 0) {
            std::map<uint32_t, uint256> slot_hashes;
            for (const auto& [cid, hash] : by_chain)
                slot_hashes[round_tree.slot_map.at(cid)] = hash;
            auto proof = round_tree.compute_root(slot_hashes, 0);
            commitment = build_auxpow_commitment(proof.root, round_tree.size);
            // The root alone does not say which chains and blocks it commits
            // to: keep its tree and leaves for the shares of this job.
            remember_committed_root_locked(proof.root, round_tree, slot_hashes, now_sec);
        }
    }

    // What the miners' work carries: the commitment, and the header infos
    // their shares claim. Unchanged (e.g. a chain without payouts retried
    // and dropped again): nothing to push.
    bool work_changed = commitment != m_cached_commitment
        || adopted.size() != m_cached_header_infos.size();
    for (size_t k = 0; !work_changed && k < adopted.size(); ++k)
        work_changed = adopted[k].chain_id != m_cached_header_infos[k].chain_id
            || adopted[k].block_header != m_cached_header_infos[k].block_header;
    ++(work_changed ? m_rebuild_work_changed : m_rebuild_work_unchanged);

    m_cached_commitment = std::move(commitment);
    // Store the cached header infos for stratum sessions to read
    m_cached_header_infos = std::move(adopted);

    LOG_INFO << "[MM-cache] rebuild complete: " << m_cached_header_infos.size()
             << " chains, commitment=" << m_cached_commitment.size() << " bytes"
             << (work_changed ? "" : " (unchanged)");
    return work_changed;
}

// ─── get_cached_header_infos_and_commitment ─────────────────────────────────
// Lock-free read (well, brief mutex) of pre-built DOGE block data.
// Called by build_connection_coinbase() — replaces the per-session rebuild.
std::pair<std::vector<MergedMiningManager::MergedHeaderInfo>, std::vector<uint8_t>>
MergedMiningManager::get_cached_header_infos_and_commitment() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return {m_cached_header_infos, m_cached_commitment};
}

void MergedMiningManager::set_payout_provider(PayoutProvider provider)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_payout_provider = std::move(provider);
}

void MergedMiningManager::set_state_root_provider(StateRootProvider provider)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_state_root_provider = std::move(provider);
}

void MergedMiningManager::set_block_relay_fn(BlockRelayFn fn)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_block_relay_fn = std::move(fn);
}

// ─── Multiaddress block construction ─────────────────────────────────────────
//
// Builds a complete aux-chain block from getblocktemplate data and PPLNS
// payouts.  The block is ready for submitblock.
//
// Block layout:
//   header(80 bytes) + auxpow + varint(tx_count) + coinbase_tx + template_txs
//
// The coinbase transaction is built fresh with the supplied payout outputs.
// Template transactions are included verbatim from getblocktemplate.

// ─── Shared helpers ──────────────────────────────────────────────────────────

// [v36-audit C4] Output ordering here is NODE-LOCAL and NOT consensus-bearing:
// the assembled DOGE coinbase is submitted only to dogecoind, which accepts any
// valid ordering. The sharechain commits to merged work via the AuxPoW merkle
// proof, not by re-deriving these outputs across peers. Donation split + dust
// tiebreak below are deterministic purely for stable local block assembly.
/*static*/ std::string MergedMiningManager::build_pplns_coinbase_hex(
    int height,
    const std::vector<std::pair<std::vector<unsigned char>, uint64_t>>& payouts,
    const uint256& the_state_root)
{
    if (payouts.empty()) return {};

    static const std::vector<unsigned char> COMBINED_DONATION = {
        0xa9, 0x14, 0x8c, 0x62, 0x72, 0x62, 0x1d, 0x89, 0xe8, 0xfa,
        0x52, 0x6d, 0xd8, 0x6a, 0xcf, 0xf6, 0x0c, 0x71, 0x36, 0xbe,
        0x8e, 0x85, 0x87
    };

    std::ostringstream cb;
    cb << "01000000" << "01"
       << "0000000000000000000000000000000000000000000000000000000000000000"
       << "ffffffff";

    // scriptSig: BIP34 height + "/c2pool/" + THE state root
    std::ostringstream sig;
    if (height > 0 && height <= 16) {
        uint8_t op = static_cast<uint8_t>(0x50 + height);
        sig << to_hex(&op, 1);
    } else {
        std::vector<uint8_t> hbytes;
        uint32_t h = static_cast<uint32_t>(height);
        while (h > 0) { hbytes.push_back(h & 0xff); h >>= 8; }
        if (!hbytes.empty() && (hbytes.back() & 0x80)) hbytes.push_back(0);
        uint8_t push_len = static_cast<uint8_t>(hbytes.size());
        sig << to_hex(&push_len, 1) << to_hex(hbytes.data(), hbytes.size());
    }
    const std::string ctag = "/c2pool/";
    for (char c : ctag) { uint8_t b = static_cast<uint8_t>(c); sig << to_hex(&b, 1); }
    if (!the_state_root.IsNull()) sig << to_hex(the_state_root.data(), 32);
    std::string sig_hex = sig.str();
    cb << varint_hex(sig_hex.size() / 2) << sig_hex << "ffffffff";

    // Separate donation from miner outputs
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> miner_outs;
    uint64_t donation_amount = 0;
    for (const auto& [script, amount] : payouts) {
        if (script == COMBINED_DONATION) donation_amount += amount;
        else if (amount > 0) miner_outs.emplace_back(script, amount);
    }
    if (donation_amount < 1 && !miner_outs.empty()) {
        // Deterministic tiebreak: deduct from largest amount (then largest script)
        auto largest = std::max_element(miner_outs.begin(), miner_outs.end(),
            [](const auto& a, const auto& b) {
                if (a.second != b.second) return a.second < b.second;
                return a.first < b.first;
            });
        largest->second -= 1;
        donation_amount += 1;
    }

    const std::string op_return_text = "P2Pool merged mining";
    std::vector<unsigned char> op_return_script;
    op_return_script.push_back(0x6a);
    op_return_script.push_back(static_cast<unsigned char>(op_return_text.size()));
    op_return_script.insert(op_return_script.end(), op_return_text.begin(), op_return_text.end());

    cb << varint_hex(miner_outs.size() + 2);
    for (const auto& [script, amount] : miner_outs) {
        uint8_t vbuf[8]; for (int i = 0; i < 8; ++i) vbuf[i] = (amount >> (8*i)) & 0xFF;
        cb << to_hex(vbuf, 8) << varint_hex(script.size()) << to_hex(script.data(), script.size());
    }
    { uint8_t z[8] = {}; cb << to_hex(z, 8)
        << varint_hex(op_return_script.size()) << to_hex(op_return_script.data(), op_return_script.size()); }
    { uint8_t vbuf[8]; for (int i = 0; i < 8; ++i) vbuf[i] = (donation_amount >> (8*i)) & 0xFF;
      cb << to_hex(vbuf, 8) << varint_hex(COMBINED_DONATION.size())
         << to_hex(COMBINED_DONATION.data(), COMBINED_DONATION.size()); }
    cb << "00000000";
    return cb.str();
}

/*static*/ uint256 MergedMiningManager::compute_tx_merkle_root(
    const std::vector<uint256>& tx_hashes)
{
    if (tx_hashes.empty()) return uint256();
    auto layer = tx_hashes;
    while (layer.size() > 1) {
        if (layer.size() % 2) layer.push_back(layer.back());
        std::vector<uint256> next;
        for (size_t i = 0; i < layer.size(); i += 2)
            next.push_back(Hash(layer[i], layer[i+1]));
        layer = std::move(next);
    }
    return layer[0];
}

/*static*/ std::vector<uint256> MergedMiningManager::compute_merkle_link(
    const std::vector<uint256>& tx_hashes, size_t leaf_index)
{
    std::vector<uint256> branches;
    auto all = tx_hashes;
    size_t idx = leaf_index;
    while (all.size() > 1) {
        if (all.size() % 2) all.push_back(all.back());
        branches.push_back(all[idx ^ 1]);
        std::vector<uint256> next;
        for (size_t i = 0; i < all.size(); i += 2)
            next.push_back(Hash(all[i], all[i+1]));
        all = std::move(next);
        idx >>= 1;
    }
    return branches;
}

/*static*/ std::vector<uint256> MergedMiningManager::collect_tx_hashes(
    const uint256& coinbase_hash, const nlohmann::json& tmpl)
{
    std::vector<uint256> tx_hashes;
    tx_hashes.push_back(coinbase_hash);
    if (tmpl.contains("transactions") && tmpl["transactions"].is_array()) {
        for (const auto& tx : tmpl["transactions"]) {
            std::string txid_str = tx.value("txid", "");
            if (!txid_str.empty()) {
                uint256 h; h.SetHex(txid_str); tx_hashes.push_back(h);
            } else {
                auto raw = from_hex(tx.value("data", ""));
                tx_hashes.push_back(Hash(raw));
            }
        }
    }
    return tx_hashes;
}

// ─── build_multiaddress_block (refactored to use shared helpers) ─────────────

std::string MergedMiningManager::build_multiaddress_block(
    const nlohmann::json& tmpl,
    const std::vector<std::pair<std::vector<unsigned char>, uint64_t>>& payouts,
    const std::string& auxpow_hex,
    const uint256& the_state_root)
{
    if (payouts.empty() || !tmpl.contains("previousblockhash"))
        return {};

    uint32_t version  = tmpl.value("version", 0x20000002u) | 0x100;
    std::string prev_hash_hex = tmpl.value("previousblockhash", "");
    uint32_t curtime  = tmpl.value("curtime", 0u);
    std::string bits_hex = tmpl.value("bits", "1d00ffff");
    int height = tmpl.value("height", 0);

    // --- Build coinbase TX using shared helper ---
    std::string coinbase_hex = build_pplns_coinbase_hex(height, payouts, the_state_root);
    if (coinbase_hex.empty()) return {};

    // Skip old inline coinbase — now built by build_pplns_coinbase_hex above.
    // Jump directly to merkle root + block assembly.
    if (false) { // ---- BEGIN DEAD CODE (replaced by shared helper) ----
    std::ostringstream cb;
    // tx version (1, LE)
    cb << "01000000";

    // 1 input
    cb << "01";
    // prev_output: null hash + 0xffffffff
    cb << "0000000000000000000000000000000000000000000000000000000000000000"
       << "ffffffff";

    // scriptSig: BIP34 height + canonical extra text (matches Python p2pool)
    std::ostringstream sig;
    if (height > 0 && height <= 16) {
        // OP_1..OP_16
        uint8_t op = static_cast<uint8_t>(0x50 + height);
        sig << to_hex(&op, 1);
    } else {
        // Encode height as minimal CScriptNum LE bytes
        std::vector<uint8_t> hbytes;
        uint32_t h = static_cast<uint32_t>(height);
        while (h > 0) { hbytes.push_back(h & 0xff); h >>= 8; }
        if (!hbytes.empty() && (hbytes.back() & 0x80))
            hbytes.push_back(0);  // sign byte
        uint8_t push_len = static_cast<uint8_t>(hbytes.size());
        sig << to_hex(&push_len, 1) << to_hex(hbytes.data(), hbytes.size());
    }
    // c2pool identity in scriptSig + THE state root (32 bytes)
    // Layout: [BIP34 height]["/c2pool/"][the_state_root(32)]
    // The state root anchors sharechain state into the merged blockchain.
    const std::string coinbase_extra = "/c2pool/";
    for (char c : coinbase_extra) {
        uint8_t b = static_cast<uint8_t>(c);
        sig << to_hex(&b, 1);
    }
    if (!the_state_root.IsNull()) {
        sig << to_hex(the_state_root.data(), 32);
    }
    std::string sig_hex = sig.str();
    cb << varint_hex(sig_hex.size() / 2) << sig_hex;

    // sequence
    cb << "ffffffff";

    // Canonical output ordering (matches Python p2pool):
    //   1. Miner outputs: sorted ascending by script bytes (already sorted by payout_provider)
    //   2. OP_RETURN output (value=0, text "P2Pool merged mining")
    //   3. Donation output (COMBINED_DONATION_SCRIPT) — always LAST

    // Separate donation from miner outputs
    static const std::vector<unsigned char> COMBINED_DONATION = {
        0xa9, 0x14,
        0x8c, 0x62, 0x72, 0x62, 0x1d, 0x89, 0xe8, 0xfa,
        0x52, 0x6d, 0xd8, 0x6a, 0xcf, 0xf6, 0x0c, 0x71,
        0x36, 0xbe, 0x8e, 0x85,
        0x87
    };
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> miner_outs;
    uint64_t donation_amount = 0;
    for (const auto& [script, amount] : payouts) {
        if (script == COMBINED_DONATION)
            donation_amount += amount;
        else if (amount > 0)
            miner_outs.emplace_back(script, amount);
    }
    // Ensure donation >= 1 satoshi (V36 consensus rule)
    if (donation_amount < 1 && !miner_outs.empty()) {
        // Deterministic tiebreak: deduct from largest amount (then largest script)
        auto largest = std::max_element(miner_outs.begin(), miner_outs.end(),
            [](const auto& a, const auto& b) {
                if (a.second != b.second) return a.second < b.second;
                return a.first < b.first;
            });
        largest->second -= 1;
        donation_amount += 1;
    }

    // OP_RETURN: c2pool identity in merged block coinbase
    const std::string op_return_text = "P2Pool merged mining";
    std::vector<unsigned char> op_return_script;
    op_return_script.push_back(0x6a); // OP_RETURN
    op_return_script.push_back(static_cast<unsigned char>(op_return_text.size()));
    op_return_script.insert(op_return_script.end(), op_return_text.begin(), op_return_text.end());

    // Total output count: miners + OP_RETURN + donation
    size_t out_count = miner_outs.size() + 1 + 1;
    cb << varint_hex(out_count);

    // Miner outputs (sorted by script — already sorted)
    for (const auto& [script, amount] : miner_outs)
    {
        uint8_t vbuf[8];
        for (int i = 0; i < 8; ++i)
            vbuf[i] = (amount >> (8 * i)) & 0xFF;
        cb << to_hex(vbuf, 8);
        cb << varint_hex(script.size())
           << to_hex(script.data(), script.size());
    }

    // OP_RETURN (value=0)
    {
        uint8_t vbuf[8] = {};
        cb << to_hex(vbuf, 8);
        cb << varint_hex(op_return_script.size())
           << to_hex(op_return_script.data(), op_return_script.size());
    }

    // Donation (COMBINED_DONATION_SCRIPT, always LAST)
    {
        uint8_t vbuf[8];
        for (int i = 0; i < 8; ++i)
            vbuf[i] = (donation_amount >> (8 * i)) & 0xFF;
        cb << to_hex(vbuf, 8);
        cb << varint_hex(COMBINED_DONATION.size())
           << to_hex(COMBINED_DONATION.data(), COMBINED_DONATION.size());
    }

    // locktime
    cb << "00000000";

    std::string coinbase_hex_DEAD = cb.str();
    } // ---- END DEAD CODE ----

    // --- Coinbase txid + tx hashes + merkle root (shared helpers) ---
    auto coinbase_bytes = from_hex(coinbase_hex);
    uint256 cb_hash = Hash(coinbase_bytes);
    auto tx_hashes = collect_tx_hashes(cb_hash, tmpl);
    uint256 merkle_root = compute_tx_merkle_root(tx_hashes);

    // Collect raw tx data for block assembly
    std::vector<std::string> tx_datas;
    if (tmpl.contains("transactions") && tmpl["transactions"].is_array())
        for (const auto& tx : tmpl["transactions"])
            tx_datas.push_back(tx.value("data", ""));

    // --- Block header (80 bytes) ---
    std::ostringstream hdr;
    hdr << encode_le32(version);

    // Previous block hash: hex is big-endian, we need LE (internal byte order)
    uint256 prev_hash;
    prev_hash.SetHex(prev_hash_hex);
    hdr << uint256_to_le_hex(prev_hash);
    hdr << uint256_to_le_hex(merkle_root);
    hdr << encode_le32(curtime);
    hdr << bits_hex; // bits already in hex LE? No — bits from GBT is hex BE (compact)
    // Actually bits from GBT is a hex string like "1d00ffff" which is already
    // the 4-byte compact target in big-endian hex. We need it in LE for the header.
    // Rewrite: parse as uint32 then emit LE
    {
        // Remove the bits_hex we just wrote and redo it properly
        std::string hdr_so_far = hdr.str();
        hdr_so_far.resize(hdr_so_far.size() - bits_hex.size());
        hdr.str(hdr_so_far);
        hdr.seekp(0, std::ios_base::end);
        uint32_t nbits = std::stoul(bits_hex, nullptr, 16);
        hdr << encode_le32(nbits);
    }
    hdr << encode_le32(0); // nonce — doesn't matter for AuxPoW

    // --- Assemble full block ---
    std::ostringstream blk;
    blk << hdr.str();          // 80 bytes header
    blk << auxpow_hex;         // AuxPoW proof
    blk << varint_hex(1 + tx_datas.size()); // transaction count
    blk << coinbase_hex;       // coinbase tx
    for (const auto& txd : tx_datas)
        blk << txd;            // template transactions

    return blk.str();
}

// ─── Block tracking implementation ───────────────────────────────────────────

void MergedMiningManager::record_discovered_block(
    const ChainState& chain, bool accepted, const std::string& parent_hash)
{
    record_discovered_block(chain,
                            accepted ? SubmitVerdict::of(SubmitVerdict::Kind::accepted)
                                     : SubmitVerdict::of(SubmitVerdict::Kind::rejected, "rejected"),
                            parent_hash, chain.current_work.block_hash,
                            chain.current_work.height, chain.current_work.coinbase_value);
}

void MergedMiningManager::record_discovered_block(
    const ChainState& chain, const SubmitVerdict& verdict, const std::string& parent_hash,
    const uint256& block_hash, int height, uint64_t coinbase_value)
{
    // Caller must hold m_mutex
    // A block found again (a share on a job whose block is already out: the
    // daemon answers "duplicate") is one block: the record is kept once, its
    // verdict improved if this answer is better; the found-block callback runs
    // again only when the block was not held before and is now.
    for (auto& old : m_discovered_blocks) {
        if (old.chain_id != chain.config.chain_id || old.block_hash != block_hash.GetHex() || !old.is_local)
            continue;
        const bool was_accepted = old.accepted;
        const bool was_held = was_accepted || old.verdict == "inconclusive" || old.verdict.rfind("unknown: ", 0) == 0;
        if (verdict.accepted() && !was_accepted) {
            old.accepted = true;
            old.verdict = verdict.label();
        } else if (!was_held && verdict.held()) {
            old.verdict = verdict.label();
        }
        LOG_INFO << "[MM:" << chain.config.symbol << "] block " << block_hash.GetHex().substr(0, 16)
                 << " found again (" << verdict.label() << "): recorded once";
        if (!was_held && verdict.held() && m_on_merged_block_found) {
            try {
                m_on_merged_block_found(chain.config.symbol, height, block_hash.GetHex(), true, coinbase_value);
            } catch (const std::exception& e) {
                LOG_ERROR << "[MM:" << chain.config.symbol << "] on_merged_block_found crashed: " << e.what();
            }
        }
        return;
    }
    LOG_INFO << "[MM:" << chain.config.symbol << "] record_discovered_block: building record...";
    DiscoveredMergedBlock blk;
    blk.chain_id    = chain.config.chain_id;
    blk.symbol      = chain.config.symbol;
    blk.height      = height;
    blk.block_hash  = block_hash.GetHex();
    blk.parent_hash = parent_hash;
    blk.timestamp      = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
    blk.accepted       = verdict.accepted();
    blk.verdict        = verdict.label();
    blk.coinbase_value = coinbase_value;
    blk.is_local       = true;  // our own submission

    m_discovered_blocks.push_back(std::move(blk));
    m_blocks_per_chain[chain.config.chain_id]++;
    LOG_INFO << "[MM:" << chain.config.symbol << "] record_discovered_block: block stored ("
             << verdict.label() << "), calling on_merged_block_found=" << !!m_on_merged_block_found;

    // Notify MiningInterface for unified block verification
    if (m_on_merged_block_found) {
        try {
            LOG_INFO << "[MM:" << chain.config.symbol << "] calling on_merged_block_found...";
            // held: accepted, duplicate or inconclusive — the found-block
            // check then follows the daemon's chain.
            m_on_merged_block_found(chain.config.symbol, height, block_hash.GetHex(), verdict.held(),
                                    coinbase_value);
            LOG_INFO << "[MM:" << chain.config.symbol << "] on_merged_block_found returned OK";
        } catch (const std::exception& e) {
            LOG_ERROR << "[MM:" << chain.config.symbol
                      << "] on_merged_block_found crashed: " << e.what();
        }
    }
}

std::vector<DiscoveredMergedBlock> MergedMiningManager::get_discovered_blocks() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_discovered_blocks;
}

std::vector<DiscoveredMergedBlock> MergedMiningManager::get_recent_blocks(size_t limit) const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (m_discovered_blocks.size() <= limit)
        return m_discovered_blocks;
    return std::vector<DiscoveredMergedBlock>(
        m_discovered_blocks.end() - static_cast<ptrdiff_t>(limit),
        m_discovered_blocks.end());
}

uint64_t MergedMiningManager::get_total_blocks() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_discovered_blocks.size();
}

uint64_t MergedMiningManager::get_chain_block_count(uint32_t chain_id) const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    auto it = m_blocks_per_chain.find(chain_id);
    return (it != m_blocks_per_chain.end()) ? it->second : 0;
}

void MergedMiningManager::add_discovered_block(const DiscoveredMergedBlock& blk)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    // Dedup by block_hash + chain_id
    for (const auto& existing : m_discovered_blocks) {
        if (existing.block_hash == blk.block_hash && existing.chain_id == blk.chain_id)
            return;
    }
    m_discovered_blocks.push_back(blk);
    m_blocks_per_chain[blk.chain_id]++;
    LOG_INFO << "[MM:" << blk.symbol << "] External block added: height=" << blk.height
             << " hash=" << blk.block_hash.substr(0, 16);
}

void MergedMiningManager::update_block_coinbase(const std::string& block_hash, uint64_t coinbase_value)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    for (auto& blk : m_discovered_blocks) {
        if (blk.block_hash == block_hash) {
            blk.coinbase_value = coinbase_value;
            LOG_INFO << "[MM:" << blk.symbol << "] Coinbase updated: height=" << blk.height
                     << " value=" << coinbase_value << " (" << (coinbase_value / 1e8) << " "
                     << blk.symbol << ")";
            return;
        }
    }
}

std::vector<MergedMiningManager::ChainInfo> MergedMiningManager::get_chain_infos() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    std::vector<ChainInfo> result;
    result.reserve(m_chains.size());
    for (const auto& c : m_chains) {
        ChainInfo info;
        info.symbol         = c.config.symbol;
        info.chain_id       = c.config.chain_id;
        info.rpc_host       = c.config.rpc_host;
        info.rpc_port       = c.config.rpc_port;
        info.multiaddress   = c.config.multiaddress;
        info.p2p_port       = c.config.p2p_port;
        info.current_height = c.current_work.height;
        info.current_tip    = c.last_tip;
        info.coinbase_value = c.current_work.coinbase_value;
        info.address_version = c.config.address_version;
        info.p2sh_version    = c.config.p2sh_version;
        info.target         = c.current_work.target;
        info.block_hash     = c.current_work.block_hash.GetHex();
        // Compute difficulty from target: diff = 2^256 / (target+1)
        // Simplified: diff ≈ 0x00000000FFFF... / target  (Dogecoin uses scrypt diff1)
        if (!c.current_work.target.IsNull()) {
            // Use compact diff1 target (0x00000000FFFF << 208)
            // diff = diff1_target / current_target
            double target_d = c.current_work.target.IsNull() ? 1.0 :
                c.current_work.target.getdouble();
            if (target_d > 0) {
                // diff1 for scrypt = 0x0000FFFF << 224 * 2^-256 ≈ 0.99998
                double diff1 = 65535.0 / 256.0;  // ≈ 255.996
                // Actually: diff = pdiff_1_target / target
                // pdiff_1_target for scrypt = 2^224 * 0xFFFF / 0x10000 ≈ 2^224 * 0.99998
                // Simpler: target_to_diff = 2^256 / 2^32 / target_as_double ≈ 2^224 / target_d
                info.difficulty = std::ldexp(1.0, 224) / target_d;
            }
        }
        if (c.last_update_time > 0) {
            auto now_s = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            info.last_update_age_s = now_s - c.last_update_time;
        }
        info.responsive = c.responsive;
        info.unresponsive_why = c.unresponsive_why;
        info.config_error = c.config_error;
        result.push_back(std::move(info));
    }
    return result;
}

} // namespace merged
} // namespace c2pool