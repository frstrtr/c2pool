#include "merged_mining.hpp"

#include <core/log.hpp>
#include <core/hash.hpp>

#include <algorithm>
#include <cmath>
#include <cstring>
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

    // Tree size = smallest power of 2 >= chain count
    uint32_t n = static_cast<uint32_t>(chain_ids.size());
    tree.size = 1;
    while (tree.size < n) tree.size <<= 1;

    // Assign slots using p2pool LCG convention:
    //   slot = ((1103515245 * chain_id + 1103515245 * 12345 + 12345) & 0xFFFFFFFF) % size
    // Simplified: slot = ((1103515245 * (chain_id + 12345) + 12345) & 0xFFFFFFFF) % size
    // Actually the exact formula from p2pool Python:
    //   pos = (1103515245 * chain_id * 1103515245 + 12345) — but let's use the real one.
    // From mm_adapter code: slot = hash_to_int(chain_id_bytes) % size, but the simpler
    // p2pool approach for make_auxpow_tree is:
    //   nonce = 0; for each chain_id: slot[chain_id] = (chain_id * 1103515245 + 12345) % size
    //   Retry with size *= 2 if collision occurs.
    
    for (;;) {
        tree.slot_map.clear();
        bool collision = false;
        std::vector<bool> used(tree.size, false);
        for (uint32_t cid : chain_ids) {
            uint32_t slot = static_cast<uint32_t>(
                (static_cast<uint64_t>(cid) * 1103515245ULL + 12345ULL) % tree.size);
            if (used[slot]) {
                collision = true;
                break;
            }
            used[slot] = true;
            tree.slot_map[cid] = slot;
        }
        if (!collision) break;
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

// ─── AuxChainRPC ─────────────────────────────────────────────────────────────

AuxChainRPC::AuxChainRPC(boost::asio::io_context& ioc, const AuxChainConfig& config)
    : m_ioc(ioc), m_config(config), m_resolver(ioc), m_stream(ioc),
      m_client(*this, jsonrpccxx::version::v2)
{
}

AuxChainRPC::~AuxChainRPC()
{
    beast::error_code ec;
    m_stream.socket().shutdown(io::ip::tcp::socket::shutdown_both, ec);
}

bool AuxChainRPC::connect()
{
    try {
        m_http_request = {http::verb::post, "/", 11};

        std::string host_port = m_config.rpc_host + ":" + std::to_string(m_config.rpc_port);
        m_http_request.set(http::field::host, host_port);
        m_http_request.set(http::field::user_agent, "c2pool-mm/1.0");
        m_http_request.set(http::field::content_type, "application/json");

        // Base64 encode auth
        const auto& up = m_config.rpc_userpass;
        std::string encoded;
        encoded.resize(beast::detail::base64::encoded_size(up.size()));
        auto n = beast::detail::base64::encode(&encoded[0], up.data(), up.size());
        encoded.resize(n);
        m_http_request.set(http::field::authorization, "Basic " + encoded);

        auto results = m_resolver.resolve(m_config.rpc_host, std::to_string(m_config.rpc_port));
        m_stream.connect(results);
        m_connected = true;

        LOG_INFO << "[MM:" << m_config.symbol << "] Connected to aux daemon at "
                 << host_port;
        return true;
    } catch (const std::exception& e) {
        LOG_WARNING << "[MM:" << m_config.symbol << "] Failed to connect: " << e.what();
        m_connected = false;
        return false;
    }
}

std::string AuxChainRPC::Send(const std::string& request)
{
    if (!m_connected) {
        throw std::runtime_error("AuxChainRPC not connected");
    }

    m_http_request.body() = request;
    m_http_request.prepare_payload();

    try {
        http::write(m_stream, m_http_request);
    } catch (const std::exception& e) {
        LOG_WARNING << "[MM:" << m_config.symbol << "] RPC write error: " << e.what();
        m_connected = false;
        throw;
    }

    beast::flat_buffer buffer;
    http::response<http::dynamic_body> response;
    try {
        http::read(m_stream, buffer, response);
    } catch (const std::exception& e) {
        LOG_WARNING << "[MM:" << m_config.symbol << "] RPC read error: " << e.what();
        m_connected = false;
        throw;
    }

    return beast::buffers_to_string(response.body().data());
}

nlohmann::json AuxChainRPC::call(const std::string& method, const nlohmann::json& params)
{
    return m_client.CallMethod<nlohmann::json>("c2pool", method,
        params.is_array() ? jsonrpccxx::positional_parameter(params)
                          : jsonrpccxx::positional_parameter{params});
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

AuxWork AuxChainRPC::create_aux_block(const std::string& address)
{
    AuxWork work;
    work.chain_id = m_config.chain_id;

    auto result = call("createauxblock", nlohmann::json::array({address}));
    std::string hash_str = result.value("hash", "");
    LOG_TRACE << "[MM:" << m_config.symbol << "] createauxblock raw hash: \"" << hash_str
              << "\" height=" << result.value("height", 0);
    work.block_hash.SetHex(hash_str);
    work.chain_id = result.value("chainid", m_config.chain_id);
    work.height = result.value("height", 0);
    work.coinbase_value = result.value("coinbasevalue", uint64_t(0));

    // Target: prefer the "target" field directly (like p2pool), fall back to "bits".
    // createauxblock returns "target" as a 64-char big-endian hex string.
    bool target_set = false;
    if (result.contains("target") && result["target"].is_string()) {
        std::string target_hex = result["target"].get<std::string>();
        if (!target_hex.empty() && target_hex.size() <= 64) {
            work.target.SetHex(target_hex);
            target_set = !work.target.IsNull();
        }
    }
    if (!target_set && result.contains("_target") && result["_target"].is_string()) {
        std::string target_hex = result["_target"].get<std::string>();
        if (!target_hex.empty() && target_hex.size() <= 64) {
            work.target.SetHex(target_hex);
            target_set = !work.target.IsNull();
        }
    }
    if (!target_set) {
        std::string bits_hex = result.value("bits", "");
        if (!bits_hex.empty()) {
            uint32_t nbits = std::stoul(bits_hex, nullptr, 16);
            work.target.SetCompact(nbits);
        } else {
            LOG_WARNING << "[MM:" << m_config.symbol
                        << "] createauxblock: no target/bits field — target will be null!";
        }
    }

    return work;
}

bool AuxChainRPC::submit_block(const std::string& block_hex)
{
    try {
        call("submitblock", nlohmann::json::array({block_hex}));
        LOG_INFO << "[MM:" << m_config.symbol << "] Block submitted successfully!";
        return true;
    } catch (const std::exception& e) {
        LOG_WARNING << "[MM:" << m_config.symbol << "] submitblock failed: " << e.what();
        return false;
    }
}

bool AuxChainRPC::submit_aux_block(const uint256& block_hash, const std::string& auxpow_hex)
{
    try {
        call("submitauxblock", nlohmann::json::array({block_hash.GetHex(), auxpow_hex}));
        LOG_INFO << "[MM:" << m_config.symbol << "] Aux block ACCEPTED by daemon!";
        return true;
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

MergedMiningManager::MergedMiningManager(boost::asio::io_context& ioc)
    : m_ioc(ioc), m_poll_timer(ioc)
{
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

    ChainState state;
    state.config = config;
    state.rpc = std::move(backend);
    m_chains.push_back(std::move(state));

    // Rebuild the AuxPoW tree
    std::vector<uint32_t> ids;
    for (const auto& c : m_chains)
        ids.push_back(c.config.chain_id);
    m_tree = AuxPowTree::build(ids);

    LOG_INFO << "[MM] Registered aux chain: " << config.symbol
             << " (chain_id=" << config.chain_id << ", slot="
             << m_tree.slot_map[config.chain_id] << "/" << m_tree.size << ")";
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

void MergedMiningManager::start()
{
    if (m_running) return;

    // Connect all RPC clients
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
    m_rpc_pool.join();
}

void MergedMiningManager::poll_loop()
{
    if (!m_running) return;

    // Offload refresh_aux_work to dedicated RPC thread — prevents blocking
    // the ioc event loop during ~1s RPC round-trips (createauxblock, etc.).
    // Skip if previous refresh is still in progress (RPC latency spike).
    if (!m_refresh_in_progress.exchange(true)) {
        boost::asio::post(m_rpc_pool, [this]() {
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

void MergedMiningManager::refresh_aux_work()
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    bool any_changed = false;

    for (auto& chain : m_chains) {
        try {
            // Check if tip changed
            auto tip = chain.rpc->get_best_block_hash();
            if (tip == chain.last_tip && !chain.current_work.block_hash.IsNull()) {
                continue;  // no change
            }
            chain.last_tip = tip;

            // Fetch new work.
            // Always call createauxblock to obtain the canonical block hash that
            // the daemon expects back in submitauxblock.  In multiaddress mode we
            // also fetch the full template (for PPLNS coinbase building), but the
            // block_hash comes from createauxblock.
            auto new_work = chain.rpc->create_aux_block(chain.config.aux_payout_address);

            // Primary returned empty work (embedded chain not synced yet).
            // Try fallback (daemon RPC) so merged mining commitment is always
            // present in the parent coinbase even when the embedded SPV node
            // is still syncing headers (e.g. testnet4alpha incompatibility).
            if (new_work.block_hash.IsNull() && new_work.height == 0) {
                if (chain.fallback && !chain.using_fallback) {
                    try {
                        new_work = chain.fallback->create_aux_block(chain.config.aux_payout_address);
                        if (!new_work.block_hash.IsNull()) {
                            // Swap to fallback as primary for this cycle
                            chain.rpc.swap(chain.fallback);
                            chain.using_fallback = true;
                            chain.last_tip = chain.rpc->get_best_block_hash();
                            LOG_INFO << "[MM:" << chain.config.symbol
                                     << "] Embedded not synced — using RPC (jumpstart)"
                                     << " height=" << new_work.height;
                        }
                    } catch (const std::exception& e3) {
                        // Fallback also unavailable
                    }
                }
                if (new_work.block_hash.IsNull() && new_work.height == 0) {
                    static std::map<uint32_t, int64_t> s_last_sync_log;
                    auto now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
                    auto& last = s_last_sync_log[chain.config.chain_id];
                    if (now_ns - last > 30'000'000'000LL) {
                        last = now_ns;
                        LOG_INFO << "[MM:" << chain.config.symbol
                                 << "] Waiting for embedded chain sync (fallback also unavailable)...";
                    }
                    continue;
                }
            }

            chain.current_work = std::move(new_work);
            if (chain.config.multiaddress) {
                auto tmpl_work = chain.rpc->get_work_template();
                // Keep the template data but preserve the createauxblock hash
                chain.current_work.block_template = std::move(tmpl_work.block_template);
                chain.current_work.prev_block_hash = std::move(tmpl_work.prev_block_hash);
                chain.current_work.coinbase_value = tmpl_work.coinbase_value;
            }

            // Like p2pool: get authoritative target from the daemon via
            // createauxblock when RPC fallback is available.  The embedded
            // backend computes target from its own difficulty calculation,
            // which can diverge from the real chain.  The daemon is canonical.
            if (chain.fallback && !chain.using_fallback) {
                try {
                    auto daemon_work = chain.fallback->create_aux_block(
                        chain.config.aux_payout_address);
                    if (!daemon_work.target.IsNull()) {
                        if (chain.current_work.target != daemon_work.target) {
                            LOG_INFO << "[MM:" << chain.config.symbol
                                     << "] Target from daemon differs from embedded:"
                                     << " embedded=" << chain.current_work.target.GetHex().substr(0, 16)
                                     << " daemon=" << daemon_work.target.GetHex().substr(0, 16)
                                     << " — using daemon (authoritative)";
                        }
                        chain.current_work.target = daemon_work.target;
                    }
                } catch (...) {
                    // RPC unavailable — keep embedded target (best effort)
                }
            }

            chain.last_update_time = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            any_changed = true;
            LOG_INFO << "[MM:" << chain.config.symbol << "] New aux work at height "
                     << chain.current_work.height
                     << " hash=" << chain.current_work.block_hash.GetHex()
                     << " target=" << chain.current_work.target.GetHex()
                     << (chain.current_work.target.IsNull() ? " [NULL — NO BLOCKS POSSIBLE]" : "");
        } catch (const std::exception& e) {
            static std::map<uint32_t, int64_t> s_last_warn;
            auto now = std::chrono::steady_clock::now().time_since_epoch().count();
            auto& lw = s_last_warn[chain.config.chain_id];
            if (now - lw > 30'000'000'000LL) { // 30s rate limit
                lw = now;
                LOG_WARNING << "[MM:" << chain.config.symbol << "] Failed to refresh: " << e.what();
            }
            // Fallback: try the other backend.
            // RPC is used as jumpstart while embedded syncs headers.
            // Once embedded has a tip, we switch back to embedded (preferred).
            if (chain.fallback) {
                chain.rpc.swap(chain.fallback);
                chain.using_fallback = !chain.using_fallback;
                try {
                    auto tip = chain.rpc->get_best_block_hash();
                    chain.last_tip = tip;
                    chain.current_work = chain.rpc->create_aux_block(chain.config.aux_payout_address);
                    if (chain.config.multiaddress) {
                        auto tmpl_work = chain.rpc->get_work_template();
                        chain.current_work.block_template = std::move(tmpl_work.block_template);
                        chain.current_work.prev_block_hash = std::move(tmpl_work.prev_block_hash);
                        chain.current_work.coinbase_value = tmpl_work.coinbase_value;
                    }
                    any_changed = true;
                    LOG_INFO << "[MM:" << chain.config.symbol
                             << "] Using " << (chain.using_fallback ? "RPC (jumpstart)" : "embedded (preferred)")
                             << " — height " << chain.current_work.height;
                } catch (const std::exception& e2) {
                    // Both failed — swap back, wait for next cycle
                    chain.rpc.swap(chain.fallback);
                    chain.using_fallback = !chain.using_fallback;
                }
            }
        }

        // Auto-promote: if using RPC fallback but embedded (primary) now has a tip,
        // switch back to embedded (preferred backend).
        if (chain.using_fallback && chain.fallback) {
            try {
                auto embedded_tip = chain.fallback->get_best_block_hash();
                if (!embedded_tip.empty()) {
                    chain.rpc.swap(chain.fallback);
                    chain.using_fallback = false;
                    LOG_INFO << "[MM:" << chain.config.symbol
                             << "] Embedded node synced — promoting to primary";
                }
            } catch (...) {
                // Embedded not ready yet — keep using RPC
            }
        }
    }

    if (any_changed) {
        // Rebuild the commitment from current work
        std::map<uint32_t, uint256> slot_hashes;
        for (const auto& chain : m_chains) {
            if (!chain.current_work.block_hash.IsNull()) {
                auto it = m_tree.slot_map.find(chain.config.chain_id);
                if (it != m_tree.slot_map.end()) {
                    slot_hashes[it->second] = chain.current_work.block_hash;
                }
            }
        }

        if (!slot_hashes.empty()) {
            auto proof = m_tree.compute_root(slot_hashes, 0);  // root only
            m_cached_commitment = build_auxpow_commitment(proof.root, m_tree.size);
        }

        // Notify stratum to push new work with the fresh MM commitment.
        // Without this, miners keep working on old coinbases that commit to
        // the previous DOGE block hash — any found DOGE blocks are stale.
        if (m_on_work_changed) {
            boost::asio::post(m_ioc, m_on_work_changed);
        }
    }
}

std::vector<uint8_t> MergedMiningManager::get_auxpow_commitment()
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_cached_commitment;
}

std::vector<uint8_t> MergedMiningManager::override_chain_block_hash(uint32_t chain_id, const uint256& pplns_block_hash)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    for (auto& chain : m_chains) {
        if (chain.config.chain_id == chain_id) {
            chain.current_work.block_hash = pplns_block_hash;
            break;
        }
    }
    // Rebuild the commitment with updated block hash and return it atomically.
    // This avoids the race where poll_loop overwrites block_hash between
    // override and get_auxpow_commitment().
    std::map<uint32_t, uint256> slot_hashes;
    for (const auto& chain : m_chains) {
        if (!chain.current_work.block_hash.IsNull()) {
            auto it = m_tree.slot_map.find(chain.config.chain_id);
            if (it != m_tree.slot_map.end())
                slot_hashes[it->second] = chain.current_work.block_hash;
        }
    }
    if (!slot_hashes.empty()) {
        auto proof = m_tree.compute_root(slot_hashes, 0);
        m_cached_commitment = build_auxpow_commitment(proof.root, m_tree.size);
    }
    return m_cached_commitment;
}

void MergedMiningManager::try_submit_merged_blocks(
    const std::string& parent_header_hex,
    const std::string& parent_coinbase_hex,
    const std::vector<std::string>& parent_merkle_branch,
    uint32_t parent_merkle_index,
    const uint256& parent_hash)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    // For each aux chain, check if the parent PoW meets the aux target
    for (auto& chain : m_chains) {
        if (chain.current_work.block_hash.IsNull()) continue;

        auto it = m_tree.slot_map.find(chain.config.chain_id);
        if (it == m_tree.slot_map.end()) continue;

        uint32_t slot = it->second;

        // Build all slot hashes using FROZEN block hashes (from commit time).
        // The LTC coinbase commitment was built from frozen hashes — the AuxPoW
        // proof must reference the same hashes or dogecoind rejects with
        // "Aux POW missing chain merkle root in parent coinbase".
        std::map<uint32_t, uint256> slot_hashes;
        for (const auto& c : m_chains) {
            auto hash = !c.frozen_block_hash.IsNull() ? c.frozen_block_hash
                                                       : c.current_work.block_hash;
            if (!hash.IsNull()) {
                auto sit = m_tree.slot_map.find(c.config.chain_id);
                if (sit != m_tree.slot_map.end())
                    slot_hashes[sit->second] = hash;
            }
        }

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

        // Build aux merkle proof for this chain's slot
        auto proof = m_tree.compute_root(slot_hashes, slot);

        // Build auxpow proof
        std::string auxpow = build_auxpow_proof(
            parent_coinbase_hex,
            parent_hash,
            parent_merkle_branch,
            parent_merkle_index,
            proof.branch,
            proof.index,
            parent_header_hex);

        // ── Extract committed root from parent coinbase ──
        // The LTC coinbase was built at stratum job time and may contain an OLDER
        // DOGE block hash than the current chain.frozen_* fields (which get
        // overwritten on every build_merged_header_info_with_commitment call).
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

        // For tree_size=1, committed_root IS the DOGE block hash.
        // For larger trees, walk the chain merkle branch to get the leaf hash.
        // (Currently only DOGE → tree_size=1, so committed_root = doge_block_hash.)
        uint256 committed_block_hash = committed_root;

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
            LOG_WARNING << "[MM:" << chain.config.symbol
                        << "] No matching snapshot for committed hash "
                        << committed_block_hash.GetHex().substr(0, 16)
                        << " — history_size=" << chain.frozen_history.size()
                        << ", skipping submission to avoid ban";
            continue;
        }

        // Build DOGE block from the matching snapshot
        {
            auto& tmpl = *use_tmpl;
            uint32_t version = tmpl.value("version", 0x20000002u) | 0x100;
            std::string prev_hash_hex = tmpl.value("previousblockhash", "");
            uint32_t curtime = tmpl.value("curtime", 0u);
            std::string bits_hex = tmpl.value("bits", "1d00ffff");

            auto coinbase_bytes = from_hex(*use_coinbase);
            uint256 cb_hash = Hash(coinbase_bytes);
            auto tx_hashes = collect_tx_hashes(cb_hash, tmpl);
            uint256 merkle_root = compute_tx_merkle_root(tx_hashes);

            // Build 80-byte header
            uint256 prev_hash; prev_hash.SetHex(prev_hash_hex);
            uint32_t nbits = std::stoul(bits_hex, nullptr, 16);
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
            if (!block_hex.empty()) {
                LOG_INFO << "[MM:" << chain.config.symbol
                         << "] Merged block submitted (" << block_hex.size()/2 << " bytes"
                         << ", snapshot hash=" << committed_block_hash.GetHex().substr(0, 16) << ")";
                {
                    std::string path = "/tmp/c2pool_doge_block_" + std::to_string(chain.current_work.height) + ".hex";
                    std::ofstream f(path);
                    if (f.is_open()) { f << block_hex; f.close(); }
                }
                bool ok = chain.rpc->submit_block(block_hex);
                record_discovered_block(chain, ok, parent_hash.GetHex());
                if (m_block_relay_fn) {
                    try { m_block_relay_fn(chain.config.chain_id, block_hex); }
                    catch (...) {}
                }
            }
        }
        LOG_INFO << "[MM:" << chain.config.symbol << "] Post-submission processing complete";
    }
    LOG_INFO << "[MM] try_submit_merged_blocks finished";
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

std::map<uint32_t, AuxWork> MergedMiningManager::get_current_work() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    std::map<uint32_t, AuxWork> result;
    for (const auto& c : m_chains) {
        result[c.config.chain_id] = c.current_work;
    }
    return result;
}

std::vector<MergedMiningManager::MergedHeaderInfo>
MergedMiningManager::build_merged_header_info() const
{
    // Snapshot chain data under lock, then release before calling
    // m_payout_provider (which calls back into tracker → would deadlock).
    struct ChainSnapshot {
        uint32_t chain_id; uint64_t coinbase_value; int height;
        nlohmann::json block_template;
    };
    std::vector<ChainSnapshot> snapshots;
    PayoutProvider payout_fn;
    StateRootProvider state_fn;
    {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        payout_fn = m_payout_provider;
        state_fn = m_state_root_provider;
        for (const auto& chain : m_chains) {
            if (chain.current_work.coinbase_value == 0) continue;
            if (chain.current_work.block_template.is_null()) continue;
            snapshots.push_back({chain.config.chain_id,
                chain.current_work.coinbase_value,
                chain.current_work.height,
                chain.current_work.block_template});
        }
    }
    // Lock released — safe to call payout_fn

    std::vector<MergedHeaderInfo> result;
    if (!payout_fn) return result;

    for (auto& snap : snapshots)
    {

        const auto& tmpl = snap.block_template;
        MergedHeaderInfo info;
        info.chain_id = snap.chain_id;
        info.coinbase_value = snap.coinbase_value;
        info.block_height = static_cast<uint32_t>(snap.height);

        // Build PPLNS coinbase for this chain (NO lock held — safe)
        LOG_TRACE << "[MM-header] building header for chain " << snap.chain_id;
        auto payouts = payout_fn(snap.chain_id, snap.coinbase_value);
        if (payouts.empty()) { LOG_TRACE << "[MM-header] empty payouts, skip"; continue; }
        LOG_TRACE << "[MM-header] got " << payouts.size() << " payouts";

        // Build coinbase hex using the same logic as build_multiaddress_block
        // (simplified — just need the coinbase hash + tx hashes for merkle)
        uint32_t version = tmpl.value("version", 1u);
        // AuxPoW blocks must have bit 0x100 set in the version. The template
        // stores the base version (without 0x100) — add it here so the committed
        // block hash matches the version used at block submission time.
        if ((version >> 16) > 0)  // has chain_id → AuxPoW chain
            version |= (1 << 8);
        std::string prev_hash_hex = tmpl.value("previousblockhash", std::string("0000000000000000000000000000000000000000000000000000000000000000"));
        uint32_t curtime = tmpl.value("curtime", 0u);
        std::string bits_hex = tmpl.value("bits", std::string("1d00ffff"));

        try {
            LOG_TRACE << "[MM-header] building coinbase hex (height="
                      << info.block_height << " payouts=" << payouts.size() << ")...";
            uint256 state_root; // zero — avoid deadlock
            LOG_TRACE << "[MM-header] calling build_pplns_coinbase_hex...";
            std::string coinbase_hex = build_pplns_coinbase_hex(
                info.block_height, payouts, state_root);
            LOG_TRACE << "[MM-header] build_pplns_coinbase_hex returned len=" << coinbase_hex.size();
            if (coinbase_hex.empty()) continue;
            LOG_TRACE << "[MM-header] computing hashes...";

            auto coinbase_bytes = from_hex(coinbase_hex);
            LOG_TRACE << "[MM-header] cb_bytes=" << coinbase_bytes.size();
            uint256 cb_hash = Hash(coinbase_bytes);
            LOG_TRACE << "[MM-header] collecting tx hashes...";
            auto tx_hashes = collect_tx_hashes(cb_hash, tmpl);
            LOG_TRACE << "[MM-header] tx_hashes=" << tx_hashes.size() << " computing merkle...";
            uint256 merkle_root = compute_tx_merkle_root(tx_hashes);
            LOG_TRACE << "[MM-header] merkle done, computing link...";
            info.coinbase_merkle_branches = compute_merkle_link(tx_hashes, 0);
            LOG_INFO << "[MM-header] link done, freezing coinbase len=" << coinbase_hex.size();
            info.coinbase_hex = coinbase_hex;
            LOG_INFO << "[MM-header] coinbase frozen, extracting scriptSig...";
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

            // DIAGNOSTIC: log frozen header hash for comparison at submit time
            {
                uint256 frozen_hdr_hash = Hash(info.block_header);
                LOG_WARNING << "[MM-FREEZE:" << snap.chain_id << "] frozen_header_hash="
                            << frozen_hdr_hash.GetHex()
                            << " version=0x" << std::hex << version << std::dec
                            << " prev=" << prev_hash_hex.substr(0, 16) << "..."
                            << " merkle=" << merkle_root.GetHex().substr(0, 16) << "..."
                            << " time=" << curtime
                            << " bits=" << bits_hex
                            << " cb_len=" << info.coinbase_hex.size()/2;
            }

            LOG_TRACE << "[MM-header] header built, pushing result";
            result.push_back(std::move(info));
            LOG_TRACE << "[MM-header] chain done";
        } catch (const std::exception& e) {
            LOG_WARNING << "[MM:chain_" << snap.chain_id
                        << "] build_merged_header_info failed: " << e.what();
        }
    }
    return result;
}

std::pair<std::vector<MergedMiningManager::MergedHeaderInfo>, std::vector<uint8_t>>
MergedMiningManager::build_merged_header_info_with_commitment()
{
    // Step 1: Build header infos (releases lock internally for payout_fn callback).
    // Each MergedHeaderInfo now contains coinbase_hex — the pre-built PPLNS coinbase.
    LOG_TRACE << "[MM-commit] Step 1: building header infos...";
    auto header_infos = build_merged_header_info();
    LOG_TRACE << "[MM-commit] Step 1 done, " << header_infos.size() << " infos";

    LOG_TRACE << "[MM-commit] Step 2: acquiring lock...";
    std::unique_lock<std::recursive_mutex> lock(m_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
        LOG_INFO << "[MM-commit] mutex busy, skipping freeze";
        return {std::move(header_infos), {}};
    }
    LOG_TRACE << "[MM-commit] lock acquired, freezing " << header_infos.size() << " chains";
    auto now_sec = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    for (const auto& hi : header_infos) {
        LOG_TRACE << "[MM-commit] freezing chain " << hi.chain_id;
        for (auto& chain : m_chains) {
            if (chain.config.chain_id != hi.chain_id) continue;
            if (hi.block_header.size() == 80) {
                chain.current_work.block_hash = Hash(hi.block_header);
                chain.frozen_block_hash = chain.current_work.block_hash;
            }
            chain.frozen_coinbase_hex = hi.coinbase_hex;
            chain.frozen_template = chain.current_work.block_template;

            // Push into frozen history so stale stratum jobs can still submit
            // valid merged blocks using the snapshot that matches their commitment.
            if (!chain.frozen_block_hash.IsNull()) {
                chain.frozen_history[chain.frozen_block_hash] = {
                    chain.frozen_template,
                    chain.frozen_coinbase_hex,
                    now_sec
                };
                // Expire old snapshots
                for (auto it = chain.frozen_history.begin(); it != chain.frozen_history.end(); ) {
                    if (now_sec - it->second.timestamp > ChainState::FROZEN_EXPIRY_SEC
                        || chain.frozen_history.size() > ChainState::MAX_FROZEN_HISTORY) {
                        it = chain.frozen_history.erase(it);
                    } else {
                        ++it;
                    }
                }
                LOG_INFO << "[MM-commit] chain " << hi.chain_id
                         << " frozen hash=" << chain.frozen_block_hash.GetHex().substr(0, 16)
                         << " history_size=" << chain.frozen_history.size();
            }
            break;
        }
    }

    LOG_TRACE << "[MM-commit] rebuilding commitment...";
    std::map<uint32_t, uint256> slot_hashes;
    for (const auto& chain : m_chains) {
        if (!chain.current_work.block_hash.IsNull()) {
            auto it = m_tree.slot_map.find(chain.config.chain_id);
            if (it != m_tree.slot_map.end())
                slot_hashes[it->second] = chain.current_work.block_hash;
        }
    }
    LOG_TRACE << "[MM-commit] slots=" << slot_hashes.size();
    if (!slot_hashes.empty()) {
        auto proof = m_tree.compute_root(slot_hashes, 0);
        m_cached_commitment = build_auxpow_commitment(proof.root, m_tree.size);
    }
    LOG_TRACE << "[MM-commit] done, returning";
    return {std::move(header_infos), m_cached_commitment};
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
    // Caller must hold m_mutex
    LOG_INFO << "[MM:" << chain.config.symbol << "] record_discovered_block: building record...";
    DiscoveredMergedBlock blk;
    blk.chain_id    = chain.config.chain_id;
    blk.symbol      = chain.config.symbol;
    blk.height      = chain.current_work.height;
    blk.block_hash  = chain.current_work.block_hash.GetHex();
    blk.parent_hash = parent_hash;
    blk.timestamp      = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
    blk.accepted       = accepted;
    blk.coinbase_value = chain.current_work.coinbase_value;

    m_discovered_blocks.push_back(std::move(blk));
    m_blocks_per_chain[chain.config.chain_id]++;
    LOG_INFO << "[MM:" << chain.config.symbol << "] record_discovered_block: block stored, "
             << "calling on_merged_block_found=" << !!m_on_merged_block_found;

    // Notify MiningInterface for unified block verification
    if (m_on_merged_block_found) {
        try {
            LOG_INFO << "[MM:" << chain.config.symbol << "] calling on_merged_block_found...";
            m_on_merged_block_found(chain.config.symbol,
                chain.current_work.height,
                chain.current_work.block_hash.GetHex(), accepted);
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
        result.push_back(std::move(info));
    }
    return result;
}

} // namespace merged
} // namespace c2pool
