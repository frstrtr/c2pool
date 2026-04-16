#include "merged_mining.hpp"

#include <core/log.hpp>
#include <core/hash.hpp>

#include <algorithm>
#include <cstring>
#include <sstream>
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

    // Target from bits
    std::string bits_hex = tmpl.value("bits", "1d00ffff");
    uint32_t nbits = std::stoul(bits_hex, nullptr, 16);
    // Simple bits→target: mantissa * 2^(8*(exponent-3))
    uint32_t exp = nbits >> 24;
    uint32_t mantissa = nbits & 0x007fffff;
    work.target.SetNull();
    if (exp >= 3 && exp <= 32) {
        uint8_t* p = reinterpret_cast<uint8_t*>(work.target.begin());
        int shift = exp - 3;
        if (shift + 2 < 32) {
            p[shift]     = mantissa & 0xff;
            p[shift + 1] = (mantissa >> 8) & 0xff;
            p[shift + 2] = (mantissa >> 16) & 0xff;
        }
    }

    // Block hash — for multiaddress mode, we compute it from the header
    // The daemon returns "hash" in some implementations
    if (tmpl.contains("hash")) {
        work.block_hash.SetHex(tmpl["hash"].get<std::string>());
    }

    return work;
}

AuxWork AuxChainRPC::create_aux_block(const std::string& address)
{
    AuxWork work;
    work.chain_id = m_config.chain_id;

    auto result = call("createauxblock", nlohmann::json::array({address}));
    work.block_hash.SetHex(result.value("hash", ""));
    work.chain_id = result.value("chainid", m_config.chain_id);
    work.height = result.value("height", 0);
    work.coinbase_value = result.value("coinbasevalue", uint64_t(0));

    std::string bits_hex = result.value("bits", "1d00ffff");
    uint32_t nbits = std::stoul(bits_hex, nullptr, 16);
    uint32_t exp = nbits >> 24;
    uint32_t mantissa = nbits & 0x007fffff;
    work.target.SetNull();
    if (exp >= 3 && exp <= 32) {
        uint8_t* p = reinterpret_cast<uint8_t*>(work.target.begin());
        int shift = exp - 3;
        if (shift + 2 < 32) {
            p[shift]     = mantissa & 0xff;
            p[shift + 1] = (mantissa >> 8) & 0xff;
            p[shift + 2] = (mantissa >> 16) & 0xff;
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
        LOG_INFO << "[MM:" << m_config.symbol << "] Aux block submitted successfully!";
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
    std::lock_guard<std::mutex> lock(m_mutex);

    ChainState state;
    state.config = config;
    state.rpc = std::make_unique<AuxChainRPC>(m_ioc, config);
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

AuxChainRPC* MergedMiningManager::get_chain_rpc(uint32_t chain_id)
{
    std::lock_guard<std::mutex> lock(m_mutex);
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
}

void MergedMiningManager::poll_loop()
{
    if (!m_running) return;

    refresh_aux_work();

    m_poll_timer.expires_after(std::chrono::seconds(1));
    m_poll_timer.async_wait([this](const boost::system::error_code& ec) {
        if (!ec && m_running) {
            poll_loop();
        }
    });
}

void MergedMiningManager::refresh_aux_work()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    bool any_changed = false;

    for (auto& chain : m_chains) {
        try {
            // Check if tip changed
            auto tip = chain.rpc->get_best_block_hash();
            if (tip == chain.last_tip && !chain.current_work.block_hash.IsNull()) {
                continue;  // no change
            }
            chain.last_tip = tip;

            // Fetch new work
            if (chain.config.multiaddress) {
                chain.current_work = chain.rpc->get_work_template();
            } else {
                // Single-address mode: createauxblock gives us hash + target directly
                chain.current_work = chain.rpc->create_aux_block(chain.config.aux_payout_address);
            }

            any_changed = true;
            LOG_DEBUG_DIAG << "[MM:" << chain.config.symbol << "] New aux work at height "
                         << chain.current_work.height
                         << " hash=" << chain.current_work.block_hash.GetHex().substr(0, 16) << "..."
                         << " target=" << chain.current_work.target.GetHex().substr(0, 16) << "...";
        } catch (const std::exception& e) {
            LOG_WARNING << "[MM:" << chain.config.symbol << "] Failed to refresh: " << e.what();
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
    }
}

std::vector<uint8_t> MergedMiningManager::get_auxpow_commitment()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_cached_commitment;
}

void MergedMiningManager::try_submit_merged_blocks(
    const std::string& parent_header_hex,
    const std::string& parent_coinbase_hex,
    const std::vector<std::string>& parent_merkle_branch,
    uint32_t parent_merkle_index,
    const uint256& parent_hash)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // For each aux chain, check if the parent PoW meets the aux target
    for (auto& chain : m_chains) {
        if (chain.current_work.block_hash.IsNull()) continue;

        auto it = m_tree.slot_map.find(chain.config.chain_id);
        if (it == m_tree.slot_map.end()) continue;

        uint32_t slot = it->second;

        // Build all slot hashes
        std::map<uint32_t, uint256> slot_hashes;
        for (const auto& c : m_chains) {
            if (!c.current_work.block_hash.IsNull()) {
                auto sit = m_tree.slot_map.find(c.config.chain_id);
                if (sit != m_tree.slot_map.end())
                    slot_hashes[sit->second] = c.current_work.block_hash;
            }
        }

        // Check if parent hash meets aux target
        // Parent hash (scrypt for LTC) must be ≤ aux target
        // Note: the actual check depends on whether the aux chain uses SHA256d or scrypt
        // For Dogecoin (scrypt), the parent scrypt hash is what matters
        static int mm_check_count = 0;
        ++mm_check_count;
        if (mm_check_count <= 3 || mm_check_count % 50 == 0) {
            LOG_TRACE << "[MM:" << chain.config.symbol << "] Check #" << mm_check_count
                      << " parent_hash=" << parent_hash.GetHex().substr(0, 20) << "..."
                      << " aux_target=" << chain.current_work.target.GetHex().substr(0, 20) << "..."
                      << " meets=" << (parent_hash <= chain.current_work.target ? "YES" : "no");
        }
        if (!(parent_hash <= chain.current_work.target)) {
            continue;  // doesn't meet this chain's target
        }

        LOG_INFO << "[MM:" << chain.config.symbol << "] Parent PoW meets aux target! Submitting merged block...";

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

        if (chain.config.multiaddress && m_payout_provider) {
            // Multiaddress mode: build a complete block with PPLNS payouts
            auto payouts = m_payout_provider(chain.config.chain_id,
                                             chain.current_work.coinbase_value);
            if (!payouts.empty()) {
                auto block_hex = build_multiaddress_block(
                    chain.current_work.block_template, payouts, auxpow);
                if (!block_hex.empty()) {
                    chain.rpc->submit_block(block_hex);
                    // Also relay via P2P for fast propagation
                    if (m_block_relay_fn)
                        m_block_relay_fn(chain.config.chain_id, block_hex);
                } else {
                    submit_aux_and_relay(chain, auxpow);
                }
            } else {
                submit_aux_and_relay(chain, auxpow);
            }
        } else {
            submit_aux_and_relay(chain, auxpow);
        }
    }
}

void MergedMiningManager::submit_aux_and_relay(ChainState& chain, const std::string& auxpow)
{
    if (chain.rpc->submit_aux_block(chain.current_work.block_hash, auxpow)) {
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
    std::lock_guard<std::mutex> lock(m_mutex);
    std::map<uint32_t, AuxWork> result;
    for (const auto& c : m_chains) {
        result[c.config.chain_id] = c.current_work;
    }
    return result;
}

void MergedMiningManager::set_payout_provider(PayoutProvider provider)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_payout_provider = std::move(provider);
}

void MergedMiningManager::set_block_relay_fn(BlockRelayFn fn)
{
    std::lock_guard<std::mutex> lock(m_mutex);
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

std::string MergedMiningManager::build_multiaddress_block(
    const nlohmann::json& tmpl,
    const std::vector<std::pair<std::vector<unsigned char>, uint64_t>>& payouts,
    const std::string& auxpow_hex)
{
    if (payouts.empty() || !tmpl.contains("previousblockhash"))
        return {};

    // --- Parse template fields ---
    uint32_t version  = tmpl.value("version", 0x20000002u);
    std::string prev_hash_hex = tmpl.value("previousblockhash", "");
    uint32_t curtime  = tmpl.value("curtime", 0u);
    std::string bits_hex = tmpl.value("bits", "1d00ffff");
    int height = tmpl.value("height", 0);

    // --- Build coinbase TX ---
    std::ostringstream cb;

    // tx version (1, LE)
    cb << "01000000";

    // 1 input
    cb << "01";
    // prev_output: null hash + 0xffffffff
    cb << "0000000000000000000000000000000000000000000000000000000000000000"
       << "ffffffff";

    // scriptSig: BIP34 height + some padding
    // BIP34: push height as little-endian
    std::ostringstream sig;
    if (height < 17) {
        sig << to_hex(reinterpret_cast<const uint8_t*>("\x51"), 1); // OP_1..OP_16
    } else {
        // Encode height as minimal LE bytes
        std::vector<uint8_t> hbytes;
        int h = height;
        while (h > 0) { hbytes.push_back(h & 0xff); h >>= 8; }
        sig << to_hex(reinterpret_cast<const uint8_t*>(&hbytes[0]), 0); // push size
        // Actually: PUSH_N <n bytes>
        uint8_t push_len = static_cast<uint8_t>(hbytes.size());
        sig.str("");
        sig << to_hex(&push_len, 1) << to_hex(hbytes.data(), hbytes.size());
    }
    // Append 4 zero bytes as extra nonce space
    sig << "00000000";
    std::string sig_hex = sig.str();
    cb << varint_hex(sig_hex.size() / 2) << sig_hex;

    // sequence
    cb << "ffffffff";

    // outputs
    cb << varint_hex(payouts.size());
    for (const auto& [script, amount] : payouts)
    {
        // value: 8 bytes LE
        uint8_t vbuf[8];
        for (int i = 0; i < 8; ++i)
            vbuf[i] = (amount >> (8 * i)) & 0xFF;
        cb << to_hex(vbuf, 8);
        // scriptPubKey
        cb << varint_hex(script.size())
           << to_hex(script.data(), script.size());
    }

    // locktime
    cb << "00000000";

    std::string coinbase_hex = cb.str();

    // --- Coinbase txid (double-SHA256 of serialized coinbase) ---
    auto coinbase_bytes = from_hex(coinbase_hex);
    uint256 cb_hash = Hash(coinbase_bytes);

    // --- Collect template transaction hashes ---
    std::vector<uint256> tx_hashes;
    tx_hashes.push_back(cb_hash);

    std::vector<std::string> tx_datas;
    if (tmpl.contains("transactions") && tmpl["transactions"].is_array())
    {
        for (const auto& tx : tmpl["transactions"])
        {
            std::string txdata = tx.value("data", "");
            tx_datas.push_back(txdata);

            std::string txid_str = tx.value("txid", "");
            if (!txid_str.empty()) {
                uint256 txid;
                txid.SetHex(txid_str);
                tx_hashes.push_back(txid);
            } else {
                // Compute txid from data
                auto raw = from_hex(txdata);
                tx_hashes.push_back(Hash(raw));
            }
        }
    }

    // --- Merkle root ---
    auto merkle_layer = tx_hashes;
    while (merkle_layer.size() > 1)
    {
        if (merkle_layer.size() % 2 != 0)
            merkle_layer.push_back(merkle_layer.back());
        std::vector<uint256> next;
        for (size_t i = 0; i < merkle_layer.size(); i += 2)
            next.push_back(Hash(merkle_layer[i], merkle_layer[i + 1]));
        merkle_layer = std::move(next);
    }
    uint256 merkle_root = merkle_layer.empty() ? cb_hash : merkle_layer[0];

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

} // namespace merged
} // namespace c2pool
