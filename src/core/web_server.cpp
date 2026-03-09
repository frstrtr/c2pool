#include "web_server.hpp"

// Real coin daemon RPC (optional - only linked when set_coin_rpc() is called)
#include <impl/ltc/coin/rpc.hpp>
#include <impl/ltc/coin/node_interface.hpp>

#include <core/hash.hpp>   // Hash(a,b) double-SHA256 for merkle computation
#include <core/random.hpp> // core::random::random_float for probabilistic fee
#include <core/target_utils.hpp> // chain::bits_to_target
#include <btclibs/util/strencodings.h>  // ParseHex, HexStr
#include <crypto/scrypt.h>  // scrypt_1024_1_1_256 for Litecoin PoW
#include <c2pool/merged/merged_mining.hpp>  // Integrated merged mining

#include <iomanip>
#include <sstream>
#include <ctime>
#include <chrono>
#include <cmath>
#include <boost/process.hpp>
#include <boost/algorithm/string.hpp>
#include "btclibs/base58.h"

namespace core {

/// Static member definition
std::atomic<uint64_t> StratumSession::job_counter_{0};

/// HttpSession Implementation
HttpSession::HttpSession(tcp::socket socket, std::shared_ptr<MiningInterface> mining_interface)
    : socket_(std::move(socket))
    , mining_interface_(mining_interface)
{
}

void HttpSession::run()
{
    read_request();
}

void HttpSession::read_request()
{
    auto self = shared_from_this();
    
    http::async_read(socket_, buffer_, request_,
        [self](beast::error_code ec, std::size_t bytes_transferred)
        {
            boost::ignore_unused(bytes_transferred);
            
            if(ec == http::error::end_of_stream)
                return self->handle_error(ec, "read_request");
                
            if(ec)
                return self->handle_error(ec, "read_request");
                
            self->process_request();
        });
}

void HttpSession::process_request()
{
    // Create HTTP response
    http::response<http::string_body> response{http::status::ok, request_.version()};
    response.set(http::field::server, "c2pool/0.0.1");
    response.set(http::field::content_type, "application/json");
    response.set(http::field::access_control_allow_origin, "*");
    response.set(http::field::access_control_allow_methods, "GET, POST, OPTIONS");
    response.set(http::field::access_control_allow_headers, "Content-Type");

    try {
        std::string response_body;
        
        if (request_.method() == http::verb::options) {
            // Handle CORS preflight
            response_body = "";
        }
        else if (request_.method() == http::verb::get) {
            // Path-based REST routing for p2pool-compatible endpoints
            std::string target(request_.target());
            // Strip query string
            auto qpos = target.find('?');
            if (qpos != std::string::npos) target = target.substr(0, qpos);

            nlohmann::json rest_result;
            if (target == "/local_rate")
                rest_result = mining_interface_->rest_local_rate();
            else if (target == "/global_rate")
                rest_result = mining_interface_->rest_global_rate();
            else if (target == "/current_payouts")
                rest_result = mining_interface_->rest_current_payouts();
            else if (target == "/users")
                rest_result = mining_interface_->rest_users();
            else if (target == "/fee")
                rest_result = mining_interface_->rest_fee();
            else if (target == "/recent_blocks")
                rest_result = mining_interface_->rest_recent_blocks();
            else
                rest_result = mining_interface_->getinfo();

            response_body = rest_result.dump();
        }
        else if (request_.method() == http::verb::post) {
            // Handle JSON-RPC POST request
            std::string request_body = request_.body();
            LOG_INFO << "Received JSON-RPC request: " << request_body;
            
            response_body = mining_interface_->HandleRequest(request_body);
            
            LOG_INFO << "Sending JSON-RPC response: " << response_body;
        }
        else {
            response.result(http::status::method_not_allowed);
            response_body = R"({"error":"Method not allowed"})";
        }
        
        response.body() = response_body;
        response.prepare_payload();
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Error processing request: " << e.what();
        response.result(http::status::internal_server_error);
        response.body() = R"({"error":"Internal server error"})";
        response.prepare_payload();
    }
    
    send_response(std::move(response));
}

void HttpSession::send_response(http::response<http::string_body> response)
{
    auto self = shared_from_this();
    
    auto response_ptr = std::make_shared<http::response<http::string_body>>(std::move(response));
    
    http::async_write(socket_, *response_ptr,
        [self, response_ptr](beast::error_code ec, std::size_t bytes_transferred)
        {
            boost::ignore_unused(bytes_transferred);
            
            if(ec)
                return self->handle_error(ec, "send_response");
                
            // Gracefully close the connection
            beast::error_code close_ec;
            self->socket_.shutdown(tcp::socket::shutdown_send, close_ec);
        });
}

void HttpSession::handle_error(beast::error_code ec, char const* what)
{
    if (ec != beast::errc::operation_canceled && ec != beast::errc::broken_pipe) {
        LOG_WARNING << "HTTP Session error in " << what << ": " << ec.message();
    }
}

/// MiningInterface Implementation
MiningInterface::MiningInterface(bool testnet, std::shared_ptr<IMiningNode> node, Blockchain blockchain)
    : m_work_id_counter(1)
    , m_rpc_client(std::make_unique<LitecoinRpcClient>(testnet))
    , m_testnet(testnet)
    , m_blockchain(blockchain)
    , m_node(node)
    , m_address_validator(blockchain, testnet ? Network::TESTNET : Network::MAINNET)
    , m_payout_manager(std::make_unique<c2pool::payout::PayoutManager>(1.0, 86400)) // 1% fee, 24h window
    , m_solo_mode(false)
    , m_solo_address("")
{
    setup_methods();
}

void MiningInterface::setup_methods()
{
    // Core mining methods - explicitly cast to MethodHandle
    Add("getwork", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getwork();
    }));
    
    Add("submitwork", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.size() < 3) {
            throw jsonrpccxx::JsonRpcException(-1, "submitwork requires 3 parameters");
        }
        return submitwork(params[0], params[1], params[2]);
    }));
    
    Add("getblocktemplate", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        nlohmann::json template_params = params.empty() ? nlohmann::json::array() : params;
        return getblocktemplate(template_params);
    }));
    
    Add("submitblock", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.empty()) {
            throw jsonrpccxx::JsonRpcException(-1, "submitblock requires hex data parameter");
        }
        return submitblock(params[0]);
    }));
    
    // Pool info methods
    Add("getinfo", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getinfo();
    }));
    
    Add("getstats", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getstats();
    }));
    
    Add("getpeerinfo", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getpeerinfo();
    }));
    
    // Stratum methods
    Add("mining.subscribe", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        std::string user_agent = params.empty() ? "" : params[0];
        return mining_subscribe(user_agent);
    }));
    
    Add("mining.authorize", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.size() < 2) {
            throw jsonrpccxx::JsonRpcException(-1, "mining.authorize requires username and password");
        }
        return mining_authorize(params[0], params[1]);
    }));
    
    Add("mining.submit", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.size() < 5) {
            throw jsonrpccxx::JsonRpcException(-1, "mining.submit requires 5 parameters");
        }
        return mining_submit(params[0], params[1], "", params[2], params[3], params[4]);
    }));
    
    // Enhanced payout and coinbase methods
    Add("validate_address", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.empty()) {
            throw jsonrpccxx::JsonRpcException(-1, "validate_address requires address parameter");
        }
        return validate_address(params[0]);
    }));
    
    Add("build_coinbase", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.empty()) {
            throw jsonrpccxx::JsonRpcException(-1, "build_coinbase requires parameters object");
        }
        return build_coinbase(params);
    }));
    
    Add("validate_coinbase", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.empty()) {
            throw jsonrpccxx::JsonRpcException(-1, "validate_coinbase requires coinbase hex parameter");
        }
        return validate_coinbase(params[0]);
    }));
    
    Add("getblockcandidate", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getblockcandidate(params);
    }));
    
    Add("getpayoutinfo", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getpayoutinfo();
    }));
    
    Add("getminerstats", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getminerstats();
    }));
}

// ─── Live coin-daemon integration ────────────────────────────────────────────

void MiningInterface::set_coin_rpc(ltc::coin::NodeRPC* rpc, ltc::interfaces::Node* coin)
{
    m_coin_rpc  = rpc;
    m_coin_node = coin;
    LOG_INFO << "MiningInterface: coin RPC " << (rpc ? "connected" : "disconnected");
}

void MiningInterface::set_on_block_submitted(std::function<void(const std::string&, int)> fn)
{
    m_on_block_submitted = std::move(fn);
}

void MiningInterface::set_on_block_relay(std::function<void(const std::string&)> fn)
{
    m_on_block_relay = std::move(fn);
}

void MiningInterface::check_merged_mining(const std::string& block_hex,
                                          const std::string& extranonce1,
                                          const std::string& extranonce2)
{
    if (!m_mm_manager) return;

    // Extract 80-byte parent header (first 160 hex chars)
    if (block_hex.size() < 160) return;
    std::string parent_header_hex = block_hex.substr(0, 160);

    // Compute parent block hash (scrypt for LTC)
    auto hdr_bytes = ParseHex(parent_header_hex);
    uint256 parent_hash;
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(hdr_bytes.data()),
                        reinterpret_cast<char*>(parent_hash.data()));

    // Build stripped coinbase tx (no witness)
    std::string coinbase_hex;
    std::vector<std::string> merkle_branches_copy;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        coinbase_hex = m_cached_coinb1 + extranonce1 + extranonce2 + m_cached_coinb2;
        merkle_branches_copy = m_cached_merkle_branches;
    }

    m_mm_manager->try_submit_merged_blocks(
        parent_header_hex,
        coinbase_hex,
        merkle_branches_copy,
        0,  // coinbase is always at index 0
        parent_hash);
}

// ─── Merkle branch computation ────────────────────────────────────────────────
// Given the list of transaction hashes EXCLUDING the coinbase
// (i.e. from getblocktemplate tx list), compute the Stratum merkle_branches
// array that enables the miner to reconstruct the merkle root as:
//   hash = coinbase_hash
//   for b in branches: hash = Hash(hash, b)
/*static*/ std::vector<std::string>
MiningInterface::compute_merkle_branches(std::vector<std::string> tx_hashes_hex)
{
    if (tx_hashes_hex.empty()) return {};

    // Convert hex strings to uint256
    std::vector<uint256> current;
    current.reserve(tx_hashes_hex.size());
    for (const auto& h : tx_hashes_hex) {
        uint256 u;
        u.SetHex(h);
        current.push_back(u);
    }

    std::vector<std::string> branches;

    // At each tree level: the first element of `current` is the sibling of our
    // path node. Consume it as a branch, then build the next level from the rest.
    while (!current.empty()) {
        // Store in internal byte order (Stratum format: raw SHA256d output hex)
        branches.push_back(HexStr(std::span<const unsigned char>(current[0].data(), 32)));
        current.erase(current.begin());      // remove the sibling we just used
        if (current.empty()) break;

        // If the remaining list is odd, duplicate the last entry
        if (current.size() % 2 == 1)
            current.push_back(current.back());

        // Pair and hash for the next level
        std::vector<uint256> next;
        next.reserve(current.size() / 2);
        for (size_t i = 0; i + 1 < current.size(); i += 2)
            next.push_back(Hash(current[i], current[i + 1]));
        current = std::move(next);
    }

    return branches;
}

// ─── Merkle root reconstruction ──────────────────────────────────────────────
// Given a fully-assembled coinbase transaction in hex and the Stratum merkle
// branches, reconstruct the block's merkle root.
//   coinbase_hash = dSHA256(coinbase_bytes)
//   for each branch: coinbase_hash = dSHA256(coinbase_hash || branch)
/*static*/ uint256
MiningInterface::reconstruct_merkle_root(const std::string& coinbase_hex,
                                         const std::vector<std::string>& merkle_branches)
{
    auto coinbase_bytes = ParseHex(coinbase_hex);
    uint256 hash = Hash(coinbase_bytes);

    for (const auto& branch_hex : merkle_branches) {
        // Branches are in internal byte order (Stratum format)
        uint256 branch;
        auto branch_bytes = ParseHex(branch_hex);
        if (branch_bytes.size() == 32)
            memcpy(branch.begin(), branch_bytes.data(), 32);
        hash = Hash(hash, branch);
    }
    return hash;
}

// ─── Build full block from Stratum parameters ────────────────────────────────
// Assembles the block header + full transaction list from the cached template
// and the miner's Stratum submit data.
std::string
MiningInterface::build_block_from_stratum(const std::string& extranonce1,
                                          const std::string& extranonce2,
                                          const std::string& ntime,
                                          const std::string& nonce) const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);

    if (!m_work_valid || m_cached_template.is_null() || m_cached_coinb1.empty())
        return {};

    // Reconstruct coinbase: coinb1 + extranonce1 + extranonce2 + coinb2
    std::string coinbase_hex = m_cached_coinb1 + extranonce1 + extranonce2 + m_cached_coinb2;

    // Reconstruct merkle root
    uint256 merkle_root = reconstruct_merkle_root(coinbase_hex, m_cached_merkle_branches);

    // Build the 80-byte block header
    // version (4 bytes LE) from cached template
    uint32_t version = m_cached_template.value("version", 536870912U);
    uint256 prev_hash;
    prev_hash.SetHex(m_cached_template.value("previousblockhash", std::string(64, '0')));

    // ntime and nonce from miner (hex strings, 4 bytes each LE)
    auto ntime_bytes = ParseHex(ntime);
    auto nonce_bytes = ParseHex(nonce);

    std::ostringstream block;
    // version LE
    block << std::hex << std::setfill('0')
          << std::setw(2) << ((version      ) & 0xff)
          << std::setw(2) << ((version >>  8) & 0xff)
          << std::setw(2) << ((version >> 16) & 0xff)
          << std::setw(2) << ((version >> 24) & 0xff);
    // prev_hash (already internal byte order in uint256)
    block << HexStr(std::span<const unsigned char>(prev_hash.data(), 32));
    // merkle_root
    block << HexStr(std::span<const unsigned char>(merkle_root.data(), 32));
    // ntime (4 bytes from miner, already LE hex)
    block << ntime;
    // nbits from template
    block << m_cached_template.value("bits", std::string("1d00ffff"));
    // nonce (4 bytes from miner, already LE hex)
    block << nonce;

    // Transaction count (varint) + coinbase + rest of transactions
    auto& txs = m_cached_template["transactions"];
    uint64_t tx_count = 1 + txs.size(); // coinbase + template txs
    // Simple varint encoding
    if (tx_count < 0xfd)
        block << std::hex << std::setfill('0') << std::setw(2) << tx_count;
    else
        block << "fd" << std::hex << std::setfill('0')
              << std::setw(2) << (tx_count & 0xff)
              << std::setw(2) << ((tx_count >> 8) & 0xff);

    // Coinbase transaction: coinb1 + extranonce1 + extranonce2 + coinb2 is the
    // non-witness (stripped) serialization used for txid computation and the
    // Stratum merkle tree.  For segwit blocks the block body must contain the
    // witness serialization which wraps the same data with marker/flag bytes
    // and a coinbase witness stack (BIP141: 1 item of 32 zero bytes).
    if (m_segwit_active) {
        // Non-witness: [version 4B][input_count 1B][inputs…][outputs…][locktime 4B]
        // Witness:     [version 4B][00 01][input_count 1B][inputs…][outputs…]
        //              [witness_stack][locktime 4B]
        block << coinbase_hex.substr(0, 8)    // version (4 bytes = 8 hex)
              << "0001"                        // segwit marker + flag
              << coinbase_hex.substr(8, coinbase_hex.size() - 16) // inputs + outputs
              << "01"                          // 1 stack item for the single coinbase input
              << "20"                          // 32 bytes
              << std::string(64, '0')          // witness nonce (32 zero bytes)
              << coinbase_hex.substr(coinbase_hex.size() - 8); // locktime
    } else {
        block << coinbase_hex;
    }

    // Remaining transactions from the template
    for (const auto& tx : txs) {
        if (tx.contains("data"))
            block << tx["data"].get<std::string>();
    }

    return block.str();
}

// ─── Coinbase parts construction ─────────────────────────────────────────────
// Encode an integer as a minimal CScriptNum (sign-magnitude, little-endian)
// prefixed by a 1-byte push-data length. Used for BIP34 block height.
static std::string encode_height_pushdata(int height)
{
    std::ostringstream os;
    if (height == 0) {
        os << "0100";  // PUSH1 [0x00]
        return os.str();
    }
    std::vector<uint8_t> bytes;
    uint32_t v = static_cast<uint32_t>(height);
    while (v > 0) {
        bytes.push_back(static_cast<uint8_t>(v & 0xFF));
        v >>= 8;
    }
    // If MSB is set, add a 0x00 sign byte (positive)
    if (bytes.back() & 0x80)
        bytes.push_back(0x00);

    // PUSHDATA opcode = len, then the data bytes (already little-endian)
    os << std::hex << std::setfill('0') << std::setw(2) << bytes.size();
    for (uint8_t b : bytes)
        os << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
    return os.str();
}

// Encode a uint64 amount as 8 little-endian hex bytes
static std::string encode_le64(uint64_t v)
{
    std::ostringstream os;
    for (int i = 0; i < 8; ++i)
        os << std::hex << std::setfill('0') << std::setw(2)
           << static_cast<int>((v >> (i * 8)) & 0xFF);
    return os.str();
}

// Build a P2PKH output script OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
// `hash160_hex` must be 40 hex chars (20 bytes).
// Returns the (length-prefixed) complete output script hex.
static std::string p2pkh_script(const std::string& hash160_hex)
{
    // 1976a914{hash160}88ac
    std::ostringstream s;
    s << "19" << "76a914" << hash160_hex << "88ac";
    return s.str();
}

/*static*/ std::pair<std::string, std::string>
MiningInterface::build_coinbase_parts(
    const nlohmann::json& tmpl,
    uint64_t coinbase_value,
    const std::vector<std::pair<std::string,uint64_t>>& outputs,
    bool raw_scripts,
    const std::vector<uint8_t>& mm_commitment,
    const std::string& witness_commitment_hex,
    const std::string& op_return_hex)
{
    // coinb1 ends just before extranonce1; coinb2 starts just after extranonce2.
    // coinbase = coinb1 + extranonce1(4B) + extranonce2(4B) + coinb2
    //
    // Coinbase tx wire layout:
    //   [version 4B][input_count 1B]
    //   [prev_hash 32B][prev_idx 4B][script_len 1B][coinb1_script][{4B extranonce1}][coinb2_script]
    //   [sequence 4B]
    //   [output_count varint][outputs ...][locktime 4B]
    //
    // Output ordering (must match generate_share_transaction()):
    //   1. Segwit witness commitment (if present) — value=0
    //   2. PPLNS payout outputs (sorted by amount desc, script asc)
    //   3. Donation output (subsidy - sum(payouts))
    //   4. OP_RETURN commitment (0x6a28 + ref_hash + last_txout_nonce) — value=0

    const int height = tmpl.value("height", 1);
    const std::string height_hex = encode_height_pushdata(height);
    const int height_bytes = static_cast<int>(height_hex.size()) / 2;

    // "/c2pool/" in ASCII = 2f 63 32 70 6f 6f 6c 2f
    const std::string pool_marker = "2f633270 6f6f6c2f";
    std::string pool_marker_stripped;
    for (char c : pool_marker) { if (c != ' ') pool_marker_stripped += c; }
    const int pool_marker_bytes = static_cast<int>(pool_marker_stripped.size()) / 2;

    // AuxPoW merged mining commitment
    std::string mm_hex;
    if (!mm_commitment.empty()) {
        static const char* HEX = "0123456789abcdef";
        mm_hex.reserve(mm_commitment.size() * 2);
        for (uint8_t b : mm_commitment) {
            mm_hex += HEX[b >> 4];
            mm_hex += HEX[b & 0x0f];
        }
    }
    const int mm_bytes = static_cast<int>(mm_commitment.size());

    // Total coinbase script length: height + extranonce1(4) + extranonce2(4) + mm_commitment + pool_marker
    const int script_total = height_bytes + 4 + 4 + mm_bytes + pool_marker_bytes;

    // Build coinb1 (version + 1 input header up to + including the height encoding)
    std::ostringstream coinb1;
    coinb1 << "01000000"   // version
           << "01"         // 1 input
           << "0000000000000000000000000000000000000000000000000000000000000000"
           << "ffffffff"   // previous index
           << std::hex << std::setfill('0') << std::setw(2) << script_total
           << height_hex;

    // Build coinb2 (mm + pool marker + sequence + outputs + locktime)
    std::ostringstream coinb2;
    if (!mm_hex.empty())
        coinb2 << mm_hex;
    coinb2 << pool_marker_stripped
           << "00000000";  // sequence = 0 (matches generate_share_transaction)

    // Count outputs: [segwit?] + PPLNS + [OP_RETURN?]
    // Note: outputs already includes PPLNS payouts + donation (from caller)
    size_t num_outputs = outputs.size();
    if (!witness_commitment_hex.empty()) ++num_outputs;
    if (!op_return_hex.empty()) ++num_outputs;

    // Varint-encode output count
    if (num_outputs < 0xfd)
        coinb2 << std::hex << std::setfill('0') << std::setw(2) << num_outputs;
    else
        coinb2 << "fd" << std::hex << std::setfill('0')
               << std::setw(2) << (num_outputs & 0xff)
               << std::setw(2) << ((num_outputs >> 8) & 0xff);

    // Output 1: Segwit witness commitment (FIRST, matching generate_share_transaction)
    if (!witness_commitment_hex.empty()) {
        coinb2 << encode_le64(0);   // 0 satoshis
        size_t wc_len = witness_commitment_hex.size() / 2;
        coinb2 << std::hex << std::setfill('0') << std::setw(2) << wc_len;
        coinb2 << witness_commitment_hex;
    }

    // Outputs 2..N: PPLNS payouts + donation (already sorted by caller)
    for (const auto& [addr, amount] : outputs) {
        coinb2 << encode_le64(amount);
        if (raw_scripts) {
            size_t script_len = addr.size() / 2;
            coinb2 << std::hex << std::setfill('0') << std::setw(2) << script_len;
            coinb2 << addr;
        } else {
            coinb2 << p2pkh_script(addr);
        }
    }

    // Output N+1: OP_RETURN commitment (LAST, matching generate_share_transaction)
    if (!op_return_hex.empty()) {
        coinb2 << encode_le64(0);   // 0 satoshis
        size_t script_len = op_return_hex.size() / 2;
        coinb2 << std::hex << std::setfill('0') << std::setw(2) << script_len;
        coinb2 << op_return_hex;
    }

    coinb2 << "00000000"; // locktime

    return { coinb1.str(), coinb2.str() };
}

std::pair<std::string, std::string>
MiningInterface::build_connection_coinbase(
    const std::string& extranonce1_hex,
    const std::vector<unsigned char>& payout_script,
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged_addrs) const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    if (!m_work_valid || m_cached_template.is_null())
        return {};

    // Build the full coinbase scriptSig for this connection:
    //   BIP34_height + extranonce1 + mm_commitment + pool_marker
    // This is share.m_coinbase and determines ref_hash.
    //
    // Parse height from coinb1 (already contains height encoding)
    // Actually, we rebuild the scriptSig from scratch:
    const int height = m_cached_template.value("height", 1);
    std::string height_hex = encode_height_pushdata(height);

    // Pool marker
    const std::string pool_marker_stripped = "2f633270" "6f6f6c2f";

    // MM commitment hex
    static const char* HEX = "0123456789abcdef";
    std::string mm_hex;
    for (uint8_t b : m_cached_mm_commitment) {
        mm_hex += HEX[b >> 4];
        mm_hex += HEX[b & 0x0f];
    }

    // Full scriptSig hex = height + extranonce1 + extranonce2(zeros) + mm + pool_marker
    // extranonce2 is 4 zero bytes; the miner fills in its own value at mining time
    // but ref_hash is computed with zeros (matching what the share verifier expects)
    std::string scriptsig_hex = height_hex + extranonce1_hex + "00000000" + mm_hex + pool_marker_stripped;

    // Decode to bytes for ref_hash computation
    std::vector<unsigned char> scriptsig_bytes;
    scriptsig_bytes.reserve(scriptsig_hex.size() / 2);
    for (size_t i = 0; i + 1 < scriptsig_hex.size(); i += 2)
        scriptsig_bytes.push_back(static_cast<unsigned char>(
            std::stoul(scriptsig_hex.substr(i, 2), nullptr, 16)));

    // Compute ref_hash via the callback (needs tracker data)
    if (!m_ref_hash_fn)
        return {};

    uint64_t subsidy = m_cached_template.value("coinbasevalue", uint64_t(0));
    uint32_t bits = 0;
    if (m_cached_template.contains("bits"))
        bits = static_cast<uint32_t>(std::stoul(
            m_cached_template["bits"].get<std::string>(), nullptr, 16));
    uint32_t timestamp = m_cached_template.value("curtime", uint32_t(0));

    auto [ref_hash, last_txout_nonce] = m_ref_hash_fn(
        scriptsig_bytes, payout_script, subsidy, bits, timestamp,
        m_segwit_active, m_cached_witness_commitment, merged_addrs);

    // Build OP_RETURN hex: 6a28 + ref_hash(32 LE) + last_txout_nonce(8 LE)
    std::string op_return_hex;
    {
        op_return_hex += "6a28";
        auto ref_chars = ref_hash.GetChars();
        for (unsigned char b : ref_chars) {
            op_return_hex += HEX[b >> 4];
            op_return_hex += HEX[b & 0x0f];
        }
        for (int i = 0; i < 8; ++i) {
            unsigned char b = static_cast<unsigned char>((last_txout_nonce >> (i * 8)) & 0xFF);
            op_return_hex += HEX[b >> 4];
            op_return_hex += HEX[b & 0x0f];
        }
    }

    // Call build_coinbase_parts with the OP_RETURN
    return build_coinbase_parts(
        m_cached_template,
        subsidy,
        m_cached_pplns_outputs,
        m_cached_raw_scripts,
        m_cached_mm_commitment,
        m_cached_witness_commitment,
        op_return_hex);
}

// Decode a Base58Check‐encoded address (P2PKH or P2SH) and return the
// 20-byte hash160 payload as a 40-char lowercase hex string.
// Returns "" if the address is invalid or the checksum fails.
static std::string base58check_to_hash160(const std::string& address)
{
    static constexpr const char* B58 =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // decoded[0..24]: 1 version byte + 20 hash160 bytes + 4 checksum bytes
    uint8_t decoded[25] = {};
    for (unsigned char ch : address) {
        const char* p = std::strchr(B58, static_cast<char>(ch));
        if (!p) return "";                      // invalid Base58 character
        int carry = static_cast<int>(p - B58);
        for (int i = 24; i >= 0; --i) {
            carry += 58 * static_cast<int>(decoded[i]);
            decoded[i] = static_cast<uint8_t>(carry & 0xFF);
            carry >>= 8;
        }
        if (carry) return "";                   // value doesn't fit in 25 bytes
    }

    // Verify checksum: SHA256d(decoded[0..20])[0..4] == decoded[21..24]
    uint8_t tmp[32], chk[32];
    CSHA256().Write(decoded, 21).Finalize(tmp);
    CSHA256().Write(tmp, 32).Finalize(chk);
    for (int i = 0; i < 4; ++i)
        if (chk[i] != decoded[21 + i]) return "";  // bad checksum

    // Return bytes [1..20] as 40-char hex (skip the version byte)
    static const char* HEX = "0123456789abcdef";
    std::string hex;
    hex.reserve(40);
    for (int i = 1; i <= 20; ++i) {
        hex += HEX[decoded[i] >> 4];
        hex += HEX[decoded[i] & 0x0f];
    }
    return hex;
}

void MiningInterface::refresh_work()
{
    if (!m_coin_rpc) return;
    try {
        auto wd = m_coin_rpc->getwork();

        // Update the coin node's Variable<WorkData> so submit_block() can read it
        if (m_coin_node)
            m_coin_node->work.set(wd);

        // Collect tx hashes from WorkData
        std::vector<std::string> tx_hashes_hex;
        for (const auto& h : wd.m_hashes)
            tx_hashes_hex.push_back(h.GetHex());

        // Compute Stratum merkle branches from those hashes
        auto merkle_branches = compute_merkle_branches(tx_hashes_hex);

        // Build coinbase parts with properly split payout outputs
        uint64_t coinbase_value = wd.m_data.value("coinbasevalue", uint64_t(5000000000));
        std::pair<std::string,std::string> cb_parts;
        bool segwit_active = false;

        // Cached PPLNS data for per-connection coinbase generation
        std::vector<std::pair<std::string,uint64_t>> pplns_outputs;
        bool pplns_raw_scripts = false;
        std::string witness_commitment;
        std::vector<uint8_t> mm_commitment;

        try {
            // V36 PPLNS path: use share-tracker proportional payouts directly
            if (m_pplns_fn && m_best_share_hash_fn) {
                auto best = m_best_share_hash_fn();
                if (!best.IsNull()) {
                    uint32_t nbits = std::stoul(
                        wd.m_data.value("bits", "1d00ffff"), nullptr, 16);
                    uint256 block_target = chain::bits_to_target(nbits);

                    auto expected = m_pplns_fn(best, block_target, coinbase_value, m_donation_script);

                    if (!expected.empty()) {
                        static const char* HEX = "0123456789abcdef";
                        for (const auto& [script_bytes, amount] : expected) {
                            uint64_t sat = static_cast<uint64_t>(amount);
                            if (sat == 0) continue;
                            std::string hex;
                            hex.reserve(script_bytes.size() * 2);
                            for (unsigned char b : script_bytes) {
                                hex += HEX[b >> 4];
                                hex += HEX[b & 0x0f];
                            }
                            pplns_outputs.push_back({std::move(hex), sat});
                        }
                        pplns_raw_scripts = true;
                        LOG_INFO << "refresh_work: V36 PPLNS coinbase with "
                                 << pplns_outputs.size() << " outputs";
                    }
                }
            }

            // Fallback: single output to zero-key (burn) so coinbase is always valid
            if (pplns_outputs.empty())
                pplns_outputs.push_back({"0000000000000000000000000000000000000000", coinbase_value});

            // Get merged mining commitment if an MM manager is wired
            if (m_mm_manager)
                mm_commitment = m_mm_manager->get_auxpow_commitment();

            // BIP141: extract segwit witness commitment from template
            if (wd.m_data.contains("rules")) {
                auto rules = wd.m_data["rules"].get<std::vector<std::string>>();
                segwit_active = std::any_of(rules.begin(), rules.end(),
                    [](const auto& r) { return r == "segwit" || r == "!segwit"; });
            }
            if (segwit_active && wd.m_data.contains("default_witness_commitment"))
                witness_commitment = wd.m_data["default_witness_commitment"].get<std::string>();

            // Build fallback coinbase (without OP_RETURN, for non-p2pool or initial work)
            cb_parts = build_coinbase_parts(wd.m_data, coinbase_value, pplns_outputs,
                                            pplns_raw_scripts, mm_commitment, witness_commitment);
        } catch (const std::exception& e) {
            LOG_WARNING << "refresh_work: coinbase build failed: " << e.what();
            cb_parts = { "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff", "ffffffff0100f2052a01000000434104" };
        }

        // Commit to cache under mutex
        std::lock_guard<std::mutex> lock(m_work_mutex);
        m_cached_template         = wd.m_data;
        m_cached_merkle_branches  = std::move(merkle_branches);
        m_cached_coinb1           = std::move(cb_parts.first);
        m_cached_coinb2           = std::move(cb_parts.second);
        m_segwit_active           = segwit_active;
        m_cached_pplns_outputs    = std::move(pplns_outputs);
        m_cached_raw_scripts      = pplns_raw_scripts;
        m_cached_witness_commitment = std::move(witness_commitment);
        m_cached_mm_commitment    = std::move(mm_commitment);
        m_work_valid              = true;

        LOG_INFO << "refresh_work: height=" << wd.m_data.value("height", 0)
                 << " txs=" << wd.m_hashes.size()
                 << " latency=" << wd.m_latency << "ms"
                 << " merkle_branches=" << m_cached_merkle_branches.size();

        // Push real network difficulty to external consumers (AdjustmentEngine)
        if (m_on_network_difficulty_fn) {
            try {
                uint32_t nbits_val = std::stoul(
                    wd.m_data.value("bits", "1d00ffff"), nullptr, 16);
                double net_diff = chain::target_to_difficulty(
                    chain::bits_to_target(nbits_val));
                if (net_diff > 0)
                    m_on_network_difficulty_fn(net_diff);
            } catch (...) {}
        }
    } catch (const std::exception& e) {
        LOG_WARNING << "refresh_work failed: " << e.what();
        m_work_valid = false;
    }
}

nlohmann::json MiningInterface::get_current_work_template() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    return m_work_valid ? m_cached_template : nlohmann::json{};
}

std::vector<std::string> MiningInterface::get_stratum_merkle_branches() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    return m_cached_merkle_branches;
}

std::pair<std::string, std::string> MiningInterface::get_coinbase_parts() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    return { m_cached_coinb1, m_cached_coinb2 };
}

// ─────────────────────────────────────────────────────────────────────────────

nlohmann::json MiningInterface::getwork(const std::string& request_id)
{
    LOG_INFO << "getwork request received";
    
    // Get current difficulty from the c2pool node
    double current_difficulty = 1.0; // Default fallback
    std::string target_hex = "00000000ffff0000000000000000000000000000000000000000000000000000";
    
    if (m_node) {
        // Get current session difficulty and global pool difficulty
        auto difficulty_stats = m_node->get_difficulty_stats();
        if (difficulty_stats.contains("global_pool_difficulty")) {
            current_difficulty = difficulty_stats["global_pool_difficulty"];
        }
        
        // Calculate target from difficulty
        // Target = max_target / difficulty
        // max_target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
        uint256 max_target;
        max_target.SetHex("00000000FFFF0000000000000000000000000000000000000000000000000000");
        
        uint256 work_target = max_target / static_cast<uint64_t>(current_difficulty * 1000000); // Scale for precision
        target_hex = work_target.GetHex();
        
        LOG_INFO << "Using pool difficulty: " << current_difficulty << ", target: " << target_hex.substr(0, 16) << "...";
    } else {
        LOG_WARNING << "No c2pool node connected, using default difficulty: " << current_difficulty;
    }
    
    // Build work data from the cached block template if available
    std::string work_data;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (m_work_valid && !m_cached_template.is_null()) {
            // Build an 80-byte header stub (version + prevhash + merkle_placeholder + time + bits + nonce_placeholder)
            uint32_t version = m_cached_template.value("version", 536870912U);
            std::string prevhash = m_cached_template.value("previousblockhash", std::string(64, '0'));
            std::string bits = m_cached_template.value("bits", std::string("1d00ffff"));
            uint32_t curtime = static_cast<uint32_t>(m_cached_template.value("curtime", uint64_t(std::time(nullptr))));

            std::ostringstream hdr;
            hdr << std::hex << std::setfill('0')
                << std::setw(2) << ((version      ) & 0xff)
                << std::setw(2) << ((version >>  8) & 0xff)
                << std::setw(2) << ((version >> 16) & 0xff)
                << std::setw(2) << ((version >> 24) & 0xff)
                << prevhash
                << std::string(64, '0') // merkle root placeholder — miners fill this in
                << std::setw(2) << ((curtime      ) & 0xff)
                << std::setw(2) << ((curtime >>  8) & 0xff)
                << std::setw(2) << ((curtime >> 16) & 0xff)
                << std::setw(2) << ((curtime >> 24) & 0xff)
                << bits
                << "00000000"; // nonce placeholder
            work_data = hdr.str();

            // Derive target from bits
            uint32_t nbits = static_cast<uint32_t>(std::stoul(bits, nullptr, 16));
            uint256 tmpl_target = chain::bits_to_target(nbits);
            target_hex = tmpl_target.GetHex();
        }
    }

    if (work_data.empty()) {
        // Fallback: static placeholder
        work_data = "00000001" + std::string(64, '0') + std::string(64, '0')
                    + "00000000" + "1d00ffff" + "00000000";
        LOG_WARNING << "getwork: no live template, returning placeholder work";
    }
    
    nlohmann::json work = {
        {"data", work_data},
        {"target", target_hex},
        {"difficulty", current_difficulty}
    };
    
    // Store work for later validation
    std::string work_id = std::to_string(m_work_id_counter++);
    m_active_work[work_id] = work;
    
    LOG_INFO << "Provided work to miner, work_id=" << work_id << ", difficulty=" << current_difficulty;
    return work;
}

nlohmann::json MiningInterface::submitwork(const std::string& nonce, const std::string& header, const std::string& mix, const std::string& request_id)
{
    LOG_INFO << "Work submission received - nonce: " << nonce << ", header: " << header.substr(0, 32) << "...";
    
    // Validate the submitted work by computing scrypt PoW hash
    bool work_valid = false;
    if (header.size() >= 160) { // 80 bytes = 160 hex chars
        auto header_bytes = ParseHex(header.substr(0, 160));
        if (header_bytes.size() == 80) {
            char pow_hash_bytes[32];
            scrypt_1024_1_1_256(reinterpret_cast<const char*>(header_bytes.data()), pow_hash_bytes);
            uint256 pow_hash;
            memcpy(pow_hash.begin(), pow_hash_bytes, 32);

            // Check against the template target
            uint256 target;
            {
                std::lock_guard<std::mutex> lock(m_work_mutex);
                if (m_work_valid && m_cached_template.contains("bits")) {
                    std::string bits_hex = m_cached_template["bits"].get<std::string>();
                    uint32_t bits = static_cast<uint32_t>(std::stoul(bits_hex, nullptr, 16));
                    target = chain::bits_to_target(bits);
                } else {
                    target.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
                }
            }
            work_valid = (pow_hash <= target);
            LOG_INFO << "PoW check: hash=" << pow_hash.GetHex().substr(0, 16)
                     << "... target=" << target.GetHex().substr(0, 16)
                     << "... valid=" << work_valid;
        }
    }
    
    if (work_valid && m_node) {
        // Track the mining_share submission for difficulty adjustment
        std::string session_id = "miner_" + std::to_string(m_work_id_counter);
        m_node->track_mining_share_submission(session_id, 1.0);
        
        // Create a new mining_share and add to the sharechain
        uint256 share_hash;
        share_hash.SetHex(header); // Simplified - would need proper hash calculation
        
        uint256 prev_hash = m_best_share_hash_fn ? m_best_share_hash_fn() : uint256::ZERO;
        uint256 target;
        {
            std::lock_guard<std::mutex> lock(m_work_mutex);
            if (m_work_valid && m_cached_template.contains("bits")) {
                std::string bits_hex = m_cached_template["bits"].get<std::string>();
                uint32_t bits = static_cast<uint32_t>(std::stoul(bits_hex, nullptr, 16));
                target = chain::bits_to_target(bits);
            } else {
                target.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
            }
        }
        
        m_node->add_local_mining_share(share_hash, prev_hash, target);
        
        LOG_INFO << "Mining share submitted and added to sharechain: " << share_hash.ToString().substr(0, 16) << "...";
        LOG_INFO << "Work submission accepted";
        return true;
    } else if (work_valid) {
        LOG_INFO << "Work submission accepted (no node connected for tracking)";
        return true;
    } else {
        LOG_WARNING << "Work submission rejected - invalid work";
        return false;
    }
}

nlohmann::json MiningInterface::getblocktemplate(const nlohmann::json& params, const std::string& request_id)
{
    LOG_INFO << "getblocktemplate request received";

    // Return live template if available
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (m_work_valid && !m_cached_template.empty())
            return m_cached_template;
    }

    // Fallback: static placeholder so callers always get a valid JSON object
    LOG_WARNING << "getblocktemplate: no live template yet, returning placeholder";
    return {
        {"version", 536870912},
        {"previousblockhash", "0000000000000000000000000000000000000000000000000000000000000000"},
        {"transactions", nlohmann::json::array()},
        {"coinbaseaux", nlohmann::json::object()},
        {"coinbasevalue", 5000000000LL},
        {"target", "00000000ffff0000000000000000000000000000000000000000000000000000"},
        {"mintime", 1234567890},
        {"mutable", nlohmann::json::array({"time", "transactions", "prevblock"})},
        {"noncerange", "00000000ffffffff"},
        {"sigoplimit", 20000},
        {"sizelimit", 1000000},
        {"curtime", static_cast<uint64_t>(std::time(nullptr))},
        {"bits", "1d00ffff"},
        {"height", 1},
        {"rules", nlohmann::json::array({"segwit"})}
    };
}

nlohmann::json MiningInterface::submitblock(const std::string& hex_data, const std::string& request_id)
{
    LOG_INFO << "Block submission received - size: " << hex_data.length() << " chars";

    // Block header is 80 bytes = 160 hex chars minimum
    if (hex_data.size() < 160) {
        LOG_ERROR << "submitblock: hex data too short for a valid block header";
        return {{"error", "block data too short"}};
    }

    // Parse the 80-byte block header:
    //   bytes  0- 3: version  (uint32 LE)
    //   bytes  4-35: prev_block_hash (32 bytes, internal byte order)
    //   bytes 36-67: merkle_root     (32 bytes, internal byte order)
    //   bytes 68-71: timestamp (uint32 LE)
    //   bytes 72-75: nbits     (uint32 LE)
    //   bytes 76-79: nonce     (uint32 LE)
    auto header_bytes = ParseHex(hex_data.substr(0, 160));

    // Extract prev_block_hash (bytes 4..35), reversed for display/comparison
    uint256 submitted_prev_hash;
    std::memcpy(submitted_prev_hash.data(), header_bytes.data() + 4, 32);

    // Extract merkle_root (bytes 36..67)
    uint256 submitted_merkle_root;
    std::memcpy(submitted_merkle_root.data(), header_bytes.data() + 36, 32);

    // Validate prev_block_hash matches our cached template
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (m_work_valid && !m_cached_template.is_null()
            && m_cached_template.contains("previousblockhash"))
        {
            uint256 expected_prev;
            expected_prev.SetHex(m_cached_template["previousblockhash"].get<std::string>());
            if (submitted_prev_hash != expected_prev) {
                LOG_WARNING << "submitblock: stale block — prev_hash mismatch"
                            << " submitted=" << submitted_prev_hash.GetHex()
                            << " expected=" << expected_prev.GetHex();
                // Fire callback with orphan stale info (253)
                if (m_on_block_submitted && hex_data.size() >= 160) {
                    m_on_block_submitted(hex_data.substr(0, 160), 253);
                }
                return {{"error", "stale block: previous block hash mismatch"}};
            }
        }

        // Reconstruct expected merkle_root from coinbase + merkle branches
        if (!m_cached_coinb1.empty() && !m_cached_coinb2.empty()) {
            // The pool's coinbase: coinb1 + extranonce1 + extranonce2 + coinb2
            // We can't know the miner's extranonce values for an external submitblock,
            // so we log the submitted merkle_root for auditing but skip the comparison
            // when the submit comes from the raw RPC endpoint.
            LOG_INFO << "submitblock: merkle_root=" << submitted_merkle_root.GetHex();
        }
    }

    if (m_coin_rpc) {
        try {
            m_coin_rpc->submit_block_hex(hex_data, "", false);
            LOG_INFO << "Block forwarded to coin daemon";
            // Notify P2P layer with stale_info=0 (none — accepted)
            if (m_on_block_submitted && hex_data.size() >= 160) {
                m_on_block_submitted(hex_data.substr(0, 160), 0);
            }
            // Relay full block via P2P for fast propagation
            if (m_on_block_relay) {
                m_on_block_relay(hex_data);
            }
        } catch (const std::exception& e) {
            LOG_ERROR << "submitblock failed: " << e.what();
            // Fire callback with doa stale info (254)
            if (m_on_block_submitted && hex_data.size() >= 160) {
                m_on_block_submitted(hex_data.substr(0, 160), 254);
            }
            return {{"error", std::string(e.what())}};
        }
    } else {
        LOG_WARNING << "submitblock: no coin RPC connected, block discarded";
    }

    return nullptr; // null = accepted in getblocktemplate spec
}

nlohmann::json MiningInterface::getinfo(const std::string& request_id)
{
    double current_difficulty = 1.0;
    double pool_hashrate = 0.0;
    uint64_t total_shares = 0;
    uint64_t connections = 0;
    
    // Get stats from c2pool node if available
    if (m_node) {
        auto difficulty_stats = m_node->get_difficulty_stats();
        if (difficulty_stats.contains("global_pool_difficulty")) {
            current_difficulty = difficulty_stats["global_pool_difficulty"];
        }
        
        auto hashrate_stats = m_node->get_hashrate_stats();
        if (hashrate_stats.contains("global_hashrate")) {
            pool_hashrate = hashrate_stats["global_hashrate"];
        }
        
        total_shares = m_node->get_total_mining_shares();
        connections = m_node->get_connected_peers_count();
    }
    
    // Read block height from cached template
    uint64_t block_height = 0;
    double network_hashps = 0.0;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (!m_cached_template.is_null() && m_cached_template.contains("height"))
            block_height = m_cached_template["height"].get<uint64_t>();
    }
    
    return {
        {"version", "c2pool/0.0.1"},
        {"protocolversion", 70015},
        {"blocks", block_height},
        {"connections", connections},
        {"difficulty", current_difficulty},
        {"networkhashps", network_hashps},
        {"poolhashps", pool_hashrate},
        {"poolshares", total_shares},
        {"generate", true},
        {"genproclimit", -1},
        {"testnet", m_testnet},
        {"paytxfee", 0.0},
        {"errors", ""}
    };
}

nlohmann::json MiningInterface::getstats(const std::string& request_id)
{
    uint64_t total_mining_shares = 0;
    uint64_t connected_peers = 0;
    double pool_hashrate = 0.0;
    double difficulty = 1.0;
    uint64_t active_miners = 0;

    if (m_node) {
        total_mining_shares = m_node->get_total_mining_shares();
        connected_peers = m_node->get_connected_peers_count();
        auto hs = m_node->get_hashrate_stats();
        if (hs.contains("global_hashrate"))
            pool_hashrate = hs["global_hashrate"];
        auto ds = m_node->get_difficulty_stats();
        if (ds.contains("global_pool_difficulty"))
            difficulty = ds["global_pool_difficulty"];
    }

    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    if (pm)
        active_miners = pm->get_active_miners_count();

    uint64_t block_height = 0;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (!m_cached_template.is_null() && m_cached_template.contains("height"))
            block_height = m_cached_template["height"].get<uint64_t>();
    }

    nlohmann::json stale = {{"orphan_count", 0}, {"doa_count", 0}, {"stale_count", 0}, {"stale_prop", 0.0}};
    if (m_node)
        stale = m_node->get_stale_stats();

    return {
        {"pool_statistics", {
            {"mining_shares", total_mining_shares},
            {"pool_hashrate", pool_hashrate},
            {"difficulty", difficulty},
            {"block_height", block_height},
            {"connected_peers", connected_peers},
            {"active_miners", active_miners},
            {"orphan_shares", stale["orphan_count"]},
            {"doa_shares", stale["doa_count"]},
            {"stale_shares", stale["stale_count"]},
            {"stale_prop", stale["stale_prop"]}
        }}
    };
}

nlohmann::json MiningInterface::getpeerinfo(const std::string& request_id)
{
    nlohmann::json peers = nlohmann::json::array();
    if (m_node) {
        size_t count = m_node->get_connected_peers_count();
        // Return minimal info — detailed peer data requires NodeImpl access
        peers.push_back({
            {"connected_peers", count}
        });
    }
    return peers;
}

nlohmann::json MiningInterface::getpayoutinfo(const std::string& request_id)
{
    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    if (!pm)
        return {{"error", "payout manager not available"}};

    return pm->get_payout_statistics();
}

nlohmann::json MiningInterface::getminerstats(const std::string& request_id)
{
    nlohmann::json result;
    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    if (pm) {
        result["active_miners"] = pm->get_active_miners_count();
        result["pplns_active"] = pm->has_pplns_data();
        result["payout_statistics"] = pm->get_payout_statistics();
    }
    if (m_node) {
        result["hashrate"] = m_node->get_hashrate_stats();
        result["difficulty"] = m_node->get_difficulty_stats();
        result["stale_stats"] = m_node->get_stale_stats();
    }
    return result;
}

// ──────────────────────── p2pool-compatible REST endpoints ────────────────────

nlohmann::json MiningInterface::rest_local_rate()
{
    double rate = 0.0;
    if (m_node) {
        auto hs = m_node->get_hashrate_stats();
        if (hs.contains("global_hashrate"))
            rate = hs["global_hashrate"];
    }
    return rate;
}

nlohmann::json MiningInterface::rest_global_rate()
{
    double rate = 0.0;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (!m_cached_template.is_null() && m_cached_template.contains("networkhashps"))
            rate = m_cached_template["networkhashps"].get<double>();
    }
    return rate;
}

nlohmann::json MiningInterface::rest_current_payouts()
{
    nlohmann::json result = nlohmann::json::object();
    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    if (pm && pm->has_pplns_data()) {
        uint64_t subsidy = 0;
        {
            std::lock_guard<std::mutex> lock(m_work_mutex);
            if (!m_cached_template.is_null())
                subsidy = m_cached_template.value("coinbasevalue", uint64_t(0));
        }
        if (subsidy > 0) {
            auto outputs = pm->calculate_pplns_outputs(subsidy);
            static const char* HEX = "0123456789abcdef";
            for (const auto& [script, amount] : outputs) {
                std::string key;
                key.reserve(script.size() * 2);
                for (unsigned char b : script) {
                    key += HEX[b >> 4];
                    key += HEX[b & 0x0f];
                }
                result[key] = amount;
            }
        }
    }
    return result;
}

nlohmann::json MiningInterface::rest_users()
{
    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    return pm ? nlohmann::json(pm->get_active_miners_count()) : nlohmann::json(0);
}

nlohmann::json MiningInterface::rest_fee()
{
    return m_pool_fee_percent;
}

nlohmann::json MiningInterface::rest_recent_blocks()
{
    nlohmann::json arr = nlohmann::json::array();
    std::lock_guard<std::mutex> lock(m_blocks_mutex);
    for (const auto& b : m_found_blocks)
        arr.push_back({{"height", b.height}, {"hash", b.hash}, {"ts", b.ts}});
    return arr;
}

void MiningInterface::record_found_block(uint64_t height, const uint256& hash, uint64_t ts)
{
    if (ts == 0) ts = static_cast<uint64_t>(std::time(nullptr));
    std::lock_guard<std::mutex> lock(m_blocks_mutex);
    m_found_blocks.insert(m_found_blocks.begin(), FoundBlock{height, hash.GetHex(), ts});
    if (m_found_blocks.size() > 100)
        m_found_blocks.resize(100);
}

void MiningInterface::set_pool_fee_percent(double fee_percent)
{
    m_pool_fee_percent = fee_percent;
}

void MiningInterface::set_node_fee_from_address(double percent, const std::string& address)
{
    auto h160 = base58check_to_hash160(address);
    if (h160.size() != 40) {
        LOG_WARNING << "set_node_fee_from_address: invalid address " << address;
        return;
    }
    std::vector<unsigned char> script = {0x76, 0xa9, 0x14};
    for (size_t i = 0; i < h160.size(); i += 2)
        script.push_back(static_cast<unsigned char>(
            std::stoul(h160.substr(i, 2), nullptr, 16)));
    script.push_back(0x88);
    script.push_back(0xac);
    set_node_fee(percent, script);
    m_node_fee_address = address;
}

void MiningInterface::set_donation_script_from_address(const std::string& address)
{
    auto h160 = base58check_to_hash160(address);
    if (h160.size() != 40) return;
    std::vector<unsigned char> script = {0x76, 0xa9, 0x14};
    for (size_t i = 0; i < h160.size(); i += 2)
        script.push_back(static_cast<unsigned char>(
            std::stoul(h160.substr(i, 2), nullptr, 16)));
    script.push_back(0x88);
    script.push_back(0xac);
    set_donation_script(script);
}

nlohmann::json MiningInterface::mining_subscribe(const std::string& user_agent, const std::string& request_id)
{
    LOG_INFO << "Stratum mining.subscribe from: " << user_agent;
    
    // Return stratum subscription response
    return nlohmann::json::array({
        nlohmann::json::array({"mining.notify", "subscription_id_1"}),
        "extranonce1",
        0 // extranonce2_size = 0 (p2pool per-connection coinbase)
    });
}

nlohmann::json MiningInterface::mining_authorize(const std::string& username, const std::string& password, const std::string& request_id)
{
    LOG_INFO << "Stratum mining.authorize for user: " << username;
    
    // Validate the username as a payout address for the configured blockchain/network
    if (!is_valid_address(username)) {
        std::string blockchain_name = m_address_validator.get_blockchain_name(m_blockchain);
        LOG_WARNING << "Authorization failed: Invalid address for " 
                   << blockchain_name << " " 
                   << (m_testnet ? "testnet" : "mainnet") << ": " << username;
        
        nlohmann::json error_response;
        error_response["result"] = false;
        error_response["error"] = {
            {"code", -1},
            {"message", "Invalid payout address for " + blockchain_name + 
                       " " + (m_testnet ? "testnet" : "mainnet")}
        };
        return error_response;
    }
    
    LOG_INFO << "Authorization successful for address: " << username;
    return true;
}

nlohmann::json MiningInterface::mining_submit(const std::string& username, const std::string& job_id, const std::string& extranonce1, const std::string& extranonce2, const std::string& ntime, const std::string& nonce, const std::string& request_id,
    const std::map<uint32_t, std::vector<unsigned char>>& merged_addresses)
{
    LOG_INFO << "Stratum mining.submit from " << username << " for job " << job_id 
             << " - nonce: " << nonce << ", extranonce2: " << extranonce2 << ", ntime: " << ntime;
    
    // Basic share validation
    bool share_valid = true;
    
    // Validate hex parameters
    if (extranonce2.empty() || ntime.empty() || nonce.empty()) {
        LOG_WARNING << "Invalid share parameters from " << username;
        return false;
    }
    
    // Validate nonce format (should be 8 hex chars)
    if (nonce.length() != 8) {
        LOG_WARNING << "Invalid nonce length from " << username << ": " << nonce;
        return false;
    }
    
    // Validate extranonce2 format
    if (extranonce2.length() != 8) {
        LOG_WARNING << "Invalid extranonce2 length from " << username << ": " << extranonce2;
        return false;
    }
    
    // Validate timestamp format (should be 8 hex chars)
    if (ntime.length() != 8) {
        LOG_WARNING << "Invalid ntime length from " << username << ": " << ntime;
        return false;
    }
    
    // Calculate share difficulty
    double share_difficulty = calculate_share_difficulty(job_id, extranonce1, extranonce2, ntime, nonce);
    
    if (m_solo_mode) {
        // Solo mining mode - work directly with blockchain
        LOG_INFO << "Solo mining share from " << username << " (difficulty: " << share_difficulty << ")";
        
        // In solo mode, check if share meets network difficulty for block submission
        std::string payout_address = m_solo_address.empty() ? username : m_solo_address;
        
        // Calculate payout allocation if we have a payout manager
        if (m_payout_manager_ptr) {
            // Simulate block reward for calculation (25 LTC = 2500000000 satoshis)
            uint64_t block_reward = 2500000000; // 25 LTC in satoshis
            auto allocation = m_payout_manager_ptr->calculate_payout(block_reward);
            
            if (allocation.is_valid()) {
                LOG_INFO << "Solo mining payout allocation:";
                LOG_INFO << "  Miner (" << payout_address << "): " << allocation.miner_percent << "% = " << allocation.miner_amount << " satoshis";
                LOG_INFO << "  Developer: " << allocation.developer_percent << "% = " << allocation.developer_amount << " satoshis (" << allocation.developer_address << ")";
                if (allocation.node_owner_amount > 0) {
                    LOG_INFO << "  Node owner: " << allocation.node_owner_percent << "% = " << allocation.node_owner_amount << " satoshis (" << allocation.node_owner_address << ")";
                }
                
                // Allocation is already baked into coinbase parts by refresh_work() →
                // build_coinbase_parts(). When a valid block is found below, it carries
                // the correct developer and node-owner fee outputs.
            }
        }
        
        LOG_INFO << "Solo mining share accepted - primary payout address: " << payout_address;
        
        // Check if share meets network difficulty and attempt block submission
        if (m_coin_rpc && !extranonce1.empty()) {
            double network_difficulty = 1.0;
            {
                std::lock_guard<std::mutex> lock(m_work_mutex);
                if (!m_cached_template.is_null() && m_cached_template.contains("target")) {
                    // Convert hex target to approximate difficulty for comparison
                    // A share at difficulty D has probability 1/D of meeting network target
                    // For now, attempt block construction for every share and let the
                    // coin daemon reject invalid blocks (the PoW check is authoritative)
                }
            }
            
            std::string block_hex = build_block_from_stratum(extranonce1, extranonce2, ntime, nonce);
            if (!block_hex.empty()) {
                // Check merged mining targets for every share (aux targets are lower)
                check_merged_mining(block_hex, extranonce1, extranonce2);

                // Validate merkle root before submitting
                auto block_bytes = ParseHex(block_hex.substr(0, 160));
                uint256 header_merkle;
                std::memcpy(header_merkle.data(), block_bytes.data() + 36, 32);

                std::string coinbase_hex;
                uint256 expected_merkle;
                {
                    std::lock_guard<std::mutex> lock(m_work_mutex);
                    coinbase_hex = m_cached_coinb1 + extranonce1 + extranonce2 + m_cached_coinb2;
                    expected_merkle = reconstruct_merkle_root(coinbase_hex, m_cached_merkle_branches);
                }

                if (header_merkle != expected_merkle) {
                    LOG_ERROR << "Block merkle_root mismatch!"
                              << " header=" << header_merkle.GetHex()
                              << " expected=" << expected_merkle.GetHex();
                } else {
                    LOG_INFO << "Block merkle_root validated, submitting to coin daemon";
                    submitblock(block_hex);
                }
            }
        }
        
        return nlohmann::json{{"result", true}};
    } else {
        // Standard pool mode - track shares for sharechain and payouts

        // V36 probabilistic node fee: with probability m_node_fee_percent%,
        // replace the miner's address with the node operator's address.
        // This means ~fee% of shares carry the operator's address in PPLNS.
        std::string share_address = username;
        if (m_node_fee_percent > 0.0 && !m_node_fee_script.empty()) {
            float roll = core::random::random_float(0.0f, 100.0f);
            if (roll < static_cast<float>(m_node_fee_percent)) {
                // Replace with node operator address for this share
                // The script is stored as raw bytes; for share tracking we pass
                // the hex representation of the hash160 (bytes 3..22 of P2PKH script)
                if (m_node_fee_script.size() == 25) { // P2PKH: 76 a9 14 <20 bytes> 88 ac
                    static const char* HEX = "0123456789abcdef";
                    std::string h160;
                    h160.reserve(40);
                    for (int i = 3; i < 23; ++i) {
                        h160 += HEX[m_node_fee_script[i] >> 4];
                        h160 += HEX[m_node_fee_script[i] & 0x0f];
                    }
                    share_address = h160;
                    LOG_DEBUG_POOL << "Node fee: share " << job_id
                                   << " address replaced → operator (roll="
                                   << roll << " < " << m_node_fee_percent << ")";
                }
            }
        }
        
        // Track mining_share submission for statistics
        if (m_node) {
            m_node->track_mining_share_submission(username, share_difficulty);
        }

        // Record share contribution for payout calculation (pool mode only)
        if (m_payout_manager) {
            m_payout_manager->record_share_contribution(share_address, share_difficulty);
            LOG_DEBUG_POOL << "Share contribution recorded: " << share_address << " (difficulty: " << share_difficulty << ")";
        }

        // Create a proper V36 share in the tracker with all block template data.
        // The payout_script is built from share_address (which may have been
        // probabilistically replaced with the node operator's address for the
        // primary chain node fee).  Merged addresses are passed through
        // unmodified — Python p2pool does NOT apply node fee to merged chains.
        if (m_create_share_fn) {
            ShareCreationParams params;

            // Build P2PKH script from share_address (40-char hex hash160)
            if (share_address.size() == 40) {
                params.payout_script = {0x76, 0xa9, 0x14};
                for (size_t i = 0; i < share_address.size(); i += 2)
                    params.payout_script.push_back(static_cast<unsigned char>(
                        std::stoul(share_address.substr(i, 2), nullptr, 16)));
                params.payout_script.push_back(0x88);
                params.payout_script.push_back(0xac);
            }

            params.merged_addresses = merged_addresses;
            params.nonce = static_cast<uint32_t>(std::stoul(nonce, nullptr, 16));
            params.timestamp = static_cast<uint32_t>(std::stoul(ntime, nullptr, 16));

            // Extract block template fields under the work mutex
            {
                std::lock_guard<std::mutex> lock(m_work_mutex);
                if (m_work_valid) {
                    params.block_version = m_cached_template.value("version", 536870912U);
                    if (m_cached_template.contains("previousblockhash")) {
                        params.prev_block_hash.SetHex(
                            m_cached_template["previousblockhash"].get<std::string>());
                    }
                    if (m_cached_template.contains("bits")) {
                        params.bits = static_cast<uint32_t>(std::stoul(
                            m_cached_template["bits"].get<std::string>(), nullptr, 16));
                    }
                    params.subsidy = m_cached_template.value("coinbasevalue", uint64_t(0));

                    // Build coinbase scriptSig from coinb1 (contains BIP34 height + pool tag)
                    // coinb1 = raw hex up to the extranonce insertion point
                    // The scriptSig is inside the coinbase tx: after version(4) + vin_count(1)
                    // + prevout_hash(32) + prevout_idx(4) + scriptSig_len comes the scriptSig.
                    // For create_local_share, we pass the pool's coinbase tag.
                    std::string full_coinbase_hex = m_cached_coinb1 + extranonce1 + extranonce2 + m_cached_coinb2;
                    // Extract scriptSig: parse the coinbase tx
                    auto cb_bytes = ParseHex(full_coinbase_hex);
                    if (cb_bytes.size() > 41) {
                        // version(4) + vin_count(1) + prevout(36) = 41
                        // Then varint scriptSig length, then scriptSig bytes
                        size_t pos = 41;
                        uint64_t scriptsig_len = cb_bytes[pos++];
                        if (scriptsig_len < 0xfd && pos + scriptsig_len <= cb_bytes.size()) {
                            params.coinbase_scriptSig.assign(
                                cb_bytes.begin() + pos,
                                cb_bytes.begin() + pos + scriptsig_len);
                        }
                    }

                    // Convert string merkle branches to uint256 (internal byte order)
                    params.merkle_branches.reserve(m_cached_merkle_branches.size());
                    for (const auto& branch_hex : m_cached_merkle_branches) {
                        uint256 h;
                        auto branch_bytes = ParseHex(branch_hex);
                        if (branch_bytes.size() == 32)
                            memcpy(h.begin(), branch_bytes.data(), 32);
                        params.merkle_branches.push_back(h);
                    }

                    // Segwit fields for SegwitData on the share
                    params.segwit_active = m_segwit_active;
                    if (m_segwit_active && m_cached_template.contains("default_witness_commitment"))
                        params.witness_commitment_hex =
                            m_cached_template["default_witness_commitment"].get<std::string>();
                }
            }

            if (!params.payout_script.empty() && params.bits != 0) {
                m_create_share_fn(params);
            }
        }
        
        // Attempt block construction + merkle validation + submission.
        // calculate_share_difficulty now computes real scrypt PoW, so in
        // production we could gate on share_difficulty >= network_difficulty.
        // For now, build + validate for every share; the coin daemon rejects
        // invalid PoW anyway.
        if (m_coin_rpc && !extranonce1.empty()) {
            std::string block_hex = build_block_from_stratum(extranonce1, extranonce2, ntime, nonce);
            if (!block_hex.empty()) {
                // Check merged mining targets for every share (aux targets are lower)
                check_merged_mining(block_hex, extranonce1, extranonce2);

                auto block_bytes = ParseHex(block_hex.substr(0, 160));
                uint256 header_merkle;
                std::memcpy(header_merkle.data(), block_bytes.data() + 36, 32);

                std::string coinbase_hex;
                uint256 expected_merkle;
                {
                    std::lock_guard<std::mutex> lock(m_work_mutex);
                    coinbase_hex = m_cached_coinb1 + extranonce1 + extranonce2 + m_cached_coinb2;
                    expected_merkle = reconstruct_merkle_root(coinbase_hex, m_cached_merkle_branches);
                }

                if (header_merkle != expected_merkle) {
                    LOG_ERROR << "Pool block merkle_root mismatch!"
                              << " header=" << header_merkle.GetHex()
                              << " expected=" << expected_merkle.GetHex();
                } else {
                    LOG_INFO << "Pool block merkle_root validated, submitting to coin daemon";
                    submitblock(block_hex);
                }
            }
        }
        
        return nlohmann::json{{"result", true}};
    }
}

nlohmann::json MiningInterface::validate_address(const std::string& address)
{
    LOG_INFO << "Address validation request for: " << address;
    
    nlohmann::json result = nlohmann::json::object();
    
    try {
        if (m_payout_manager) {
            // Use the existing address validator from payout manager
            auto validation_result = m_payout_manager->get_address_validator()->validate_address(address);
            
            result["valid"] = validation_result.is_valid;
            result["address"] = address;
            result["type"] = static_cast<int>(validation_result.type);
            result["blockchain"] = static_cast<int>(validation_result.blockchain);
            result["network"] = static_cast<int>(validation_result.network);
            
            if (!validation_result.is_valid) {
                result["error"] = validation_result.error_message;
            }
            
            LOG_INFO << "Address validation result: " << (validation_result.is_valid ? "VALID" : "INVALID");
            
        } else {
            result["valid"] = false;
            result["error"] = "Payout manager not available";
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Address validation error: " << e.what();
        result["valid"] = false;
        result["error"] = std::string("Validation failed: ") + e.what();
    }
    
    return result;
}

nlohmann::json MiningInterface::build_coinbase(const nlohmann::json& params)
{
    LOG_INFO << "Coinbase construction request received";
    
    try {
        if (!m_payout_manager) {
            throw std::runtime_error("Payout manager not available");
        }
        
        // Extract parameters
        uint64_t block_reward = params.value("block_reward", 2500000000ULL); // Default 25 LTC
        std::string miner_address = params.value("miner_address", "");
        double dev_fee_percent = params.value("dev_fee_percent", 0.0);
        double node_fee_percent = params.value("node_fee_percent", 0.0);
        
        if (miner_address.empty()) {
            throw std::runtime_error("Miner address is required");
        }
        
        // Validate the miner address first
        auto addr_validation = m_payout_manager->get_address_validator()->validate_address(miner_address);
        if (!addr_validation.is_valid) {
            throw std::runtime_error("Invalid miner address: " + addr_validation.error_message);
        }
        
        // Build detailed coinbase
        auto result = m_payout_manager->build_coinbase_detailed(block_reward, miner_address, 
                                                               dev_fee_percent, node_fee_percent);
        
        LOG_INFO << "Coinbase construction successful for " << miner_address;
        return result;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Coinbase construction error: " << e.what();
        return nlohmann::json{
            {"error", std::string("Coinbase construction failed: ") + e.what()}
        };
    }
}

nlohmann::json MiningInterface::validate_coinbase(const std::string& coinbase_hex)
{
    LOG_INFO << "Coinbase validation request - hex length: " << coinbase_hex.length();
    
    nlohmann::json result = nlohmann::json::object();
    
    try {
        if (!m_payout_manager) {
            throw std::runtime_error("Payout manager not available");
        }
        
        bool is_valid = m_payout_manager->validate_coinbase_transaction(coinbase_hex);
        
        result["valid"] = is_valid;
        result["coinbase_hex"] = coinbase_hex;
        result["hex_length"] = coinbase_hex.length();
        result["byte_length"] = coinbase_hex.length() / 2;
        
        if (!is_valid) {
            result["error"] = "Coinbase transaction validation failed";
        }
        
        LOG_INFO << "Coinbase validation result: " << (is_valid ? "VALID" : "INVALID");
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Coinbase validation error: " << e.what();
        result["valid"] = false;
        result["error"] = std::string("Validation failed: ") + e.what();
    }
    
    return result;
}

nlohmann::json MiningInterface::getblockcandidate(const nlohmann::json& params)
{
    LOG_INFO << "Block candidate request received";
    
    try {
        // Get base block template (this would normally come from the coin node)
        auto base_template = getblocktemplate(nlohmann::json::array());
        
        // Enhance with coinbase construction if payout manager available
        if (m_payout_manager && params.contains("miner_address")) {
            std::string miner_address = params["miner_address"];
            uint64_t coinbase_value = base_template.value("coinbasevalue", 2500000000ULL);
            
            // Build coinbase with payout distribution
            auto coinbase_result = m_payout_manager->build_coinbase_detailed(coinbase_value, miner_address);
            
            // Add coinbase info to block template
            base_template["coinbase_outputs"] = coinbase_result["outputs"];
            base_template["coinbase_hex"] = coinbase_result["coinbase_hex"];
            base_template["payout_distribution"] = true;
            
            LOG_INFO << "Block candidate with payout distribution generated";
        } else {
            base_template["payout_distribution"] = false;
            LOG_INFO << "Basic block candidate generated (no payout distribution)";
        }
        
        // Add validation info
        base_template["candidate_valid"] = true;
        base_template["generation_time"] = static_cast<uint64_t>(std::time(nullptr));
        
        return base_template;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Block candidate generation error: " << e.what();
        return nlohmann::json{
            {"error", std::string("Block candidate generation failed: ") + e.what()},
            {"candidate_valid", false}
        };
    }
}

/// WebServer Implementation
WebServer::WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet)
    : ioc_(ioc)
    , acceptor_(ioc)
    , bind_address_(address)
    , port_(port)
    , stratum_port_(port + 10)  // Default stratum port is +10 from main port
    , running_(false)
    , testnet_(testnet)
    , blockchain_(Blockchain::LITECOIN)
    , solo_mode_(false)
{
    mining_interface_ = std::make_shared<MiningInterface>(testnet);
}

WebServer::WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet, std::shared_ptr<IMiningNode> node)
    : ioc_(ioc)
    , acceptor_(ioc)
    , bind_address_(address)
    , port_(port)
    , stratum_port_(port + 10)
    , running_(false)
    , testnet_(testnet)
    , blockchain_(Blockchain::LITECOIN)
    , solo_mode_(false)
{
    mining_interface_ = std::make_shared<MiningInterface>(testnet, node);
}

WebServer::WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet, std::shared_ptr<IMiningNode> node, Blockchain blockchain)
    : ioc_(ioc)
    , acceptor_(ioc)
    , bind_address_(address)
    , port_(port)
    , stratum_port_(port + 10)
    , running_(false)
    , testnet_(testnet)
    , blockchain_(blockchain)
    , solo_mode_(false)
{
    mining_interface_ = std::make_shared<MiningInterface>(testnet, node, blockchain);
}

WebServer::~WebServer()
{
    stop();
}

bool WebServer::start()
{
    try {
        // Bind and listen on the HTTP port
        auto const address = net::ip::make_address(bind_address_);
        tcp::endpoint endpoint{address, port_};
        
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(net::socket_base::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen(net::socket_base::max_listen_connections);
        
        LOG_INFO << "WebServer started on " << bind_address_ << ":" << port_;
        
        // Start accepting HTTP connections
        accept_connections();
        
        // Start stratum server if configured
        if (stratum_port_ > 0) {
            start_stratum_server();
        }

        // If a coin RPC is connected, schedule a recurring work-refresh timer
        if (m_coin_rpc_) {
            auto timer = std::make_shared<net::steady_timer>(ioc_);
            // Use a shared_ptr<function> so the lambda can reschedule itself
            auto fn = std::make_shared<std::function<void(beast::error_code)>>();
            *fn = [this, timer, fn](beast::error_code ec) {
                if (ec || !running_) return;
                try { mining_interface_->refresh_work(); }
                catch (const std::exception& e) { LOG_WARNING << "refresh_work failed: " << e.what(); }
                catch (...) { LOG_WARNING << "refresh_work failed: unknown error"; }
                timer->expires_after(std::chrono::seconds(5));
                timer->async_wait(*fn);
            };
            // First poll after a short delay to let the io_context settle
            timer->expires_after(std::chrono::milliseconds(500));
            timer->async_wait(*fn);
            LOG_INFO << "Work-refresh timer scheduled (every 5 s)";
        }
        
        running_ = true;
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to start WebServer: " << e.what();
        return false;
    }
}

void WebServer::set_on_block_submitted(std::function<void(const std::string&, int)> fn)
{
    mining_interface_->set_on_block_submitted(std::move(fn));
}

void WebServer::set_on_block_relay(std::function<void(const std::string&)> fn)
{
    mining_interface_->set_on_block_relay(std::move(fn));
}

void WebServer::trigger_work_refresh()
{
    mining_interface_->refresh_work();
}

void WebServer::set_coin_rpc(ltc::coin::NodeRPC* rpc, ltc::interfaces::Node* coin)
{
    m_coin_rpc_  = rpc;
    m_coin_node_ = coin;
    mining_interface_->set_coin_rpc(rpc, coin);
    LOG_INFO << "WebServer: coin RPC " << (rpc ? "attached" : "detached");
}

void WebServer::set_best_share_hash_fn(std::function<uint256()> fn)
{
    mining_interface_->set_best_share_hash_fn(std::move(fn));
}

void WebServer::set_pplns_fn(MiningInterface::pplns_fn_t fn)
{
    mining_interface_->set_pplns_fn(std::move(fn));
}

void WebServer::set_merged_mining_manager(c2pool::merged::MergedMiningManager* mgr)
{
    mining_interface_->set_merged_mining_manager(mgr);
}

bool WebServer::start_solo()
{
    solo_mode_ = true;
    
    try {
        // In solo mode, only start stratum server
        if (stratum_port_ > 0) {
            start_stratum_server();
            LOG_INFO << "WebServer started in solo mode on Stratum port " << stratum_port_;
            running_ = true;
            return true;
        } else {
            LOG_ERROR << "Solo mode requires Stratum port configuration";
            return false;
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to start WebServer in solo mode: " << e.what();
        return false;
    }
}

void WebServer::stop()
{
    if (running_) {
        try {
            acceptor_.close();
            stop_stratum_server();
            running_ = false;
            LOG_INFO << "WebServer stopped";
        } catch (const std::exception& e) {
            LOG_ERROR << "Error stopping WebServer: " << e.what();
        }
    }
}

bool WebServer::start_stratum_server()
{
    try {
        if (!stratum_server_) {
            stratum_server_ = std::make_unique<StratumServer>(ioc_, bind_address_, stratum_port_, mining_interface_);
        }
        
        bool started = stratum_server_->start();
        if (started) {
            LOG_INFO << "Stratum server started on port " << stratum_port_;
        }
        return started;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to start Stratum server: " << e.what();
        return false;
    }
}

void WebServer::stop_stratum_server()
{
    if (stratum_server_) {
        stratum_server_->stop();
        stratum_server_.reset();
        LOG_INFO << "Stratum server stopped";
    }
}

void WebServer::set_stratum_port(uint16_t port)
{
    stratum_port_ = port;
}

void WebServer::accept_connections()
{
    acceptor_.async_accept(
        [this](beast::error_code ec, tcp::socket socket)
        {
            handle_accept(ec, std::move(socket));
        });
}

void WebServer::handle_accept(beast::error_code ec, tcp::socket socket)
{

    if (!ec) {
        // Create and run HTTP session
        std::make_shared<HttpSession>(std::move(socket), mining_interface_)->run();
    } else {
        LOG_ERROR << "HTTP accept error: " << ec.message();
    }
    
    // Continue accepting new connections
    if (running_) {
        accept_connections();
    }
}

bool WebServer::is_stratum_running() const
{
    return stratum_server_ && stratum_server_->is_running();
}

uint16_t WebServer::get_stratum_port() const
{
    return stratum_port_;
}

/// LitecoinRpcClient Implementation
LitecoinRpcClient::LitecoinRpcClient(bool testnet)
    : testnet_(testnet)
{
}

LitecoinRpcClient::SyncStatus LitecoinRpcClient::get_sync_status()
{
    SyncStatus status;
    status.is_synced = true;  // Assume synced for now
    status.progress = 1.0;
    status.current_blocks = 3945867;  // Mock value for testing
    status.total_headers = 3945867;
    status.initial_block_download = false;
    status.error_message = "";
    
    return status;
}

bool LitecoinRpcClient::is_connected()
{
    return true;  // Assume connected for now
}

std::string LitecoinRpcClient::execute_cli_command(const std::string& command)
{
    return "OK";  // Mock response for testing
}

/// StratumServer Implementation
StratumServer::StratumServer(net::io_context& ioc, const std::string& address, uint16_t port, std::shared_ptr<MiningInterface> mining_interface)
    : ioc_(ioc)
    , acceptor_(ioc)
    , mining_interface_(mining_interface)
    , bind_address_(address)
    , port_(port)
    , running_(false)
{
}

StratumServer::~StratumServer()
{
    stop();
}

bool StratumServer::start()
{
    try {
        auto const address = net::ip::make_address(bind_address_);
        tcp::endpoint endpoint{address, port_};
        
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(net::socket_base::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen(net::socket_base::max_listen_connections);
        
        running_ = true;
        accept_connections();
        
        LOG_INFO << "StratumServer started on " << bind_address_ << ":" << port_;
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to start StratumServer: " << e.what();
        return false;
    }
}

void StratumServer::stop()
{
    if (running_) {
        try {
            acceptor_.close();
            running_ = false;
            LOG_INFO << "StratumServer stopped";
        } catch (const std::exception& e) {
            LOG_ERROR << "Error stopping StratumServer: " << e.what();
        }
    }
}

void StratumServer::accept_connections()
{
    acceptor_.async_accept(
        [this](boost::system::error_code ec, tcp::socket socket)
        {
            handle_accept(ec, std::move(socket));
        });
}

void StratumServer::handle_accept(boost::system::error_code ec, tcp::socket socket)
{
    if (!ec) {
        // Create and start Stratum session
        std::make_shared<StratumSession>(std::move(socket), mining_interface_)->start();
    } else {
        LOG_ERROR << "Stratum accept error: " << ec.message();
    }
    
    // Continue accepting new connections
    if (running_) {
        accept_connections();
    }
}

/// StratumSession Implementation
StratumSession::StratumSession(tcp::socket socket, std::shared_ptr<MiningInterface> mining_interface)
    : socket_(std::move(socket))
    , mining_interface_(mining_interface)
{
    subscription_id_ = generate_subscription_id();
    extranonce1_ = generate_extranonce1();
    hashrate_tracker_.set_difficulty_bounds(0.001, 65536.0);
    hashrate_tracker_.set_target_time_per_mining_share(15.0);
}

void StratumSession::start()
{
    LOG_INFO << "StratumSession started for client: " << socket_.remote_endpoint();
    read_message();
}

std::string StratumSession::generate_subscription_id()
{
    static std::atomic<uint64_t> subscription_counter{0};
    return "sub_" + std::to_string(subscription_counter.fetch_add(1));
}

void StratumSession::read_message()
{
    auto self = shared_from_this();
    
    boost::asio::async_read_until(socket_, buffer_, '\n',
        [self](boost::system::error_code ec, std::size_t bytes_read)
        {
            if (!ec) {
                self->process_message(bytes_read);
                self->read_message();  // Continue reading
            } else {
                LOG_INFO << "StratumSession ended: " << ec.message();
            }
        });
}

void StratumSession::process_message(std::size_t bytes_read)
{
    try {
        std::istream is(&buffer_);
        std::string line;
        std::getline(is, line);
        
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();  // Remove \r if present
        }
        
        LOG_INFO << "Stratum message received: " << line;
        
        auto request = nlohmann::json::parse(line);
        std::string method = request.value("method", "");
        auto params = request.value("params", nlohmann::json::array());
        auto id = request.value("id", nlohmann::json{});
        
        nlohmann::json response;
        
        if (method == "mining.subscribe") {
            response = handle_subscribe(params, id);
        } else if (method == "mining.authorize") {
            response = handle_authorize(params, id);
        } else if (method == "mining.submit") {
            response = handle_submit(params, id);
        } else if (method == "mining.set_merged_addresses") {
            response = handle_set_merged_addresses(params, id);
        } else {
            // Unknown method
            send_error(-1, "Unknown method", id);
            return;
        }
        
        send_response(response);

        // After subscribe response is sent, follow up with difficulty + work
        if (method == "mining.subscribe") {
            send_set_difficulty(hashrate_tracker_.get_current_difficulty());
            send_notify_work();
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Error processing Stratum message: " << e.what();
        send_error(-2, "Invalid JSON", nlohmann::json{});
    }
}

nlohmann::json StratumSession::handle_subscribe(const nlohmann::json& params, const nlohmann::json& request_id)
{
    subscribed_ = true;
    
    nlohmann::json response;
    response["id"] = request_id;
    response["result"] = nlohmann::json::array({
        nlohmann::json::array({
            nlohmann::json::array({"mining.set_difficulty", subscription_id_}),
            nlohmann::json::array({"mining.notify", subscription_id_})
        }),
        extranonce1_,
        4  // extranonce2_size = 4 bytes
    });
    response["error"] = nullptr;
    
    LOG_INFO << "Mining subscription successful for: " << subscription_id_;
    
    // NOTE: set_difficulty + notify are sent from process_message()
    // AFTER this response is written, so the miner gets the subscribe
    // reply (with extranonce1) before any work notifications.
    
    return response;
}

nlohmann::json StratumSession::handle_authorize(const nlohmann::json& params, const nlohmann::json& request_id)
{
    if (params.size() >= 1 && params[0].is_string()) {
        username_ = params[0];
        authorized_ = true;

        // Parse merged addresses from username: ADDRESS/CHAIN_ID:ADDR/CHAIN_ID:ADDR
        auto slash_pos = username_.find('/');
        if (slash_pos != std::string::npos) {
            std::string remainder = username_.substr(slash_pos + 1);
            username_ = username_.substr(0, slash_pos);
            std::istringstream ss(remainder);
            std::string token;
            while (std::getline(ss, token, '/')) {
                auto colon = token.find(':');
                if (colon != std::string::npos && colon > 0 && colon + 1 < token.size()) {
                    try {
                        uint32_t chain_id = static_cast<uint32_t>(std::stoul(token.substr(0, colon)));
                        merged_addresses_[chain_id] = token.substr(colon + 1);
                    } catch (...) {
                        // skip malformed entries
                    }
                }
            }
            if (!merged_addresses_.empty())
                LOG_INFO << "Merged addresses from username: " << merged_addresses_.size() << " chain(s)";
        }
        
        LOG_INFO << "Mining authorization successful for: " << username_;
        
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = true;
        response["error"] = nullptr;
        
        return response;
    } else {
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = false;
        response["error"] = nlohmann::json::array({21, "Invalid username", nullptr});
        
        return response;
    }
}

// mining.set_merged_addresses extension
// params: [{ "chain_id": "address", ... }]  — keys are chain_id as strings
// Example: [{"98": "DQkwFoo...", "2": "1btcAddr..."}]
nlohmann::json StratumSession::handle_set_merged_addresses(const nlohmann::json& params, const nlohmann::json& request_id)
{
    if (params.empty() || !params[0].is_object()) {
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = false;
        response["error"] = nlohmann::json::array({20, "Expected object param {chain_id: address}", nullptr});
        return response;
    }

    for (auto& [key, val] : params[0].items()) {
        if (val.is_string()) {
            try {
                uint32_t chain_id = static_cast<uint32_t>(std::stoul(key));
                merged_addresses_[chain_id] = val.get<std::string>();
            } catch (...) {
                // skip malformed
            }
        }
    }

    LOG_INFO << "Set merged addresses for " << username_ << ": " << merged_addresses_.size() << " chain(s)";

    nlohmann::json response;
    response["id"] = request_id;
    response["result"] = true;
    response["error"] = nullptr;
    return response;
}

nlohmann::json StratumSession::handle_submit(const nlohmann::json& params, const nlohmann::json& request_id)
{
    if (!authorized_) {
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = false;
        response["error"] = nlohmann::json::array({24, "Unauthorized", nullptr});
        return response;
    }
    
    // Extract Stratum submit parameters: [username, job_id, extranonce2, ntime, nonce]
    if (params.size() < 5 || !params[1].is_string() || !params[2].is_string()
        || !params[3].is_string() || !params[4].is_string()) {
        ++rejected_shares_;
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = false;
        response["error"] = nlohmann::json::array({20, "Invalid parameters", nullptr});
        return response;
    }
    
    std::string job_id      = params[1].get<std::string>();
    std::string extranonce2 = params[2].get<std::string>();
    std::string ntime       = params[3].get<std::string>();
    std::string nonce       = params[4].get<std::string>();
    
    // Stale detection: check if job_id is still active
    auto job_it = active_jobs_.find(job_id);
    if (job_it == active_jobs_.end()) {
        ++stale_shares_;
        LOG_INFO << "Stale share from " << username_ << " for expired job " << job_id;
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = false;
        response["error"] = nlohmann::json::array({21, "Stale share", nullptr});
        return response;
    }
    
    // Calculate share difficulty using per-connection coinbase and job-specific template data
    const auto& job = job_it->second;
    double share_difficulty = MiningInterface::calculate_share_difficulty(
        job.coinb1, job.coinb2,
        extranonce1_, extranonce2, ntime, nonce,
        job.version, job.gbt_prevhash, job.nbits, job.merkle_branches);
    double required_difficulty = hashrate_tracker_.get_current_difficulty();
    
    if (share_difficulty < required_difficulty) {
        ++rejected_shares_;
        LOG_WARNING << "Low difficulty share from " << username_
                    << ": got " << share_difficulty << ", need " << required_difficulty;
        nlohmann::json response;
        response["id"] = request_id;
        response["result"] = false;
        response["error"] = nlohmann::json::array({23, "Low difficulty share", nullptr});
        return response;
    }
    
    // Valid share — record and adjust VARDIFF
    ++accepted_shares_;
    double old_difficulty = required_difficulty;
    hashrate_tracker_.record_mining_share_submission(share_difficulty, true);
    
    double new_difficulty = hashrate_tracker_.get_current_difficulty();
    if (new_difficulty != old_difficulty) {
        send_set_difficulty(new_difficulty);
        LOG_INFO << "VARDIFF adjustment for " << username_ << ": "
                 << old_difficulty << " -> " << new_difficulty;
    }
    
    // Forward the accepted share to MiningInterface for block-level checking.
    // Convert per-chain merged addresses (Base58Check strings) to scriptPubKeys.
    std::map<uint32_t, std::vector<unsigned char>> merged_scripts;
    for (const auto& [chain_id, addr] : merged_addresses_) {
        auto h160 = base58check_to_hash160(addr);
        if (h160.size() == 40) {
            std::vector<unsigned char> script = {0x76, 0xa9, 0x14};
            for (size_t i = 0; i < h160.size(); i += 2)
                script.push_back(static_cast<unsigned char>(
                    std::stoul(h160.substr(i, 2), nullptr, 16)));
            script.push_back(0x88);
            script.push_back(0xac);
            merged_scripts[chain_id] = std::move(script);
        }
    }
    mining_interface_->mining_submit(username_, job_id, extranonce1_, extranonce2, ntime, nonce, "", merged_scripts);
    
    LOG_INFO << "Share accepted from " << username_ << " (diff=" << share_difficulty
             << ", accepted=" << accepted_shares_ << ", stale=" << stale_shares_
             << ", rejected=" << rejected_shares_ << ")";
    
    nlohmann::json response;
    response["id"] = request_id;
    response["result"] = true;
    response["error"] = nullptr;
    
    return response;
}

void StratumSession::send_response(const nlohmann::json& response)
{
    try {
        std::string message = response.dump() + "\n";
        boost::asio::write(socket_, boost::asio::buffer(message));
    } catch (const std::exception& e) {
        LOG_ERROR << "Error sending Stratum response: " << e.what();
    }
}

void StratumSession::send_error(int code, const std::string& message, const nlohmann::json& request_id)
{
    nlohmann::json response;
    response["id"] = request_id;
    response["result"] = nullptr;
    response["error"] = nlohmann::json::array({code, message, nullptr});
    
    send_response(response);
}

void StratumSession::send_set_difficulty(double difficulty)
{
    nlohmann::json notification;
    notification["id"] = nullptr;
    notification["method"] = "mining.set_difficulty";
    notification["params"] = nlohmann::json::array({difficulty});
    
    send_response(notification);
}

// Convert GBT previousblockhash (big-endian display hex) to Stratum prevhash format.
// Stratum prevhash = internal LE bytes with each 4-byte chunk reversed.
static std::string gbt_to_stratum_prevhash(const std::string& gbt_hex)
{
    if (gbt_hex.size() != 64) return gbt_hex;
    // 1. Parse BE hex to bytes
    std::vector<unsigned char> bytes;
    bytes.reserve(32);
    for (size_t i = 0; i < 64; i += 2)
        bytes.push_back(static_cast<unsigned char>(
            std::stoul(gbt_hex.substr(i, 2), nullptr, 16)));
    // 2. Reverse to get internal LE  
    std::reverse(bytes.begin(), bytes.end());
    // 3. Reverse each 4-byte chunk
    for (int i = 0; i < 32; i += 4)
        std::reverse(bytes.begin() + i, bytes.begin() + i + 4);
    // 4. Hex encode
    static const char* HEX = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (unsigned char b : bytes) {
        result += HEX[b >> 4];
        result += HEX[b & 0x0f];
    }
    return result;
}

void StratumSession::send_notify_work()
{
    nlohmann::json notification;
    notification["id"] = nullptr;
    notification["method"] = "mining.notify";

    std::string job_id  = "job_" + std::to_string(job_counter_.fetch_add(1));

    // Defaults (used when no live template is available yet)
    std::string prevhash = "0000000000000000000000000000000000000000000000000000000000000000";
    std::string gbt_prevhash = "0000000000000000000000000000000000000000000000000000000000000000";
    std::string version  = "00000001";
    uint32_t    version_u32 = 1;
    std::string nbits    = "1d00ffff";
    uint32_t    curtime  = static_cast<uint32_t>(std::time(nullptr));
    nlohmann::json merkle_branches = nlohmann::json::array();
    std::vector<std::string> merkle_branches_vec;
    std::string coinb1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff";
    std::string coinb2 = "0000000000f2052a010000001976a914000000000000000000000000000000000000000088ac00000000";

    // Override with live block template data if available
    auto tmpl = mining_interface_->get_current_work_template();
    if (!tmpl.empty() && !tmpl.is_null()) {
        if (tmpl.contains("previousblockhash")) {
            gbt_prevhash = tmpl["previousblockhash"].get<std::string>();
            prevhash = gbt_to_stratum_prevhash(gbt_prevhash);
        }

        if (tmpl.contains("version")) {
            version_u32 = static_cast<uint32_t>(tmpl["version"].get<int>());
            std::ostringstream ss;
            ss << std::hex << std::setw(8) << std::setfill('0')
               << version_u32;
            version = ss.str();
        }

        if (tmpl.contains("bits"))
            nbits = tmpl["bits"].get<std::string>();

        if (tmpl.contains("curtime"))
            curtime = static_cast<uint32_t>(tmpl["curtime"].get<uint64_t>());

        LOG_INFO << "send_notify_work: live template height="
                 << tmpl.value("height", 0) << " prevhash=" << prevhash.substr(0, 16) << "...";
    } else {
        LOG_WARNING << "send_notify_work: no live template, using placeholder work";
    }

    // Encode curtime as 8-hex-char (4-byte big-endian)
    std::ostringstream ntime_ss;
    ntime_ss << std::hex << std::setw(8) << std::setfill('0') << curtime;
    std::string ntime = ntime_ss.str();

    // Merkle branches
    merkle_branches_vec = mining_interface_->get_stratum_merkle_branches();
    for (const auto& h : merkle_branches_vec)
        merkle_branches.push_back(h);

    // Per-connection coinbase: build with ref_hash from this session's extranonce1
    // This ensures the OP_RETURN commitment matches this miner's specific coinbase.
    {
        // Build P2PKH payout script from username (authorized address)
        std::vector<unsigned char> payout_script;
        if (!username_.empty()) {
            auto h160 = base58check_to_hash160(username_);
            if (h160.size() == 40) {
                payout_script = {0x76, 0xa9, 0x14};
                for (size_t i = 0; i < h160.size(); i += 2)
                    payout_script.push_back(static_cast<unsigned char>(
                        std::stoul(h160.substr(i, 2), nullptr, 16)));
                payout_script.push_back(0x88);
                payout_script.push_back(0xac);
            }
        }

        // Build merged address entries
        std::vector<std::pair<uint32_t, std::vector<unsigned char>>> merged_addrs;
        for (const auto& [chain_id, addr] : merged_addresses_) {
            auto h160 = base58check_to_hash160(addr);
            if (h160.size() == 40) {
                std::vector<unsigned char> script = {0x76, 0xa9, 0x14};
                for (size_t i = 0; i < h160.size(); i += 2)
                    script.push_back(static_cast<unsigned char>(
                        std::stoul(h160.substr(i, 2), nullptr, 16)));
                script.push_back(0x88);
                script.push_back(0xac);
                merged_addrs.push_back({chain_id, std::move(script)});
            }
        }

        auto [cb1, cb2] = mining_interface_->build_connection_coinbase(
            extranonce1_, payout_script, merged_addrs);
        if (!cb1.empty()) {
            coinb1 = std::move(cb1);
            coinb2 = std::move(cb2);
        } else {
            // Fallback to global coinbase (no ref_hash callback wired)
            auto [gcb1, gcb2] = mining_interface_->get_coinbase_parts();
            if (!gcb1.empty()) {
                coinb1 = std::move(gcb1);
                coinb2 = std::move(gcb2);
            }
        }
    }

    bool clean_jobs = true;

    // Track this job for stale detection
    if (clean_jobs) {
        active_jobs_.clear();
    }
    // Evict oldest if at capacity
    while (active_jobs_.size() >= MAX_ACTIVE_JOBS) {
        active_jobs_.erase(active_jobs_.begin());
    }
    active_jobs_[job_id] = {prevhash, gbt_prevhash, nbits, curtime, coinb1, coinb2,
                            version_u32, merkle_branches_vec};

    notification["params"] = nlohmann::json::array({
        job_id, prevhash, coinb1, coinb2, merkle_branches,
        version, nbits, ntime, clean_jobs
    });

    send_response(notification);
}

std::string StratumSession::generate_extranonce1()
{
    static std::atomic<uint32_t> extranonce_counter{0};
    uint32_t value = extranonce_counter.fetch_add(1);
    std::stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << value;
    return ss.str();
}

bool MiningInterface::is_valid_address(const std::string& address) const
{
    if (m_payout_manager) {
        auto validator = m_payout_manager->get_address_validator();
        if (validator) {
            auto result = validator->validate_address(address);
            return result.is_valid;
        }
    }
    
    // Basic validation - check length and format
    if (address.length() < 26 || address.length() > 62) {
        return false;
    }
    
    // Check for valid characters (alphanumeric + some special chars)
    for (char c : address) {
        if (!std::isalnum(c) && c != '1' && c != '2' && c != '3') {
            return false;
        }
    }
    
    return true;
}

double MiningInterface::calculate_share_difficulty(const std::string& job_id, const std::string& extranonce1,
                                                   const std::string& extranonce2,
                                                   const std::string& ntime, const std::string& nonce) const
{
    // Build the 80-byte block header, compute scrypt hash, and derive difficulty.
    std::lock_guard<std::mutex> lock(m_work_mutex);

    if (!m_work_valid || m_cached_template.is_null() || m_cached_coinb1.empty())
        return 0.0;

    // Reconstruct coinbase: coinb1 + extranonce1 + extranonce2 + coinb2
    std::string coinbase_hex = m_cached_coinb1 + extranonce1 + extranonce2 + m_cached_coinb2;
    uint256 merkle_root = reconstruct_merkle_root(coinbase_hex, m_cached_merkle_branches);

    // Build 80-byte header (little-endian fields)
    uint32_t version = m_cached_template.value("version", 536870912U);
    uint256 prev_hash;
    prev_hash.SetHex(m_cached_template.value("previousblockhash", std::string(64, '0')));

    std::vector<unsigned char> header;
    header.reserve(80);

    // version (4 bytes LE)
    header.push_back(static_cast<unsigned char>((version      ) & 0xff));
    header.push_back(static_cast<unsigned char>((version >>  8) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 16) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 24) & 0xff));

    // prev_hash (32 bytes, internal byte order)
    header.insert(header.end(), prev_hash.data(), prev_hash.data() + 32);

    // merkle_root (32 bytes)
    header.insert(header.end(), merkle_root.data(), merkle_root.data() + 32);

    // ntime (4 bytes LE — miner sends BE hex, reverse for header)
    auto ntime_bytes = ParseHex(ntime);
    std::reverse(ntime_bytes.begin(), ntime_bytes.end());
    header.insert(header.end(), ntime_bytes.begin(), ntime_bytes.end());

    // nbits (4 bytes LE — GBT gives BE hex, reverse for header)
    std::string bits_hex = m_cached_template.value("bits", std::string("1d00ffff"));
    auto bits_bytes = ParseHex(bits_hex);
    std::reverse(bits_bytes.begin(), bits_bytes.end());
    header.insert(header.end(), bits_bytes.begin(), bits_bytes.end());

    // nonce (4 bytes LE — miner sends BE hex, reverse for header)
    auto nonce_bytes = ParseHex(nonce);
    std::reverse(nonce_bytes.begin(), nonce_bytes.end());
    header.insert(header.end(), nonce_bytes.begin(), nonce_bytes.end());

    if (header.size() != 80)
        return 0.0;

    // Compute scrypt hash
    char pow_hash_bytes[32];
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(header.data()), pow_hash_bytes);

    uint256 pow_hash;
    memcpy(pow_hash.begin(), pow_hash_bytes, 32);

    // difficulty = truediffone / pow_hash_as_double
    // truediffone = 0x00000000FFFF0000... (Litecoin difficulty-1 target)
    // For a 256-bit hash, difficulty = 2^224 / pow_hash (approximate)
    static const double truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0; // 0xFFFF * 2^208
    if (pow_hash.IsNull())
        return 0.0;

    // Convert pow_hash to a double (most significant bytes)
    double hash_val = 0.0;
    for (int i = 31; i >= 0; --i)
        hash_val = hash_val * 256.0 + static_cast<double>(pow_hash.data()[i]);

    if (hash_val == 0.0)
        return 0.0;

    return truediffone / hash_val;
}

double MiningInterface::calculate_share_difficulty(const std::string& coinb1, const std::string& coinb2,
                                                   const std::string& extranonce1, const std::string& extranonce2,
                                                   const std::string& ntime, const std::string& nonce) const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);

    if (!m_work_valid || m_cached_template.is_null())
        return 0.0;

    // Reconstruct coinbase from per-connection parts
    std::string coinbase_hex = coinb1 + extranonce1 + extranonce2 + coinb2;
    uint256 merkle_root = reconstruct_merkle_root(coinbase_hex, m_cached_merkle_branches);

    uint32_t version = m_cached_template.value("version", 536870912U);
    uint256 prev_hash;
    prev_hash.SetHex(m_cached_template.value("previousblockhash", std::string(64, '0')));

    std::vector<unsigned char> header;
    header.reserve(80);

    header.push_back(static_cast<unsigned char>((version      ) & 0xff));
    header.push_back(static_cast<unsigned char>((version >>  8) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 16) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 24) & 0xff));

    header.insert(header.end(), prev_hash.data(), prev_hash.data() + 32);
    header.insert(header.end(), merkle_root.data(), merkle_root.data() + 32);

    // ntime, nbits, nonce: miner/GBT sends as BE hex, header needs LE bytes
    auto ntime_bytes = ParseHex(ntime);
    std::reverse(ntime_bytes.begin(), ntime_bytes.end());
    header.insert(header.end(), ntime_bytes.begin(), ntime_bytes.end());

    std::string bits_hex = m_cached_template.value("bits", std::string("1d00ffff"));
    auto bits_bytes = ParseHex(bits_hex);
    std::reverse(bits_bytes.begin(), bits_bytes.end());
    header.insert(header.end(), bits_bytes.begin(), bits_bytes.end());

    auto nonce_bytes = ParseHex(nonce);
    std::reverse(nonce_bytes.begin(), nonce_bytes.end());
    header.insert(header.end(), nonce_bytes.begin(), nonce_bytes.end());

    if (header.size() != 80)
        return 0.0;

    char pow_hash_bytes[32];
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(header.data()), pow_hash_bytes);

    uint256 pow_hash;
    memcpy(pow_hash.begin(), pow_hash_bytes, 32);

    static const double truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0;
    if (pow_hash.IsNull())
        return 0.0;

    double hash_val = 0.0;
    for (int i = 31; i >= 0; --i)
        hash_val = hash_val * 256.0 + static_cast<double>(pow_hash.data()[i]);

    if (hash_val == 0.0)
        return 0.0;

    return truediffone / hash_val;
}

/*static*/
double MiningInterface::calculate_share_difficulty(
    const std::string& coinb1, const std::string& coinb2,
    const std::string& extranonce1, const std::string& extranonce2,
    const std::string& ntime, const std::string& nonce,
    uint32_t version, const std::string& prevhash_hex,
    const std::string& nbits_hex,
    const std::vector<std::string>& merkle_branches)
{
    // Reconstruct coinbase from per-connection parts
    std::string coinbase_hex = coinb1 + extranonce1 + extranonce2 + coinb2;
    uint256 merkle_root = reconstruct_merkle_root(coinbase_hex, merkle_branches);

    uint256 prev_hash;
    prev_hash.SetHex(prevhash_hex);

    std::vector<unsigned char> header;
    header.reserve(80);

    header.push_back(static_cast<unsigned char>((version      ) & 0xff));
    header.push_back(static_cast<unsigned char>((version >>  8) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 16) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 24) & 0xff));

    header.insert(header.end(), prev_hash.data(), prev_hash.data() + 32);
    header.insert(header.end(), merkle_root.data(), merkle_root.data() + 32);

    // ntime: miner sends as BE hex, header needs LE bytes
    auto ntime_bytes = ParseHex(ntime);
    std::reverse(ntime_bytes.begin(), ntime_bytes.end());
    header.insert(header.end(), ntime_bytes.begin(), ntime_bytes.end());

    // nbits: GBT sends as BE hex, header needs LE bytes
    auto bits_bytes = ParseHex(nbits_hex);
    std::reverse(bits_bytes.begin(), bits_bytes.end());
    header.insert(header.end(), bits_bytes.begin(), bits_bytes.end());

    // nonce: miner sends as BE hex, header needs LE bytes
    auto nonce_bytes = ParseHex(nonce);
    std::reverse(nonce_bytes.begin(), nonce_bytes.end());
    header.insert(header.end(), nonce_bytes.begin(), nonce_bytes.end());

    if (header.size() != 80)
        return 0.0;

    char pow_hash_bytes[32];
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(header.data()), pow_hash_bytes);

    uint256 pow_hash;
    memcpy(pow_hash.begin(), pow_hash_bytes, 32);

    static const double truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0;
    if (pow_hash.IsNull())
        return 0.0;

    double hash_val = 0.0;
    for (int i = 31; i >= 0; --i)
        hash_val = hash_val * 256.0 + static_cast<double>(pow_hash.data()[i]);

    if (hash_val == 0.0)
        return 0.0;

    return truediffone / hash_val;
}
} // namespace core
