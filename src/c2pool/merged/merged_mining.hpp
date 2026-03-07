#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>
#include <cstdint>

#include <core/uint256.hpp>
#include <nlohmann/json.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <jsonrpccxx/client.hpp>
#include <jsonrpccxx/iclientconnector.hpp>

namespace c2pool {
namespace merged {

// ─── Aux chain configuration ─────────────────────────────────────────────────
struct AuxChainConfig
{
    std::string symbol;              // e.g. "DOGE"
    uint32_t    chain_id{0};         // e.g. 98 for Dogecoin
    std::string rpc_host;            // e.g. "127.0.0.1"
    uint16_t    rpc_port{0};         // e.g. 22555
    std::string rpc_userpass;        // "user:pass"
    uint8_t     address_version{0};  // P2PKH version byte
    uint8_t     p2sh_version{0};     // P2SH version byte
    bool        multiaddress{true};  // true = getblocktemplate mode; false = createauxblock
};

// ─── Cached work from an auxiliary chain daemon ───────────────────────────────
struct AuxWork
{
    uint256         block_hash;       // hash of the aux block being mined
    uint256         target;           // PoW target for the aux chain
    uint32_t        chain_id{0};
    int             height{0};
    uint64_t        coinbase_value{0};
    nlohmann::json  block_template;   // full getblocktemplate result (multiaddress mode)
    std::string     prev_block_hash;  // previousblockhash from template
};

// ─── AuxPoW tree ─────────────────────────────────────────────────────────────
// Assigns chain_ids to slots in a binary merkle tree.
// p2pool convention: slot = lcg(chain_id) % size
// Size is smallest power of 2 >= number of chains.

struct AuxPowTree
{
    uint32_t                        size{0};    // tree size (power of 2)
    std::map<uint32_t, uint32_t>    slot_map;   // chain_id → slot_index

    // Build from a set of chain_ids
    static AuxPowTree build(const std::vector<uint32_t>& chain_ids);

    // Compute the merkle root from per-slot hashes (empty slots = uint256{})
    // Returns (root, branch for slot_index, index)
    struct MerkleProof {
        uint256                  root;
        std::vector<uint256>     branch;
        uint32_t                 index{0};
    };
    MerkleProof compute_root(const std::map<uint32_t, uint256>& slot_hashes,
                             uint32_t target_slot) const;
};

// ─── AuxPoW coinbase commitment ──────────────────────────────────────────────
// Returns the bytes to embed in parent coinbase scriptSig:
//   magic(4) + mm_root(32) + tree_size(4) + nonce(4) = 44 bytes
std::vector<uint8_t> build_auxpow_commitment(const uint256& mm_root,
                                              uint32_t tree_size,
                                              uint32_t nonce = 0);

// ─── AuxPoW proof serialization ──────────────────────────────────────────────
// Builds the auxpow structure that gets prepended to merged block txs:
//   parent_coinbase_tx + parent_block_hash + parent_coinbase_merkle_link
//   + aux_merkle_branch + aux_merkle_index + parent_block_header
std::string build_auxpow_proof(
    const std::string& parent_coinbase_hex,    // stripped (no witness) parent coinbase
    const uint256& parent_block_hash,
    const std::vector<std::string>& parent_merkle_branch,   // coinbase→parent merkle root
    uint32_t parent_merkle_index,
    const std::vector<uint256>& aux_merkle_branch,           // aux hash→mm root
    uint32_t aux_merkle_index,
    const std::string& parent_header_hex);     // 80-byte parent block header

// ─── RPC client for one auxiliary chain daemon ───────────────────────────────
class AuxChainRPC : public jsonrpccxx::IClientConnector
{
public:
    AuxChainRPC(boost::asio::io_context& ioc, const AuxChainConfig& config);
    ~AuxChainRPC();

    bool connect();

    // Multiaddress mode: getblocktemplate with auxpow capabilities
    AuxWork get_work_template();

    // Single-address fallback: createauxblock
    AuxWork create_aux_block(const std::string& address);

    // Submit a complete block (multiaddress)
    bool submit_block(const std::string& block_hex);

    // Submit auxpow proof (single-address)
    bool submit_aux_block(const uint256& block_hash, const std::string& auxpow_hex);

    // Tip detection
    std::string get_best_block_hash();

    const AuxChainConfig& config() const { return m_config; }

private:
    std::string Send(const std::string& request) override;
    nlohmann::json call(const std::string& method,
                        const nlohmann::json& params = nlohmann::json::array());

    AuxChainConfig m_config;
    boost::asio::io_context& m_ioc;
    boost::beast::tcp_stream m_stream;
    boost::asio::ip::tcp::resolver m_resolver;
    boost::beast::http::request<boost::beast::http::string_body> m_http_request;
    jsonrpccxx::JsonRpcClient m_client;
    bool m_connected{false};
};

// ─── Integrated Merged Mining Manager ────────────────────────────────────────
// Replaces the standalone mm-adapter Python process.
// Polls aux chain daemons, builds commitments for parent coinbase,
// and submits merged blocks when parent PoW meets aux target.

class MergedMiningManager
{
public:
    explicit MergedMiningManager(boost::asio::io_context& ioc);
    ~MergedMiningManager();

    // Register an auxiliary chain
    void add_chain(const AuxChainConfig& config);

    // Start polling aux daemons for new work (call after add_chain)
    void start();
    void stop();

    // Called by refresh_work() — returns 44-byte commitment to embed in parent coinbase scriptSig
    // Also caches current aux work so submit_merged_blocks() can use it.
    std::vector<uint8_t> get_auxpow_commitment();

    // Called after a parent block is found / share meets aux target.
    // Builds and submits merged blocks for all aux chains whose target is met.
    // parent_header_hex: 80 bytes of the parent block header
    // parent_coinbase_hex: stripped coinbase tx hex (no witness)
    // parent_merkle_branch: coinbase→merkle_root branch
    // parent_hash: hash of the parent block
    void try_submit_merged_blocks(
        const std::string& parent_header_hex,
        const std::string& parent_coinbase_hex,
        const std::vector<std::string>& parent_merkle_branch,
        uint32_t parent_merkle_index,
        const uint256& parent_hash);

    // Current aux work per chain_id
    std::map<uint32_t, AuxWork> get_current_work() const;

    // Check if any aux chains are configured
    bool has_chains() const { return !m_chains.empty(); }

    // Number of registered chains
    size_t chain_count() const { return m_chains.size(); }

private:
    void poll_loop();
    void refresh_aux_work();

    boost::asio::io_context& m_ioc;
    boost::asio::steady_timer m_poll_timer;
    std::atomic<bool> m_running{false};

    // Registered aux chains
    struct ChainState {
        AuxChainConfig                   config;
        std::unique_ptr<AuxChainRPC>     rpc;
        AuxWork                          current_work;
        std::string                      last_tip;   // for change detection
    };
    std::vector<ChainState> m_chains;

    // Current AuxPoW tree (rebuilt when chains change)
    AuxPowTree m_tree;

    // Cached commitment
    std::vector<uint8_t> m_cached_commitment;

    mutable std::mutex m_mutex;
};

} // namespace merged
} // namespace c2pool
