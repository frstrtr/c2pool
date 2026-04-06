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
#include <core/netaddress.hpp>
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
    std::string aux_payout_address;  // payout address for createauxblock (non-multiaddress mode)

    // P2P broadcaster (optional — for fast block relay to merged daemon)
    uint16_t    p2p_port{0};         // 0 = disabled; e.g. 22556 for DOGE
    std::string p2p_address;         // defaults to rpc_host if empty
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

// ─── Abstract interface for auxiliary chain backend ──────────────────────────
// Supports both RPC-based (external daemon) and embedded node implementations.
class IAuxChainBackend
{
public:
    virtual ~IAuxChainBackend() = default;
    virtual bool connect() = 0;
    virtual AuxWork get_work_template() = 0;
    virtual AuxWork create_aux_block(const std::string& address) = 0;
    virtual bool submit_block(const std::string& block_hex) = 0;
    virtual bool submit_aux_block(const uint256& block_hash, const std::string& auxpow_hex) = 0;
    virtual std::string get_block_hex(const std::string& block_hash) = 0;
    virtual std::string get_best_block_hash() = 0;
    virtual std::vector<NetService> getpeerinfo() = 0;
    virtual const AuxChainConfig& config() const = 0;
};

// ─── RPC client for one auxiliary chain daemon ───────────────────────────────
class AuxChainRPC : public IAuxChainBackend, public jsonrpccxx::IClientConnector
{
public:
    AuxChainRPC(boost::asio::io_context& ioc, const AuxChainConfig& config);
    ~AuxChainRPC();

    bool connect() override;
    AuxWork get_work_template() override;
    AuxWork create_aux_block(const std::string& address) override;
    bool submit_block(const std::string& block_hex) override;
    bool submit_aux_block(const uint256& block_hash, const std::string& auxpow_hex) override;
    std::string get_block_hex(const std::string& block_hash) override;
    std::string get_best_block_hash() override;
    std::vector<NetService> getpeerinfo() override;
    const AuxChainConfig& config() const override { return m_config; }

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

// ─── Discovered merged block record ──────────────────────────────────────────
struct DiscoveredMergedBlock
{
    uint32_t    chain_id{0};
    std::string symbol;
    int         height{0};        // aux chain height
    std::string block_hash;       // aux block hash
    std::string parent_hash;      // parent (LTC) block hash
    int64_t     timestamp{0};     // unix epoch seconds
    bool        accepted{true};   // RPC returned success
    uint64_t    coinbase_value{0}; // aux block reward in satoshis
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

    // Register an auxiliary chain (creates AuxChainRPC internally)
    void add_chain(const AuxChainConfig& config);

    // Register with a pre-built backend (for embedded DOGE node)
    void add_chain(const AuxChainConfig& config, std::unique_ptr<IAuxChainBackend> backend);

    // Set a fallback backend for a chain — auto-switch when primary fails
    void set_fallback_backend(uint32_t chain_id, std::unique_ptr<IAuxChainBackend> fallback);

    // Start polling aux daemons for new work (call after add_chain)
    void start();
    void stop();

    // Called by refresh_work() — returns 44-byte commitment to embed in parent coinbase scriptSig
    // Also caches current aux work so submit_merged_blocks() can use it.
    std::vector<uint8_t> get_auxpow_commitment();

    // Override the cached block hash for a chain and return the fresh auxpow commitment.
    // Used after build_merged_header_info() computes the PPLNS-derived DOGE header —
    // the block hash from that header must replace the daemon's createauxblock hash
    // so mm_data is consistent with merged_coinbase_info. Returns the rebuilt commitment
    // atomically to avoid race with poll_loop overwriting the hash.
    std::vector<uint8_t> override_chain_block_hash(uint32_t chain_id, const uint256& pplns_block_hash);

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

    // V36: Build merged block header info for share_info.merged_coinbase_info.
    // Returns (80-byte header, coinbase_merkle_link_branches) per chain.
    // Builds the PPLNS coinbase, computes merkle root, assembles header.
    struct MergedHeaderInfo {
        uint32_t chain_id{0};
        uint64_t coinbase_value{0};
        uint32_t block_height{0};
        std::vector<unsigned char> block_header;  // 80 bytes
        std::vector<uint256> coinbase_merkle_branches;
        std::vector<unsigned char> coinbase_script;  // scriptSig from the merged coinbase
        std::string coinbase_hex;  // full coinbase TX hex (for freezing at submission time)
    };
    std::vector<MergedHeaderInfo> build_merged_header_info() const;

    // Atomic: build header info + compute matching auxpow commitment in one operation.
    // Eliminates race where poll_loop updates current_work between header build and
    // commitment generation. Returns (header_infos, fresh_mm_commitment).
    std::pair<std::vector<MergedHeaderInfo>, std::vector<uint8_t>>
    build_merged_header_info_with_commitment();

    // Check if any aux chains are configured
    bool has_chains() const { return !m_chains.empty(); }

    // Number of registered chains
    size_t chain_count() const { return m_chains.size(); }

    // Get RPC client for a chain (for wiring broadcaster getpeerinfo)
    IAuxChainBackend* get_chain_rpc(uint32_t chain_id);

    // ─── Block tracking ──────────────────────────────────────────────────
    // Thread-safe accessors for discovered merged blocks.
    std::vector<DiscoveredMergedBlock> get_discovered_blocks() const;
    std::vector<DiscoveredMergedBlock> get_recent_blocks(size_t limit = 20) const;
    uint64_t get_total_blocks() const;
    uint64_t get_chain_block_count(uint32_t chain_id) const;
    // Add externally discovered block (e.g. from peer share scan)
    void add_discovered_block(const DiscoveredMergedBlock& blk);

    // Per-chain config snapshots (for REST)
    struct ChainInfo {
        std::string symbol;
        uint32_t    chain_id{0};
        std::string rpc_host;
        uint16_t    rpc_port{0};
        bool        multiaddress{false};
        uint16_t    p2p_port{0};
        int         current_height{0};
        std::string current_tip;
        uint64_t    coinbase_value{0};  // satoshis
        double      difficulty{0.0};    // from target
        uint256     target;             // current aux chain target (for peer block detection)
        std::string block_hash;         // current aux block hash hex
        int64_t     last_update_age_s{0}; // seconds since last successful work refresh
    };
    std::vector<ChainInfo> get_chain_infos() const;

    // ─── Multiaddress payout provider ────────────────────────────────────
    // Callback: given (chain_id, coinbase_value) returns sorted payout list
    //   vector<(scriptPubKey, satoshis)>.
    // Set by the integration layer that owns the ShareTracker.
    using PayoutProvider = std::function<
        std::vector<std::pair<std::vector<unsigned char>, uint64_t>>(
            uint32_t chain_id, uint64_t coinbase_value)>;

    void set_payout_provider(PayoutProvider provider);
    /// Get merged payouts for a chain (delegates to payout_provider)
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>>
    get_payouts(uint32_t chain_id, uint64_t coinbase_value) const
    {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        if (m_payout_provider) return m_payout_provider(chain_id, coinbase_value);
        return {};
    }

    /// Callback to get current THE state root for sharechain anchoring in merged coinbases.
    using StateRootProvider = std::function<uint256()>;
    void set_state_root_provider(StateRootProvider provider);

    /// Callback for P2P block relay: (chain_id, block_hex) after successful RPC submission.
    using BlockRelayFn = std::function<void(uint32_t chain_id, const std::string& block_hex)>;
    void set_block_relay_fn(BlockRelayFn fn);

    /// Callback when a merged block is found: (symbol, height, block_hash, accepted)
    /// Used by MiningInterface to record in FoundBlock list for unified verification.
    using MergedBlockFoundFn = std::function<void(const std::string& symbol, int height,
                                                   const std::string& block_hash, bool accepted)>;
    void set_on_merged_block_found(MergedBlockFoundFn fn) { m_on_merged_block_found = std::move(fn); }

    /// Callback when aux work changes (new block on any merged chain).
    /// Used to trigger stratum work refresh so miners get fresh MM commitments.
    using WorkChangedFn = std::function<void()>;
    void set_on_work_changed(WorkChangedFn fn) { m_on_work_changed = std::move(fn); }

private:
    void poll_loop();
    void refresh_aux_work();

public:
    // ─── Shared helpers (used by both build_multiaddress_block and build_merged_header_info) ───

    // Build canonical merged coinbase TX hex from PPLNS payouts.
    // Matches p2pool's build_canonical_merged_coinbase output ordering.
    static std::string build_pplns_coinbase_hex(
        int height,
        const std::vector<std::pair<std::vector<unsigned char>, uint64_t>>& payouts,
        const uint256& the_state_root);

    // Compute merkle root from a list of tx hashes (first = coinbase).
    static uint256 compute_tx_merkle_root(const std::vector<uint256>& tx_hashes);

    // Compute merkle link (proof branches) from leaf at index to root.
    static std::vector<uint256> compute_merkle_link(
        const std::vector<uint256>& tx_hashes, size_t leaf_index);

    // Collect tx hashes from block template JSON + coinbase hash.
    static std::vector<uint256> collect_tx_hashes(
        const uint256& coinbase_hash, const nlohmann::json& tmpl);

    // Build a complete aux block in multiaddress mode from getblocktemplate
    // result, PPLNS payout outputs, AuxPoW proof hex, and THE state root
    // for sharechain anchoring (embedded in coinbase scriptSig).
    static std::string build_multiaddress_block(
        const nlohmann::json& block_template,
        const std::vector<std::pair<std::vector<unsigned char>, uint64_t>>& payouts,
        const std::string& auxpow_hex,
        const uint256& the_state_root = uint256());
private:

    boost::asio::io_context& m_ioc;
    boost::asio::steady_timer m_poll_timer;
    std::atomic<bool> m_running{false};

    // Dedicated thread for RPC calls — prevents blocking the ioc event loop.
    // refresh_aux_work() calls createauxblock/getblocktemplate which are ~1s
    // round-trip RPC calls; running them on ioc blocks stratum notifications.
    boost::asio::thread_pool m_rpc_pool{1};
    std::atomic<bool> m_refresh_in_progress{false};

    // Registered aux chains
    struct ChainState {
        AuxChainConfig                       config;
        std::unique_ptr<IAuxChainBackend>    rpc;       // primary backend (RPC or embedded)
        std::unique_ptr<IAuxChainBackend>    fallback;  // fallback backend (embedded if primary is RPC)
        AuxWork                              current_work;
        std::string                          last_tip;
        bool                                 using_fallback{false};
        int64_t                              last_update_time{0}; // monotonic seconds
        // Frozen DOGE block data from build_merged_header_info_with_commitment.
        // Contains the pre-built DOGE coinbase hex and template snapshot that
        // match the block hash committed in the LTC parent's mm_data.
        // try_submit_merged_blocks uses these instead of rebuilding.
        std::string frozen_coinbase_hex;   // pre-built PPLNS coinbase from ref_hash_fn time
        nlohmann::json frozen_template;    // template snapshot from ref_hash_fn time
        uint256 frozen_block_hash;         // block hash at commit time (for AuxPoW proof)

        // History of frozen snapshots keyed by block hash.
        // Solves the stale-commitment race: the LTC coinbase contains an MM root
        // from freeze time T1, but by submission time T2 a newer freeze may have
        // overwritten the single frozen_* fields.  The history lets us look up
        // the exact template/coinbase that matches the committed root.
        struct FrozenSnapshot {
            nlohmann::json tmpl;
            std::string    coinbase_hex;
            int64_t        timestamp;   // monotonic seconds for expiration
        };
        std::map<uint256, FrozenSnapshot> frozen_history;  // block_hash → snapshot
        // Keep enough frozen snapshots to cover FROZEN_EXPIRY_SEC (300s).
        // Each new share creates a snapshot (~3s on testnet, ~15s on mainnet).
        // p2pool uses RPC submitauxblock which handles stale work natively —
        // embedded mode needs this history because there's no daemon RPC.
        static constexpr size_t MAX_FROZEN_HISTORY = 100;
        static constexpr int64_t FROZEN_EXPIRY_SEC = 300;  // 5 minutes
    };
    std::vector<ChainState> m_chains;

    // Submit via submitauxblock and relay the accepted block via P2P
    void submit_aux_and_relay(ChainState& chain, const std::string& auxpow,
                              const std::string& parent_hash_hex = "");

    // Current AuxPoW tree (rebuilt when chains change)
    AuxPowTree m_tree;

    // Cached commitment
    std::vector<uint8_t> m_cached_commitment;

    // Per-chain payout provider (set by integration layer)
    PayoutProvider m_payout_provider;

    // THE state root provider for sharechain anchoring
    StateRootProvider m_state_root_provider;

    // P2P block relay callback (set by integration layer)
    BlockRelayFn m_block_relay_fn;
    MergedBlockFoundFn m_on_merged_block_found;
    WorkChangedFn m_on_work_changed;

    // Discovered merged blocks history
    std::vector<DiscoveredMergedBlock> m_discovered_blocks;
    std::map<uint32_t, uint64_t>       m_blocks_per_chain;

    // Helper: record a discovered block (caller must hold m_mutex)
    void record_discovered_block(const ChainState& chain, bool accepted,
                                 const std::string& parent_hash = "");

    // recursive_mutex: build_merged_header_info_with_commitment called from
    // ASIO io_context can be triggered while MM timer holds the mutex on
    // another thread → cross-thread deadlock with plain std::mutex.
    mutable std::recursive_mutex m_mutex;
};

} // namespace merged
} // namespace c2pool
