// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <functional>
#include <optional>
#include <cstdint>

#include <core/uint256.hpp>
#include <core/netaddress.hpp>
#include <c2pool/merged/payout_source.hpp>
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

    // RPC client (AuxChainRPC) limits. A daemon that accepts the connection
    // and never answers costs at most connect + rpc timeout per call, and the
    // reconnect after a failure backs off (1 s doubling, at most
    // rpc_reconnect_max_ms) so a dead daemon is probed, not hammered.
    uint32_t    rpc_connect_timeout_ms{3'000};
    uint32_t    rpc_timeout_ms{10'000};
    uint32_t    rpc_reconnect_max_ms{10'000};
    // submitblock goes over its own connection, never waits for the polls'
    // backoff, and gets this long for the daemon's answer (block validation).
    uint32_t    rpc_submit_timeout_ms{15'000};

    // Largest stripped block (no witness; header with AuxPoW included) the
    // chain's CheckBlock accepts; 0 = the chain id's own (aux_block_limit).
    uint32_t    max_block_bytes{0};

    // Checks the createauxblock address against the network the daemon says
    // it is on (getblockchaininfo "chain": "main", "test", "regtest", ...):
    // "" when it is the network's (or the network is not known), else why
    // not. Checked once, at the first answer; a failure keeps the chain out.
    std::function<std::string(const std::string& chain_name)> check_payout_address;
};

// ─── What a daemon answered to submitblock ───────────────────────────────────
// BIP22 as Dogecoin Core 1.14 (and its forks: PepeCoin Core) implements it in
// rpc/mining.cpp submitblock: a null result is a block connected to the best
// chain; "duplicate" a block the daemon already has fully validated;
// "inconclusive" a block stored but not connected (a side branch: it lost the
// race, or may still win it); "duplicate-inconclusive" the same for a block
// whose header was known; "duplicate-invalid" and any other string a
// rejection with that reason; JSON-RPC error -22 "Block decode failed" an
// error. No answer (no connection, a timeout, a backend that threw) or any
// other JSON-RPC error (-28 warming up, ...) is unknown: the daemon may have
// the block, and the P2P relay sent it too. Only accepted and duplicate are a
// win at submit time; an inconclusive or unknown block is decided by the
// chain.
struct SubmitVerdict
{
    enum class Kind { accepted, duplicate, inconclusive, rejected, error, unknown };
    Kind        kind{Kind::error};
    std::string reason;   // the daemon's string, or the error

    bool accepted() const { return kind == Kind::accepted || kind == Kind::duplicate; }
    // The block may be on the chain (accepted, duplicate, inconclusive, or no
    // answer): the found-block check follows the chain. Not for a block the
    // daemon refused.
    bool held() const { return accepted() || kind == Kind::inconclusive || kind == Kind::unknown; }
    // "accepted", "duplicate", "inconclusive", "rejected: <reason>",
    // "error: <reason>", "unknown: <reason>".
    std::string label() const;

    static SubmitVerdict of(Kind k, std::string why = {}) { return {k, std::move(why)}; }
};

/// Maps a submitblock result (the JSON-RPC "result") to a verdict, as above.
SubmitVerdict classify_submitblock_result(const nlohmann::json& result);

/// CheckBlock's size limits of the chain with this AuxPoW chain id, on the
/// block as serialized with the AuxPoW in its header: the stripped size (no
/// witness, SERIALIZE_TRANSACTION_NO_WITNESS) at most max_stripped, and, on a
/// segwit chain, the weight (stripped * 3 + full) at most max_weight
/// (Namecoin/Bellscoin/Junkcoin: stripped * 4 <= 4,000,000 and weight <=
/// 4,000,000; the Dogecoin family: stripped <= MAX_BLOCK_BASE_SIZE).
/// {0, 0}: not known (no guard).
struct AuxBlockLimit {
    uint32_t max_stripped{0};
    uint32_t max_weight{0};   // 0: no weight rule
    bool known() const { return max_stripped != 0; }
    // "" when a block of these sizes passes, else why not.
    std::string check(uint64_t stripped_bytes, uint64_t full_bytes) const;
};
AuxBlockLimit aux_block_limit(uint32_t chain_id);

/// The config's max_block_bytes (as max_stripped), else aux_block_limit(chain_id).
inline AuxBlockLimit aux_block_limit(const AuxChainConfig& cfg)
{
    AuxBlockLimit l = aux_block_limit(cfg.chain_id);
    if (cfg.max_block_bytes)
        l.max_stripped = cfg.max_block_bytes;
    return l;
}

/// Size of a raw transaction without its witness (BIP144 marker, flag and
/// witness stacks removed); the full size when it has none; nullopt when it
/// does not parse.
std::optional<size_t> tx_stripped_size(const std::vector<uint8_t>& tx);

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
// Assigns chain_ids to slots in a binary merkle tree: the slot the aux
// daemons expect, CAuxPow::getExpectedIndex(nonce 0, chain_id, log2(size)).
// Size is smallest power of 2 >= number of chains.

struct AuxPowTree
{
    uint32_t                        size{0};    // tree size (power of 2)
    std::map<uint32_t, uint32_t>    slot_map;   // chain_id → slot_index

    // The tallest tree built. CAuxPow::check allows a branch of 30, but the
    // tree is materialized leaf by leaf (compute_root): 2^30 leaves would be
    // 32 GB. Every chain set in the merged chain table fits in height 5; ids
    // that collide up to this height are a configuration error.
    static constexpr unsigned kMaxHeight = 12;   // 4096 slots

    // Build from a set of chain_ids. size 0 (no tree) when the ids cannot be
    // given distinct slots within kMaxHeight.
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

// ─── Aux block size budget ───────────────────────────────────────────────────
// dogecoind refuses a block whose serialization, AuxPoW in the header
// included, exceeds MAX_BLOCK_BASE_SIZE = 1,000,000 bytes (CheckBlock
// bad-blk-length, validation.cpp:2972; primitives/block.h serializes the
// auxpow with the header). The AuxPoW carries the whole parent (LTC) coinbase,
// so with PPLNS coinbases of many outputs on both chains a template filled to
// 1 MB of transactions cannot be a valid block.
inline constexpr uint32_t kAuxMaxBlockBytes = 1'000'000;
inline constexpr uint32_t kAuxBlockSizeMargin = 1'000;
// Before the first parent coinbase is known: room for one of ~4,000 outputs.
inline constexpr uint32_t kUnknownParentCoinbaseBytes = 200'000;

/// Bytes of an aux block that are not its transactions: header (80), the
/// AuxPoW as build_auxpow_proof writes it (parent coinbase, parent hash 32,
/// coinbase branch, its index 4, chain branch, its index 4, parent header 80),
/// the tx count (at most 9) and the aux coinbase, plus kAuxBlockSizeMargin.
/// A zero parent coinbase size means unknown (kUnknownParentCoinbaseBytes);
/// a zero aux coinbase size means unknown (taken as large as the parent's).
inline uint32_t aux_block_reserve_bytes(uint32_t parent_coinbase_bytes, uint32_t parent_branch_len,
                                        uint32_t aux_branch_len, uint32_t aux_coinbase_bytes)
{
    const uint64_t parent_cb = parent_coinbase_bytes ? parent_coinbase_bytes : kUnknownParentCoinbaseBytes;
    const uint64_t aux_cb = aux_coinbase_bytes ? aux_coinbase_bytes : parent_cb;
    const uint64_t auxpow = parent_cb + 32 + 9 + 32ull * parent_branch_len + 4
                          + 9 + 32ull * aux_branch_len + 4 + 80;
    const uint64_t total = 80 + auxpow + 9 + aux_cb + kAuxBlockSizeMargin;
    return static_cast<uint32_t>(std::min<uint64_t>(total, kAuxMaxBlockBytes));
}

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
    // Bytes of the next aux block that go to the header, AuxPoW and coinbase
    // (aux_block_reserve_bytes): a backend that builds its own template keeps
    // its transactions within the rest. A daemon's template cannot be told.
    virtual void set_block_size_reserve(uint32_t /*bytes*/) {}
    // Legacy sigops of the next aux block's coinbase (block_sigop_reserve):
    // a backend that builds its own template keeps the block's sigops within
    // the chain's limit with this reserved.
    virtual void set_block_sigop_reserve(uint32_t /*sigops*/) {}

    // submit_block with the daemon's answer kept (SubmitVerdict). A backend
    // that only knows yes/no: accepted or rejected.
    virtual SubmitVerdict submit_block_verdict(const std::string& block_hex)
    {
        return submit_block(block_hex) ? SubmitVerdict::of(SubmitVerdict::Kind::accepted)
                                       : SubmitVerdict::of(SubmitVerdict::Kind::rejected, "rejected");
    }
    // submit_block_verdict may run at the same time as any other call (its
    // own connection): a find never waits for a poll. Otherwise the manager
    // serializes the backend's calls.
    virtual bool submit_independent() const { return false; }

    // The backend's best chain, for found-block verdicts (aux_backend_verdict):
    // its height, the block at a height, a known block's height. nullopt when
    // the backend cannot tell (not supported, or no answer).
    virtual std::optional<uint32_t> get_block_count() { return std::nullopt; }
    virtual std::optional<uint256> get_block_hash_at(uint32_t /*height*/) { return std::nullopt; }
    virtual std::optional<uint32_t> get_block_height(const uint256& /*hash*/) { return std::nullopt; }
    // The daemon's network (getblockchaininfo "chain"); nullopt when unknown.
    virtual std::optional<std::string> get_chain_name() { return std::nullopt; }

    // Make a call blocked on the network return now, and every later one
    // fail at once (shutdown).
    virtual void cancel_io() {}
};

// ─── RPC client for one auxiliary chain daemon ───────────────────────────────
// Two HTTP keep-alive connections: one for the polls and lookups (calls from
// several threads are serialized on it), one for submitblock only, so a find
// is never queued behind a slow poll. Every network step has a deadline
// (AuxChainConfig::rpc_connect_timeout_ms, rpc_timeout_ms,
// rpc_submit_timeout_ms), run on that connection's own io_context by the
// calling thread. A connection the daemon closed (restart, or its idle
// timeout: bitcoind's -rpcservertimeout, 30 s) is replaced on the next call,
// which is sent again once on the fresh connection. After a failed connect or
// a timeout the poll connection waits before connecting again (1 s, doubling,
// at most rpc_reconnect_max_ms); a submit always tries.
class AuxChainRPC : public IAuxChainBackend, public jsonrpccxx::IClientConnector
{
public:
    AuxChainRPC(boost::asio::io_context& ioc, const AuxChainConfig& config);
    ~AuxChainRPC();

    bool connect() override;
    AuxWork get_work_template() override;
    AuxWork create_aux_block(const std::string& address) override;
    bool submit_block(const std::string& block_hex) override;
    SubmitVerdict submit_block_verdict(const std::string& block_hex) override;
    bool submit_independent() const override { return true; }
    bool submit_aux_block(const uint256& block_hash, const std::string& auxpow_hex) override;
    std::string get_block_hex(const std::string& block_hash) override;
    std::string get_best_block_hash() override;
    std::vector<NetService> getpeerinfo() override;
    std::optional<uint32_t> get_block_count() override;
    std::optional<uint256> get_block_hash_at(uint32_t height) override;
    std::optional<uint32_t> get_block_height(const uint256& hash) override;
    std::optional<std::string> get_chain_name() override;
    void cancel_io() override;
    const AuxChainConfig& config() const override { return m_config; }

    bool connected() const;
    // Poll connections opened so far (the first included).
    uint64_t connects() const { return m_connects.load(std::memory_order_relaxed); }

    // One HTTP connection and the io_context its steps run on.
    struct Conn {
        boost::asio::io_context io;
        boost::asio::ip::tcp::resolver resolver{io};
        std::unique_ptr<boost::beast::tcp_stream> stream;
        boost::beast::http::request<boost::beast::http::string_body> request;
        bool used{false};   // has answered a request (keep-alive)
    };

private:
    std::string Send(const std::string& request) override;
    nlohmann::json call(const std::string& method,
                        const nlohmann::json& params = nlohmann::json::array());
    // With the connection's mutex held.
    void open(Conn& c, const char* what);
    void close(Conn& c);
    void note_failure_locked();
    std::string exchange(Conn& c, const std::string& request, std::chrono::milliseconds timeout,
                         bool& stale_connection);

    AuxChainConfig m_config;
    Conn m_poll;                     // under m_io_mutex
    Conn m_submit;                   // under m_submit_mutex
    jsonrpccxx::JsonRpcClient m_client;
    mutable std::mutex m_io_mutex;
    std::mutex m_submit_mutex;
    std::atomic<bool> m_connected{false};   // the poll connection
    std::chrono::steady_clock::time_point m_next_connect{};
    std::chrono::milliseconds m_backoff{0};
    std::atomic<bool> m_cancelled{false};
    std::atomic<uint64_t> m_connects{0};
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
    bool        accepted{true};   // the daemon took it: submitblock null or "duplicate"
    std::string verdict;          // SubmitVerdict::label() ("accepted", "inconclusive", "rejected: ...")
    uint64_t    coinbase_value{0}; // aux block reward in satoshis
    bool        is_local{false};  // true = our own submission, false = detected from peer share
    uint32_t    parent_height{0}; // parent (LTC) block height (absheight)
    std::string miner;            // miner address who found the block
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

    // The parent (LTC) coinbase the next shares carry: its size without
    // witness (bytes) and its merkle branch length. Set by the web server on
    // every coinbase it builds; sizes the aux blocks' AuxPoW for the template
    // budget (aux_block_reserve_bytes).
    void set_parent_coinbase_shape(uint32_t coinbase_bytes, uint32_t branch_len)
    {
        m_parent_coinbase_bytes.store(coinbase_bytes, std::memory_order_relaxed);
        m_parent_branch_len.store(branch_len, std::memory_order_relaxed);
    }
    // The reserve the chain's next template leaves (see aux_block_reserve_bytes).
    uint32_t block_size_reserve(uint32_t chain_id) const;

    // Aux blocks refused at assembly, by "<symbol>:<code>": oversize,
    // no_snapshot (no frozen block for the committed hash), root_mismatch and,
    // with several chains, no_commitment (the coinbase root was not built
    // here or has expired) and not_committed (no block of this chain in it).
    nlohmann::json get_block_refusals_json() const;

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
        // The sharechain best share the coinbase's PPLNS payouts were split
        // at (note_payout_basis); null when they do not come from the
        // sharechain. Only a job whose LTC share has this prev share may
        // carry the block: a V36 peer re-derives the payouts from the share's
        // previous_share_hash.
        uint256 payout_basis;
    };

    // ─── Cached DOGE block data (p2pool: merged_work variable) ──────────
    // Built ONCE per work cycle in refresh_aux_work() / rebuild_cached_blocks().
    // Stratum sessions read from this cache — never rebuild per session.

    // Signal that PPLNS weights changed (new best_share).  The next
    // refresh_aux_work() cycle will rebuild the DOGE block with fresh payouts.
    void mark_pplns_dirty() { m_pplns_dirty.store(true, std::memory_order_relaxed); }
    bool is_pplns_dirty() const { return m_pplns_dirty.load(std::memory_order_relaxed); }

    // Lock-free read of cached header_infos + commitment.
    // Called by build_connection_coinbase() instead of the old per-session rebuild.
    std::pair<std::vector<MergedHeaderInfo>, std::vector<uint8_t>>
    get_cached_header_infos_and_commitment() const;

    // Force an immediate rebuild of cached DOGE blocks (PPLNS + coinbase +
    // merkle + header + freeze + commitment).  Called from refresh_work()
    // when PPLNS changed so the commitment is fresh before notify_all().
    // Runs the expensive payout_fn outside m_mutex to avoid deadlock.
    // Returns true when the commitment or the header infos changed (what
    // the miners' work carries), false when the rebuild left them as they were.
    bool rebuild_cached_blocks();

    // Check if any aux chains are configured
    bool has_chains() const { return !m_chains.empty(); }

    // Number of registered chains
    size_t chain_count() const { return m_chains.size(); }

    // True if a chain with this chain_id is registered (embedded OR rpc).
    // NOTE: distinct from get_chain_rpc(), which returns only the RPC
    // fallback backend (null for embedded-primary chains with no fallback).
    bool has_chain(uint32_t chain_id) const;

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
    // Update coinbase_value on a discovered block (after fetching full block from P2P)
    void update_block_coinbase(const std::string& block_hash, uint64_t coinbase_value);

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
        uint8_t     address_version{0}; // P2PKH version byte (from aux chain config)
        uint8_t     p2sh_version{0};    // P2SH version byte (from aux chain config)
        double      difficulty{0.0};    // from target
        uint256     target;             // current aux chain target (for peer block detection)
        std::string block_hash;         // current aux block hash hex
        int64_t     last_update_age_s{0}; // seconds since last successful work refresh
        bool        responsive{true};   // answered the last poll (else out of the commitment)
        std::string unresponsive_why;   // the last failure, when not responsive
        std::string config_error;       // set: the chain is disabled (chain id / address)
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

    /// Where a payout provider gets the payouts while the sharechain
    /// tracker's lock is busy (payout_source.hpp); its counters are in
    /// get_rebuild_stats_json()["payout_source"].
    std::shared_ptr<MergedPayoutSource> payout_source() const { return m_payout_source; }
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

    /// Callback when a merged block is found:
    /// (symbol, height, block_hash, accepted, coinbase_value = aux block reward in satoshis,
    ///  difficulty = the aux chain's network difficulty from the job target; 0 = unknown)
    /// Used by MiningInterface to record in FoundBlock list for unified verification.
    /// accepted: the daemon holds the block (SubmitVerdict::held: accepted,
    /// duplicate or inconclusive), so its chain decides it; false for a
    /// rejection or an error. Called on the thread that called
    /// try_submit_merged_blocks.
    using MergedBlockFoundFn = std::function<void(const std::string& symbol, int height,
                                                   const std::string& block_hash, bool accepted,
                                                   uint64_t coinbase_value, double difficulty)>;
    void set_on_merged_block_found(MergedBlockFoundFn fn) { m_on_merged_block_found = std::move(fn); }

    /// Callback when aux work changes (new block on any merged chain).
    /// Used to trigger stratum work refresh so miners get fresh MM commitments.
    using WorkChangedFn = std::function<void()>;
    void set_on_work_changed(WorkChangedFn fn) { m_on_work_changed = std::move(fn); }

    /// One poll of the aux chains (called every second by poll_loop on the
    /// RPC thread; public so a test can drive one). A chain's template is
    /// fetched when its tip changed, and again on every poll while the last
    /// one came back degraded (core::coin::kTemplateDegradedKey).
    void refresh_aux_work();

    /// How long a poll waits for the chains' answers before it builds the
    /// commitment (default 2 s); a slower answer is applied when it comes,
    /// the chain's last work staying committed meanwhile. The chains are
    /// fetched in parallel, without m_mutex held.
    void set_refresh_round_deadline(std::chrono::milliseconds d);
    /// With more than one chain, a chain whose fetch fails, or is still
    /// running this long after it started (a hung daemon; default 15 s, about
    /// AuxChainRPC's connect and call deadlines), drops out of the commitment
    /// until it answers.
    void set_unresponsive_after(std::chrono::milliseconds d);

    /// Read-only view of an aux chain's current block template (symbol,
    /// case-insensitive), for local cross-checks: prev, height, bits,
    /// curtime, coinbase value, the tx list (txid, raw, fee), tx bytes, the
    /// degraded mark, the block hash the parent commits to and the frozen
    /// coinbase. null when there is no such chain.
    nlohmann::json aux_template_json(const std::string& symbol) const;

    /// Per chain symbol: {"degraded": templates fetched degraded,
    /// "refetched_clean": clean templates fetched after a degraded one}.
    nlohmann::json get_template_gate_json() const;

    /// The chain keeps a frozen snapshot for this committed block hash (a
    /// share committing to it can still be turned into a block).
    bool has_frozen_snapshot(uint32_t chain_id, const uint256& block_hash) const;

    /// Run one poll of the aux chains now, on the RPC thread, instead of
    /// waiting for the next 1 s tick (e.g. the DOGE tip just moved). Skipped
    /// when a poll is already running.
    void request_refresh();

    /// The payout provider calls this before returning no payouts, with why
    /// ("no_best_share", "tracker_busy", ...); the rebuild that asked counts
    /// it (get_rebuild_stats_json).
    static void note_payout_miss(const std::string& reason);
    /// The payout provider calls this with the sharechain best share its
    /// payouts are (or would be) split at; the rebuild records it with the
    /// block (MergedHeaderInfo::payout_basis).
    static void note_payout_basis(const uint256& best);
    /// True on the merged-mining RPC thread (polls / refreshes), where a
    /// payout provider may wait a little for a busy lock; false on the
    /// network thread, which must not.
    static bool on_rpc_thread();

    /// {"no_payouts": {reason: rebuilds}, "kept_last_block": n,
    ///  "dropped_commitment": n, "dropped_best_moved": n, "stale_results": n, "work_changed": n,
    ///  "work_unchanged": n, "snapshot_target_refusals": n,
    ///  "no_payout_seconds": s, "no_payout_now": [symbols],
    ///  "payout_source": {published, from_weights, computed, busy}}.
    nlohmann::json get_rebuild_stats_json() const;

    /// Steady-clock seconds the manager stamps snapshots and episodes with
    /// (a test drives its own clock).
    using ClockFn = std::function<int64_t()>;
    void set_clock_for_test(ClockFn fn);

private:
    void poll_loop();

public:
    // ─── Shared helpers (used by both build_multiaddress_block and rebuild_cached_blocks) ───

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
        // Calls into this chain's backends from a poll's fetch and a find's
        // submit, which run without m_mutex: one call at a time per backend
        // (lock_for), held for that call only, so a submit waits for at most
        // one call of the same backend, and none for a backend whose submit
        // has its own connection (submit_independent).
        struct ChainIo {
            std::mutex        locks_mu;
            std::map<const IAuxChainBackend*, std::shared_ptr<std::mutex>> locks;
            std::shared_ptr<std::mutex> lock_for(const IAuxChainBackend* b)
            {
                std::lock_guard<std::mutex> l(locks_mu);
                auto& m = locks[b];
                if (!m)
                    m = std::make_shared<std::mutex>();
                return m;
            }
            std::atomic<bool>    in_flight{false};   // a fetch of this chain is running
            std::atomic<int64_t> fetch_started_ns{0}; // steady clock, when it started
            std::atomic<int64_t> last_sync_log_ns{0};   // rate limits
            std::atomic<int64_t> last_warn_ns{0};
            std::atomic<bool>    network_checked{false};   // check_payout_address passed
        };
        std::shared_ptr<ChainIo>             io = std::make_shared<ChainIo>();
        // Answered its last fetch in time. With more than one chain, a chain
        // that did not is left out of the commitment until it answers.
        bool                                 responsive{true};
        std::string                          unresponsive_why;
        uint64_t                             dropouts{0};
        // A configuration error found at run time (the daemon's chain id is
        // not the configured one, the payout address is not of the daemon's
        // network): the chain is out of the commitment and not polled again.
        std::string                          config_error;
        // A run of rebuilds that got no payouts for this chain (logged once).
        bool                                 no_payout_episode{false};
        int64_t                              no_payout_since{0};      // steady seconds
        uint64_t                             no_payout_rebuilds{0};
        int64_t                              no_payout_seconds{0};    // closed episodes
        AuxChainConfig                       config;
        std::unique_ptr<IAuxChainBackend>    rpc;       // primary backend (RPC or embedded)
        std::unique_ptr<IAuxChainBackend>    fallback;  // fallback backend (embedded if primary is RPC)
        AuxWork                              current_work;
        std::string                          last_tip;
        bool                                 using_fallback{false};
        int64_t                              last_update_time{0}; // monotonic seconds
        // The last template came back degraded (the mempool was not cleaned
        // for the tip yet): the tip is not latched, the next poll fetches again.
        bool                                 template_degraded{false};
        uint64_t                             templates_degraded{0};
        uint64_t                             templates_refetched_clean{0};
        uint64_t                             templates_still_degraded{0};  // re-fetches kept back
        // Frozen DOGE block data from rebuild_cached_blocks().
        // Contains the pre-built DOGE coinbase hex and template snapshot that
        // match the block hash committed in the LTC parent's mm_data.
        // try_submit_merged_blocks uses these instead of rebuilding.
        std::string frozen_coinbase_hex;   // pre-built PPLNS coinbase from ref_hash_fn time
        nlohmann::json frozen_template;    // template snapshot from ref_hash_fn time
        uint256 frozen_block_hash;         // block hash at commit time (for AuxPoW proof)
        uint256 frozen_payout_basis;       // best share its payouts were split at

        // History of frozen snapshots keyed by block hash.
        // Solves the stale-commitment race: the LTC coinbase contains an MM root
        // from freeze time T1, but by submission time T2 a newer freeze may have
        // overwritten the single frozen_* fields.  The history lets us look up
        // the exact template/coinbase that matches the committed root.
        struct FrozenSnapshot {
            nlohmann::json tmpl;
            std::string    coinbase_hex;
            int64_t        timestamp;   // monotonic seconds for expiration
            uint64_t       seq{0};      // insertion order: the cap drops the oldest
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
    uint64_t m_frozen_seq{0};  // FrozenSnapshot::seq source (under m_mutex)

    // ── Fetching and submitting without m_mutex ──
    // A poll snapshots each chain under m_mutex, fetches outside it on
    // m_io_pool (one task per chain, under the chain's io lock), and applies
    // each answer under m_mutex. A find assembles its blocks under m_mutex
    // and submits them outside it, each chain on its own thread.
    struct FetchInput;
    struct FetchResult;
    struct SubmitJob;
    static FetchResult fetch_chain(const FetchInput& in);
    // With m_mutex held. True when what the commitment is built from changed.
    bool apply_fetch_locked(size_t index, FetchResult& r);
    void run_submit_jobs(std::vector<SubmitJob>& jobs, const std::string& parent_hash_hex);
    boost::asio::thread_pool& io_pool();   // with m_mutex held (sized from m_chains)
    std::unique_ptr<boost::asio::thread_pool> m_io_pool;
    std::mutex m_io_pool_mutex;
    std::chrono::milliseconds m_refresh_deadline{2'000};
    std::chrono::milliseconds m_unresponsive_after{15'000};
    std::atomic<bool> m_work_dirty{false};   // an answer changed the work since the last rebuild

    // Submit via submitauxblock and relay the accepted block via P2P
    void submit_aux_and_relay(ChainState& chain, const std::string& auxpow,
                              const std::string& parent_hash_hex = "");

    // Current AuxPoW tree (rebuilt when chains change)
    AuxPowTree m_tree;

    // Cached commitment (44 bytes: magic + mm_root + tree_size + nonce)
    std::vector<uint8_t> m_cached_commitment;

    // Multi-chain commitments: the leaves each root in a parent coinbase was
    // built from (remember_committed_root_locked), keyed by the root. Unused
    // with one chain, where the root is the chain's block hash.
    struct CommittedRoot {
        std::map<uint32_t, uint32_t> slots;       // chain id -> slot
        std::map<uint32_t, uint256> slot_hashes;  // slot -> committed block hash
        uint32_t tree_size{0};
        int64_t  timestamp{0};   // same clock as FrozenSnapshot::timestamp
        uint64_t seq{0};         // insertion order: the cap drops the oldest
    };
    std::map<uint256, CommittedRoot> m_committed_roots;
    // Commitments per chain can move independently: room for every chain's
    // frozen window.
    static constexpr size_t kMaxCommittedRoots = 256;
    void remember_committed_root_locked(const uint256& root, const AuxPowTree& tree,
                                        const std::map<uint32_t, uint256>& slot_hashes,
                                        int64_t now);

    // Cached header_infos — built once per work cycle, read by all stratum sessions.
    // Protected by m_mutex (writes in rebuild_cached_blocks, reads via getter).
    std::vector<MergedHeaderInfo> m_cached_header_infos;

    // PPLNS dirty flag — set by mark_pplns_dirty(), cleared by rebuild_cached_blocks().
    // When true, next poll cycle or explicit rebuild will recompute DOGE blocks.
    std::atomic<bool> m_pplns_dirty{false};

    // Per-chain payout provider (set by integration layer)
    PayoutProvider m_payout_provider;
    std::shared_ptr<MergedPayoutSource> m_payout_source = std::make_shared<MergedPayoutSource>();

    // Rebuilds without payouts (guarded by m_mutex).
    std::map<std::string, uint64_t> m_rebuild_no_payouts;
    uint64_t m_rebuild_kept_last_block{0};
    uint64_t m_rebuild_dropped_commitment{0};
    // ...of which because the last block's payouts are for another best share.
    uint64_t m_rebuild_dropped_best_moved{0};
    uint64_t m_rebuild_stale_results{0};
    // Rebuilds whose result reached the miners (work pushed) or did not
    // change what they commit to (no push).
    uint64_t m_rebuild_work_changed{0};
    uint64_t m_rebuild_work_unchanged{0};
    // Finds refused at submit: the parent PoW meets the current target but
    // not the bits of the snapshot the block is built from.
    uint64_t m_snapshot_target_refusals{0};

    ClockFn m_clock;
    int64_t now_sec() const;

    // THE state root provider for sharechain anchoring
    StateRootProvider m_state_root_provider;

    // P2P block relay callback (set by integration layer)
    BlockRelayFn m_block_relay_fn;
    MergedBlockFoundFn m_on_merged_block_found;
    WorkChangedFn m_on_work_changed;

    // Parent coinbase shape for the aux size budget (set_parent_coinbase_shape).
    std::atomic<uint32_t> m_parent_coinbase_bytes{0};
    std::atomic<uint32_t> m_parent_branch_len{0};
    // Aux blocks refused at assembly (guarded by m_mutex).
    std::map<std::string, uint64_t> m_block_refusals_by_code;
    uint32_t block_size_reserve_locked(const ChainState& chain) const;
    // The legacy sigops of the chain's frozen coinbase plus a margin for a
    // few new payees; with none frozen yet, kAuxCoinbaseSigopsUnknown.
    uint32_t block_sigop_reserve_locked(const ChainState& chain) const;
    static constexpr uint32_t kAuxCoinbaseSigopMargin = 20;
    static constexpr uint32_t kAuxCoinbaseSigopsUnknown = 4'200;  // 4,000 P2PKH payees and a margin

    // Discovered merged blocks history
    std::vector<DiscoveredMergedBlock> m_discovered_blocks;
    std::map<uint32_t, uint64_t>       m_blocks_per_chain;

    // Helper: record a discovered block (caller must hold m_mutex)
    void record_discovered_block(const ChainState& chain, bool accepted,
                                 const std::string& parent_hash = "");
    // The block a share actually committed to: its hash, height and coinbase
    // value from the frozen snapshot the block was built from (a stale job's
    // is not the current work).
    void record_discovered_block(const ChainState& chain, const SubmitVerdict& verdict,
                                 const std::string& parent_hash, const uint256& block_hash,
                                 int height, uint64_t coinbase_value, double aux_difficulty);

    // recursive_mutex: rebuild_cached_blocks() acquires/releases m_mutex
    // in phases (snapshot → payout_fn → re-acquire to store).  poll_loop
    // also holds m_mutex on the RPC thread.
    mutable std::recursive_mutex m_mutex;
};

// createauxblock / getauxblock "target" and "_target" are the raw
// little-endian bytes of the uint256 (HexStr(BEGIN, END)), low byte first.
// Reverses them into the big-endian form uint256::SetHex reads. Returns false
// and leaves out untouched unless le_hex is exactly 64 hex digits.
bool aux_target_from_le_hex(const std::string& le_hex, uint256& out);

// Maps a createauxblock reply to AuxWork: hash, chainid (default_chain_id when
// absent), height, coinbasevalue, and the target from "target", then
// "_target" (both little-endian, see above), then "bits".
AuxWork aux_work_from_createauxblock(const nlohmann::json& result,
                                     uint32_t default_chain_id,
                                     const std::string& symbol);

} // namespace merged
} // namespace c2pool