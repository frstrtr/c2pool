// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
//
// dashboard_found_block.hpp — the ANY-PARTICIPANT found-block feed for DASH.
//
// THE GAP THIS CLOSES
// -------------------
// /recent_blocks is served from MiningInterface::m_found_blocks, and the only
// thing that ever appends to it is record_found_block(). On DASH the only
// binding of that was the LOCAL stratum win (main_dash.cpp, DASHWorkSource
// set_on_found_block_fn), so a block found by ANY OTHER pool participant --
// gossiped in as a share whose X11 header hash also clears the coin's BLOCK
// target -- was paid out correctly but NEVER appeared on the dashboard.
//
// dash::ShareTracker already fires m_on_block_found for exactly that event
// (share_tracker.hpp: declared :368, fired from attempt_verify :574-578 and
// from scan_chain_for_blocks :398). ltc/btc/dgb/bch all bind that hook; DASH
// never did. This header holds the handler DASH binds, factored so the parts
// that carry logic are unit-testable off a real ShareTracker.
//
// THREADING / LOCK CONTRACT (the #878/#881 dead-callee class)
// ----------------------------------------------------------
// m_on_block_found fires from INSIDE the tracker, with the CALLER already
// holding m_tracker_mutex EXCLUSIVELY:
//   * peer share  : io -> post(m_think_pool) -> compute thread takes
//                   unique_lock(m_tracker_mutex) (node.cpp:540/972/…) ->
//                   tracker.think() -> attempt_verify() -> hook.
//   * local mint  : add_local_share() holds unique_lock(m_tracker_mutex,
//                   try_to_lock) (node.cpp:1387) -> attempt_verify() -> hook.
// So the handler MUST NOT take m_tracker_mutex itself. It reads the share
// through Node::read_tracker(), which is reentrancy-aware: on the compute
// thread it takes NO lock (the exclusive one is already held), off it a
// shared try-lock. It then copies out PLAIN DATA (no tracker pointers escape,
// #828 GP-fault class) and hands the finished row to `post` so the actual
// dashboard write -- which takes m_blocks_mutex and can hit LevelDB and the
// THE-checkpoint hook -- runs on the io_context with NO tracker lock held.
//
// DEDUP. A locally-won block reaches the dashboard twice: once from the
// stratum win, and again after #888 mints that same winning share onto the
// sharechain (attempt_verify -> this hook). Both carry the SAME uint256 --
// for DASH the share hash IS X11(block header) (share_check.hpp:334), which
// is exactly what the stratum path records as its block hash -- and the same
// chain label "DASH". record_found_block() dedups on (block hash, chain)
// under m_blocks_mutex (web_server.cpp:3311-3318), the same block-hash-keyed
// contract web_server.cpp:1911 already relies on. Nothing here keys on a
// prev-hash.
//
// Display only. No block submission, minting, target or payout logic is
// reachable from this file.

#include <core/address_utils.hpp>     // core::script_to_address
#include <core/coinbase_builder.hpp>  // c2pool::ParsedScriptSig (BIP34 height)
#include <core/target_utils.hpp>      // chain::bits_to_target / target_to_difficulty
#include <core/uint256.hpp>

#include <impl/dash/share_check.hpp>  // dash::pubkey_hash_to_script2

#include <cstdint>
#include <functional>
#include <string>
#include <utility>

namespace dash::dashboard {

// Dash base58 version bytes (web_server.cpp:2353-2356 is the same SSOT):
// mainnet P2PKH 'X' = 76 / P2SH '7' = 16; testnet 'y' = 140 / '8'-'9' = 19.
inline constexpr uint8_t P2PKH_VERSION_MAINNET = 76;
inline constexpr uint8_t P2PKH_VERSION_TESTNET = 140;
inline constexpr uint8_t P2SH_VERSION_MAINNET  = 16;
inline constexpr uint8_t P2SH_VERSION_TESTNET  = 19;

/// The DASH chain label every found-block row carries. record_found_block()
/// dedups on (hash, chain), so the sharechain arm and the stratum arm MUST
/// agree on this exact string or a local win double-lists.
inline constexpr const char* CHAIN_LABEL = "DASH";

/// One dashboard row. Field-for-field the argument list
/// MiningInterface::record_found_block() takes, so main_dash.cpp forwards it
/// verbatim and the mapping cannot drift. network_difficulty / pool_hashrate
/// are deliberately absent: they are live node readings, not share facts, and
/// are read at record time on the io_context.
struct FoundBlockRow
{
    uint64_t    height{0};            ///< coin block height (BIP34, from the coinbase)
    uint256     block_hash;           ///< X11(block header) == the share hash on DASH
    uint64_t    timestamp{0};         ///< the block header's nTime
    std::string chain{CHAIN_LABEL};
    std::string miner;                ///< finder's DASH address ('X…' / 'y…')
    std::string share_hash;
    double      share_difficulty{0.0};
    uint64_t    subsidy{0};           ///< block reward the share committed to
};

/// Derive the dashboard row from a verified share that met the BLOCK target.
/// Pure: no locks, no I/O, no globals. `share_hash` is the tracker's own key
/// for the share and, on DASH, the block's identity hash -- it is used rather
/// than the share's cached m_hash so the row can never disagree with the key
/// the tracker fired on.
template <class ShareT>
inline FoundBlockRow row_from_share(const uint256& share_hash,
                                    const ShareT& s,
                                    bool testnet)
{
    FoundBlockRow row;
    row.block_hash = share_hash;
    row.share_hash = share_hash.GetHex();
    row.timestamp  = static_cast<uint64_t>(s.m_min_header.m_timestamp);
    row.chain      = CHAIN_LABEL;

    // Share difficulty from the share's OWN committed target (share_info bits),
    // matching what the tracker reports through m_on_share_difficulty.
    if (s.m_bits != 0)
        row.share_difficulty = chain::target_to_difficulty(chain::bits_to_target(s.m_bits));

    if constexpr (requires { s.m_subsidy; })
        row.subsidy = s.m_subsidy;

    // Coin block height: the BIP34 push at the head of the share's coinbase
    // scriptSig. dashd's ContextualCheckBlock enforces that prefix (bad-cb-
    // height), so it is the height the finder actually built on -- not the
    // sharechain absheight, which would render as a nonsense block number
    // next to the stratum-recorded rows.
    {
        const auto& cb = s.m_coinbase.m_data;
        if (!cb.empty()) {
            c2pool::ParsedScriptSig parsed;
            (void)c2pool::ParsedScriptSig::parse(cb.data(), cb.size(), parsed);
            if (parsed.block_height > 0)
                row.height = static_cast<uint64_t>(parsed.block_height);
        }
    }

    // Finder address. DASH shares are always P2PKH over m_pubkey_hash.
    if constexpr (requires { s.m_pubkey_hash; }) {
        row.miner = core::script_to_address(
            dash::pubkey_hash_to_script2(s.m_pubkey_hash),
            /*bech32_hrp=*/"",
            testnet ? P2PKH_VERSION_TESTNET : P2PKH_VERSION_MAINNET,
            testnet ? P2SH_VERSION_TESTNET  : P2SH_VERSION_MAINNET);
    }

    return row;
}

/// Writes a finished row to the dashboard's found-block store. Supplied by
/// main_dash.cpp as a verbatim forward into record_found_block().
using RowSink = std::function<void(const FoundBlockRow&)>;

/// Hands work to the io_context. Supplied by main_dash.cpp as
/// boost::asio::post(ioc, …) so the dashboard write never runs under the
/// tracker lock (see the lock contract above).
using PostFn = std::function<void(std::function<void()>)>;

/// Build the handler main_dash.cpp installs as ShareTracker::m_on_block_found.
///
/// `node` must expose read_tracker() with dash::NodeImpl's semantics: truthy
/// without locking on the compute thread (exclusive lock already held by the
/// caller of this hook), shared try-lock elsewhere, falsy when that try-lock
/// loses. A falsy guard is a SKIP, never a blocking wait -- an io-thread
/// caller must not stall behind think(), and the only path that reaches here
/// with a falsy guard is the local mint, which the stratum arm has already
/// recorded.
template <class NodeT>
inline std::function<void(const uint256&)>
make_on_block_found(NodeT* node, bool testnet, PostFn post, RowSink sink)
{
    return [node, testnet, post = std::move(post), sink = std::move(sink)]
           (const uint256& share_hash)
    {
        if (!node || !post || !sink) return;

        FoundBlockRow row;
        bool have_row = false;

        {
            // No lock is taken on the compute thread (the hook's caller holds
            // the exclusive one); off it this is a shared TRY-lock.
            auto guard = node->read_tracker();
            if (!guard) return;
            auto& tracker_chain = guard->chain;
            if (!tracker_chain.contains(share_hash)) return;
            tracker_chain.get(share_hash).share.invoke([&](auto* s) {
                if (!s) return;
                row = row_from_share(share_hash, *s, testnet);
                have_row = true;
            });
        }   // guard released -- nothing below touches the tracker

        if (!have_row) return;

        // Plain-data copy only; the dashboard write happens on the io_context.
        post([sink, row = std::move(row)]() { sink(row); });
    };
}

} // namespace dash::dashboard
