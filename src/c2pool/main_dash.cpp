// SPDX-License-Identifier: AGPL-3.0-or-later
// c2pool-dash — DASH (X11 standalone parent, older-than-v35 -> V36) p2pool node
// entry point.
//
// EXE-WIRE slice 2 (integrator 2026-06-23, stacked on launcher slice 1 #387):
// closes the "DASH is impl-files-only, not runnable" gap. Slice 1 registered
// DASH in the unified launcher dispatch (parse_blockchain / port / net-magic);
// this slice gives DASH its own runnable executable that drives the REAL dash
// consensus primitives, so `dash` is no longer a dispatch label with no body.
//
// PER-COIN ISOLATION: src/impl/dash headers only (params/crypto/subsidy); no
// src/impl/<other-coin> edit, no shared-base/core source edit, dashd RPC
// fallback untouched. Mirrors the c2pool-bch / c2pool-dgb add_executable shape,
// pruned to the header-only consensus path (DASH carries no node.cpp run-loop
// TU on master yet — that is the S7/S8 block-submission lane).
//
// ONE MODE TODAY:
//   --selftest (default) : drive the LIVE dash consensus paths std-only, network
//       free, exercising the exact code the sharechain depends on, then exit:
//         (1) make_coin_params  — the oracle-sourced CoinParams factory wired,
//             incl. the X11 pow_func reachable through the coin-params seam.
//         (2) X11 PoW           — DASH mainnet genesis + a real-node testnet3
//             block header reproduce their published hashes (CI-pinned KATs,
//             test_dash_x11_kat.cpp).
//         (3) subsidy           — post-V20 block reward + 3/4 MN payment match
//             the live-validated mainnet value (test_dash_subsidy.cpp).
//
// BLOCK-SUBMISSION (--run) — LIVE, dual-path (S8). A won DASH block reaches the
// network via dash::coin::broadcast_won_block over BOTH independent arms, wired
// into the DASHWorkSource won-block sink (stratum_submit_fn):
//   - ARM A embedded P2P relay (ALWAYS-PRIMARY, daemonless): the E1 CoinClient
//     (coin/p2p_client.hpp, --coin-p2p-connect) submit_block_p2p_raw pushes the
//     packed block onto the coin P2P net. With NO local dashd, a won block still
//     reaches the network on this arm alone — the daemonless critical path.
//   - ARM B dashd submitblock RPC backup (on-demand): the DASH NodeRPC TU
//     (coin/rpc.cpp, submit_block_hex), fired whenever a local dashd is armed
//     (also covers a cold/faulted relay). --no-p2p-relay suppresses ARM A only
//     (A/B isolation). NEVER a silent drop: reaching NEITHER sink logs LOUDLY.
//
// Conformance oracle: frstrtr/p2pool-dash (older-than-v35; transition 16 -> v36).
// External dashd RPC stays as a fallback alongside the (future) embedded path.

#include <impl/dash/params.hpp>
#include <impl/dash/crypto/hash_x11.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>   // must precede subsidy.hpp (dash_txid in scope)
#include <impl/dash/coin/subsidy.hpp>

#include <core/coin_params.hpp>
#include <core/coinbase_builder.hpp>       // c2pool::MAX_OPERATOR_TEXT_SOLO (--coinbase-text budget SSOT)
#include <core/core_util.hpp>              // raise_nofile_limit (hotel interim fix #4)
#include <core/uint256.hpp>
#include <core/netaddress.hpp>             // NetService (dashd RPC endpoint)

#include <impl/dash/coin/rpc.hpp>          // dash::coin::NodeRPC — external-dashd submitblock arm (slice 3)
#include <impl/dash/coin/work_source.hpp>   // dash::coin::select_dash_work -- embedded-gbt live-wire + dashd fallback (S8 capstone)
#include <impl/dash/coin/rpc_conf.hpp>     // dash.conf creds resolution (rpcpassword off argv)
#include <impl/dash/coin/node_interface.hpp>
#include <impl/dash/coin/p2p_client.hpp>   // dash::coin::p2p::CoinClient — OPT-IN coin-network dial (E1, --coin-p2p-connect)
#include <impl/dash/coin/coin_peer_manager.hpp> // dash::coin::DashCoinPeerManager — DASH-ISOLATED scored/diverse peer discovery (--coin-p2p-discover; network-standalone gate)
#include <impl/dash/coin/chain_seeds.hpp>  // dash::coin::dash_dns_seeds / dash_fixed_seeds — DASH mainnet/testnet seed bootstrap
#include <impl/dash/coin/won_block_dispatch.hpp> // dash::coin::broadcast_won_block — S8 dual-path won-block dispatcher (embedded P2P primary + submitblock RPC backup)
#include <impl/dash/coin/zmq_tip_notify.hpp> // dash::coin::TipHashDedup / ZmqHashblockSubscriber — dashd ZMQ hashblock INSTANT tip-notify (opt-in, hardening on the #770 poll)
#include <impl/dash/coin/coin_p2p_magic.hpp>      // dash::coin::select_coin_p2p_magic — E5 --coin-p2p-magic override (regtest ARM A dial)
#include <impl/dash/coin/node_coin_state.hpp>  // dash::coin::NodeCoinState (embedded work bundle)
#include <impl/dash/coin/arm_resolution.hpp>   // dash::coin::resolve_embedded_arm (#738 arm decision, one place)
#include <impl/dash/coin/embedded_startup_invariant.hpp>  // C-startup-invariant: embedded fresh-gate => body-first serve tip
#include <impl/dash/coin/dkg_window.hpp>       // dash::coin::is_dkg_commitment_window (BLOCKER-1 guard)
#include <impl/dash/coin/dkg_commitments.hpp>  // E1: build_daemonless_qc_plan (serve DKG windows daemonlessly)
#include <impl/dash/coin/mined_commitment_index.hpp>  // PR-2 FORWARD: dashd's mined-commitment store, from OUR replay
#include <impl/dash/coin/qc_episode_classifier.hpp>  // [QC-EPISODE] terminal-event classifier (null-arm design §8)
#include <impl/dash/coin/vendor/bls_verify.hpp>  // E1 Phase-L: make_commitment_bls_verifier (real qc verify seam)
#include <impl/dash/coin/chainlock_verify.hpp>   // live-path ChainLock quorum selection + BLS verify gate
#include <impl/dash/coin/islock_verify.hpp>      // G4 isdlock ROTATED quorum selection + BLS verify gate
#include <impl/dash/coin/llmq_type_reconciler.hpp>  // negative-capable enabled_llmqs backstop
#include <impl/dash/coin/quorum_member_source.hpp>  // E1 Phase-L: daemonless member-set sourcing (the provider)
#include <impl/dash/coin/utxo_lane.hpp>    // dash::coin::UtxoLane — embedded UTXO/fee lane (E2b, #738)
#include <impl/dash/coin/header_chain.hpp>       // dash::coin::HeaderChain — SPV header/tip authority (E2a)
#include <impl/dash/coin/block_confirm.hpp>      // dash::coin::block_confirm — post-broadcast confirm/orphan verdict
#include <impl/dash/coin/chain_rpc.hpp>          // dash::coin::chain_rpc — daemonless getbestblockhash/getblockhash/getblockchaininfo
#include <impl/dash/coin/bestblock_diag.hpp>     // #1046 bestblock out=0 diagnostic classifier (RpcNotString/BadHexLen/Ok)
#include <impl/dash/coin/coin_state_maintainer.hpp>  // dash::coin::CoinStateMaintainer — populate ordering gate (E2a)
#include <impl/dash/coin/sml_quorum_db.hpp>      // dash::coin::SMLDb / QuorumDb — SML+quorum persistence (incremental restart)
#include <impl/dash/coin/credit_pool_db.hpp>     // dash::coin::CreditPoolDb — credit-pool tip persistence (E2 restart resume)
#include <impl/dash/coin/live_feed.hpp>          // E2a live-feed bridge (raw wire events -> derived ingest events)
#include <impl/dash/coin/mempool_ingest.hpp>     // wire_mempool_ingest (leg 1)
#include <impl/dash/coin/tip_ingest.hpp>         // wire_tip_ingest (leg 2)
#include <impl/dash/coin/embedded_oracle_shadow.hpp> // dash::coin::EmbeddedOracleShadow — per-block dashd cross-check (OBSERVE-only)
#include <impl/dash/coin/embedded_shadow_compare.hpp> // dash::coin::EmbeddedShadowCompare — serve-vs-dashd template diff (OBSERVE-only, NOT a gate)
#include <impl/dash/coin/mempool_validity_gate.hpp>   // dash::coin::MempoolValidityGate — THE --embedded-serve-mempool-txs arming condition
#include <impl/dash/coin/block_connect_ingest.hpp>   // wire_block_connect_ingest (leg 3)
#include <impl/dash/coin/mn_list_ingest.hpp>     // wire_mn_list_ingest (leg 4)
#include <impl/dash/coin/govsync_ingest.hpp>     // wire_govobject_ingest / wire_govvote_ingest (E-SUPERBLOCK)
#include <impl/dash/coin/superblock.hpp>         // get_superblock_payments / superblock_budget (E-SUPERBLOCK)
#include <impl/dash/coin/vendor/bls_verify.hpp>  // R3: verify_govvote_operator_sig — governance-vote BLS operator-key verify
#include <impl/dash/coin/mn_seed.hpp>            // E2c: RPC protx-list MN-set seed (parse_protx_list_seed)
#include <impl/dash/coin/mn_checkpoint.hpp>      // E2d: pinned MN-set checkpoint format + fail-closed parser
#include <impl/dash/coin/mn_checkpoint_lane.hpp> // E2d: checkpoint -> forward-replay bridge -> leg-4 publish
#include <impl/dash/coin/replay_bulk_fetch.hpp>  // W2: full-history replay bulk block-fetch lane (--replay-bulk)
#include <impl/dash/coin/replay_utxo_fold.hpp>   // W3: full-history replay standalone UTXO fold (--replay-utxo-*)
#include <impl/dash/coin/replay_prestate.hpp>    // W5: anchor prestate loader (--replay-fold-prestate)
#include <impl/dash/coin/mn_checkpoint_dump.hpp> // self-derived MN-set checkpoint dump (--dump-mn-checkpoint)
#include <impl/dash/coin/replay_fold_consumer.hpp> // W5: bulk lane -> W1 DML fold + per-block root check
#include <impl/dash/coin/replay_quorum_bridge.hpp> // SEAM: W4 quorum lane <-> W1 MembersFn
#include <impl/dash/coin/historical_sml.hpp> // authenticate_historical_snapshot (DIP-4 R3, straddle-seed)
#include <impl/dash/coin/replay_payee_publish.hpp> // SEAM: W1 fold -> the PAYEE queue that gates serving
#include <impl/dash/coin/mn_diff_store.hpp>      // dashd evodb dmn_D4/dmn_S3 port: per-block MN list diffs + snapshots
#include <impl/dash/coin/mn_gap_repair.hpp>      // payee-queue gap-repair seam (maintainer + checkpoint bridge)
#include <impl/dash/node.hpp>          // dash::Node — sharechain pool-node (NodeBridge<NodeImpl,Legacy,Actual>)
#include <impl/dash/config.hpp>        // dash::Config (PoolConfig/CoinConfig)
#include <impl/dash/config_pool.hpp>   // dash::SharechainConfig — P2P_PORT / PREFIX / min-proto SSOT
#include <core/filesystem.hpp>         // core::filesystem::config_path()
#include <btclibs/util/strencodings.h> // ParseHexBytes (prefix isolation primitive)
#include <filesystem>
#include <system_error>
#include <impl/dash/coin/block_producer.hpp>  // dash::coin::mine_block / serialize_full_block_hex (slice 5)
#include <impl/dash/coinbase_builder.hpp>      // dash::coinbase::build / compute_dash_payouts (slice 5)
#include <impl/dash/params.hpp>                // dash::make_coin_params (already via top include)
#include <core/uint256.hpp>                    // uint160 payout pubkey hash
#include <core/target_utils.hpp>              // chain::target_to_difficulty (dashboard net-diff)
#include <impl/dash/dashboard_found_block.hpp> // any-participant /recent_blocks feed (peer-found blocks)
#include <impl/dash/dashboard_views.hpp>       // sharechain window / delta / share-detail read-models
#include <impl/dash/dashboard_pplns.hpp>       // PPLNS payout read-model (pool-wide + per-share)

#include <core/stratum_server.hpp>             // core::StratumServer — miner-facing accept-loop (run-path caller)
#include <impl/dash/stratum/work_source.hpp>   // dash::stratum::DASHWorkSource — concrete core::stratum::IWorkSource
#include <impl/dash/mint_runloop.hpp>          // dash::mint — run-loop share minting (slice 3/3)
#include <impl/dash/stratum/tip_refresh.hpp>   // dash::stratum::fire_share_tip_refresh — bump + notify_all + dashboard refresh
#include <impl/dash/local_mint_ledger.hpp>     // dash::mint::LocalMintLedger — display-only local orphan/sibling gauge
#include <impl/dash/share_messages.hpp>        // dash::validate_message_data — operator message-blob validation (EMIT side, mirrors main_ltc.cpp)
#include <c2pool/storage/found_block_store.hpp>  // FoundBlockStore/Record + LevelDBStore (persistence, main_ltc parity)
#include <core/web_server.hpp>                 // core::WebServer — the EXISTING c2pool dashboard (same wiring main_ltc.cpp uses)
#include <impl/dash/enhanced_node.hpp>         // dash::EnhancedDashNode — core::IMiningNode the WebServer ctor takes
#include <impl/dash/share_messages.hpp>        // dash::unpack_share_messages — signed transitional-blob DISPLAY+VERIFY feed
#include <core/log.hpp>
#include <impl/dash/coin/serve_staleness.hpp>  // REPORT-ONLY serve-staleness sentinel (2026-08-07 dead-height incident)

#include <algorithm>    // std::copy (pool-share-cap pubkey_hash extract)
#include <array>        // std::array<uint8_t,20> — AddrRateMap key
#include <chrono>
#include <ctime>
#include <optional>
#include <random>

#include <boost/asio.hpp>
#include <boost/asio/thread_pool.hpp>   // io-thread-decouple: background RPC pool
#include <boost/asio/post.hpp>

#include <cstdint>
#include <cctype>       // std::tolower (--replay-utxo-expect normalize)
#include <cstdlib>      // std::getenv
#include <utility>      // std::as_const (qc-plan lambda: read-only qmgr access)
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <thread>       // the serve-staleness sentinel's DEDICATED poller
#include <vector>

#ifndef C2POOL_VERSION
#define C2POOL_VERSION "dev"
#endif

namespace {

// -- Sharechain (pool-to-pool) peering CONTRACT (launcher-peering-cli slice) --
// The DASH dual-pool G2 ratchet (LIVE rows C1-C4) needs main_dash to accept the
// peering argv the way main_btc does (--sharechain-port + bootstrap). This slice
// lands the argv CONTRACT + validation those rows invoke. The LIVE bind/dial is
// driven by DASH's sharechain pool Node (the pool::NodeBridge analog of btc::Node
// / dgb::Node = node.hpp + peer/messages/share_tracker), which is NOT yet on
// master and is the next S8 leaf; this surface wires straight into it when it
// lands. No shared-base / other-coin edit; dashd-RPC fallback untouched.
struct PeeringConfig {
    std::string listen_host = "0.0.0.0";   // --listen [HOST:]PORT bind interface
    uint16_t    listen_port = 0;           // 0 => sharechain SSOT default (8999/18999)
    bool        listen_set  = false;
    std::vector<NetService> addnodes;      // --addnode HOST:PORT (persistent outbound)
    std::vector<NetService> connects;      // --connect HOST:PORT (connect-only; no listen/discovery)
};

// Parse "HOST:PORT" (PORT mandatory; IPv4/hostname single-colon form).
bool parse_hostport(const std::string& str, NetService& out)
{
    const auto colon = str.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= str.size())
        return false;
    const std::string host = str.substr(0, colon);
    const std::string pstr = str.substr(colon + 1);
    if (pstr.find_first_not_of("0123456789") != std::string::npos) return false;
    const long p = std::strtol(pstr.c_str(), nullptr, 10);
    if (p <= 0 || p > 65535) return false;
    out = NetService(host, static_cast<uint16_t>(p));
    return true;
}

// Parse "[HOST:]PORT". Bare PORT keeps the caller-supplied default host.
bool parse_listen(const std::string& str, std::string& host, uint16_t& port)
{
    const auto colon = str.rfind(':');
    std::string pstr = (colon == std::string::npos) ? str : str.substr(colon + 1);
    if (colon != std::string::npos) {
        if (colon == 0) return false;
        host = str.substr(0, colon);
    }
    if (pstr.empty() || pstr.find_first_not_of("0123456789") != std::string::npos) return false;
    const long p = std::strtol(pstr.c_str(), nullptr, 10);
    if (p <= 0 || p > 65535) return false;
    port = static_cast<uint16_t>(p);
    return true;
}

// ── E2d (#738): the release-pinned masternode-set trust anchor ────────────
// Compiled INTO the binary (not loaded from disk) so a daemonless cold start
// cannot depend on a file the operator could lose, swap, or forget to install.
//
// ⚠ THESE ARE TRUST ANCHORS. A node that cold-starts the payout-bearing
// masternode set from one of them is trusting this release build for the set
// contents at the anchor height — there is no consensus commitment to check
// them against (the P2P Simplified MN List omits scriptPayout and
// nLastPaidHeight). What IS verified locally: the anchor's chain position
// against our own PoW-validated header chain, its SHA-256 integrity digest,
// and every replayed block's coinbase against the projected payee. See
// src/impl/dash/coin/checkpoints/README.md and the README section
// "DASH daemonless masternode-set checkpoint".
//
// Re-pinned at release time by tools/dash/gen_mn_checkpoint.py — never by
// hand: the digest line commits the contents, so a hand edit fails closed.
const char* const kDashMnCheckpointMainnet =
#include <impl/dash/coin/checkpoints/dash_mn_checkpoint_mainnet.inc>
    ;
const char* const kDashMnCheckpointTestnet =
#include <impl/dash/coin/checkpoints/dash_mn_checkpoint_testnet.inc>
    ;

// --embedded-mn-bridge-max: how many blocks the checkpoint bridge will replay
// before declaring the anchor STALE and refusing to arm. Held at file scope
// rather than threaded through run_node's already-long parameter list purely
// to keep this slice's diff off that signature; it is written once during
// argument parsing in main(), before any thread exists, and only read
// afterwards.
uint32_t g_mn_bridge_max_blocks =
    dash::coin::MnCheckpointLane::kDefaultMaxBridgeBlocks;

// --embedded-mn-bridge-no-cursor (#91): DISABLE the bridge's resumable replay
// cursor, so every process start replays the whole window from the pinned
// anchor — exactly the behaviour before #91 existed.
//
// This is a CONTROL, and it is here because the claim #91 makes is a TIMING
// claim ("a restart no longer costs ~26 minutes"), and a timing claim needs an
// A/B on the same binary, same host, same peers. Same file-scope posture as
// g_mn_bridge_max_blocks: written once during argument parsing, read once at
// wiring.
bool g_mn_bridge_no_cursor = false;

// ── W2 FULL-HISTORY REPLAY bulk-fetch flags (replay_bulk_fetch.hpp) ─────────
// Same file-scope posture (and the same rationale) as g_mn_bridge_max_blocks:
// written once during argument parsing, read once at wiring. All default OFF —
// absent, no replay object is constructed, no CoinClient filter is registered,
// and the serve path is byte-identical to the released posture.
bool        g_replay_bulk = false;            // --replay-bulk: arm the lane
std::string g_replay_bulk_capture_dir;        // --replay-bulk-capture DIR (implies --replay-bulk)
uint32_t    g_replay_bulk_start = 0;          // --replay-bulk-start H (0 = network default: mainnet DIP3 1028160)
// ── DASHD-CUT: self-derived MN-set checkpoint dump (--dump-mn-checkpoint H FILE) ─
// When the --replay-bulk DML fold's cursor reaches H, serialize its REGISTERED
// masternode set to the checkpoint .inc at FILE — SELF-DERIVED from the fold's
// own root-checked ReplayMNState, no dashd RPC, no trusted protx snapshot
// (operator decision 2026-08-17). One-shot; the fold is unaffected otherwise.
uint32_t    g_dump_mn_checkpoint_height = 0;  // 0 = off
std::string g_dump_mn_checkpoint_file;

// ── W5 INTEGRATION: drive the W1 DML fold from the W2 bulk lane ───────────
// --replay-fold-prestate FILE seeds the W1 fold engine from a full-state
// anchor prestate (tools/dash/gen_replay_kat.py prestate) and installs the
// FoldReplayConsumer, so every bulk-delivered body is folded and its computed
// merkleRootMNList compared byte-exact against that block's own committed cbTx
// root. Implies --replay-bulk, and pins the lane's start to anchor+1 (the fold
// is forward-contiguous -- a gap refuses the whole fold).
std::string g_replay_fold_prestate;           // --replay-fold-prestate FILE
// ── THE SEAM: --replay-fold-quorums arms W4's QuorumReplayEngine and hands
// its DERIVED member sets to the fold's MembersFn (replay_quorum_bridge.hpp),
// so a commitment that marks members invalid no longer needs anchor-supplied
// member sets. --replay-fold-qsnapshot FILE seeds the three PRE-ANCHOR
// rotated-cycle snapshots a Phase-1 run cannot have produced yet (skip-list
// bitsets, NOT member sets); every cycle from the anchor forward is produced
// by the replay itself.
bool        g_replay_fold_quorums = false;    // --replay-fold-quorums
std::string g_replay_fold_qsnapshot;          // --replay-fold-qsnapshot FILE
std::string g_replay_fold_worklists;          // --replay-fold-worklists FILE
// --embedded-no-dashd-mn-seed: cut the PAYEE axis off from dashd while KEEPING
// the dashd RPC for the OBSERVE-only shadow-compare. The E2c `protx list` seed
// and the E2d checkpoint bridge are both skipped, so the root-checked replay
// fold is the only thing that can populate the payee queue. Exists to make a
// parity run measurable: a run that was dashd-seeded proves the fold and the
// serve are both fine WITHOUT proving the serve is daemonless.
bool        g_no_dashd_mn_seed = false;       // --embedded-no-dashd-mn-seed

// ── PR-2 FORWARD: --replay-mined-commitment-index ─────────────────────────
// Arms the forward half of dashd's mined-commitment store
// (mined_commitment_index.hpp, ported from v23.1.7 llmq/blockprocessor.cpp)
// off the replay lane, and — ONLY once armed — offers it as a SECOND
// "already mined" source to the daemonless qc plan, alongside the
// mnlistdiff/qrinfo-fed QuorumManager.
//
// ⚠ MONEY PATH, default OFF. A slot that reads already-mined is a type-6 tx
// the served template no longer carries, so this is byte-visible. The index
// itself REFUSES TO ARM when the node's tip is live (dashd's UndoBlock half
// is not ported; a reorg would leave a phantom mined record and the template
// would be short one qfcommit => bad-qc-missing => lost block). The flag is
// therefore two gates deep: the operator must ask for it AND the tip posture
// must permit it.
bool        g_mined_commitment_index = false; // --replay-mined-commitment-index

// ───────────────────────────────────────────────────────────────────────────
// [BLOCK-LEDGER] — our own block accounting, from PERSISTENT state
// ───────────────────────────────────────────────────────────────────────────
//
// 2026-08-05, hotel: block h=2516911 was WON by the pool and ACCEPTED by the
// chain (our exact PPLNS payout structure), and NEITHER node's log showed a
// "BLOCK FOUND" line for it — the primary's log had been rotated that morning
// and the reserve had restarted mid-evening. Counting our own blocks by
// grepping the log produced two wrong answers in ten minutes.
//
// The defect is not the missing line, it is the SOURCE. This reads the
// found-blocks LevelDB (loaded at startup, 107 entries that day) rather than
// log history, so rotation and restart cost scrollback but not truth: the next
// ledger line still prints the real totals. Emitted at standup and every 300 s.
//
// Telemetry only — it reads the ledger, it never writes it.
void log_block_ledger(core::MiningInterface* mi)
{
    if (!mi) return;
    using BS = core::MiningInterface::BlockStatus;
    size_t   total = 0, accepted = 0, orphan = 0, stale = 0, pending = 0;
    size_t   attributed = 0;
    uint64_t last_found = 0, last_accepted = 0, last_found_ts = 0;
    for (const auto& b : mi->get_found_blocks()) {
        if (b.chain != "DASH") continue;
        ++total;
        // SAME ROW SEMANTICS AS /recent_blocks (#1127): a row with neither a
        // local share hash nor a miner address was NOT found by this node —
        // it was learned over relay, or it is a legacy row the enrichment
        // path has not upgraded yet. Counting those into a bare "found_total"
        // would overstate our own wins, which is the class of error this line
        // exists to end; they are counted separately instead of silently.
        if (!b.share_hash.empty() || !b.miner.empty()) ++attributed;
        switch (b.status) {
            case BS::confirmed: ++accepted; break;
            case BS::orphaned:  ++orphan;   break;
            case BS::stale:     ++stale;    break;
            case BS::pending:   ++pending;  break;
        }
        if (b.height >= last_found) { last_found = b.height; last_found_ts = b.ts; }
        if (b.status == BS::confirmed && b.height > last_accepted)
            last_accepted = b.height;
    }
    const auto now = static_cast<uint64_t>(std::time(nullptr));
    LOG_INFO << "[BLOCK-LEDGER] chain=DASH"
             << " found_total=" << total
             << " attributed=" << attributed
             << " relay_or_unenriched=" << (total - attributed)
             << " accepted=" << accepted
             << " orphan=" << orphan
             << " stale=" << stale
             << " pending=" << pending
             << " last_found=" << (last_found ? "h=" + std::to_string(last_found)
                                              : std::string("n/a"))
             << " last_found_age="
             << (last_found_ts && now > last_found_ts
                     ? std::to_string(now - last_found_ts) + "s"
                     : std::string("n/a"))
             << " last_accepted="
             << (last_accepted ? "h=" + std::to_string(last_accepted)
                               : std::string("n/a"))
             << " source=found_blocks_db"
             << " rotation_safe=1";
}

// Report the requested sharechain peering topology at run-loop bring-up. Honest
// about the deferred live bind: a won/seen share does NOT yet cross the wire
// until the sharechain pool-node leaf lands.
void report_peering(const PeeringConfig& peer, bool testnet)
{
    const uint16_t ssot = testnet ? 18999 : 8999;
    const uint16_t bind = peer.listen_port ? peer.listen_port : ssot;
    if (!peer.connects.empty() && !peer.listen_set) {
        std::cout << "[run] sharechain peering: --connect mode ("
                  << peer.connects.size() << " peer[s]); listen + discovery suppressed\n";
    } else {
        std::cout << "[run] sharechain peering: listen " << peer.listen_host << ":" << bind
                  << (peer.listen_set ? " (--listen)\n" : " (sharechain SSOT default)\n");
    }
    for (const auto& a : peer.addnodes)
        std::cout << "[run]   addnode (persistent outbound) -> " << a.to_string() << "\n";
    for (const auto& c : peer.connects)
        std::cout << "[run]   connect (connect-only)        -> " << c.to_string() << "\n";
    std::cout << "[run] peering argv contract is LIVE and the sharechain pool Node\n"
                 "[run]       (node.hpp: NodeBridge<NodeImpl,Legacy,Actual>) binds the listener\n"
                 "[run]       below (S8-p2p.3); reception rides #656/#657.\n";
}

using dash::coin::compute_dash_block_reward_post_v20;
using dash::coin::compute_dash_mn_payment_post_v20;

void print_banner(const char* argv0)
{
    std::cout
        << "c2pool-dash " << C2POOL_VERSION << " — DASH (X11, older-than-v35 -> V36)\n\n"
        << "Usage: " << argv0 << " [--version] [--help] [--selftest]\n"
        << "  --data-dir PATH  root all per-instance state here (default ~/.c2pool);\n"
        << "                   isolates co-located instances\n"
        << "       " << argv0 << " --run [--coin-rpc H:P] [--coin-rpc-auth PATH]\n"
        << "           [--testnet] [--submit-block HEX | --submit-block-file PATH]\n"
        << "           [--listen [HOST:]PORT] [--addnode HOST:PORT]... [--connect HOST:PORT]...\n"
        << "           [--stratum [HOST:]PORT] [--coin-p2p-connect HOST:PORT]... [--coin-p2p-discover]\n"
        << "           [--web-port PORT] [--web-host ADDR] [--dashboard-dir PATH]\n"
        << "           [--external-ip ADDR]\n"
        << "           [--embedded-utxo] [--embedded-mainnet] [--embedded-null-arm] [--embedded-mn-bridge-max N]\n"
        << "           [--embedded-mn-bridge-no-cursor]\n"
        << "           [--embedded-utxo-immature-serve-empty] [--embedded-serve-mempool-txs]\n"
        << "           [--embedded-accrue-asset-locks] [--embedded-accrue-asset-unlocks]\n"
        << "           [--embedded-ingest-isdlock]\n"
        << "           [--pin-local-tx-hex FILE]  (zero-fee self-mined tx, e.g. donation consolidation)\n"
        << "           [--pin-splice-xcheck-arm]  (let pins ride an xcheck-SWAPPED dashd template; default OFF)\n"
        << "           [--pin-splice-block-budget] (EXCLUDE a pin that pushes the template past the block size cap; default OFF)\n"
        << "           [--bestcl-policy freshness|consensus-exact]\n"
        << "           [--embedded-oracle-shadow]\n"
        << "           [--embedded-shadow-compare]\n"
        << "           [--serve-staleness-sentinel=off]\n"
        << "           [--replay-bulk] [--replay-bulk-capture DIR] [--replay-bulk-start H]\n"
        << "           [--replay-fold-prestate FILE] [--replay-fold-quorums]\n"
        << "           [--replay-fold-qsnapshot FILE] [--replay-fold-worklists FILE]\n"
        << "           [--replay-mined-commitment-index]\n"
        << "           [--dump-mn-checkpoint H FILE]\n"
        << "           [--embedded-no-dashd-mn-seed]\n"
        << "           [--oracle-graduation-blocks N] [--oracle-class-coverage K]\n"
        << "           [--give-author PCT] [-f|--fee PCT] [--node-owner-address ADDR]\n"
        << "           [--redistribute pplns|fee|boost|donate]\n"
        << "           [--coin-zmq-hashblock tcp://HOST:PORT]\n"
        << "           [--message-blob-hex HEX] [--coinbase-text TEXT]\n"
        << "       " << argv0 << " --mine-block [--coin-rpc H:P] [--coin-rpc-auth PATH]\n"
        << "           [--testnet] [--payout-pubkey-hash HEX] [--max-nonce N]\n"
        << "       " << argv0 << " --replay-utxo-db PATH [--replay-utxo-hash]\n"
        << "           [--replay-utxo-expect HEX]\n"
        << "        FULL-HISTORY REPLAY (W3) standalone UTXO-fold utility: names the\n"
        << "        fold store's resume cursor; with --replay-utxo-hash computes the\n"
        << "        dashd-compatible gettxoutsetinfo hash_serialized_2 over the whole\n"
        << "        set and, with --replay-utxo-expect, exits 0 only on a byte-exact\n"
        << "        match (the Tier-B gate). Runs and exits; never serves.\n\n"
        << "Status: consensus layer live (X11 PoW, subsidy, oracle CoinParams).\n"
        << "        --run stands up the run-loop and ARMS the external-dashd\n"
        << "        submitblock fallback (creds from dash.conf, never on argv).\n"
        << "        --stratum [HOST:]PORT binds the miner-facing Stratum accept-\n"
        << "        loop (DASHWorkSource seam; e.g. --stratum 3333 or\n"
        << "        --stratum 127.0.0.1:3333); omit to disable. Won X11 blocks\n"
        << "        dispatch via the retained dashd-RPC submitblock arm.\n"
        << "        --submit-block[-file] drives ONE real submitblock then exits\n"
        << "        (the won-block-reaches-network leg); embedded P2P relay = S8.\n"
        << "        --coin-p2p-connect HOST:PORT (repeatable) OPT-IN dials the DASH\n"
        << "        coin network directly (version/verack + keep-alive + reconnect);\n"
        << "        absent => no coin P2P client, dashd-RPC fallback path unchanged.\n"
        << "        --coin-zmq-hashblock tcp://HOST:PORT (opt-in) subscribes to dashd's\n"
        << "        ZMQ `hashblock` topic for INSTANT (~0 s) new-tip template refresh +\n"
        << "        clean_jobs notify on the fallback arm; absent/unreachable => the 3 s\n"
        << "        getbestblockhash poll is the active path (requires dashd\n"
        << "        zmqpubhashblock=tcp://HOST:PORT). No consensus effect.\n"
        << "        --embedded-mainnet (DEFAULT OFF) is the single opt-in for the\n"
        << "        DAEMONLESS embedded template arm on MAINNET. It lifts the arm gate\n"
        << "        AND arms the coin-state feed that populates it (seed-based peer\n"
        << "        discovery unless --coin-p2p-connect names peers), so one flag takes\n"
        << "        the arm end to end. WITHOUT it a mainnet node ALWAYS serves the\n"
        << "        reward-safe dashd-RPC fallback: --coin-p2p-connect/--coin-p2p-discover\n"
        << "        are transport only and NEVER move the arm. Even when armed, every\n"
        << "        per-template gate (SML fresh at tip, non-superblock, credit-pool seed\n"
        << "        height, bestCL, MN-payee cursor, DKG plan) fails closed to dashd.\n"
        << "        --bestcl-policy selects HOW the bestCL gate decides. `freshness`\n"
        << "        (DEFAULT) keeps the conservative proxy: refuse unless the best\n"
        << "        observed ChainLock is within one block of the tip. `consensus-exact`\n"
        << "        enforces dashcore CheckCbTxBestChainlock itself -- the committed\n"
        << "        ChainLock must merely be non-null and NOT OLDER than the one the\n"
        << "        previous block committed -- which is what dashd's own miner does\n"
        << "        (it re-commits the previous block's signature when it holds nothing\n"
        << "        fresher). Still fails closed: it refuses unless the previous block's\n"
        << "        own committed ChainLock is held, and a value ADVANCED past it must\n"
        << "        have passed local BLS verification.\n"
        << "        --coin-p2p-magic HEX overrides the embedded coin-P2P wire magic\n"
        << "        (default mainnet bf0c6bbd / testnet cee2caff; regtest fcc1b7dc).\n"
        << "        --regtest-force-won-block (regtest E5 harness, fail-closed) drives\n"
        << "        ONE real won block through the run-path dual-path dispatch.\n"
        << "        --coinbase-text TEXT sets the coinbase scriptSig text written\n"
        << "        after the BIP34 height push (README \"Coinbase structure\"; max\n"
        << "        64 bytes, no merged mining on the DASH lane). Default\n"
        << "        \"/P2Pool-DASH/c2pool/\" (testnet \"/P2Pool-tDASH/c2pool/\") --\n"
        << "        the /P2Pool-DASH/ marker is what block explorers match on to\n"
        << "        attribute a block to this pool; the c2pool suffix says which\n"
        << "        implementation mined it. Non-consensus: the coinbase text is\n"
        << "        never re-derived by peers, so overriding it cannot orphan a\n"
        << "        share -- but an override that drops /P2Pool-DASH/ makes your\n"
        << "        blocks unattributable on explorers.\n"
        << "        --coin-p2p-discover arms the DASH-isolated peer manager: seed\n"
        << "        (dnsseed.dash.org + fixed) bootstrap, source-scored + group-diverse\n"
        << "        (Sybil-capped) peer selection, anchors, and a self-healing dial\n"
        << "        rotation INDEPENDENT of the local dashd — the network-standalone\n"
        << "        arm (daemonless witness). Any --coin-p2p-connect peer is kept as a\n"
        << "        pinned/preferred node alongside the discovered set.\n"
        << "        --coin-p2p-peers N (default 8, cap 16) sets how many coin-network\n"
        << "        peers the embedded arm holds CONCURRENTLY. This is an EVIDENCE\n"
        << "        knob, not bandwidth: a DKG final commitment (qfcommit) and a\n"
        << "        ChainLock (clsig) are each announced EXACTLY ONCE by inv and\n"
        << "        served only by their own digest, so an announcement you did not\n"
        << "        witness is an object you can never fetch. Holding N peers drops\n"
        << "        the miss probability geometrically -- which is what makes\n"
        << "        \"we hold no commitment, therefore mine null\" trustworthy.\n"
        << "        --web-port PORT (alias --http-port, default 8080) serves the FULL\n"
        << "        c2pool web dashboard + JSON API on --web-host (default 0.0.0.0)\n"
        << "        from --dashboard-dir (default web-static); --web-port 0 disables.\n"
        << "        --embedded-oracle-shadow runs the OBSERVE-only per-block dashd\n"
        << "        cross-check: dashd getblocktemplate{mode:proposal} is the VERDICT,\n"
        << "        regime-aware field-compare is the DIAGNOSIS; a persisted graduation\n"
        << "        ledger + /embedded_oracle verdict signal when the embedded arm is\n"
        << "        proven equivalent (safe to disable dashd, served domain). Needs the\n"
        << "        dashd RPC arm; never changes serving. N/K tune the graduation gate.\n"
        << "        --serve-staleness-sentinel=off DISABLES the report-only\n"
        << "        serve-staleness detector, which is ON by default. It compares\n"
        << "        the height actually handed to miners against an independently\n"
        << "        observed one, from a DEDICATED thread (never the io loop), and\n"
        << "        alarms with [STALE-SERVE]. It is report-only: a log line and a\n"
        << "        node_topology field, never a serve decision. Turn it off only\n"
        << "        if it is noisy -- with it off, a dead height served to miners\n"
        << "        raises NOTHING, which is the 2026-08-07 failure it exists for.\n"
        << "        --embedded-shadow-compare is a SEPARATE, simpler OBSERVE-only\n"
        << "        diagnostic (NOT a serve gate, no graduation state): on every\n"
        << "        template SERVE it best-effort field-compares the served template\n"
        << "        against dashd getblocktemplate at the same height on a WORKER\n"
        << "        thread (off the miner hot path) and logs one [SHADOW] line\n"
        << "        (MATCH / MISMATCH / SERVED-MISMATCH / no-oracle) + counters. Needs\n"
        << "        a reachable dashd RPC arm; a strict no-op in pure-daemonless mode.\n"
        << "        Live sharechain tip/stats, pool hashrate and per-share difficulty\n"
        << "        are bound to the REAL DASH tracker; local hashrate comes from the\n"
        << "        DASH stratum acceptor. If stratum and web ports collide the web\n"
        << "        port moves to stratum+1.\n"
        << "        --replay-bulk (needs --coin-p2p-connect/--coin-p2p-discover) arms\n"
        << "        the FULL-HISTORY REPLAY bulk block-fetch lane (W2): full-genesis\n"
        << "        header backfill join-checked against the fast-start anchor, then\n"
        << "        pipelined multi-peer body fetch from DIP3 (h=1028160) forward,\n"
        << "        merkle-verified, handed IN ORDER to the replay consumer and\n"
        << "        --replay-fold-prestate FILE seeds the W1 DML fold from a\n"
        << "        full-state anchor prestate and makes the bulk lane DRIVE it:\n"
        << "        every delivered body is folded and its computed\n"
        << "        merkleRootMNList compared byte-exact with that block's own\n"
        << "        committed cbTx root (implies --replay-bulk; pins the lane to\n"
        << "        anchor+1). --replay-fold-quorums additionally arms the W4\n"
        << "        quorum lane and hands its DERIVED member sets to the fold's\n"
        << "        resolver, so commitments that mark members invalid fold\n"
        << "        without any anchor-supplied member set;\n"
        << "        --replay-fold-qsnapshot FILE seeds ONLY the pre-anchor\n"
        << "        rotated-cycle snapshots a Phase-1 run cannot have produced.\n"
        << "        THE SERVE SEAM: once the fold is PROVEN CURRENT (not\n"
        << "        poisoned, DIVERGED=none, roots_matched == folded, the list\n"
        << "        re-hashes to the root its last block committed, cursor AT\n"
        << "        the header tip) it publishes that list into the PAYEE queue\n"
        << "        as source=replay-fold, which is what flips the serve gate's\n"
        << "        have_mn on a node with no dashd. Anything short of the full\n"
        << "        guard WITHHOLDS and names the blocking condition; the dashd\n"
        << "        seed and the checkpoint bridge are unchanged.\n"
        << "        --embedded-mn-bridge-no-cursor DISABLES the MN-CKPT\n"
        << "        bridge's persistent replay cursor, so every start replays\n"
        << "        the whole window from the pinned anchor (the pre-#91\n"
        << "        behaviour). Default ON: the bridge saves the set it has\n"
        << "        actually folded, with the height and block hash it folded\n"
        << "        to and the anchor it descends from, and a restart RESUMES\n"
        << "        there instead of re-walking ~3900 blocks at one window per\n"
        << "        tip change. A record that cannot be tied to this build's\n"
        << "        anchor, to our own header chain at that height, and to a\n"
        << "        contiguous span from the anchor is DISCARDED (cold start,\n"
        << "        naming the rule) — it is never half-resumed. Use this flag\n"
        << "        to measure cold-vs-warm on one binary.\n"
        << "        --embedded-no-dashd-mn-seed cuts the PAYEE axis off from a\n"
        << "        configured dashd (no `protx list` seed, no checkpoint\n"
        << "        bridge) while KEEPING the RPC for --embedded-shadow-compare:\n"
        << "        the posture in which a serve-vs-dashd parity run actually\n"
        << "        measures a DAEMONLESS serve instead of a dashd-seeded one.\n"
        << "        PRUNED (bodies never persisted). Strictly lower priority than\n"
        << "        the tip lane; resumable (high-water cursor); [BULK] telemetry.\n"
        << "        OBSERVE-only in W2 (counting consumer stands in for the W1 fold);\n"
        << "        NEVER changes serving. --replay-bulk-capture DIR additionally\n"
        << "        caches raw bodies into append-only segment files (fleet re-fold\n"
        << "        cache; implies --replay-bulk). --replay-bulk-start H overrides\n"
        << "        the first fetched height (default: mainnet DIP3 1028160).\n"
        << "        --dump-mn-checkpoint H FILE serializes the --replay-fold DML\n"
        << "        set at height H to the checkpoint .inc at FILE, SELF-DERIVED\n"
        << "        from the fold's own root-checked state (no dashd RPC, no\n"
        << "        protx snapshot; registered-not-valid; reuses the runtime\n"
        << "        parser field order + digest, self-verifies before writing).\n"
        << "        --external-ip ADDR (alias --stratum-advertise / --public-host)\n"
        << "        overrides the miner-facing host shown in the dashboard Stratum\n"
        << "        URL -- for NAT / port-mapped nodes whose outbound IP is not the\n"
        << "        address miners dial; unset => auto-detect (no regression).\n"
        << "        --message-blob-hex HEX (alias --transition-message) supplies an\n"
        << "        encrypted authority-signed message_data blob (from\n"
        << "        util/create_transition_message.py). Validated against the DASH\n"
        << "        authority keys; drives the dashboard transition-notice panel now,\n"
        << "        and is embedded in locally minted shares once v36 shares activate\n"
        << "        (the live v16 wire has no message_data field). No consensus effect.\n"
        << "Consensus: X11 PoW + block identity; 2.5 min spacing; 5 DASH post-V20\n"
        << "        base, -1/14 per 210240; masternode payment 3/4 of block value.\n";
}

// Serialize an 80-byte DASH block header (LE; host is LE on the x86_64 target).
void serialize_header(unsigned char out[80], uint32_t version, const char* prev_hex,
                      const char* merkle_hex, uint32_t time, uint32_t bits, uint32_t nonce)
{
    uint256 prev_block;  prev_block.SetHex(prev_hex);
    uint256 merkle_root; merkle_root.SetHex(merkle_hex);
    size_t off = 0;
    std::memcpy(out + off, &version, 4);             off += 4;
    std::memcpy(out + off, prev_block.data(), 32);   off += 32;
    std::memcpy(out + off, merkle_root.data(), 32);  off += 32;
    std::memcpy(out + off, &time, 4);                off += 4;
    std::memcpy(out + off, &bits, 4);                off += 4;
    std::memcpy(out + off, &nonce, 4);               off += 4;
}

// (1) The oracle CoinParams factory is wired and self-consistent, AND the X11
//     pow_func is reachable through the coin-params seam (the path the work
//     source + block-identity checks consume).
int check_coin_params()
{
    const core::CoinParams main = dash::make_coin_params(/*testnet=*/false);
    const core::CoinParams test = dash::make_coin_params(/*testnet=*/true);

    int fails = 0;
    auto want = [&](bool ok, const char* what) {
        std::cout << "[selftest]   coin_params: " << what << (ok ? " ok\n" : " FAIL\n");
        if (!ok) ++fails;
    };
    want(main.symbol == "DASH",            "symbol == DASH");
    // CoinParams.p2p_port is the SHARECHAIN/pool peer port (dash::PoolConfig SSOT),
    // distinct from the DASH coin-daemon P2P port (9999/19999) wired in slice-1's
    // get_coin_p2p_port. Assert the sharechain SSOT here.
    want(main.p2p_port == 8999,            "mainnet sharechain p2p_port == 8999 (SSOT)");
    want(test.p2p_port == 18999,           "testnet sharechain p2p_port == 18999 (SSOT)");
    want(main.current_share_version == 16, "share_version == 16 (older-than-v35 baseline)");
    want(main.address_version == 76,       "mainnet pubkey addr version == 76 (X...)");
    want(static_cast<bool>(main.pow_func), "pow_func wired");

    // Drive X11 THROUGH the CoinParams pow_func seam against the genesis header.
    if (main.pow_func) {
        unsigned char hdr[80];
        serialize_header(hdr, 1, "0000000000000000000000000000000000000000000000000000000000000000",
            "e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7",
            1390095618u, 0x1e0ffff0u, 28917698u);
        const uint256 pow = main.pow_func(std::span<const unsigned char>(hdr, 80));
        const bool ok = pow.GetHex() == "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6";
        want(ok, "pow_func(genesis) reproduces genesis hash");
    }
    return fails;
}

// (2) X11 PoW KATs: mainnet genesis + a real-node testnet3 block (CI-pinned,
//     test_dash_x11_kat.cpp). Pins BLAKE->...->ECHO end to end via the direct
//     dash::crypto::hash_x11 entry.
int check_x11_kats()
{
    int fails = 0;
    struct Vec { const char* name; uint32_t v; const char* prev; const char* merkle;
                 uint32_t t; uint32_t bits; uint32_t nonce; const char* expect; };
    const Vec vecs[] = {
        { "mainnet-genesis", 1,
          "0000000000000000000000000000000000000000000000000000000000000000",
          "e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7",
          1390095618u, 0x1e0ffff0u, 28917698u,
          "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6" },
        { "testnet3-#1497944", 536870912u,
          "000000dbbc08ee519459b38b02bb7754b455dd00cd74069a1352f08f0dd986db",
          "0464a4ac5f058a742f6aa42b2b3c7489abde7609b529612bcfa5da34b10bdb1b",
          1781737170u, 0x1e00f256u, 721236u,
          "000000b6a4e5ea1a0854ef83f0028dde5b96cdaacc604decd8b064d0cea38234" },
    };
    for (const auto& vc : vecs) {
        unsigned char hdr[80];
        serialize_header(hdr, vc.v, vc.prev, vc.merkle, vc.t, vc.bits, vc.nonce);
        const uint256 pow = dash::crypto::hash_x11(hdr, sizeof(hdr));
        const bool ok = pow.GetHex() == vc.expect;
        std::cout << "[selftest]   x11 KAT " << vc.name << ": " << pow.GetHex()
                  << (ok ? " ok\n" : " FAIL\n");
        if (!ok) ++fails;
    }
    return fails;
}

// (3) Subsidy: post-V20 block reward + 3/4 MN payment (test_dash_subsidy.cpp,
//     live-validated against dashd getblocktemplate at h=2459985).
int check_subsidy()
{
    int fails = 0;
    const int64_t reward = compute_dash_block_reward_post_v20(2459985);
    const bool r_ok = reward == 177'022'505LL;
    std::cout << "[selftest]   subsidy h=2459985 reward = " << reward
              << (r_ok ? " ok\n" : " FAIL (want 177022505)\n");
    if (!r_ok) ++fails;

    const int64_t mn = compute_dash_mn_payment_post_v20(200'000'000LL);
    const bool mn_ok = mn == 150'000'000LL;
    std::cout << "[selftest]   masternode payment 3/4 of 2.0 DASH = " << mn
              << (mn_ok ? " ok\n" : " FAIL (want 150000000)\n");
    if (!mn_ok) ++fails;
    return fails;
}

int run_selftest()
{
    std::cout << "[selftest] driving live DASH consensus (network-free)\n";
    int fails = 0;
    fails += check_coin_params();
    fails += check_x11_kats();
    fails += check_subsidy();
    if (fails == 0) {
        std::cout << "[selftest] OK — CoinParams + X11 PoW + subsidy all conform to oracle\n";
        return 0;
    }
    std::cout << "[selftest] FAIL — " << fails << " consensus check(s) failed\n";
    return 1;
}

// --run: stand up a real run-loop and ARM the external-dashd submitblock fallback
// arm (rpc.cpp submit_block_hex -- the RPC leg of the won-block dual-path
// broadcaster). The embedded-P2P relay leg is still S8-deferred; this slice lights
// the dashd-RPC sink so a won DASH block CAN reach the network today.
//
// Creds posture (operator self-provision, 2026-06-19): the rpcpassword NEVER
// reaches the process table. --coin-rpc HOST:PORT carries only the endpoint;
// rpcuser/rpcpassword come from dash.conf (default ~/.dashcore/dash.conf, override
// --coin-rpc-auth PATH). No creds (or no port) => the arm stays UNARMED and
// submit_block_hex is never reached -- the run-loop still stands up cleanly.
//
// --submit-block HEX drives ONE real submitblock against the configured dashd and
// reports accept/reject, then exits: the G2 "won-block-reaches-network" evidence
// lever (point it at the VM200/201 dashd). NodeRPC::Send is synchronous with a
// blocking sync_reconnect fallback, so the submit self-connects -- no async race.
// A synthetic-only pass does NOT earn block-viable; the live dashd-reached run is
// the gate.
//
// --coin-p2p-connect HOST:PORT (repeatable) — E1 OPT-IN embedded coin-network
// dial. ABSENT (the released/prod path): no coin P2P client is instantiated,
// NodeCoinState stays default-unpopulated, and get_work() keeps taking the
// retained dashd-RPC fallback — byte-identical run_node behavior. PRESENT:
// a dash::coin::p2p::CoinClient dials the given dashd P2P endpoint(s)
// (version/verack handshake, ping keep-alive, 30s reconnect rotating over
// repeated targets). E1 establishes + maintains the connection only; the
// ingest legs that would populate NodeCoinState are later slices, so the
// fallback arm still serves templates even WITH the flag.
// Fee/donation flags (README design, LTC-path port — see the mint wiring):
//   dev_donation        --give-author (donation_percentage), default 0.1%
//   node_owner_fee      -f/--fee (node_owner_fee), default 0
//   node_owner_address  --node-owner-address (fee destination, P2PKH)
//   redistribute_mode   --redistribute (pplns/fee/boost/donate)
int run_node(bool testnet, const std::string& rpc_endpoint,
             const std::string& rpc_conf_path, const std::string& submit_hex,
             const PeeringConfig& peer,
             const std::string& stratum_host, uint16_t stratum_port,
             const std::string& web_host, uint16_t web_port,
             const std::string& dashboard_dir,
             const std::vector<NetService>& coin_p2p_targets,
             bool coin_p2p_discover,
             bool embedded_utxo,
             double dev_donation, double node_owner_fee,
             const std::string& node_owner_address,
             const std::string& redistribute_mode,
             bool no_p2p_relay,
             bool embedded_mainnet,
             const std::string& coin_zmq_hashblock,
             const std::string& external_ip,
             const std::string& coin_p2p_magic_hex,
             bool force_won_block,
             const std::string& operator_message_blob_hex,
             bool embedded_superblock,
             bool embedded_oracle_shadow = false,
             uint64_t oracle_grad_blocks = 5000,
             uint64_t oracle_class_coverage = 20,
             // --coin-p2p-peers N: how many CONCURRENT coin-network peers the
             // embedded arm holds. Not a throughput knob: qfcommit/clsig are
             // announced exactly once each, so miss probability falls
             // geometrically in this number (see p2p_client.hpp).
             std::size_t coin_p2p_peers =
                 dash::coin::p2p::CoinClient<dash::Config>::DEFAULT_POOL_PEERS,
             const std::string& bestcl_policy = "freshness",
             // --embedded-utxo-immature-serve-empty: pure-daemonless OPT-IN --
             // during the blocks_connected<106 window serve a coinbase-only
             // (empty mempool tx set) template: consensus-valid, fees exactly 0,
             // nothing to overstate. Default false = REFUSE the window (p2pool
             // semantics: an unsynced node does not serve templates; the dashd
             // fallback serves full ones where armed) -- the pre-policy behaviour.
             bool embedded_utxo_immature_serve_empty = false,
             // --embedded-serve-mempool-txs: OPT-IN fee-carrying embedded
             // templates. Default false = coinbase-only body even with a
             // mature UTXO lane (cause "mempool-txs-disabled"); the mempool-tx
             // body path (G1-G4 guards, mempool.hpp) only enters block
             // production when the operator explicitly arms it.
             bool embedded_serve_mempool_txs = false,
             // --embedded-shadow-compare: OBSERVE-only serve-vs-dashd block-
             // template field diff (diagnostic; NOT a serve gate). Off the hot
             // path (worker-thread dashd fetch). Default false; only meaningful
             // when a dashd RPC oracle is reachable — a strict no-op otherwise.
             bool embedded_shadow_compare = false,
             // --embedded-mempool-ingest: arm the coin-P2P MSG_TX pull so the
             // mempool actually FILLS. Phase 1 of c2pool's own DASH mempool
             // (the/docs/DASH-OWN-MEMPOOL-DESIGN.md). Default false: turning it
             // on changes what this node asks its peers for. It does NOT by
             // itself put a single transaction into a served template — that
             // remains --embedded-serve-mempool-txs' decision, gated on the
             // [MEMPOOL-VALIDITY] testmempoolaccept series
             // (mempool_validity_gate.hpp) -- NOT on the [SHADOW-TXSET]
             // ours_only coverage number, which is informational.
             bool embedded_mempool_ingest = false,
             // --pin-local-tx-hex <file>: PINNED LOCAL TX (donation-dust
             // consolidation). File holds the hex of an externally-signed,
             // ZERO-fee tx spending our own P2PKH outputs; it rides OUR OWN
             // embedded template (relay rejects 0-fee, so self-mining is its
             // only chain-ward path). Parsed once here; per-template admission
             // (inputs unspent + coinbase-mature + fee exactly 0) is re-gated
             // in the builder against the live UTXO view — a bad or already-
             // mined pin is EXCLUDED, never a refused template, never a lost
             // block. Empty (default) = no pin, byte-unchanged.
             const std::string& pin_local_tx_hex_path = std::string(),
             // --serve-staleness-sentinel=off: KILL SWITCH for the report-only
             // serve-staleness sentinel (2026-08-07 dead-height incident). It
             // is DEFAULT ON, which the money-path flag rule permits because it
             // changes NOTHING about what is served: its only outputs are a log
             // line and a JSON field. The flag exists for ops hygiene (a noisy
             // detector must be silenceable without a redeploy), not for
             // safety — there is no code path from an alarm to a serve
             // decision. See coin/serve_staleness.hpp for why report-only was
             // chosen over a detector that can stop serving.
             bool serve_staleness_sentinel = true,
// --embedded-creditpool-publish-at-serve-tip: publish the derived
             // DIP-0027 credit pool AT THE SERVE TIP instead of at the folded
             // body height (dashd derives the pool for the block you ask
             // about -- creditpool.cpp:224 GetCreditPool(block_index), read at
             // pindexPrev by both the template and validation paths). Removes
             // the `creditpool-stale value=threshold+1` window that opens when
             // the fourth-axis conjunct holds promotion. MONEY PATH: it makes
             // the arm SERVE where it previously refused, so default false.
             // Only meaningful on the body-first (coin-P2P daemonless) arm.
             bool embedded_creditpool_publish_at_serve_tip = false,
             // --pin-splice-xcheck-arm: let the pinned txs ride a template the
             // GBT cross-check SWAPPED IN. DEFAULT OFF -- money path.
             //
             // The cross-check discards an embedded template that already
             // carries the pins and serves a fresh dashd one; that replacement
             // has never run the splice. Measured on the primary 2026-08-07,
             // 66 of 197 served fallback templates came from that swap and one
             // of them won h=2518044 without the donation. OFF, the miss is now
             // NAMED (cause=xcheck-swap-pin-gate-off) and served bytes are
             // unchanged; ON, the pins ride it too, through the same unchanged
             // admission gate plus a height check and a block-size budget that
             // can only EXCLUDE.
             bool pin_splice_xcheck_arm = false,
             // --pin-splice-block-budget: ENFORCE the block-level size budget
             // in the pin splice. DEFAULT OFF -- money path.
             //
             // The budget caps a pin against what the template already holds
             // (2 MB minus a named reserve). Enforcing it turns an inclusion
             // into an exclusion on the declined-embedded arm, which has been
             // splicing pins onto served templates in production since before
             // this flag existed -- so it CHANGES SERVED BYTES and may not
             // default on. OFF, the overflow is a WARNING and a recorded flag
             // on the template; ON, the pin is excluded with cause=block-budget
             // (block 2517855 was lost to bad-txns-oversize).
             bool pin_splice_block_budget = false,
             // --embedded-accrue-asset-locks (#107 PHASE 2): accrue the pending
             // type-8 DIP-0027 asset-lock term into the embedded CbTx
             // creditPoolBalance so it matches dashd's and the
             // gbt-xcheck-modulo-special-explained swap stops firing on the
             // type-8-only case. DEFAULT OFF — money/consensus path. A block
             // committing this accrual is valid ONLY once the same type-8 txs
             // ride the served body (tx-serving, blocked on #125); with a
             // coinbase-only body a submitted block is bad-cbtx-assetlocked-
             // amount. See asset_lock_fold.hpp + set_accrue_pending_asset_locks.
             bool embedded_accrue_asset_locks = false,
             // --embedded-null-arm (#127): SUB-arm of the embedded arm. When
             // a DKG mining-window slot is required and not-yet-mined on a
             // view PROVEN fresh to the tip, serve the consensus-valid NULL
             // commitment optimistically (dashd's own GetMineableCommitments
             // behaviour, llmq/blockprocessor.cpp:748-762) instead of failing
             // the whole height to the dashd fallback; the normal
             // work-generation refresh upgrades the template to the REAL
             // commitment the instant it arrives (null does not set
             // HasMinedCommitment, so the real can still be mined). DEFAULT
             // OFF, money/consensus path: when off the null_evidence argument
             // at the build_daemonless_qc_plan call site is literally nullptr
             // and every served template + decline decision is byte-identical
             // to master. Freshness unproven => no null => dashd fallback
             // (worst case = today's benign gap, never a reject). Only has
             // effect when the embedded arm is already enabled.
             bool embedded_null_arm = false,
             // --embedded-accrue-asset-unlocks (#143 Variant B): DEFAULT OFF.
             // Admit BLS-verified type-9 asset-unlock txs into the embedded
             // template ONLY under the CreditPool INDEX follower's full
             // fail-closed predicate (credit_pool_idx.hpp: proven-complete
             // gap-free index since the v20 floor, fresh at the template's
             // exact parent, per-candidate quorumSig/limit/window/dedup).
             // OFF => the AssetUnlockAdmission* seam at the single
             // build_embedded_workdata call site is literally nullptr and
             // every served template is byte-identical to today's
             // exclude-all. ON without a seeded+proven follower lane (the
             // live 531k-block seed is a follow-up soak) still yields
             // exclude-all — the predicate, not the flag, admits.
             bool embedded_accrue_asset_unlocks = false,
             // --embedded-ingest-isdlock: arm the BLS-verified isdlock lane
             // (new_isdlock → maintainer BLS gate → G4 conflict-tx-lock
             // adoption). DEFAULT OFF: the MSG_ISDLOCK pull itself and the
             // fee-only-safe new_islock feed (#1230) run unconditionally;
             // off, the handler never fires new_isdlock, so the VERIFIED
             // adoption path stays dormant. ON, every isdlock is
             // individually BLS-gated against the rotated LLMQ_60_75 quorum
             // dashd's SelectQuorumForSigning designates (islock_verify.hpp;
             // fail-closed at every hop).
             bool embedded_ingest_isdlock = false)
{
    namespace io = boost::asio;

    dash::coin::RpcConf conf;
    std::string conf_path = rpc_conf_path;
    if (conf_path.empty()) {
        const char* home = std::getenv("HOME");
        conf_path = std::string(home ? home : ".") + "/.dashcore/dash.conf";
    }
    dash::coin::load_rpc_conf(conf_path, conf);
    dash::coin::apply_endpoint_override(rpc_endpoint, conf);
    if (conf.port == 0)
        conf.port = testnet ? 19998 : 9998;   // dashd default RPC ports

    io::io_context ioc;

    // Miner-facing Stratum acceptor handle, declared BEFORE the signal_set so
    // the shutdown callback can stop it (cancel acceptor + close sessions)
    // ahead of ioc.stop(). Populated below once the DASHWorkSource is built.
    std::unique_ptr<core::StratumServer> stratum_server;

    io::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&ioc, &stratum_server](const boost::system::error_code&, int) {
        std::cout << "[run] shutdown signal -- stopping run-loop\n";
        // Stop stratum BEFORE ioc.stop() so the acceptor cancels and live miner
        // sessions close cleanly (their pending async ops unwind on the loop).
        if (stratum_server)
            stratum_server->stop();
        ioc.stop();
    });

    dash::interfaces::Node coin_state;
    std::unique_ptr<dash::coin::NodeRPC> rpc;
    // DASHD-CUT arm authority (hotel-reserve thrash fix). The dashd-fallback
    // CoindRPC is constructed ONLY when the operator EXPLICITLY named a coin RPC
    // -- via --coin-rpc / --coin-daemon (endpoint), --coin-rpc-auth (creds path),
    // or a dashd-only one-shot on this path (--submit-block) -- AND creds
    // resolved. With NONE of those the node is in DAEMONLESS CUT MODE: rpc stays
    // nullptr, the embedded/null arm is authoritative, and a stray
    // ~/.dashcore/dash.conf can no longer re-arm a hot-spinning fallback behind
    // the operator's back (conf.armed() alone used to do exactly that, which is
    // why removing --coin-rpc was cosmetic). See rpc_conf.hpp::resolve_dashd_arm.
    const bool coin_rpc_requested =
        !rpc_endpoint.empty() || !rpc_conf_path.empty() || !submit_hex.empty();
    const dash::coin::DashdArmDecision arm_decision =
        dash::coin::resolve_dashd_arm(coin_rpc_requested, conf.armed());
    if (arm_decision.construct_rpc) {
        rpc = std::make_unique<dash::coin::NodeRPC>(&ioc, &coin_state, testnet);
        rpc->connect(NetService(conf.host, conf.port), conf.userpass());
        std::cout << "[run] external-daemon submit arm ARMED: NodeRPC -> "
                  << conf.host << ":" << conf.port << " (creds from dash.conf) -- "
                  << arm_decision.reason << "\n";
    } else {
        std::cout << "[run] external-daemon submit arm DISARMED -- "
                  << arm_decision.reason
                  << ".\n[run]       the embedded coin-P2P relay is the primary "
                     "won-block path (daemonless) when --coin-p2p-connect / "
                     "--coin-p2p-discover is set.\n";
    }

    // One-shot submit: the G2 won-block-reaches-network evidence path.
    if (!submit_hex.empty()) {
        if (!rpc) {
            std::cout << "[run] --submit-block given but submit arm UNARMED; supply "
                         "dashd creds via dash.conf or --coin-rpc-auth PATH\n";
            return 2;
        }
        std::cout << "[run] submitting block (" << submit_hex.size() / 2
                  << " bytes) to dashd " << conf.host << ":" << conf.port << "...\n";
        const bool accepted = rpc->submit_block_hex(submit_hex, /*ignore_failure=*/false);
        std::cout << "[run] submitblock " << (accepted ? "ACCEPTED" : "REJECTED")
                  << " by dashd\n";
        return accepted ? 0 : 1;
    }

    report_peering(peer, testnet);

    // ── S8-p2p.3: bind the REAL sharechain P2P listener ───────────────────
    // node.cpp reception bodies landed (#656/#657), so dash::Node is now fully
    // linkable and --run opens an actual socket instead of only echoing the
    // topology. Mirrors the dgb::Node bring-up (src/c2pool/main_dgb.cpp).
    dash::SharechainConfig::is_testnet = testnet;

    // Effective coinbase scriptSig text, resolved from the coin SSOT (operator
    // --coinbase-text override, else the network default). Logged at startup so
    // the bytes explorers will see are visible without decoding a block.
    std::cout << "[run] coinbase text: \""
              << dash::SharechainConfig::coinbase_text(testnet) << "\""
              << (dash::SharechainConfig::coinbase_text_override.empty()
                      ? " (default; --coinbase-text to customize)"
                      : " (--coinbase-text override)")
              << "\n";

    // Bucket-1 ISOLATION PRIMITIVE: DASH keeps its own net subdir + PREFIX,
    // per-coin AND per-pool-instance, in v36 and v37 — never standardised.
    const std::string net_subdir = testnet ? "dash_testnet" : "dash";
    std::error_code mkdir_ec;
    std::filesystem::create_directories(
        core::filesystem::config_path() / net_subdir, mkdir_ec);  // best effort

    dash::Config config(net_subdir);
    // PREFIX sourced from the frstrtr/p2pool-dash oracle constants (SharechainConfig).
    config.pool()->m_prefix = ParseHexBytes(dash::SharechainConfig::prefix_hex());
    config.m_testnet        = testnet;
    // --addnode (persistent outbound) + --connect (connect-only) both seed the
    // bootstrap addr store the NodeImpl ctor dials via start_outbound_connections().
    for (const auto& a : peer.addnodes)  config.pool()->m_bootstrap_addrs.push_back(a);
    for (const auto& c : peer.connects)  config.pool()->m_bootstrap_addrs.push_back(c);

    dash::Node p2p_node(&ioc, &config);

    // ── Mint slice 3/3: consensus params + sharechain persistence ────────
    // The tracker's CoinParams carry the X11 pow_func + targets every
    // reception/mint verify consumes — MUST be set before any share is
    // processed (an empty pow_func fails every share_init_verify).
    const core::CoinParams mint_params = dash::make_coin_params(testnet);
    p2p_node.tracker().m_coin_params = mint_params;
    // Live-template source for the dashboard PPLNS view. The WebServer seams
    // are bound (and web_server->start() runs) well BEFORE DASHWorkSource
    // exists, so the payout callbacks cannot capture the work source directly
    // and a bare std::function assigned later would race the already-serving
    // IO thread. TemplateSource publishes the peek under its own mutex and
    // copies it out before calling. Until it is bound the PPLNS view answers
    // an empty document — "no template yet", never a fabricated subsidy.
    auto dash_tmpl = std::make_shared<dash::dashboard::TemplateSource>();
    // LevelDB sharechain store under the SAME per-net subdir as the rest of
    // the node state (bucket-1 isolation), loading any persisted shares.
    p2p_node.init_storage(net_subdir);

    // --connect (connect-only, no --listen) suppresses the inbound listener,
    // matching report_peering() above.
    const bool connect_only = !peer.connects.empty() && !peer.listen_set;
    const uint16_t bind_port =
        peer.listen_port ? peer.listen_port : dash::SharechainConfig::p2p_port();
    if (!connect_only) {
        // #755: an uncaught bind failure (EADDRINUSE from a lingering prior
        // instance) here threw boost::system::system_error straight through
        // main -> terminate -> Exit 134 core dump. The log made it LOOK like
        // a share-load crash (the throw lands right after the "Loaded N
        // persisted shares" lines). Fail CLEANLY with the actual reason.
        try {
            p2p_node.core::Server::listen(bind_port);
        } catch (const std::exception& e) {
            std::cerr << "[run] FATAL: cannot bind sharechain P2P port "
                      << bind_port << ": " << e.what()
                      << "\n[run] (another c2pool-dash instance running? "
                         "stop it or pass a different --listen port)\n";
            return 1;
        }
        std::cout << "[run] sharechain peer LISTENING on " << peer.listen_host << ":"
                  << bind_port
                  << " — min-proto=" << dash::SharechainConfig::MINIMUM_PROTOCOL_VERSION
                  << " prefix=" << dash::SharechainConfig::prefix_hex() << "\n";
    } else {
        // Symmetry with the LISTENING branch above: the --connect leg frames
        // every outbound packet with this same prefix (pool/node.hpp:88
        // get_prefix), so it must be observable on the connect path too — a
        // peered regtest showed the listen leg logged prefix= but the connect
        // leg did not, leaving connect-mode prefix agreement unverifiable from
        // the log alone.
        std::cout << "[run] --connect mode: inbound listener suppressed"
                  << " — min-proto=" << dash::SharechainConfig::MINIMUM_PROTOCOL_VERSION
                  << " prefix=" << dash::SharechainConfig::prefix_hex() << "\n";
    }
    // #754 download/outbound slice: ACTIVE outbound dialing from the addr
    // store (--addnode/--connect seeds registered by the NodeImpl ctor) plus
    // the share-download pumps (handshake best-share advert drain here;
    // think()'s desired-set dispatch rides run_think). This is what lets an
    // EMPTY node JOIN an established p2pool-dash chain instead of only
    // serving inbound peers.
    p2p_node.start_outbound_connections();
    if (!config.pool()->m_bootstrap_addrs.empty())
        std::cout << "[run] outbound dialing started ("
                  << config.pool()->m_bootstrap_addrs.size()
                  << " seed peer[s]); share-download leg ARMED\n";


    // ── Local-mint orphan/sibling gauge (display only) ────────────────────
    // Declared HERE (before the dashboard wiring) because two later blocks
    // need it: the sharechain stats fn reads it, and the mint fn records into
    // it. shared_ptr so both closures can hold it without lifetime coupling to
    // this frame. Nothing consensus-visible reads this — see
    // local_mint_ledger.hpp.
    auto mint_ledger = std::make_shared<dash::mint::LocalMintLedger>();

    // ── DASH web dashboard standup (the EXISTING c2pool dashboard) ────────
    // This is main_ltc.cpp's WebServer wiring, reused verbatim where the DASH
    // side has a real source for the datum. No stub metrics are invented: a
    // stat with no live DASH producer in this slice is left UNSET so the
    // dashboard reports its own honest "absent" state rather than a zero that
    // reads as a real measurement.
    //
    // Runs on THIS ioc (WebServer moves HTTP onto its own thread internally),
    // declared AFTER p2p_node so the callbacks it holds never outlive the node.
    //
    // DELIBERATE DIVERGENCE FROM main_ltc.cpp: we do NOT call
    // web_server.set_stratum_port(). On the LTC path that setter makes
    // WebServer::start() construct its OWN core::StratumServer driven by
    // MiningInterface (web_server.cpp:8409 -> start_stratum_server, :8722).
    // c2pool-dash already binds its own core::StratumServer to the
    // DASHWorkSource below; setting it here would double-bind the port and
    // serve X11 miners from the LTC work source. The dashboard is told the
    // miner-facing port through mining_interface->set_worker_port() (display)
    // and fed real stratum rates from the DASH acceptor after it starts.
    // Embedded ORACLE-SHADOW validator (--embedded-oracle-shadow). Declared here
    // (before web_server) so the /embedded_oracle endpoint closure can read it;
    // constructed + subscribed to the tip event later in the coin_p2p block, once
    // node_coin_state exists. OBSERVE-only: stats_json() touches no serving state.
    std::shared_ptr<dash::coin::EmbeddedOracleShadow> oracle_shadow;

    std::unique_ptr<core::WebServer> web_server;
    auto enhanced_node = std::make_shared<dash::EnhancedDashNode>(testnet);
    if (web_port != 0) {
        web_server = std::make_unique<core::WebServer>(
            ioc, web_host, web_port, testnet,
            std::static_pointer_cast<core::IMiningNode>(enhanced_node),
            c2pool::address::Blockchain::DASH);

        auto* mi = web_server->get_mining_interface();

        // ── Peer-info liveness: serialize the HTTP-cache rebuild onto the
        // io_context thread (main_ltc.cpp parity). Once the io_context is wired,
        // thread_safe_wrap serves the WebServer's HTTP thread a published RCU
        // snapshot (CacheEntry::get) while the periodic refresh below rebuilds
        // those caches on THIS thread — the same thread that mutates the
        // peer/tracker containers in think(). That removes the dashboard-thread-
        // vs-think() read race at its source (the GP-fault crash class),
        // completing the wiring that mark_last_cache_tip_driven() below and the
        // already-merged published-snapshot reads (#828/#830) were built for.
        // Defense-in-depth: the snapshots keep the read safe on any thread; this
        // keeps the rebuild off the HTTP thread. Threading/liveness only — no
        // share/consensus/subsidy/payout path is touched.
        mi->set_io_context(&ioc);

        // ── Real, non-negotiable node identity ────────────────────────────
        mi->set_coin_label("DASH");

        // --- Stats persistence: load prior graph_db on start (DASH) ---
        // Parity with main_ltc.cpp:1968 — restores the persisted stat_log so
        // hashrate/DOA history survives node restarts instead of resetting to
        // empty on every bounce. Same per-net data dir + WebServer stat_log
        // machinery already in master; display/history only, no consensus path.
        {
            std::string graph_db_path = (core::filesystem::config_path()
                / net_subdir / "graph_db").string();
            mi->set_stat_log_path(graph_db_path);
            mi->load_stat_log();
        }

        // --- Persistent found-block storage (DASH) ---
        // Parity with main_ltc.cpp:1977 — won DASH blocks survive node
        // restarts on the dashboard /recent_blocks + history cards instead of
        // vanishing every bounce. Dedicated LevelDB under the per-net data
        // dir. Persistence/display only; touches no share/consensus path.
        {
            std::string fblk_db_path = (core::filesystem::config_path()
                / net_subdir / "found_blocks_db").string();
            auto fblk_leveldb = std::make_shared<core::LevelDBStore>(
                fblk_db_path, core::LevelDBOptions{});
            if (fblk_leveldb->open()) {
                auto fblk_store = std::make_shared<c2pool::storage::FoundBlockStore>(*fblk_leveldb);
                using MI = core::MiningInterface;
                mi->set_found_block_persistence(
                    [fblk_store, fblk_leveldb](const MI::FoundBlock& blk) -> bool {
                        c2pool::storage::FoundBlockRecord rec;
                        rec.chain = blk.chain;
                        rec.height = blk.height;
                        rec.block_hash = blk.hash;
                        rec.timestamp = blk.ts;
                        rec.status = static_cast<uint8_t>(blk.status);
                        rec.check_count = blk.check_count;
                        rec.confirmations = blk.confirmations;
                        rec.last_checked = static_cast<uint64_t>(std::time(nullptr));
                        return fblk_store->store(rec);
                    },
                    [fblk_store, fblk_leveldb]() -> std::vector<MI::FoundBlock> {
                        auto records = fblk_store->load_all();
                        std::vector<MI::FoundBlock> result;
                        result.reserve(records.size());
                        for (const auto& rec : records) {
                            MI::FoundBlock blk;
                            blk.height = rec.height;
                            blk.hash = rec.block_hash;
                            blk.ts = rec.timestamp;
                            blk.status = static_cast<MI::BlockStatus>(rec.status);
                            blk.check_count = rec.check_count;
                            blk.chain = rec.chain;
                            blk.confirmations = rec.confirmations;
                            result.push_back(std::move(blk));
                        }
                        return result;
                    }
                );
                mi->load_persisted_found_blocks();
                LOG_INFO << "[Pool] DASH found-block persistence enabled at " << fblk_db_path;
            } else {
                LOG_WARNING << "[Pool] DASH found-block persistence DISABLED (LevelDB open failed at "
                            << fblk_db_path << ")";
            }
        }
#ifdef C2POOL_VERSION
        mi->set_pool_version("c2pool/" C2POOL_VERSION);
#endif
        mi->set_worker_port(stratum_port);   // display only (see divergence note)
        mi->set_p2p_port(bind_port);
        // Serve the operator-advertised miner-facing host (--external-ip) so
        // the dashboard Stratum URL renders the NAT-external address miners
        // actually dial, not the auto-detected outbound gateway IP. Unset =>
        // MiningInterface keeps its auto-detect path (no regression).
        if (!external_ip.empty())
            mi->set_external_ip(external_ip);
        // p2pool-compat protocol_version for /local_stats. The core seam
        // documents this exact value for DASH (web_server.hpp:565) and it
        // matches the sharechain SSOT floor.
        mi->set_protocol_version(
            static_cast<int>(dash::SharechainConfig::MINIMUM_PROTOCOL_VERSION));
        // c2pool-dash drives its own work pipeline (DASHWorkSource), so the
        // WebServer's internal refresh_work()/m_cached_template gating would
        // hold the dashboard on the loading page forever. This seam exists in
        // core for exactly this caller (web_server.hpp:557).
        mi->set_dashboard_always_ready(true);
        // Truthful /api/node_topology has_rpc: c2pool-dash reaches its daemon
        // through the external dashd NodeRPC arm (armed above when creds
        // resolved), not an ICoinNode, so tell the dashboard RPC is present.
        mi->set_coin_rpc_available(static_cast<bool>(rpc));

        // ── /embedded_oracle stats endpoint (OBSERVE-only) ────────────────
        // JSON coverage ledger + objective GRADUATION verdict (safe-to-disable-
        // dashd gate). Reads the shadow validator's own structures; never the
        // serving path. Empty/disabled shape when --embedded-oracle-shadow off.
        mi->set_embedded_oracle_fn([&oracle_shadow]() -> nlohmann::json {
            if (oracle_shadow) return oracle_shadow->stats_json();
            return nlohmann::json{{"mode", "disabled"},
                {"note", "run with --embedded-oracle-shadow to enable"}};
        });

        web_server->set_dashboard_dir(dashboard_dir);
        // Explicitly DISABLE the WebServer's own stratum acceptor. Its ctor
        // defaults stratum_port_ to (web_port + 10) (web_server.cpp:8330/8344/
        // 8358) and start() binds it unconditionally when non-zero
        // (web_server.cpp:8409 -> start_stratum_server, :8719), which on the
        // DASH path silently opened a SECOND miner-facing listener driven by
        // MiningInterface instead of DASHWorkSource (observed on the first
        // smoke run: "StratumServer started on 0.0.0.0:18909" for --web-port
        // 18899). c2pool-dash owns its stratum acceptor; this is the one place
        // the LTC wiring cannot be reused verbatim.
        web_server->set_stratum_port(0);

        // ── REAL sharechain tip (ported from main_ltc.cpp:3860) ───────────
        // std::nullopt is the honest "sharechain still bootstrapping" signal;
        // never a fabricated height.
        {
            dash::Node* node_ptr = &p2p_node;
            mi->set_sharechain_tip_fn(
                [node_ptr]() -> std::optional<core::SharechainTip> {
                    auto guard = node_ptr->read_tracker();
                    if (!guard) {
                        auto snap = node_ptr->get_tracker_snapshot();
                        if (snap.chain_count == 0)
                            return std::nullopt;
                        core::SharechainTip t;
                        t.hash   = "";
                        t.height = snap.verified_count > 0 ? snap.chain_count : -1;
                        t.total  = snap.chain_count;
                        return t;
                    }
                    auto& chain = guard->chain;
                    uint256 best;
                    int32_t best_height = -1;
                    for (const auto& [head_hash, tail_hash] : chain.get_heads()) {
                        auto h = chain.get_height(head_hash);
                        if (h > best_height) { best = head_hash; best_height = h; }
                    }
                    if (best.IsNull() && chain.size() == 0)
                        return std::nullopt;
                    core::SharechainTip t;
                    t.hash   = best.IsNull() ? "" : best.GetHex().substr(0, 16);
                    t.height = best_height;
                    t.total  = static_cast<int>(chain.size());
                    return t;
                });
            mi->mark_last_cache_tip_driven();

            // ── REAL sharechain stats ─────────────────────────────────────
            // Straight off the live tracker / published snapshot. Emits the same
            // vote/sampling/propagation fields main_ltc.cpp's stats_fn does, so the
            // SHARED core::rest_version_signaling() lights the v16→v36 transition
            // gauges for DASH exactly as it does for LTC's v35→v36 crossing. All
            // reads are display-only (no consensus mutation): the desired-version
            // tally + work-weighted sampling mirror what apply_min_protocol_ratchet
            // keys on (version_negotiation::get_desired_version_weights), so the
            // dashboard shows the SAME numbers the ratchet decides on.
            mi->set_sharechain_stats_fn([node_ptr, mint_ledger]() -> nlohmann::json {
                // Last-good cache (mirrors main_ltc.cpp's stats_fn): think() holds the
                // tracker lock frequently during normal operation, and returning a
                // 4-field snapshot then would make the transition gauge (which reads
                // shares_by_desired_version / sampling weights) flap to 0 every time.
                // On a busy tick we return the last FULL result with volatile fields
                // refreshed from the snapshot, so the crossing gauge stays steady.
                static std::mutex s_cache_mutex;
                static nlohmann::json s_last_good;

                auto snap = node_ptr->get_tracker_snapshot();
                nlohmann::json out;
                const int chain_len = static_cast<int>(dash::SharechainConfig::chain_length());
                out["chain_length"]   = chain_len;
                out["fork_count"]     = snap.fork_count;
                out["verified_count"] = snap.verified_count;
                out["orphan_shares"]  = snap.orphan_shares;
                out["dead_shares"]    = snap.dead_shares;

                // ── Local-mint orphan/sibling gauge (display only) ─────────────
                // snap.orphan_shares/dead_shares are the sharechain-wide StaleInfo
                // tally, and every share WE mint is stamped StaleInfo::none — so a
                // locally minted share that is verified and then loses the head
                // race shows up in NEITHER. These fields answer the question those
                // cannot: of the shares this node minted, how many are still on the
                // best chain? Consensus-invisible (no StaleInfo stamping change).
                {
                    const auto lm = mint_ledger->stats();
                    out["local_minted_shares"]   = lm.minted;
                    out["local_on_chain_shares"] = lm.on_chain;
                    out["local_orphan_shares"]   = lm.orphaned;
                    out["local_pending_shares"]  = lm.pending;
                    out["local_gone_shares"]     = lm.gone;
                    out["local_orphan_rate"]     = lm.orphan_rate;
                }

                // Protocol-floor gauge inputs (v16→v36 crossing). The live accept-floor
                // is the ratchet output (1700 pre-crossing → 3600 once ≥95% v36-weighted);
                // advertised is our v36-capability advert.
                const int64_t live_floor = static_cast<int64_t>(node_ptr->runtime_min_protocol_version());
                out["min_protocol_version"]     = live_floor;
                out["cold_min_protocol_version"] = static_cast<int64_t>(dash::SharechainConfig::MINIMUM_PROTOCOL_VERSION);
                out["new_min_protocol_version"] = static_cast<int64_t>(dash::SharechainConfig::NEW_MINIMUM_PROTOCOL_VERSION);
                out["advertised_protocol_version"] = static_cast<int64_t>(dash::SharechainConfig::ADVERTISED_PROTOCOL_VERSION);
                // DASH shares are wire-format v16 through the whole crossing (only the
                // desired-version vote moves 16→36; there is no v36 share FORMAT for
                // DASH), so the node's live share version is 16 until the floor latches.
                out["live_share_version"] = (live_floor >= static_cast<int64_t>(dash::SharechainConfig::NEW_MINIMUM_PROTOCOL_VERSION)) ? 36 : 16;

                auto guard = node_ptr->read_tracker();
                if (!guard) {
                    // Tracker busy — prefer the last FULL result (with the vote/sampling
                    // fields) over a bare snapshot so the gauge doesn't flap.
                    std::lock_guard<std::mutex> lock(s_cache_mutex);
                    if (!s_last_good.is_null()) {
                        nlohmann::json cached = s_last_good;
                        // Refresh volatile fields + the live floor from this snapshot.
                        cached["chain_height"]   = snap.chain_count;
                        cached["total_shares"]   = snap.chain_count;
                        cached["verified_count"] = snap.verified_count;
                        cached["fork_count"]     = snap.fork_count;
                        cached["min_protocol_version"]  = live_floor;
                        cached["live_share_version"]    = out["live_share_version"];
                        // Local-mint gauge is lock-free (its own mutex) — always fresh.
                        cached["local_minted_shares"]   = out["local_minted_shares"];
                        cached["local_on_chain_shares"] = out["local_on_chain_shares"];
                        cached["local_orphan_shares"]   = out["local_orphan_shares"];
                        cached["local_pending_shares"]  = out["local_pending_shares"];
                        cached["local_gone_shares"]     = out["local_gone_shares"];
                        cached["local_orphan_rate"]     = out["local_orphan_rate"];
                        return cached;
                    }
                    out["chain_height"] = snap.chain_count;
                    out["total_shares"] = snap.chain_count;
                    return out;
                }
                auto& chain = guard->chain;
                uint256 best;
                int32_t best_height = -1;
                for (const auto& [head_hash, tail_hash] : chain.get_heads()) {
                    auto h = chain.get_height(head_hash);
                    if (h > best_height) { best = head_hash; best_height = h; }
                }
                const int chain_ht = best.IsNull() ? 0 : chain.get_height(best);
                out["chain_tip_hash"] = best.IsNull() ? "" : best.GetHex();
                out["chain_height"]   = chain_ht;
                out["stored_shares"]  = static_cast<int>(chain.size());  // all shares in the DB (incl. forks)

                // ── Single backward walk: desired-version votes, share-format
                //    counts, per-miner tally, and V36 propagation depth ──────────
                std::map<int, int> desired_counts;   // m_desired_version → count
                std::map<std::string, int> miner_counts;
                int format_v16 = 0;
                int deepest_v36_pos = 0;
                int v36_contiguous_from_tip = 0;
                bool contiguous = true;
                // Gauge inputs the SHARED core /global_stats path expects and DASH
                // never published, so it fell back to a literal 1.0 (#864):
                //   min_difficulty  = target_to_difficulty(best_share.max_target)
                //                     -- p2pool web.py get_global_stats(). This is
                //                     the pool's share-difficulty FLOOR, NOT the
                //                     window average; the two are different
                //                     quantities and only the floor is p2pool's.
                //   average_difficulty = window mean of the per-share difficulty,
                //                     which getinfo()/rest_sharechain_stats read.
                // Both DISPLAY ONLY. m_max_bits / m_bits are read straight off the
                // share header; nothing here mutates the tracker or the retarget.
                double best_min_difficulty = 0.0;
                double difficulty_sum = 0.0;
                const int skip_count   = std::min(chain_ht, chain_len * 9 / 10);
                const int sample_count = std::min(chain_ht - skip_count, chain_len / 10);
                uint256 sampling_start;
                const int full_walk = std::min(chain_ht, chain_len);
                if (!best.IsNull() && full_walk > 0) {
                    int i = 0;
                    for (auto&& [hash, data] : chain.get_chain(best, static_cast<uint64_t>(full_walk))) {
                        if (i == skip_count) sampling_start = hash;
                        data.share.invoke([&](auto* s) {
                            int dv = static_cast<int>(s->m_desired_version);
                            desired_counts[dv] += 1;
                            format_v16 += 1;  // DashShare is wire-format v16
                            miner_counts[s->m_pubkey_hash.GetHex()] += 1;
                            // i == 0 is the best share (get_chain walks tip-first).
                            if (i == 0 && s->m_max_bits != 0)
                                best_min_difficulty = chain::target_to_difficulty(
                                    chain::bits_to_target(s->m_max_bits));
                            if (s->m_bits != 0)
                                difficulty_sum += chain::target_to_difficulty(
                                    chain::bits_to_target(s->m_bits));
                            if (dv >= 36) {
                                deepest_v36_pos = i + 1;
                                if (contiguous) v36_contiguous_from_tip = i + 1;
                            } else if (contiguous) {
                                contiguous = false;
                            }
                        });
                        ++i;
                    }
                }
                if (sampling_start.IsNull() && skip_count == 0) sampling_start = best;

                // total_shares == the active-chain window actually tallied (matches
                // main_ltc.cpp, where total_shares is the windowed skiplist count), so
                // the gauge's version percentages divide by the same denominator.
                out["total_shares"] = format_v16;

                // Only publish when we actually measured one; an absent key makes
                // /global_stats emit min_difficulty:null, which is the honest
                // answer on a chain too young to have a floor (p2pool returns the
                // whole payload as None below 10 shares).
                if (best_min_difficulty > 0.0)
                    out["min_difficulty"] = best_min_difficulty;
                if (format_v16 > 0 && difficulty_sum > 0.0)
                    out["average_difficulty"] = difficulty_sum / format_v16;

                nlohmann::json sbv = nlohmann::json::object();
                if (format_v16 > 0) sbv["16"] = format_v16;
                out["shares_by_version"] = sbv;

                nlohmann::json sbdv = nlohmann::json::object();
                for (auto& [ver, cnt] : desired_counts) sbdv[std::to_string(ver)] = cnt;
                out["shares_by_desired_version"] = sbdv;
                out["shares_by_miner"]        = miner_counts;
                out["deepest_v36_position"]   = deepest_v36_pos;
                out["v36_contiguous_from_tip"] = v36_contiguous_from_tip;

                // ── Work-weighted sampling window: oldest CHAIN_LENGTH/10 shares.
                //    Same weighting the v36 activation gate consumes, so the
                //    dashboard's "% of hashpower-by-work on v36" matches the ratchet.
                nlohmann::json sampling = nlohmann::json::object();
                if (sample_count > 0 && !sampling_start.IsNull()) {
                    auto weights = dash::version_negotiation::get_desired_version_weights(
                        chain, sampling_start, static_cast<uint64_t>(sample_count));
                    for (auto& [ver, w] : weights)
                        sampling[std::to_string(ver)] = w.getdouble();
                }
                out["sampling_desired_version"] = sampling;

                // Publish as last-good so busy ticks can serve the full gauge fields.
                {
                    std::lock_guard<std::mutex> lock(s_cache_mutex);
                    s_last_good = out;
                }
                return out;
            });

            // ── Sharechain WINDOW / DELTA / SHARE DETAIL (dashboard read-models) ─
            //
            // These three seams had exactly ONE caller each repo-wide —
            // main_ltc.cpp:3730 / :3946 / :4077 — so on the DASH lane core fell
            // through to its fallback STUBS (web_server.cpp:2907 / :3313 / :6768).
            // A stub answers HTTP 200 with a well-formed EMPTY document, which is
            // why this failed silently: no 404, no log line, and the front-end's
            // `if (!data.shares) return` guard (dashboard.html:5011) sails through
            // a truthy `[]`. Measured on the live DASH node before this change:
            // /sharechain/window = 55 bytes, /sharechain/delta = 23 bytes,
            // /web/share/<hash> = {"error":"share not found"} for a hash that IS
            // in the tracker. The data was never missing — only the binding.
            //
            // The builders live in impl/dash/dashboard_views.hpp (ports of the LTC
            // lambdas above) so they are KAT-able against a real ShareTracker; the
            // work here is purely assembling the ViewContext and holding the
            // tracker read guard.
            {
                auto view_ctx = [mi, owner_addr = node_owner_address]() {
                    dash::dashboard::ViewContext ctx;
                    ctx.testnet     = dash::SharechainConfig::is_testnet;
                    ctx.window_size = dash::SharechainConfig::chain_length();
                    // DASH has no node-level mining address (every miner
                    // authorizes with its own address over stratum), so the
                    // closest true "this node" identity is the configured
                    // node-owner address. Left EMPTY when unset rather than
                    // guessed — an empty my_address makes the dashboard render
                    // "None (node not mining)", which is the honest answer.
                    ctx.my_address  = owner_addr;
                    if (mi) {
                        ctx.fee_hash160 = mi->get_node_fee_hash160();
                        for (const auto& fb : mi->get_found_blocks())
                            if (!fb.share_hash.empty())
                                ctx.found_block_short_hashes.push_back(
                                    fb.share_hash.substr(0, 16));
                    }
                    return ctx;
                };

                // The pool-wide PPLNS split, shared by /current_payouts, the main
                // dashboard treemap (via /current_merged_payouts) and the
                // window's own `pplns_current` fallback. best_share_hash() is
                // read BEFORE the guard: it takes its own try-shared-lock, and
                // re-entering the same shared_mutex from a thread that already
                // holds it is exactly the kind of nested acquire that stops
                // being harmless the moment a writer queues up.
                auto current_pplns =
                    [node_ptr, dash_tmpl, mint_params]() -> nlohmann::json {
                        const uint256 best = node_ptr->best_share_hash();
                        if (best.IsNull()) return nlohmann::json::object();
                        auto guard = node_ptr->read_tracker();
                        if (!guard) return nlohmann::json::object();
                        auto v = dash::dashboard::pplns_payouts_current(
                            guard->chain, mint_params, best, *dash_tmpl,
                            dash::SharechainConfig::is_testnet);
                        return v.ok ? v.payouts : nlohmann::json::object();
                    };

                // #939's direct-source seam. Its only callers repo-wide were in
                // a unit test (core/test/web_server_current_payouts_test.cpp) —
                // the seam shipped green and inert, which is why
                // rest_current_payouts() kept returning {} on a DASH node with
                // a full window and live balances (web_server.cpp:2375 takes
                // this branch only when a coin actually wires it). This is that
                // real, non-test caller.
                //
                // It also lights /current_merged_payouts, because
                // compute_current_merged_payouts() (web_server.cpp:5964) starts
                // from rest_current_payouts() — and /current_merged_payouts is
                // what the MAIN dashboard PPLNS treemap fetches
                // (dashboard.html loadMainPPLNS). /pplns/current's miners[]
                // array comes off the same cache.
                mi->set_current_payouts_fn(current_pplns);

                mi->set_sharechain_window_fn(
                    [node_ptr, view_ctx, current_pplns]() -> nlohmann::json {
                        auto cur = current_pplns();          // takes + releases the guard
                        auto guard = node_ptr->read_tracker();
                        if (!guard) return nlohmann::json::object();
                        auto w = dash::dashboard::build_window(*guard, view_ctx());
                        if (cur.is_object() && !cur.empty())
                            w["pplns_current"] = std::move(cur);
                        return w;
                    });
                // The grid IS the sharechain — refresh it on tip change, not on
                // the 1 Hz periodic timer (main_ltc.cpp:3908).
                mi->mark_last_cache_tip_driven();

                mi->set_sharechain_delta_fn(
                    [node_ptr, view_ctx](const std::string& since_hash) -> nlohmann::json {
                        auto guard = node_ptr->read_tracker();
                        if (!guard) return nlohmann::json::object();
                        return dash::dashboard::build_delta(*guard, since_hash, view_ctx());
                    });

                // Individual share page + THE PPLNS VIEW FOR THAT SHARE.
                //
                // LTC serves per-share PPLNS out of a precomputed cache
                // (start_pplns_precompute -> m_pplns_per_tip, read back by the
                // window as `pplns[<short hash>]`). That machinery is gated on
                // refresh_work() having populated m_cached_template
                // (web_server.cpp:2947), and refresh_work() never runs on the
                // DASH lane (:3902) — porting it would have wired green and
                // stayed empty, which is the exact failure this changeset
                // exists to remove. DASH computes the share's own window on
                // demand instead: ONE tracker walk per page view, inside the
                // guard already held, attached to the share document itself.
                mi->set_share_lookup_fn(
                    [node_ptr, view_ctx, mint_params](const std::string& hash_hex) -> nlohmann::json {
                        auto guard = node_ptr->read_tracker();
                        if (!guard) return nlohmann::json{{"error", "tracker busy"}};
                        auto doc = dash::dashboard::build_share_detail(
                            *guard, hash_hex, view_ctx());
                        if (doc.contains("error")) return doc;

                        uint256 h;
                        h.SetHex(hash_hex);
                        auto v = dash::dashboard::pplns_payouts_for_share(
                            guard->chain, mint_params, h,
                            dash::SharechainConfig::is_testnet);
                        if (v.ok) {
                            doc["pplns"] = v.payouts;
                            doc["pplns_meta"] = {
                                {"subsidy",        static_cast<double>(v.subsidy) / 1e8},
                                {"payments_total", static_cast<double>(v.payments_total) / 1e8},
                                {"worker_payout",  static_cast<double>(v.worker_payout) / 1e8},
                                {"recipients",     v.recipients},
                            };
                        }
                        return doc;
                    });
            }

            // ── Signed transitional-message feed (DISPLAY + VERIFY) ────────────
            // Reuses the LTC crossing's exact signed-message component: read the
            // best share's m_message_data blob, decrypt+verify the ECDSA signature
            // against the pinned authority pubkeys (dash::unpack_share_messages →
            // decrypt_message_data checks the 2 DONATION_AUTHORITY_PUBKEYS), and
            // hand the SHARED core::rest_version_signaling() the same JSON shape
            // main_ltc.cpp emits so the dashboard renders the signed v16→v36
            // transition notice + pool announcements with a verified badge + signer.
            //
            // Phase A: DASH shares carry an EMPTY m_message_data (share.hpp:142), so
            // this returns {decrypted:false, messages:[]} and the panel stays hidden
            // until a signed blob is minted into shares (Phase B — see PR notes:
            // the operator signs a MSG_TRANSITION_SIGNAL/0x20 payload with the
            // authority privkey and the mint path embeds it in m_message_data).
            // The DISPLAY+VERIFY path is fully wired now; only the emit side is Phase B.
            mi->set_protocol_messages_fn([node_ptr]() -> nlohmann::json {
                nlohmann::json result = {
                    {"best_share_hash", ""},
                    {"message_data_hex", ""},
                    {"decrypted", false},
                    {"authority_pubkey_hex", ""},
                    {"messages", nlohmann::json::array()}
                };

                auto best = node_ptr->best_share_hash();
                if (best.IsNull()) return result;
                auto guard = node_ptr->read_tracker();
                if (!guard) return result;
                if (!guard->chain.contains(best)) return result;
                result["best_share_hash"] = best.GetHex();

                std::vector<unsigned char> blob;
                guard->chain.get(best).share.invoke([&](auto* s) {
                    if constexpr (requires { s->m_message_data; })
                        blob = s->m_message_data.m_data;
                });
                if (blob.empty()) return result;

                result["message_data_hex"] = HexStr(blob);
                auto unpacked = dash::unpack_share_messages(blob.data(), blob.size());
                result["decrypted"] = unpacked.decrypted;   // true ⇒ signature verified
                if (!unpacked.decrypted || unpacked.authority_pubkey == nullptr)
                    return result;

                result["authority_pubkey_hex"] = HexStr(std::vector<unsigned char>(
                    unpacked.authority_pubkey->begin(), unpacked.authority_pubkey->end()));
                nlohmann::json msgs = nlohmann::json::array();
                for (const auto& msg : unpacked.messages) {
                    msgs.push_back({
                        {"type", msg.msg_type},
                        {"flags", msg.flags},
                        {"timestamp", msg.timestamp},
                        {"payload_hex", HexStr(msg.payload)},
                        {"signature_hex", HexStr(msg.signature)},
                        {"protocol_authority", (msg.wire_flags & dash::FLAG_PROTOCOL_AUTHORITY) != 0},
                        {"is_transition_signal", msg.msg_type == dash::MSG_TRANSITION_SIGNAL}
                    });
                }
                result["messages"] = msgs;
                return result;
            });

            // Seed the cached "live share version" the /v36_status fallback reads
            // when the chain is too short (<10 shares) for version_signaling to run.
            // Core defaults this to 36 (LTC-family); DASH mines wire-format v16 until
            // the accept-floor ratchets 1700→3600, so seed from the live floor to
            // avoid a spurious "v36 active" on an empty/young DASH chain. Once the
            // chain matures the stats fn's "live_share_version" drives it. Display-only.
            mi->set_cached_share_version(
                node_ptr->runtime_min_protocol_version()
                    >= dash::SharechainConfig::NEW_MINIMUM_PROTOCOL_VERSION ? 36 : 16);

            // ── REAL pool hashrate (ported from main_ltc.cpp:2865) ────────
            // dash::ShareTracker::get_pool_attempts_per_second is the same
            // p2pool estimator LTC uses (share_tracker.hpp:1353). Returns the
            // last good value on lock contention rather than a spurious 0.
            //
            // DISPLAY LOOKBEHIND (#864): p2pool web.py get_global_stats() averages
            // the gauge over ONE HOUR of shares -- min(height, 3600//SHARE_PERIOD)
            // -- which is 180 shares on DASH, not TARGET_LOOKBEHIND (100). This is
            // the DISPLAY window ONLY. The CONSENSUS retarget keeps
            // TARGET_LOOKBEHIND (p2pool data.py:137,140), and c2pool already
            // matches canonical there; nothing on this hook feeds the retarget --
            // m_pool_hashrate_fn is read exclusively by web_server REST handlers.
            mi->set_pool_hashrate_fn([node_ptr]() -> double {
                static double s_last_good = 0.0;
                auto best = node_ptr->best_share_hash();
                if (best.IsNull()) return s_last_good;
                auto guard = node_ptr->read_tracker();
                if (!guard) return s_last_good;
                if (!guard->chain.contains(best)) return s_last_good;
                int height = guard->chain.get_height(best);
                if (height < 3) return s_last_good;
                const int display_lookbehind =
                    3600 / static_cast<int>(dash::SharechainConfig::share_period());
                auto lookbehind = std::min(height - 1, display_lookbehind);
                auto aps = guard->get_pool_attempts_per_second(best, lookbehind, false);
                double hr = static_cast<double>(aps.GetLow64());
                if (hr > 0) s_last_good = hr;
                return s_last_good;
            });

            // ── REAL best-share hash ──────────────────────────────────────
            web_server->set_best_share_hash_fn(
                [node_ptr]() { return node_ptr->best_share_hash(); });

            // ── REAL pool-peer info (node-status card) ────────────────────
            // /local_stats {peers:{incoming,outgoing}} + the peer table read
            // this. Without it the node-status card reported 0 peers on DASH
            // (the m_node fallback in rest_local_stats never sees the pool
            // p2p peers). Same shape main_ltc.cpp:2830 uses. Display only.
            mi->set_peer_info_fn(
                [&p2p_node]() -> nlohmann::json {
                    return p2p_node.get_peer_info_json();
                });
        }

        // ── REAL per-share difficulty feed (main_ltc.cpp:4213) ────────────
        // Every verified DASH share reports its difficulty + miner through the
        // tracker hook (share_tracker.hpp:374); that is what drives the
        // dashboard's per-miner share tables and the share-difficulty graph.
        // NOT chained: nothing else on the DASH path installs this hook today
        // (verified by grep for m_on_share_difficulty in main_dash.cpp).
        {
            core::WebServer* ws = web_server.get();
            p2p_node.tracker().m_on_share_difficulty =
                [ws, testnet](double diff, const std::string& miner,
                              const uint256& share_hash) {
                    // ── ENCODE THE MINER (hotel primary, 2026-08-05) ──────
                    // The tracker reports the share's committed payout as a
                    // RAW hash160 hex, and the best_share card rendered it
                    // verbatim ("cfc7a034…3b8d") while the reserve — whose
                    // record came via stratum usernames — showed a proper
                    // address. Same entity, two spellings, read as a bug.
                    // Encode here, where testnet-ness is known, with the
                    // exact version bytes dashboard_found_block.hpp uses.
                    std::string shown = miner;
                    if (miner.size() == 40) {
                        uint160 h160;
                        h160.SetHex(miner);
                        std::string addr = core::script_to_address(
                            dash::pubkey_hash_to_script2(h160),
                            /*bech32_hrp=*/"",
                            testnet ? dash::dashboard::P2PKH_VERSION_TESTNET
                                    : dash::dashboard::P2PKH_VERSION_MAINNET,
                            testnet ? dash::dashboard::P2SH_VERSION_TESTNET
                                    : dash::dashboard::P2SH_VERSION_MAINNET);
                        if (!addr.empty()) shown = std::move(addr);
                    }
                    // The share hash rides through so best_share.hash names
                    // the record share instead of rendering "".
                    ws->get_mining_interface()->record_share_difficulty(
                        diff, shown, share_hash.GetHex());
                };
        }

        // ── ANY-PARTICIPANT found-block feed (main_ltc.cpp:4230 parity) ────
        // /recent_blocks is fed exclusively by record_found_block(), and the
        // ONLY DASH binding of it was the LOCAL stratum win below
        // (set_on_found_block_fn). A block found by another pool participant
        // arrives as a gossiped share whose X11 header hash also clears the
        // coin BLOCK target; the tracker already fires m_on_block_found for
        // it (share_tracker.hpp:368/574-578) and ltc/btc/dgb/bch all bind
        // that hook -- DASH never did, so peer-found blocks paid out but
        // showed up nowhere on the dashboard.
        //
        // LOCKS. The hook fires with the caller holding m_tracker_mutex
        // EXCLUSIVELY (compute thread in think()->attempt_verify, or
        // add_local_share's try-lock). read_tracker() is reentrancy-aware and
        // takes NO lock on the compute thread, so the handler cannot self-
        // lock; it snapshots plain data and posts the dashboard write -- which
        // takes m_blocks_mutex and may hit LevelDB -- onto the io_context, so
        // nothing heavy and no second mutex is entered under the tracker lock.
        //
        // DEDUP. A local win is recorded by the stratum arm first and then
        // re-fires here once #888 mints the winning share; both carry the same
        // block hash (on DASH the share hash IS X11(block header)) and the same
        // "DASH" label, and record_found_block dedups on exactly that pair.
        //
        // Display only: no submit, mint, target or payout path is reachable.
        {
            core::WebServer* ws = web_server.get();
            dash::Node* node = &p2p_node;
            p2p_node.tracker().m_on_block_found =
                dash::dashboard::make_on_block_found(
                    node, testnet,
                    [&ioc](std::function<void()> work) {
                        boost::asio::post(ioc, std::move(work));
                    },
                    [ws](const dash::dashboard::FoundBlockRow& row) {
                        auto* mi = ws->get_mining_interface();
                        LOG_INFO << "[DASH] GOT BLOCK FROM POOL! height=" << row.height
                                 << " hash=" << row.block_hash.GetHex().substr(0, 16)
                                 << " miner=" << row.miner;
                        mi->record_found_block(
                            row.height, row.block_hash, row.timestamp,
                            row.chain, row.miner, row.share_hash,
                            mi->get_network_difficulty(),
                            row.share_difficulty,
                            // pool_hashrate_at_find: 0 routes the core to the
                            // real POOL estimator (m_pool_hashrate_fn); this
                            // site passed get_local_hashrate(), which is only
                            // the pool rate when every rig sits on this node.
                            /*pool_hashrate=*/0.0,
                            row.subsidy,
                            // Sharechain peer path: another node built the
                            // template that won. Our pins and our tx selection
                            // are not in it, and our address may still be in
                            // the coinbase as our share of the pool payout.
                            // row.miner is that peer's own payout address,
                            // derived from the winning share's pubkey hash.
                            core::MiningInterface::BlockAuthorship
                                ::sharechain_peer);
                        // Arm the post-broadcast confirm/orphan poller so this
                        // peer-found block flips off "pending" (main_ltc.cpp:6315
                        // parity). Telemetry only; never gates a broadcast.
                        mi->schedule_block_verification(row.block_hash.GetHex());
                    });
        }

        // ── REAL node-owner fee (already parsed from argv above) ──────────
        if (node_owner_fee > 0.0 && !node_owner_address.empty())
            mi->set_node_fee_from_address(node_owner_fee, node_owner_address);

        // ── V36 transition-message EMIT side (mirror of main_ltc.cpp:3196) ─
        // (a) Optional operator-provided encrypted authority message blob.
        //     Validated against the DASH COMBINED_DONATION_SCRIPT authority
        //     keys and cached on the MiningInterface. It is embedded into
        //     locally created shares as message_data ONLY once the DASH
        //     sharechain mints v36 shares (DashV36Share, wire-type 36) — the
        //     live v16 DashShare wire format has no message_data field, so at
        //     v16 this blob feeds ONLY the dashboard display/verify path
        //     (rest_version_signaling fallback). See the mint-path note below.
        if (!operator_message_blob_hex.empty()) {
            if (operator_message_blob_hex.size() % 2 != 0) {
                LOG_ERROR << "--message-blob-hex must have even length";
                return 1;
            }
            std::vector<unsigned char> blob;
            try {
                blob = ParseHex(operator_message_blob_hex);
            } catch (const std::exception& e) {
                LOG_ERROR << "Invalid --message-blob-hex: " << e.what();
                return 1;
            }
            auto err = dash::validate_message_data(blob);
            if (!err.empty()) {
                LOG_ERROR << "Rejected --message-blob-hex: " << err;
                return 1;
            }
            mi->set_operator_message_blob(blob);
            LOG_INFO << "Operator message blob configured (" << blob.size() << " bytes)";
        }

        // (b) Load transition message blobs from shipped + data directories.
        //     Three dirs, mirroring main_ltc.cpp:3219. Each call is a no-op if
        //     the directory is absent (load_transition_blobs guards is_directory).
        {
            std::error_code exe_ec;
            auto exe_path = std::filesystem::read_symlink("/proc/self/exe", exe_ec);
            if (!exe_ec) {
                auto exe_dir = exe_path.parent_path();
                // 1. Next to executable: <deploy>/transition_messages/
                mi->load_transition_blobs((exe_dir / "transition_messages").string());
                // 2. Shipped with source: <repo>/transition_messages/ (build dir layout)
                mi->load_transition_blobs(
                    (exe_dir / ".." / ".." / ".." / "transition_messages").string());
            }
            // 3. User data dir: ~/.c2pool/transition_messages/
            auto data_dir = core::filesystem::config_path();
            mi->load_transition_blobs((data_dir / "transition_messages").string());
        }

        // Auto-detect the public IP for the "connect to this pool" panel.
        // Non-blocking, detached; identical to the LTC path.
        mi->auto_detect_external_info();

        if (web_server->start()) {
            std::cout << "[run] web dashboard LIVE on http://" << web_host << ":"
                      << web_port << " (dashboard-dir=" << dashboard_dir
                      << ") — real sharechain tip/stats/pool-hashrate + per-share\n"
                         "[run]       difficulty feed bound; stratum rates bind below\n";
        } else {
            std::cout << "[run] web dashboard FAILED to bind " << web_host << ":"
                      << web_port << " — dashboard disabled (mining unaffected)\n";
            web_server.reset();
        }
    } else {
        std::cout << "[run] web dashboard disabled (--web-port 0)\n";
    }

    // ── #738: resolve WHICH template arm this invocation takes, ONCE ──────
    // Before this, taking the embedded arm needed TWO conditions that no single
    // flag satisfied: the work-source gate (--embedded-mainnet, half 1) AND a
    // live coin-state feed (--coin-p2p-connect/--coin-p2p-discover, half 2,
    // which is what constructs the maintainer that flips populated()). The
    // embedded opt-in armed only half 1, so NodeCoinState was never fed and the
    // arm could not be taken from any documented invocation. resolve_embedded_
    // arm() closes that with a ONE-WAY implication: the embedded opt-in implies
    // its own feed. The converse is deliberately absent — a transport flag NEVER
    // moves the arm (the hotel incident where --coin-p2p-connect activated an
    // unguarded embedded arm on a live production node). Pinned by
    // test_dash_stratum_work_source's DashRunArmResolution suite.
    const dash::coin::ArmResolution run_arm =
        dash::coin::resolve_embedded_arm(dash::coin::ArmInputs{
            testnet, embedded_mainnet,
            !coin_p2p_targets.empty(), coin_p2p_discover });
    // Discovery is turned on for a pinned-peer-less embedded opt-in: daemonless
    // needs somewhere to sync from. Operator-named transport is never overridden.
    const bool coin_p2p_discover_eff = coin_p2p_discover || run_arm.discover_implied;
    std::cout << "[run] template arm=" << dash::coin::arm_name(run_arm.arm)
              << " — " << dash::coin::arm_reason_text(run_arm.reason)
              << "\n[run]       (embedded_arm_enabled="
              << (run_arm.embedded_arm_enabled ? "yes" : "no")
              << " coin_state_feed=" << (run_arm.coin_feed_armed ? "armed" : "off")
              << (run_arm.discover_implied ? " discovery=implied-by-opt-in" : "")
              << ")\n";

    // ── E1: OPT-IN embedded coin-network P2P dial ─────────────────────────
    // GUARANTEE: this block is a no-op unless the invocation asked for a
    // coin-state feed — an explicit --coin-p2p-connect / --coin-p2p-discover,
    // or the --embedded-mainnet opt-in that implies one (#738). With NONE of
    // those on argv, coin_p2p stays null, the run path is unchanged and the
    // mining-hotel prod posture (NodeCoinState unpopulated -> dashd-RPC
    // fallback) is untouched. Arming the feed alone still does NOT move the
    // arm: without --embedded-mainnet, work_source keeps serving the dashd
    // fallback no matter what this block populates. The coin-network wire MAGIC (dashd pchMessageStart: mainnet
    // bf0c6bbd / testnet cee2caff, same constants as the slice-1 launcher
    // dispatch) is DISTINCT from the sharechain PREFIX set above — different
    // layers, never conflated. The client rides the SAME ioc as the
    // sharechain node and stratum; declared after config/coin_state (both of
    // which it borrows), so it is destroyed before them at scope exit.
    // DASH-ISOLATED scored/diverse peer discovery (--coin-p2p-discover). Owns
    // its own peer table + seed bootstrap + scoring; feeds the single embedded
    // connection an INDEPENDENT (non-dashd) diverse peer set. Declared FIRST of
    // the three so it is destroyed LAST — the CoinClient's callbacks and the
    // refresh timer both capture it by raw pointer, so it must outlive both.
    std::unique_ptr<dash::coin::DashCoinPeerManager> coin_peer_mgr;
    std::unique_ptr<dash::coin::p2p::CoinClient<dash::Config>> coin_p2p;
    // Refresh timer declared LAST -> destroyed FIRST: it stops (and its lambda
    // stops capturing coin_p2p / coin_peer_mgr) before either is torn down.
    std::unique_ptr<core::Timer> coin_dial_refresh_timer;
    if (run_arm.coin_feed_armed) {
        config.coin()->m_testnet = testnet;
        // Coin-network wire magic (dashd pchMessageStart). Default: mainnet
        // bf0c6bbd / testnet cee2caff. A dev regtest dashd uses a DISTINCT magic
        // (empirically fcc1b7dc on Dash Core v22 regtest), so --coin-p2p-magic
        // HEX overrides it to let ARM A dial a regtest coin daemon for the E5
        // live-accept harness. Transport-only; consensus/reward-neutral; the
        // mainnet/testnet defaults are byte-for-byte unchanged when unset.
        const std::string net_magic_hex =
            dash::coin::select_coin_p2p_magic(coin_p2p_magic_hex, testnet);
        config.coin()->m_p2p.prefix = ParseHexBytes(net_magic_hex);
        if (!coin_p2p_targets.empty())
            config.coin()->m_p2p.address = coin_p2p_targets.front();

        coin_p2p = std::make_unique<dash::coin::p2p::CoinClient<dash::Config>>(
            &ioc, &coin_state, &config, "COIN-P2P");
        // MULTI-PEER POOL. The embedded arm holds N concurrent coin-network
        // peers instead of one. This is the precondition for ever trusting
        // "we hold no commitment for this slot, therefore mine null": a DKG
        // final commitment is announced exactly ONCE (RelayInv at finalize)
        // and served only by its own digest, so an announcement missed is an
        // object that can never be fetched. One peer made "we didn't hear it"
        // a guess; N peers make it evidence. See p2p_client.hpp.
        coin_p2p->set_max_peers(coin_p2p_peers);

        if (coin_p2p_discover_eff) {
            // ── Network-standalone arm: seed-discovered, SCORED, group-diverse
            // peer set INDEPENDENT of the local dashd. The pinned local dashd
            // (--coin-p2p-connect front target, if any) is registered as the
            // PROTECTED/preferred peer that carries the redundant block-relay
            // leg; it coexists with — never suppresses — the discovered set.
            const uint16_t coin_port = testnet ? 19999 : 9999;
            dash::coin::DashPeerManagerConfig pm_cfg;
            pm_cfg.valid_ports = { coin_port };
            // The manager BOUNDS the candidate set it hands back per call; with
            // the shipped default (3) it could never propose enough targets to
            // fill an 8-peer pool no matter how many peers it knew. Raise the
            // per-call budget to the pool target. Selection itself — scoring,
            // /16 group diversity, backoff — is unchanged and still the
            // manager's job; this only stops it capping the pool.
            pm_cfg.max_concurrent_connections =
                static_cast<int>(coin_p2p->max_peers());
            pm_cfg.max_connections_per_cycle =
                static_cast<int>(coin_p2p->max_peers());
            const std::string pm_data_dir = (core::filesystem::config_path()
                / net_subdir / "dash_embedded_peers").string();
            coin_peer_mgr = std::make_unique<dash::coin::DashCoinPeerManager>(
                ioc, "DASH", pm_data_dir, pm_cfg);

            // Pin the local dashd (if supplied) as the protected preferred peer.
            std::string pinned_str = "(none — fully daemonless)";
            if (!coin_p2p_targets.empty()) {
                if (coin_peer_mgr->set_local_node(coin_p2p_targets.front()))
                    pinned_str = coin_p2p_targets.front().to_string();
            }
            coin_peer_mgr->set_dns_seeds(dash::coin::dash_dns_seeds(testnet));
            coin_peer_mgr->set_fixed_seeds(dash::coin::dash_fixed_seeds(testnet));
            // HTTP peer fallback: when DNS + fixed seeds are exhausted, query
            // known c2pool nodes via GET /api/coin_peers for peer addresses —
            // the third and last bootstrap tier. Mirrors main_ltc.cpp:1875.
            coin_peer_mgr->set_http_peer_seeds({{"voidbind.com", 8080}});

            // ── ACTIVE daemon-disjointness (connect+discover / oracle-shadow) ──
            // When a local dashd RPC is armed, feed its getpeerinfo so the
            // manager tracks the daemon's OWN peers (m_coind_peers). That is
            // what makes the coind-source -20 penalty AND the daemon-peer
            // overlap filter engage — without it those ported mechanisms stay
            // dormant (m_coind_peers empty => no peer ever Source::coind) and
            // only passive independence holds. Mirrors main_ltc.cpp:5484.
            // Absent RPC (fully daemonless) => seeds-only, passive independence.
            if (rpc) {
                coin_peer_mgr->set_getpeerinfo_fn(
                    [rp = rpc.get()]() -> std::vector<NetService> {
                        try { return rp->getpeerinfo(); }
                        catch (...) { return {}; }
                    });
                std::cout << "[run]       daemon-disjointness ACTIVE: dashd getpeerinfo "
                             "wired -> coind -20 penalty + overlap filter engage\n";
            }

            coin_peer_mgr->start();

            // addr-crawl discoveries feed back into the manager (source-scored
            // +50); handshake connect/disconnect drive scoring + anchors.
            coin_p2p->set_addr_callback(
                [mgr = coin_peer_mgr.get()](const std::vector<NetService>& addrs) {
                    for (auto& a : addrs) mgr->add_discovered_peer(a);
                });
            coin_p2p->set_on_peer_connected(
                [mgr = coin_peer_mgr.get()](const NetService& s) {
                    mgr->notify_connected(s.to_string());
                });
            coin_p2p->set_on_peer_disconnected(
                [mgr = coin_peer_mgr.get()](const NetService& s) {
                    mgr->notify_disconnected(s.to_string());
                });
            // #940: dial failures (ECONNREFUSED/ETIMEDOUT/resolve error) never
            // reach connect/disconnect scoring — feed them explicitly so dead
            // top-scored seeds are penalised instead of re-dialed forever.
            coin_p2p->set_on_dial_failed(
                [mgr = coin_peer_mgr.get()](const NetService& s) {
                    mgr->notify_dial_failed(s.to_string());
                });

            // Pinned keys: passed to get_peers_to_connect() as the "already
            // handled" set so the protected pinned node (score 999999, always
            // ranked first) is NOT also appended by the scorer — the pinned
            // entries are prepended explicitly, so this dedups them out.
            std::set<std::string> pinned_keys;
            for (auto& t : coin_p2p_targets) pinned_keys.insert(t.to_string());

            // Initial dial plan: pinned local dashd first (preferred), then the
            // top scored+diverse discovered peers (pinned excluded from that set).
            std::vector<NetService> dial;
            for (auto& t : coin_p2p_targets) dial.push_back(t);
            for (auto& ep : coin_peer_mgr->get_peers_to_connect(pinned_keys))
                dial.push_back(ep.to_net_service());
            coin_p2p->connect(dial);

            // Periodic dial-plan refresh (60s): rebuild from the freshly-scored,
            // group-diverse set so newly-discovered high-score peers enter the
            // rotation on the next reconnect — the self-healing witness loop.
            coin_dial_refresh_timer = std::make_unique<core::Timer>(&ioc, /*repeat=*/true);
            coin_dial_refresh_timer->start(60, [cp = coin_p2p.get(),
                                                mgr = coin_peer_mgr.get(),
                                                pinned = coin_p2p_targets,
                                                pinned_keys]() {
                std::vector<NetService> refreshed = pinned; // pinned always preferred, first
                // Feed the scorer the peers we ACTUALLY HOLD, not just the
                // pinned ones. Two things depend on it with a pool: it stops
                // proposing peers we are already connected to (which would
                // waste every refill slot), and its /16 group-diversity
                // accounting is computed against the live pool instead of an
                // empty set — so the eight peers we end up with are eight
                // independent witnesses, not eight sockets into one datacentre.
                std::set<std::string> held = pinned_keys;
                for (auto& k : cp->connected_peer_keys()) held.insert(k);
                for (auto& ep : mgr->get_peers_to_connect(held))
                    refreshed.push_back(ep.to_net_service());
                cp->update_dial_targets(std::move(refreshed));
            });

            std::cout << "[run] coin-network P2P DISCOVERY armed ("
                      << (run_arm.discover_implied
                              ? "implied by --embedded-mainnet"
                              : "--coin-p2p-discover")
                      << "): DASH-isolated scored/diverse peer set, pinned="
                      << pinned_str << " magic=" << net_magic_hex
                      << " proto=70230 dns_seeds=" << dash::coin::dash_dns_seeds(testnet).size()
                      << " fixed_seeds=" << dash::coin::dash_fixed_seeds(testnet).size()
                      << " initial_dial=" << dial.size() << " target[s]"
                      << " pool=" << coin_p2p->max_peers() << " concurrent peer[s]\n"
                         "[run]       (network-standalone witness: independent peers -> independent\n"
                         "[run]       mempool/relay view; oracle-shadow standalone graduation gate)\n";
        } else {
            // Legacy single/pinned dial (--coin-p2p-connect only, no discovery).
            coin_p2p->connect(coin_p2p_targets);
            std::cout << "[run] coin-network P2P client dialing "
                      << coin_p2p_targets.front().to_string()
                      << (coin_p2p_targets.size() > 1
                              ? " (+" + std::to_string(coin_p2p_targets.size() - 1)
                                    + " alternate[s]; pool holds up to "
                                    + std::to_string(coin_p2p->max_peers())
                                    + " concurrently)"
                              : "")
                      << " magic=" << net_magic_hex
                      << " proto=70230 (E1: dial+handshake+keep-alive only;\n"
                         "[run]       ingest legs are later slices — templates still source from\n"
                         "[run]       the dashd-RPC fallback until NodeCoinState is fed)\n";
        }
    }

    // ── S8 miner-facing Stratum accept-loop standup (run-path caller) ─────
    // This is the production caller the DASHWorkSource 4a/4b skeleton (#706)
    // and the subscribe->notify->submit KATs (#630-634) were built for: a real
    // main constructs the work source and binds a core::StratumServer to it.
    //
    // node_coin_state MUST outlive work_source and stratum_server (DASHWorkSource
    // holds a non-owning const ref to it). It is declared here, in run_node's
    // scope, BEFORE work_source; the explicit stratum_server.reset() after
    // ioc.run() tears the acceptor down while node_coin_state is still alive.
    // Constructed UNPOPULATED: populated()==false, so get_work() takes the
    // retained dashd-fallback arm until a coin-state feed publishes a tip. With
    // no feed armed (run_arm.coin_feed_armed == false) nothing ever publishes
    // one, and the fallback arm is the whole run.
    //
    // E2b (#738) UTXO/fee lane: utxo_lane is declared BEFORE node_coin_state
    // deliberately -- attach() hands the lane's UTXOViewCache pointer to the
    // bundle's Mempool (set_utxo), so the lane must outlive the mempool that
    // references it (reverse destruction order at scope exit).
    dash::coin::UtxoLane utxo_lane;
    dash::coin::NodeCoinState node_coin_state;

    // ── Mempool-tx serving switch (--embedded-serve-mempool-txs) ────────────
    // DEFAULT OFF: embedded templates carry a coinbase-only body even once the
    // UTXO lane matures (suppress cause "mempool-txs-disabled" on the template
    // + log). The fee-carrying mempool-tx body path — topological selection
    // (G1), sigop cap (G2), coinbase-maturity (G3), islock-conflict (G4)
    // guards, mempool.hpp — is an explicit soak-gated operator opt-in, not an
    // implicit consequence of UTXO maturity. Audit:
    // DASH_CONNECTBLOCK_REJECT_SURFACE_AUDIT.md §1. The dashd fallback arm is
    // unaffected (its GBT bodies come from dashd itself).
    //
    // THE CONDITION for that opt-in is the MEMPOOL VALIDITY GATE
    // (mempool_validity_gate.hpp): zero transactions refused by dashd's
    // testmempoolaccept over a sustained window of consecutive
    // evidence-bearing heights. It is NOT `ours_only == 0` -- that
    // set-membership test is unreachable (two independently-connected mempools
    // never coincide) and blind to a strict SUBSET that contains an invalid
    // transaction, which is exactly the case that costs a whole block.
    node_coin_state.set_serve_mempool_txs(embedded_serve_mempool_txs);
    // ── IS/CL MINING-SAFETY HOLD arming (dashd TestPackageTransactions) ─────
    // dashd's miner refuses any not-yet-islocked tx with vins younger than 10
    // minutes when spork2 (InstantSend) AND spork3 (RejectConflictingBlocks)
    // are active (node/miner.cpp:374-391; WAIT_FOR_ISLOCK_TIMEOUT,
    // chainlock/handler.cpp:35) — its defence against mining a tx that then
    // LOSES to a conflicting islock (conflict-tx-lock block reject). Mirror
    // the SAME spork gate: derive the arm-bit from the coin-P2P SporkState
    // (assume-active mainnet seed, refined by verified spork messages),
    // recomputed on the io thread — the spork map's writer thread — whenever a
    // verified spork applies, and pushed into the mempool as an atomic. The
    // hold additionally self-gates on isdlock-feed LIVENESS inside the mempool
    // (mempool.hpp ISLOCK_FEED_FRESH_SECS), so a dark isdlock leg degrades to
    // the pre-hold include-immediately behaviour instead of holding every
    // young tx for 10 minutes. No coin-P2P arm => no isdlock feed => the
    // arm-bit below is never set and the hold stays OFF.
    if (coin_p2p) {
        auto arm_is_hold = [&cp = *coin_p2p, &ncs = node_coin_state]() {
            const int64_t now = static_cast<int64_t>(std::time(nullptr));
            const auto& ss = cp.spork_state();
            ncs.mempool().set_instantsend_mining_hold(
                ss.is_active(dash::coin::SPORK_2_INSTANTSEND_ENABLED, now)
                && ss.is_active(dash::coin::SPORK_3_INSTANTSEND_BLOCK_FILTERING,
                                now));
        };
        arm_is_hold();   // seed posture now (mainnet seed: both active)
        coin_p2p->set_spork_change_callback(arm_is_hold);
    }
    // #107 PHASE 2 (--embedded-accrue-asset-locks): DEFAULT OFF. When ON the
    // embedded CbTx creditPoolBalance accrues the pending type-8 asset-lock term
    // dashd commits, so the gbt-xcheck-modulo-special-explained swap stops
    // firing on the type-8-only case (asset_lock_fold.hpp). CONSENSUS: a block
    // committing this accrual is valid only once the same type-8 txs ride the
    // served body (blocked on #125); otherwise a submitted coinbase-only block
    // is bad-cbtx-assetlocked-amount. Hence OFF by default.
    node_coin_state.set_accrue_pending_asset_locks(embedded_accrue_asset_locks);
    std::cout << "[run] embedded #107 asset-lock accrual: "
              << (embedded_accrue_asset_locks
                      ? "ON (--embedded-accrue-asset-locks: CbTx creditPool "
                        "accrues pending type-8 locks; VALID block needs those "
                        "txs in the served body -- #125/tx-serving)"
                      : "OFF (default: creditPool = seed + platform reward only)")
              << "\n";
    // #143 Variant B (--embedded-accrue-asset-unlocks): DEFAULT OFF. The
    // template-side seam (build_embedded_workdata admitted_asset_unlocks)
    // stays nullptr unless the CreditPool INDEX follower reports
    // accrual_permitted() — which additionally requires a completed, proven
    // gap-free seed from the v20 floor (a follow-up soak arms that lane).
    // Until then the flag documents intent and the posture below names the
    // state; the served template is exclude-all either way.
    std::cout << "[run] embedded #143 asset-UNLOCK (type-9) accrual: "
              << (embedded_accrue_asset_unlocks
                      ? "ARMED (--embedded-accrue-asset-unlocks: admission "
                        "still gated on the CreditPool INDEX follower's "
                        "fail-closed predicate — proven-complete seed + real "
                        "BLS + fresh-at-parent; NO follower lane is seeded in "
                        "this build, so templates remain exclude-all)"
                      : "OFF (default: templates exclude ALL type-9 — "
                        "today's proven-valid behavior)")
              << "\n";
    std::cout << "[run] embedded mempool-tx serving: "
              << (embedded_serve_mempool_txs
                      ? "ON (--embedded-serve-mempool-txs: fee-carrying "
                        "templates once the UTXO lane matures)"
                      : "OFF (default: coinbase-only body, cause="
                        "mempool-txs-disabled; fees forgone, values exact)")
              << "\n";

    // ── Pinned local tx (--pin-local-tx-hex): parse + park in NodeCoinState.
    if (!pin_local_tx_hex_path.empty()) {
        // ONE TRANSACTION PER LINE. The donation consolidation had to be SPLIT
        // after a single 152258-byte pin was rejected as bad-txns-oversize and
        // cost block 2517855; four quarter-sized transactions now ride ONE
        // template. Multiple lines rather than a repeatable flag on purpose:
        // the systemd drop-in stays byte-identical and only the FILE changes,
        // so re-arming the lane cannot silently drop a transaction by editing
        // the wrong place. A single-line file behaves exactly as before.
        std::ifstream pf(pin_local_tx_hex_path);
        std::vector<dash::coin::MutableTransaction> pin_txs;
        bool pin_ok = false;
        std::string line;
        unsigned lineno = 0;
        while (std::getline(pf, line)) {
            ++lineno;
            line.erase(std::remove_if(line.begin(), line.end(),
                                      [](unsigned char c) { return std::isspace(c); }),
                       line.end());
            if (line.empty()) continue;
            if (line.size() % 2 != 0) {
                std::cout << "[run] --pin-local-tx-hex line " << lineno
                          << ": odd hex length — pin DISABLED\n";
                pin_txs.clear();
                break;
            }
            try {
                auto raw = ParseHex(line);
                PackStream ps(raw);
                dash::coin::MutableTransaction tx;
                ps >> tx;
                // classic tx only: a special-type (extra_payload) pin would
                // interact with the CbTx roots the template commits — refuse
                // at load, loudly, rather than gate per template.
                if (tx.type != 0 || tx.vin.empty() || tx.vout.empty()) {
                    std::cout << "[run] --pin-local-tx-hex line " << lineno
                              << ": not a classic non-empty tx — pin DISABLED\n";
                    pin_txs.clear();
                    break;
                }
                pin_txs.push_back(std::move(tx));
            } catch (const std::exception& e) {
                std::cout << "[run] --pin-local-tx-hex line " << lineno
                          << " PARSE FAILED (" << e.what() << ") — pin DISABLED\n";
                pin_txs.clear();
                break;
            }
        }
        // ALL-OR-NOTHING at load. A partially-loaded set would mine some of a
        // split consolidation and silently strand the rest, which is worse
        // than not arming: the operator would see money move and assume the
        // whole of it did.
        pin_ok = !pin_txs.empty();
        dash::coin::MutableTransaction pin_tx;
        if (pin_ok) pin_tx = pin_txs.front();   // for the existing log/lookup
        if (pin_ok) {
            // SECOND SOURCE for the pin's inputs (money-path, 2026-08-07).
            // The embedded UTXO view is built FORWARD from the height this node
            // started at, so coins older than that are simply ABSENT from it —
            // the gate then reports input-missing-or-spent for inputs that are
            // in fact unspent. Measured on the production primary, which
            // refused a pin whose 1032 inputs the local daemon confirmed
            // unspent to the duff.
            //
            // This does NOT relax the gate. Value and spentness still come from
            // an authoritative source, so fee==0 stays COMPUTED rather than
            // assumed, and an input neither source can resolve is still
            // refused. An unreachable daemon returns false — never a guess.
            if (rpc) {
                dash::coin::NodeRPC* rpc_raw = rpc.get();
                node_coin_state.set_pin_external_coin_lookup(
                    [rpc_raw](const ::core::coin::Outpoint& op,
                              ::core::coin::Coin& out) -> bool {
                        try {
                            auto j = rpc_raw->gettxout(op.txid, op.index);
                            if (j.is_null() || !j.contains("value")) return false;
                            const double v = j.value("value", 0.0);
                            out.value = static_cast<int64_t>(v * 1e8 + 0.5);
                            // gettxout reports confirmations, not the height the
                            // coin was created at. A confirmed non-coinbase coin
                            // needs no maturity window; a coinbase one does, so
                            // mark it height 0 and let the maturity arm refuse
                            // unless the caller knows better. Conservative by
                            // construction.
                            out.coinbase = j.value("coinbase", false);
                            const int confs = j.value("confirmations", 0);
                            if (confs <= 0) return false;   // unconfirmed => refuse
                            // HEIGHT, not a placeholder. Measured on the
                            // production primary: an earlier version set
                            // height 0 "conservatively", which made the
                            // maturity arm read every coinbase-sourced coin as
                            // immature and refuse it forever — and the donation
                            // inputs ARE coinbase outputs (they are mining
                            // payouts), so that conservatism refused exactly
                            // the transaction it was meant to protect:
                            //   pinned tx EXCLUDED cause=immature-coinbase-input
                            // gettxout reports confirmations, and the coin's
                            // height is the chain tip minus (confirmations-1).
                            // We take the tip from the daemon's own answer
                            // rather than a local view, so the number and the
                            // coin come from the same source.
                            const int tip = rpc_raw->blockcount_cached();
                            if (tip <= 0) return false;     // no tip => refuse
                            const long h = static_cast<long>(tip)
                                         - static_cast<long>(confs) + 1;
                            if (h < 0) return false;
                            out.height = static_cast<uint32_t>(h);
                            return true;
                        } catch (const std::exception&) {
                            return false;
                        }
                    });
                std::cout << "[run] pin input lookup: embedded UTXO view + "
                             "coin-RPC second source (gettxout) ARMED\n";
            }
            node_coin_state.set_pinned_local_txs(pin_txs);
            size_t total_bytes = 0;
            for (const auto& t : pin_txs) total_bytes += ::pack(t).get_span().size();
            std::cout << "[run] pinned local tx ARMED: " << pin_txs.size()
                      << " transaction(s), " << total_bytes << " bytes total";
            for (const auto& t : pin_txs)
                std::cout << "\n[run]   " << dash::coin::dash_txid(t).GetHex()
                          << " vin=" << t.vin.size()
                          << " bytes=" << ::pack(t).get_span().size();
            std::cout
                      << " (admission re-gated per template: inputs unspent,"
                      << " coinbase-mature, fee==0; excluded-not-refused on"
                      << " failure; auto-retires once mined)\n";
        } else {
            std::cout << "[run] --pin-local-tx-hex: file empty/unreadable/"
                      << "invalid (" << pin_local_tx_hex_path
                      << ") — pin DISABLED\n";
        }
    }

    // ── E2b (#738): the embedded UTXO/fee lane -- OPT-IN via --embedded-utxo.
    // Transliterated from the PROVEN LTC wiring (main_ltc.cpp ~1750-1801 con-
    // struction + set_utxo + maturity gate; ~2385-2433 block-connect leg; see
    // utxo_lane.hpp). This is the root-cause fix for the fee_known=false ->
    // empty-template defect: Mempool::set_utxo previously had zero dash-arm
    // callers, so every relayed tx stayed unknown-fee and the conservative
    // selection guard (unknown fees EXCLUDED so coinbasevalue never overstates
    // vs dashd's GBT -- guard untouched) returned an empty selection forever.
    //
    // Default (flag absent): NOTHING here is constructed or subscribed -- the
    // dashd-RPC fallback path (mining-hotel prod) is byte-unchanged. With the
    // flag: the lane opens its LevelDB, arms the mempool's fee machinery, and
    // subscribes the coin-state block_connected seam (leg 3, the same event
    // block_connect_ingest.hpp routes to CoinStateMaintainer). The LIVE block
    // feed that FIRES that event is the E1/E2a coin-P2P leg; until it lands
    // the lane sits armed-but-dormant and get_work still routes to the
    // retained dashd fallback (populated()==false).
    std::shared_ptr<EventDisposable> utxo_block_sub;
    if (embedded_utxo) {
        const auto utxo_path = (core::filesystem::config_path()
            / net_subdir / "utxo_leveldb").string();
        if (utxo_lane.open(utxo_path)) {
            utxo_lane.attach(node_coin_state.mempool());
            // Mining gate: coinbase_maturity + reorg buffer = 100 + 6 = 106
            // (DASH_MINING_GATE_DEPTH, utxo_adapter.hpp; mirrors the LTC
            // set_utxo_ready_fn gate) -- embedded templates stay off until
            // the UTXO view is deep enough to exclude immature coinbase
            // spends. The dashd fallback is unaffected.
            node_coin_state.set_utxo_ready_fn(
                [&utxo_lane]() { return utxo_lane.mining_utxo_ready(); });
            // What the arm DOES during that window. Default (flag absent):
            // REFUSE -- p2pool semantics, the project design law: an unsynced
            // node does not serve block templates; miners idling is correct,
            // and where the dashd fallback is armed it serves FULL templates
            // for the whole window. --embedded-utxo-immature-serve-empty is
            // the pure-daemonless opt-in: serve a coinbase-only body instead
            // (consensus never requires a mempool tx; with zero txs the fee
            // term is exactly 0, so the subsidy, MN payment and creditPool the
            // template commits are all exact -- nothing to overstate). The
            // trade is the forgone fees, which the builder reports on every
            // such template.
            node_coin_state.set_utxo_immature_policy(
                embedded_utxo_immature_serve_empty
                    ? dash::coin::UtxoImmaturePolicy::ServeEmptyTxSet
                    : dash::coin::UtxoImmaturePolicy::Refuse);
            utxo_block_sub = coin_state.block_connected.subscribe(
                [&utxo_lane](const dash::interfaces::BlockConnected& bc) {
                    utxo_lane.on_block_connected(bc.block, bc.height);
                });
            std::cout << "[run] embedded UTXO/fee lane ARMED: db=" << utxo_path
                      << " best_height=" << utxo_lane.cache()->get_best_height()
                      << " (mempool fee pricing live; block feed = E1/E2a leg;"
                         " maturity gate " << dash::coin::DASH_MINING_GATE_DEPTH
                      << " blocks, immature-window policy="
                      << (embedded_utxo_immature_serve_empty
                              ? "SERVE-EMPTY-TXSET (opt-in: coinbase-only, fees=0)"
                              : "REFUSE (default: dashd fallback for the whole window)")
                      << ")\n";
        } else {
            std::cout << "[run] embedded UTXO/fee lane FAILED to open " << utxo_path
                      << " -- fees stay unknown; dashd-RPC fallback unaffected\n";
        }
    }

    // REQUIRED always-reachable dashd-RPC fallback arm -- the safety +
    // [GBT-XCHECK] cross-check path, NEVER removed (operator standing rule).
    // Wired to NodeRPC::getwork() (dashd getblocktemplate -> rich DashWorkData,
    // the same seam run_mine_block uses). When the RPC arm is UNARMED (no
    // dash.conf creds) it returns the documented empty set-gap default and logs
    // loudly -- never a silent drop. &rpc is lifetime-safe: rpc is declared
    // above work_source in this scope, so work_source (which owns this lambda)
    // is destroyed BEFORE rpc at scope exit.
    std::function<dash::coin::DashWorkData()> dashd_fallback =
        [&rpc]() -> dash::coin::DashWorkData {
            if (!rpc) {
                std::cout << "[DASH-STRATUM-GBT] fallback arm UNARMED (no dashd "
                             "RPC creds) -- serving empty set-gap template\n";
                return dash::coin::DashWorkData{};
            }
            return rpc->getwork();
        };

    // Won-block dispatch (S8): the DUAL-PATH broadcaster, mirroring DGB's
    // make_on_block_found dual-arm structure. A won X11 block reaches the network
    // over BOTH independent arms via dash::coin::broadcast_won_block:
    //   ARM A -- embedded P2P relay (ALWAYS-PRIMARY, daemonless): the E1
    //            CoinClient's submit_block_p2p_raw pushes the packed block onto
    //            the coin P2P net. This closes the daemonless critical path: with
    //            NO local dashd, a won block still reaches the network here alone.
    //   ARM B -- submitblock RPC backup (on-demand): dashd submitblock, fired
    //            whenever a local dashd is armed (also covers a cold/faulted relay).
    // NEVER a silent drop: broadcast_won_block logs LOUDLY and any()==false if the
    // block reaches NEITHER sink, and the stratum surface below echoes that.
    //
    // ARM A binding: the sink is EMPTY (no embedded relay) when no
    // --coin-p2p-connect peer is dialed OR --no-p2p-relay suppresses it (the A/B
    // isolation toggle: prove the RPC backup lands the block ON ITS OWN, not
    // masked by a silent relay). Present: the relay fires from the stratum/compute
    // path, so the peer write is posted onto the io thread (CoinClient is
    // single-thread-confined), mirroring DGB's io::post relay sink.
    dash::coin::P2pRelaySink p2p_relay;
    if (coin_p2p && !no_p2p_relay) {
        p2p_relay =
            [&ioc, &coin_p2p](const std::vector<unsigned char>& block_bytes) -> bool {
                // H1 honest reporting: submit_block_p2p_raw SILENTLY DROPS a won
                // block when the coin-P2P peer is disconnected, and the io::post
                // returns before the send even runs -- so only claim a P2P relay
                // when the peer is actually connected+handshaked at dispatch time.
                // If not, return false so broadcast_won_block relies on ARM B
                // (submitblock RPC) and the NEVER-SILENT-DROP contract holds
                // (loud dispatcher log if neither arm is reachable).
                if (!coin_p2p || !coin_p2p->is_handshake_complete()) {
                    std::cout << "[DASH-STRATUM-BLOCK] embedded P2P relay skipped: "
                                 "no handshaked coin-P2P peer -- relying "
                                 "on submitblock-RPC backup\n";
                    return false;
                }
                // RELAY POLICY: BROADCAST TO EVERY HANDSHAKED PEER (money path).
                // submit_block_p2p_raw writes the block to all of them and
                // returns the count. Duplicate submission of a found block is a
                // non-event -- every node that receives it forwards it anyway,
                // and one that already has it ignores the copy. A MISSED
                // submission is a lost block with no retry, because the share is
                // already spent. The asymmetry is the whole argument: we buy
                // redundancy with bandwidth we do not care about, on the one
                // message per day where it matters.
                std::cout << "[DASH-STRATUM-BLOCK] embedded P2P relay: broadcasting to "
                          << coin_p2p->handshaked_peer_count()
                          << " handshaked peer(s)\n";
                io::post(ioc, [&coin_p2p, bytes = block_bytes]() {
                    if (coin_p2p) coin_p2p->submit_block_p2p_raw(bytes);
                });
                return true;
            };
    } else if (no_p2p_relay) {
        std::cout << "[run] --no-p2p-relay: embedded P2P-relay arm SUPPRESSED; "
                     "submitblock-RPC backup remains live (A/B isolation)\n";
    }

    // ARM B binding: EMPTY when no dashd creds are armed (daemonless deployment).
    // ignore_failure=false: submitblock_result_accepted() ALREADY treats
    // duplicate/inconclusive/already-have as success (so an ARM A accept is
    // never re-reported as failure); what ignore_failure=true additionally
    // suppressed was the ONLY record of a REAL dashd rejection reason. On the
    // hotel mainnet orphans (h2508929/h2509044) the bad-cb-payee verdict was
    // swallowed and the log showed just "no-ack", masking a consensus-invalid
    // block as a mere broadcast hiccup. A won-block rejection reason is
    // reward-critical diagnosis: log it loudly.
    dash::coin::RpcSubmitSink rpc_submit;
    if (rpc) {
        rpc_submit = [&rpc](const std::string& block_hex) -> bool {
            return rpc->submit_block_hex(block_hex, /*ignore_failure=*/false);
        };
    }

    dash::stratum::DASHWorkSource::SubmitBlockFn stratum_submit_fn =
        [p2p_relay, rpc_submit](const std::vector<unsigned char>& block_bytes,
                                uint32_t height,
                                bool height_race) -> bool {
            const std::string block_hex = HexStr(block_bytes);
            std::cout << "[DASH-STRATUM-BLOCK] won block height=" << height
                      << " bytes=" << block_bytes.size()
                      << (height_race
                              ? " (HEIGHT RACE -- RPC-first: dashd validates before"
                                " any coin-P2P relay)"
                              : "")
                      << " -- dispatching dual-path (embedded P2P primary + "
                         "submitblock-RPC backup)\n";
            const auto bcast = dash::coin::broadcast_won_block(
                p2p_relay, rpc_submit, block_bytes, block_hex,
                /*prefer_rpc_first=*/height_race);
            if (!bcast.any()) {
                // #987: a submitblock RPC arm that FIRED and was REJECTED (e.g.
                // bad-chainlock / bad-cb-payee) is NOT the no-creds path. The
                // rejection REASON was already logged LOUDLY by
                // NodeRPC::submit_block_hex above; name the cause here instead of
                // the old hardcoded "no dashd RPC creds", which mislabelled a
                // consensus rejection as an absent daemon.
                if (bcast.rpc_rejected()) {
                    std::cout << "[DASH-STRATUM-BLOCK] reached NEITHER sink: dashd "
                                 "submitblock RPC REJECTED the block (see the "
                                 "submit_block_hex reason logged above) and no "
                                 "embedded P2P relay landed it -- won block NOT "
                                 "broadcast\n";
                } else {
                    std::cout << "[DASH-STRATUM-BLOCK] reached NEITHER sink "
                                 "(no embedded P2P peer AND no dashd RPC creds) -- "
                                 "won block NOT broadcast\n";
                }
                return false;
            }
            std::cout << "[DASH-STRATUM-BLOCK] relayed: p2p="
                      << (bcast.p2p_sent ? "sent" : "off")
                      << " rpc=" << (bcast.rpc_ok ? "ok" : "off")
                      << " landed_first=" << bcast.landed_first << "\n";
            return true;
        };

    // ── E5 REGTEST-GATED forced-won-block LIVE seam (--regtest-force-won-block) ──
    //
    // The DASH analog of DGB's #82 --regtest-force-won-share. It drives ONE real
    // won block through the SAME run-path dual-path dispatch (stratum_submit_fn ->
    // broadcast_won_block: ARM A embedded coin-P2P relay primary + ARM B
    // submitblock RPC backup) so the embedded-relay arm is proven LIVE end to end
    // -- not just by the KAT (whose sinks are synthetic). The block is a GENUINE
    // one: pulled from the coin daemon's getblocktemplate, coinbase built by the
    // SSOT dash::coinbase::build, and X11-mined to satisfy the template bits (on
    // regtest bits 0x207fffff the target is trivial so a winner is found at once).
    //
    // FAIL-CLOSED GATE: fires ONLY when (a) --regtest/--testnet is set (never a
    // mainnet path) AND (b) a coin-daemon RPC arm is armed (the GBT + submitblock
    // seam). Even if mis-invoked on the real testnet, the block is built at that
    // net's real difficulty, so no winning nonce is found in the bounded range and
    // nothing is dispatched -- only a trivial-difficulty regtest actually produces
    // a block. Reward/consensus-NEUTRAL: broadcast/relay path only; a no-op unless
    // the flag is explicitly passed. Fired on a readiness-gated timer so the ARM A
    // coin-P2P peer handshake has completed before the relay leg is exercised.
    io::steady_timer force_won_timer(ioc);
    if (force_won_block) {
        if (!testnet) {
            std::cout << "[run] REFUSED --regtest-force-won-block: not a "
                         "regtest/testnet run (mainnet path) -- fail-closed, seam "
                         "NOT armed\n";
        } else if (!rpc) {
            std::cout << "[run] REFUSED --regtest-force-won-block: no coin-daemon "
                         "RPC arm (need --coin-rpc/--coin-daemon for getblocktemplate "
                         "+ submitblock) -- fail-closed, seam NOT armed\n";
        } else {
            auto forced_dispatch = stratum_submit_fn;   // copy BEFORE work_source moves it
            auto fw_attempt = std::make_shared<int>(0);
            constexpr int FW_MAX_ATTEMPTS = 40;         // 40 * 1.5s = 60s cap
            auto fw_poll = std::make_shared<
                std::function<void(const boost::system::error_code&)>>();
            auto fire_forced =
                [&ioc, &rpc, testnet, no_p2p_relay, forced_dispatch](const char* why) {
                    std::cout << "[run] E5 forced-won-block seam firing (regtest, "
                              << why << "); "
                              << (no_p2p_relay ? "ARM B (submitblock) ISOLATED "
                                                 "(--no-p2p-relay)"
                                               : "BOTH arms (embedded P2P relay + "
                                                 "submitblock)")
                              << "\n";
                    try {
                        // 1) Pull the coin-daemon template (real prev/bits/height).
                        dash::coin::DashWorkData work = rpc->getwork();
                        std::cout << "[run] E5 template: height=" << work.m_height
                                  << " bits=0x" << std::hex << work.m_bits << std::dec
                                  << " coinbase_value=" << work.m_coinbase_value << "\n";
                        // 2) Build a genesis-style coinbase (finder-only payout).
                        const core::CoinParams params = dash::make_coin_params(testnet);
                        uint160 payout_pkh;   // all-zero placeholder finder
                        std::map<std::vector<unsigned char>, uint64_t> empty_weights;
                        auto tx_outs = dash::coinbase::compute_dash_payouts(
                            work.m_coinbase_value, work.m_packed_payments, payout_pkh,
                            empty_weights, /*total_weight=*/0, params);
                        auto layout = dash::coinbase::build(
                            work, tx_outs,
                            /*coinbase_text=*/dash::SharechainConfig::coinbase_text(params.is_testnet),
                            params, /*ref_hash=*/uint256::ZERO);
                        // 3) X11-mine to satisfy the template bits.
                        dash::coin::MineResult mr = dash::coin::mine_block(
                            work, layout.bytes, /*max_nonce=*/2000000ull);
                        if (!mr.found) {
                            std::cout << "[run] E5 forced-won-block: NO winning nonce "
                                         "in bound (real-difficulty net?) -- nothing "
                                         "dispatched\n";
                            return;
                        }
                        std::cout << "[run] E5 WON: nonce=" << mr.nonce << " powhash="
                                  << mr.block_hash.GetHex() << " block="
                                  << (mr.block_hex.size() / 2) << " bytes\n";
                        // 4) Drive the REAL run-path dual-path dispatch.
                        std::vector<unsigned char> block_bytes = ParseHex(mr.block_hex);
                        if (forced_dispatch)
                            forced_dispatch(block_bytes, work.m_height,
                                            /*height_race=*/false);
                        else
                            std::cout << "[run] E5 forced-won-block: dispatch sink "
                                         "UNBOUND -- nothing fired\n";
                    } catch (const std::exception& e) {
                        std::cout << "[run] E5 forced-won-block: FAILED (" << e.what()
                                  << ") -- named blocker, no block dispatched\n";
                    }
                };
            *fw_poll = [&force_won_timer, &coin_p2p, fw_poll, fw_attempt,
                        no_p2p_relay, fire_forced](const boost::system::error_code& ec) {
                if (ec) return;
                // Readiness: the ARM A coin-P2P peer handshake must be complete so
                // submit_block_p2p_raw has a live peer. When ARM A is suppressed
                // (--no-p2p-relay) OR no peer was dialed, do not wait on it.
                const bool relay_ready =
                    no_p2p_relay || !coin_p2p || coin_p2p->is_handshake_complete();
                if (relay_ready) {
                    fire_forced("readiness latched");
                    return;
                }
                if (++(*fw_attempt) >= FW_MAX_ATTEMPTS) {
                    fire_forced("readiness TIMEOUT (coin-P2P handshake never "
                                "completed -- NAMED BLOCKER)");
                    return;
                }
                force_won_timer.expires_after(std::chrono::milliseconds(1500));
                force_won_timer.async_wait(*fw_poll);
            };
            force_won_timer.expires_after(std::chrono::milliseconds(1500));
            force_won_timer.async_wait(*fw_poll);
            std::cout << "[run] E5 --regtest-force-won-block ARMED "
                         "(readiness-gated one-shot; regtest harness)\n";
        }
    }

    // DASHWorkSource holds a non-owning ref to node_coin_state (declared above,
    // same scope). The StratumServer co-owns the work source via shared_ptr.
    auto work_source = std::make_shared<dash::stratum::DASHWorkSource>(
        node_coin_state, std::move(dashd_fallback), std::move(stratum_submit_fn),
        core::stratum::StratumConfig{}, testnet);
    // Gate-lift (v0.2.4): allow the daemonless embedded arm on mainnet when the
    // operator opts in via --embedded-mainnet. The CbTx is proven byte-identical
    // to real dashd (both merkle roots reproduced from the mnlistdiff wire); the
    // SML+quorum freshness + superblock viability gates keep it fail-safe.
    work_source->set_embedded_mainnet(embedded_mainnet);
    // Publish the live template to the dashboard PPLNS view (declared far above,
    // where the WebServer seams are bound). peek_template() is the SAME
    // non-fetching peek the block-value card already uses — it never triggers a
    // GBT fetch and never touches the coinbase the miners hash.
    dash_tmpl->bind([wsrc = work_source.get()]() { return wsrc->peek_template(); });
    // Reward-safety backstop: when a dashd fallback is ARMED, cross-check the
    // embedded creditPool against dashd's GBT before serving (catches any seed
    // pool bug the daemonless self-checks miss).
    //
    // THE `&& rpc`, added 2026-08-03 — it is not a tightening, it makes the
    // code do what this comment always claimed. The cross-check invokes the
    // dashd_fallback lambda on EVERY embedded template. On a daemonless node
    // that lambda is unarmed, so it printed
    //   "[DASH-STRATUM-GBT] fallback arm UNARMED ... serving empty set-gap
    //    template"
    // immediately before every SUCCESSFUL EMBEDDED serve: the empty payload
    // then failed parse_cbtx, the mismatch branch was skipped, and EMBEDDED
    // was served correctly. Harmless to correctness, but it made a healthy
    // daemonless log read as if the node fell back on every single template
    // — and it stole the ONE line that should mean a real fallback. With the
    // arm-check the line now fires only when the fallback is genuinely
    // consulted, i.e. during an actual embedded outage.
    const bool xcheck_wanted = (testnet || embedded_mainnet);
    work_source->set_gbt_xcheck(xcheck_wanted && static_cast<bool>(rpc));
    // Pin splice on the xcheck-SWAPPED arm (default OFF). Announce the state
    // either way: with it off the donation still misses every swapped
    // template -- it just no longer does so silently.
    work_source->set_pin_splice_xcheck_arm(pin_splice_xcheck_arm);
    std::cout << "[DASH-STRATUM-GBT] pin splice on xcheck-swapped arm: "
              << (pin_splice_xcheck_arm ? "ON (--pin-splice-xcheck-arm)"
                                        : "OFF (default; misses are named, "
                                          "not spliced)")
              << "\n";
    // Block-size budget for the pin splice (default OFF). It is a flag because
    // ENFORCING it removes a pin from a template the declined-embedded arm is
    // already serving -- that changes served bytes, which is exactly what a
    // money-path change may not do unannounced. OFF it still SAYS the budget
    // was blown; it just does not act.
    work_source->set_pin_splice_block_budget(pin_splice_block_budget);
    std::cout << "[DASH-STRATUM-GBT] pin splice block-size budget: "
              << (pin_splice_block_budget
                      ? "ENFORCED (--pin-splice-block-budget; an over-budget "
                        "pin is EXCLUDED)"
                      : "OFF (default; an over-budget pin still rides and the "
                        "overflow is logged BLOCK-BUDGET EXCEEDED, NOT "
                        "ENFORCED)")
              << "\n";
    if (xcheck_wanted && !rpc) {
        std::cout << "[DASH-STRATUM-GBT] GBT cross-check DISABLED: dashd RPC "
                     "arm UNARMED (pure-daemonless) -- the embedded arm relies "
                     "on the independent seed-height + pre-emit gates\n";
    }

    // ── Embedded-vs-dashd SHADOW-COMPARE DIAGNOSTIC (--embedded-shadow-compare) ──
    // A pure OBSERVABILITY probe, DISTINCT from set_gbt_xcheck above: gbt_xcheck
    // is a reward-safety GATE that can SWAP the served arm on a creditPool
    // mismatch; this probe can NEVER change what is served. On every template
    // re-source it hands the just-resolved template (by copy) to a WORKER THREAD
    // that best-effort fetches dashd's getblocktemplate for the SAME height,
    // field-compares (payee / merkleRootMNList / merkleRootQuorums / cbTx
    // height+version / scriptSig height) and logs one [SHADOW] line. The oracle
    // fetch is entirely off the miner-facing path; a slow/absent dashd just logs
    // `no-oracle`. Only meaningful when a dashd RPC arm is ARMED — pure-daemonless
    // (no rpc) leaves it a strict no-op.
    if (embedded_shadow_compare) {
        if (rpc) {
            auto shadow = std::make_shared<dash::coin::EmbeddedShadowCompare>(
                // OracleFn: dashd getblocktemplate -> DashWorkData, or nullopt on
                // any failure/absence (so the probe degrades to `no-oracle`,
                // never a stall). rp is valid for the probe's lifetime: work_source
                // (which owns this probe) is destroyed before rpc at scope exit,
                // and the probe's dtor joins the worker before returning.
                [rp = rpc.get()]() -> std::optional<dash::coin::DashWorkData> {
                    try { return rp->getwork(); }
                    catch (...) { return std::nullopt; }
                },
                // AcceptFn: dashd testmempoolaccept for ONE transaction we hold
                // and would serve. THE condition that decides when
                // --embedded-serve-mempool-txs may be armed, replacing the
                // unreachable-and-blind `ours_only == 0` set-membership test.
                // Runs on the SAME worker thread as the oracle fetch, so it is
                // off the miner-facing path; a null answer counts UNPROBED,
                // never as a pass. It arms NOTHING -- the flag stays OFF.
                [rp = rpc.get()](const std::string& raw_tx_hex) -> nlohmann::json {
                    return rp->test_mempool_accept(raw_tx_hex);
                });
            work_source->set_shadow_compare(std::move(shadow));
            std::cout << "[run] --embedded-shadow-compare ARMED: OBSERVE-only "
                         "serve-vs-dashd template diff (worker-thread dashd fetch; "
                         "NOT a serve gate; [SHADOW] log lines + counters)\n"
                      << "      [MEMPOOL-VALIDITY] gate ARMED with it: every tx we "
                         "would serve goes to dashd testmempoolaccept. Condition "
                         "for arming --embedded-serve-mempool-txs = ZERO INVALID "
                         "over "
                      << dash::coin::MempoolValidityGate::kCleanHeightsRequired
                      << " consecutive evidence-bearing DISTINCT heights (the "
                         "probe fires ~5-6x per block; repeats do not advance "
                         "the window). ours_only is "
                         "INFORMATIONAL and gates nothing.\n";
        } else {
            std::cout << "[run] --embedded-shadow-compare given but no dashd RPC "
                         "arm is armed (pure-daemonless) -- no oracle to compare "
                         "against; probe NOT armed (no-op)\n";
        }
    }

    // ── Mint slice 3/3: run-loop share minting wiring ─────────────────────
    // ShareAccept -> build_mint_share -> tracker insert -> peer broadcast.
    // All callbacks below run on THIS ioc (StratumServer shares it), so the
    // node's IO-thread invariants (try_to_lock tracker access) hold.
    {
        dash::Node* node_ptr = &p2p_node;
        auto mint_registry = std::make_shared<dash::mint::FrozenJobRegistry>();

        // ── Fee policy (README flags, LTC sharechain-lane port) ───────────
        // --give-author -> the share's donation field (oracle dev-fee channel;
        // the donation output itself is ALWAYS emitted by the gentx, even at
        // 0% — the dust-marker semantic is preserved by construction).
        // --fee/--node-owner-address -> probabilistic identity substitution
        // (consensus-safe). --redistribute -> broken-credential policy.
        dash::mint::MintFeePolicy fee_policy;
        fee_policy.donation_u16       = dash::mint::donation_percent_to_u16(dev_donation);
        fee_policy.node_owner_fee_pct = node_owner_fee;
        fee_policy.redistribute =
            dash::mint::MintFeePolicy::parse_redistribute(redistribute_mode);
        if (!node_owner_address.empty()) {
            auto owner_script = core::address_to_script(node_owner_address);
            if (dash::stratum::pubkey_hash_from_p2pkh(owner_script)) {
                fee_policy.node_owner_script = std::move(owner_script);
            } else {
                std::cout << "[run] --node-owner-address is not a P2PKH DASH "
                             "address -- node-owner fee/redistribute-to-owner "
                             "DISABLED (shares are pubkey_hash-keyed)\n";
            }
        }
        if (fee_policy.node_owner_fee_pct > 0.0 && fee_policy.node_owner_script.empty())
            std::cout << "[run] --fee " << node_owner_fee << " set but no usable "
                         "--node-owner-address -- node-owner fee DISABLED\n";
        std::cout << "[run] fee policy: give-author=" << dev_donation
                  << "% (donation_u16=" << fee_policy.donation_u16
                  << ") node-owner-fee=" << node_owner_fee
                  << "% (owner=" << (fee_policy.node_owner_script.empty() ? "unset" : node_owner_address)
                  << ") redistribute=" << redistribute_mode << "\n";

        // Best-share election: prev_share_hash for new jobs = the live tip
        // think() elected (verified-work-first; ZERO with peers-but-no-
        // verified-chain so we never mint on an unverified foreign chain).
        work_source->set_best_share_hash_fn(
            [node_ptr]() -> uint256 { return node_ptr->best_share_hash(); });

        // ── REAL best-share feed for the dashboard "Best Share" card ──────
        // Every ACCEPTED stratum submit reports the actual PoW difficulty of
        // the found hash (target_to_difficulty(pow_hash)) + miner + pow-hash.
        // record_share_difficulty tracks the pool-wide/session/round max WITH
        // the hash + timestamp; /best_share + /local_stats render it. This is
        // the PRIMARY best-share feed on the DASH solo path — the tracker's
        // verified-share m_on_share_difficulty hook (wired above) almost never
        // fires here because solo shares seldom mint onto the sharechain, so
        // without this the 🎯 Best Share card sat empty. Display only; the
        // callback touches no share/target/payout logic (consensus-neutral).
        if (web_server) {
            core::WebServer* ws = web_server.get();
            work_source->set_on_share_difficulty_fn(
                [ws](double diff, const std::string& miner, const uint256& pow_hash) {
                    ws->get_mining_interface()->record_share_difficulty(
                        diff, miner, pow_hash.GetHex());
                });

            // ── Recent-blocks feed: DASH block wins into the history card ──
            // Every dispatched block solution records to /recent_blocks with
            // the height, X11 block hash (== pow_hash for DASH), miner, and the
            // net difficulty at find time. Without this DASH block wins never
            // appeared on the recent-blocks card (main_ltc.cpp:2970 parity).
            // Display only; the callback runs after dispatch, never gates it.
            work_source->set_on_found_block_fn(
                [ws](uint32_t height, const uint256& block_hash,
                     const std::string& miner, bool reached_network) {
                    auto* mi = ws->get_mining_interface();
                    // Subsidy: the WebServer-held template is empty on the
                    // embedded arm (row 2516914 recorded subsidy=0 from it on
                    // 2026-08-05); record_found_block now falls back to the
                    // live coin template itself, so 0 here means "let the
                    // core ask the template". Same for pool hashrate: this
                    // site passed get_local_hashrate() into a field named
                    // pool_hashrate_at_find — correct only while every rig
                    // in the pool happens to sit on this node. 0 routes the
                    // core to m_pool_hashrate_fn (the real pool estimator),
                    // which is the rate expected_time/luck are defined over.
                    uint64_t subsidy = 0;
                    {
                        auto tmpl = mi->get_current_work_template();
                        if (!tmpl.is_null() && tmpl.contains("coinbasevalue"))
                            subsidy = tmpl["coinbasevalue"].get<uint64_t>();
                    }
                    mi->record_found_block(
                        height, block_hash,
                        static_cast<uint64_t>(std::time(nullptr)),
                        "DASH", miner, block_hash.GetHex(),
                        mi->get_network_difficulty(),
                        /*share_difficulty=*/0.0,
                        /*pool_hashrate=*/0.0,
                        subsidy,
                        // Local dispatch: THIS node built the template and
                        // sent the block. Whatever we pinned rode it.
                        core::MiningInterface::BlockAuthorship::this_node);
                    // Arm the post-broadcast confirm/orphan poller so this local
                    // win flips off "pending" (main_ltc.cpp:4258 parity).
                    // Telemetry only; runs after dispatch, never gates it.
                    mi->schedule_block_verification(block_hash.GetHex());
                    if (!reached_network)
                        LOG_WARNING << "[DASH] recorded found block height="
                                    << height << " that reached NO network sink";
                });
        }

        // Producer job: the stratum coinbase IS the producer share gentx
        // (byte-parity with the mint-time rebuild by construction). The
        // frozen per-job context is registered under its ref_hash.
        //
        // Per-(prev, payout, template) CACHE: sessions re-notify every ~1 s;
        // a fresh random share_nonce per notify would make every job's bytes
        // unique — defeating the session's shared-payload reuse AND churning
        // the frozen-job registry past its eviction window. Rebuilding is
        // deterministic given the same inputs, so within a 30 s TTL (the
        // template staleness window) the SAME job is served.
        struct ProducerJobCacheEntry {
            dash::mint::ProducerJobBuild build;
            uint256 coin_tip;
            uint32_t height{0};
            std::chrono::steady_clock::time_point at;
        };
        using ProducerJobKey = std::pair<uint256, std::vector<unsigned char>>;
        auto job_cache = std::make_shared<
            std::map<ProducerJobKey, ProducerJobCacheEntry>>();

        work_source->set_producer_job_fn(
            // stratum_server is captured BY REFERENCE (the sibling lambdas'
            // established style — set_on_best_share_changed below, and
            // set_on_state_dirty): the acceptor is constructed further down and
            // stays null under --stratum-port 0, and it is reset BEFORE
            // work_source unwinds, so every use is null-guarded. It supplies the
            // per-address hashrate the 1.67% pool-share cap modulates on.
            [node_ptr, mint_params, mint_registry, job_cache, fee_policy,
             &stratum_server](
                const uint256& prev_share_hash,
                const std::vector<unsigned char>& payout_script,
                const dash::coin::DashWorkData& wd)
                -> std::optional<dash::stratum::DASHWorkSource::ProducerJob>
            {
                const auto now = std::chrono::steady_clock::now();
                const ProducerJobKey key{prev_share_hash, payout_script};

                // Cache hit: same sharechain tip, same coin template, fresh.
                //
                // "Same coin template" MUST mean the same TX SET, not merely the
                // same tip+height: dashd re-sources GBT ~every 30 s at the SAME
                // (tip, height) while the mempool moves, and the masternode
                // payout amount inside the cached gentx is fee-dependent
                // (MN share of subsidy+fees). Serving a cached gentx built over
                // an older poll's fee total while build_connection_coinbase
                // freezes the CURRENT wd's tx set around it yields a merkle-
                // consistent but consensus-INVALID block: the coinbase underpays
                // the MN payee by the fee delta's share and dashd rejects it
                // with bad-cb-payee (hotel mainnet h2508929: paid the exact
                // GBT@fees=1074 amount vs expected GBT@fees=1301 amount;
                // h2509044: paid GBT@fees=85791 vs expected GBT@fees=88051 --
                // both found blocks lost). desired_tx_hashes equality pins the
                // cached coinbase to the exact tx set (and therefore the exact
                // fee total) it was computed for; payment_amount equality is the
                // cheap belt for any same-height payment-array drift.
                if (auto it = job_cache->find(key); it != job_cache->end()) {
                    auto& e = it->second;
                    if (e.coin_tip == wd.m_previous_block && e.height == wd.m_height
                        && e.build.frozen.payment_amount == wd.m_payment_amount
                        && e.build.frozen.desired_tx_hashes == wd.m_tx_hashes
                        && now - e.at < std::chrono::seconds(30)) {
                        mint_registry->put(e.build.job.ref_hash, e.build.frozen);
                        return e.build.job;
                    }
                    if (e.coin_tip == wd.m_previous_block && e.height == wd.m_height
                        && now - e.at < std::chrono::seconds(30)) {
                        static int drift_log = 0;
                        if (drift_log++ % 20 == 0)
                            LOG_INFO << "[MINT] producer job cache invalidated: "
                                        "template tx-set/fee drift at same tip "
                                        "(h=" << wd.m_height << ") -- rebuilding "
                                        "gentx over the current template";
                    }
                    job_cache->erase(it);
                }
                // Lazy TTL sweep keeps the cache bounded across miner churn.
                if (job_cache->size() > 128) {
                    for (auto it = job_cache->begin(); it != job_cache->end();) {
                        if (now - it->second.at > std::chrono::seconds(60))
                            it = job_cache->erase(it);
                        else
                            ++it;
                    }
                }

                auto guard = node_ptr->read_tracker();
                if (!guard)
                    return std::nullopt;   // compute thread busy — degrade this job

                static std::mt19937 nonce_rng{std::random_device{}()};
                const uint32_t share_nonce = static_cast<uint32_t>(nonce_rng());

                // Fee policy: one roll per job build (p2pool's per-get_work
                // fee roll); resolve the share identity + donation.
                const uint32_t roll_x100 = static_cast<uint32_t>(nonce_rng() % 10000u);
                auto identity = dash::mint::resolve_mint_identity(
                    fee_policy, payout_script, roll_x100);
                if (!identity) {
                    static int redist_log = 0;
                    if (redist_log++ % 50 == 0)
                        LOG_WARNING << "[MINT] no usable share identity for this "
                                       "miner (non-P2PKH credentials; redistribute="
                                    << "policy declined) -- job degrades to the "
                                       "non-producer coinbase";
                    return std::nullopt;
                }
                if (identity->substituted) {
                    static int fee_log = 0;
                    if (fee_log++ % 50 == 0)
                        LOG_INFO << "[MINT] share identity substituted by fee/"
                                    "redistribute policy (node-owner)";
                }

                // ── Canonical 1.67% pool-share cap input (work.py:309-312) ──
                //
                // The measured hashrate of THIS miner, keyed on its own payout
                // pubkey_hash — the same RateMonitor aggregation p2pool's
                // get_local_addr_rates() feeds the cap with. Mirrors the LTC
                // wiring (main_ltc.cpp:4504-4550, with the band clip at
                // :4595-4597): pull the hash160 straight out of the P2PKH payout
                // script, look it up, apply Cap 1, and hand the result to
                // compute_share_target as the pre-clip desired target.
                //
                // Keyed on the MINER's script, NOT identity->payout_script: the
                // --fee/--redistribute substitution changes whose PPLNS weight
                // the share carries, but the work was done by this miner and the
                // cap is a property of that work rate.
                //
                // Unknown rate (fresh session, no pseudoshare in the RateMonitor
                // window, non-P2PKH credentials, --stratum-port 0) -> 0.0 -> the
                // cap is inert and the desired target is bit-identical to the
                // previous params.max_target behaviour.
                //
                // Lock note: get_local_addr_rates() takes only StratumServer's
                // RateMonitor/cache LEAF mutexes (no sessions_mutex_, no
                // m_work_mutex), so no new lock-order edge is introduced on the
                // build_connection_coinbase path.
                double local_hash_rate = 0.0;
                if (stratum_server && payout_script.size() == 25 &&
                    payout_script[0] == 0x76 && payout_script[1] == 0xa9 &&
                    payout_script[2] == 0x14 && payout_script[23] == 0x88 &&
                    payout_script[24] == 0xac)
                {
                    std::array<uint8_t, 20> miner_pubkey{};
                    std::copy(payout_script.begin() + 3, payout_script.begin() + 23,
                              miner_pubkey.begin());
                    const auto rates = stratum_server->get_local_addr_rates();
                    auto it = rates.find(miner_pubkey);
                    if (it != rates.end() && it->second > 0.0)
                        local_hash_rate = it->second;
                }

                auto built = dash::mint::build_producer_job(
                    guard->chain, mint_params, prev_share_hash,
                    identity->payout_script, wd,
                    static_cast<uint32_t>(std::time(nullptr)), share_nonce,
                    identity->donation_u16,
                    /*coinbase_text=*/dash::SharechainConfig::coinbase_text(mint_params.is_testnet),
                    local_hash_rate);
                if (!built)
                    return std::nullopt;

                {
                    // Observability for the consensus-visible target choice:
                    // what the cap asked for vs what the chain band allowed.
                    static int cap_log = 0;
                    if (cap_log++ % 50 == 0) {
                        const uint256 desired = dash::mint::desired_share_target(
                            mint_params, local_hash_rate);
                        LOG_INFO << "[MINT-CAP] local_hr=" << local_hash_rate
                                 << " H/s desired="
                                 << desired.GetHex().substr(0, 16)
                                 << " -> share_bits=0x" << std::hex
                                 << built->job.share_bits << " max_bits=0x"
                                 << built->job.share_max_bits << std::dec
                                 << " share_diff="
                                 << chain::target_to_difficulty(
                                        chain::bits_to_target(built->job.share_bits));
                    }
                }

                mint_registry->put(built->job.ref_hash, built->frozen);
                // Template txs -> m_known_txs so share relay can serve
                // remember_tx for the share's new_transaction_hashes.
                node_ptr->register_template_txs(wd.m_txs, wd.m_tx_hashes);

                auto job = built->job;
                (*job_cache)[key] = ProducerJobCacheEntry{
                    std::move(*built), wd.m_previous_block, wd.m_height, now};
                return job;
            });

        // The mint itself: registry lookup by the coinbase's OP_RETURN
        // commitment, deterministic producer rebuild (X11 identity gate +
        // pow<=target ban-safety gate inside), tracker insert + broadcast.
        work_source->set_mint_share_fn(
            [node_ptr, mint_params, mint_registry, mint_ledger](
                const dash::stratum::DASHWorkSource::MintShareInputs& in) -> uint256
            {
                if (in.ref_hash.IsNull()) {
                    LOG_WARNING << "[MINT] solve on a non-producer job (zero ref) — "
                                   "no sharechain credit (fail-closed)";
                    return uint256();
                }
                auto frozen = mint_registry->get(in.ref_hash);
                if (!frozen) {
                    LOG_WARNING << "[MINT] no frozen job for ref="
                                << in.ref_hash.GetHex().substr(0, 16)
                                << " (evicted/foreign) — declined";
                    return uint256();
                }

                // #889: a WON BLOCK is unrepeatable — there is no next solve to
                // mint instead, and an unminted block-winning share is a block
                // no p2pool peer can ever see (they detect pool blocks by
                // watching the sharechain for a share meeting the block target,
                // p2pool/node.py:145-147). So the block arm takes a BOUNDED WAIT
                // for the tracker; the ordinary share arm keeps today's single
                // try-and-decline, which is the right trade when the next solve
                // mints. THE BLOCK IS ALREADY SUBMITTED at this point — the
                // won-block arm in work_source.cpp dispatches it before invoking
                // this seam — so no wait here can delay or endanger it.
                //
                // #878/#881: this lambda holds ZERO locks on entry (stratum
                // asio handler -> process_message -> handle_submit ->
                // mining_submit -> mint seam; verified lock-free end to end),
                // which is what makes a bounded wait viable instead of a
                // deadlock. The guard below is scoped and RELEASED before
                // add_local_share takes the exclusive lock — never nested.
                const auto urgency = in.won_block
                    ? dash::tracker_acquire::Urgency::BlockWinning
                    : dash::tracker_acquire::Urgency::Opportunistic;

                std::optional<dash::producer::BuiltShare> built;
                {
                    auto guard = node_ptr->read_tracker(urgency);
                    if (!guard) {
                        if (in.won_block) {
                            LOG_ERROR << "[MINT-BLOCK] FORFEIT — tracker still "
                                         "busy after "
                                      << dash::tracker_acquire::
                                             BLOCK_SHARE_LOCK_BUDGET.count()
                                      << "ms; cannot even REBUILD the "
                                         "block-winning share. The block was "
                                         "already submitted, but no p2pool peer "
                                         "will see it.";
                        } else {
                            LOG_WARNING << "[MINT] tracker busy — solve declined "
                                           "(retry on next share)";
                        }
                        return uint256();
                    }
                    built = dash::mint::mint_from_inputs(
                        guard->chain, mint_params, in, *frozen);
                }
                if (!built) {
                    LOG_WARNING << "[MINT] producer rebuild declined the solve "
                                   "(identity/target gate) — NOT minted";
                    return uint256();
                }

                dash::ShareType share;
                share = new dash::DashShare(std::move(built->share));
                // #889: same urgency for the tracker WRITE. add_local_share
                // still returns ZERO if the bounded wait expires — the decline
                // is preserved, it is just no longer silent (LOG_ERROR + a
                // forfeit counter) and no longer triggered by a merely
                // momentary think().
                const uint256 minted =
                    node_ptr->add_local_share(share, in.won_block);
                if (minted.IsNull()) {
                    // Not inserted (busy/duplicate) — reclaim the allocation.
                    share.invoke([](auto* obj) { delete obj; });
                    return uint256();
                }
                LOG_INFO << "[MINT] share " << minted.GetHex().substr(0, 16)
                         << " minted onto the sharechain (prev="
                         << in.prev_share_hash.GetHex().substr(0, 16) << ")";
                // Display-only: remember what we minted so the best-share-changed
                // leg below can tell us later whether it stayed on the best chain
                // (see local_mint_ledger.hpp). Never gates the mint.
                mint_ledger->record_mint(minted);
                return minted;
            });

        // PPLNS fallback-coinbase weights (non-producer path): oracle-window
        // tracker walk so even a degraded job pays the live PPLNS window.
        // block_bits from the prev share's own header (same difficulty epoch);
        // ref stays ZERO — a solve on this path can never mint (fail-closed).
        work_source->set_pplns_weights_fn(
            [node_ptr, mint_params](const uint256& prev_share_hash)
                -> std::optional<dash::stratum::DASHWorkSource::PplnsWeights>
            {
                auto guard = node_ptr->read_tracker();
                if (!guard)
                    return std::nullopt;
                if (prev_share_hash.IsNull() || !guard->chain.contains(prev_share_hash))
                    return std::nullopt;
                uint32_t block_bits = 0;
                guard->chain.get_share(prev_share_hash).invoke([&](auto* obj) {
                    block_bits = obj->m_min_header.m_bits;
                });
                return dash::mint::pplns_weights_for(
                    guard->chain, mint_params, prev_share_hash, block_bits);
            });

        // New best share -> PUSH new work to every stratum session, plus a
        // debounced dashboard work refresh, so /api tip + graphs move on the
        // real tip-change event (main_ltc.cpp:2768) rather than a poll timer.
        //
        // The notify_all() leg is the fix for the sibling/orphan defect: this
        // callback used to only bump_work_generation(), which INVALIDATES the
        // served payload but pushes nothing. Connected rigs therefore kept
        // hashing the previous prev_share_hash until their per-session
        // keepalive timer fired (StratumConfig::keepalive_notify_sec = 25 s,
        // work_source.cpp; stratum_server.cpp idle-timer leg), and because the
        // producer job_cache is keyed (prev_share_hash, payout_script) every
        // solve in that window rebuilt the SAME frozen job -> a fan of siblings
        // at one sharechain height instead of a linear chain. notify_all()
        // issues send_notify_work(force_clean=true), i.e. clean_jobs=true, so
        // the miner switches to the new prev_share immediately (p2pool
        // behaviour) -- exactly what the coin-tip legs below already do
        // (set_on_state_dirty, the coin-P2P tip leg, and fire_refresh).
        //
        // stratum_server is captured BY REFERENCE (the sibling lambda's style):
        // the acceptor is constructed further down, and stays null under
        // --stratum-port 0. fire_share_tip_refresh null-guards every leg.
        //
        // Reward-safety: a tip change means a NEW prev_share_hash -> a new
        // job_cache key -> a fresh build_producer_job. No existing share's
        // committed bytes are touched; we only stop re-serving a stale job.
        {
            core::WebServer* web = web_server.get();   // may be null (dashboard off)
            p2p_node.set_on_best_share_changed(
                [ws = work_source.get(), web, &stratum_server, node_ptr,
                 mint_ledger]() {
                    dash::stratum::fire_share_tip_refresh(
                        ws, stratum_server.get(), web);

                    // Display-only: settle the local-mint orphan gauge against
                    // the new best chain. Runs AFTER the notify (miners first)
                    // and on a try-lock read guard, so a busy tracker simply
                    // defers the verdict to the next tip change.
                    if (mint_ledger->pending_count() > 0) {
                        auto guard = node_ptr->read_tracker();
                        if (guard) {
                            const uint256 best = node_ptr->snapshot_best_share();
                            auto& chain = guard->chain;
                            mint_ledger->settle(
                                [&chain, &best](const uint256& h) {
                                    return dash::mint::classify_local_mint(
                                        chain, best, h,
                                        dash::mint::LocalMintLedger::kSettleDepth);
                                });
                        }
                    }
                });
        }

        std::cout << "[run] mint wiring LIVE: ShareAccept -> producer rebuild -> "
                     "tracker insert + broadcast (legacy v16 shares; PPLNS window "
                     "walk bound)\n";
    }

    // Stale-payee fix (defect 3): bind the CoindRPC reconnect-churn observer.
    // A "CoindRPC reconnecting" window means any cached template — and the
    // masternode payee frozen inside it — may predate the reconnect; the
    // observer drops the DASHWorkSource template cache and bumps the work
    // generation so every stratum session re-pulls FRESH work instead of
    // mining (and later submitting) a payee from before the churn. weak_ptr:
    // rpc outlives work_source in this scope (declared earlier), so the
    // callback must not extend or assume the work source's lifetime.
    //
    // This is the conservative DEFAULT (covers the embedded arm, and the
    // fallback arm before its tip poll is armed): every reconnect invalidates
    // unconditionally. On the fallback arm the tip-poll block below OVERRIDES
    // this with a tip-aware version that skips the invalidate when the tip is
    // provably unchanged (#751 idle-reconnect churn fix) -- see there.
    if (rpc) {
        std::weak_ptr<dash::stratum::DASHWorkSource> ws_weak = work_source;
        rpc->set_on_reconnect([ws_weak]() {
            if (auto ws = ws_weak.lock())
                ws->invalidate_template_cache("CoindRPC reconnect churn");
        });
    }

    if (stratum_port != 0) {
        stratum_server = std::make_unique<core::StratumServer>(
            ioc, stratum_host, stratum_port, work_source);
        if (stratum_server->start()) {
            std::cout << "[run] stratum listening on " << stratum_host << ":"
                      << stratum_port
                      << " (work source: DASHWorkSource 4c/4d -- X11 template"
                      << " serving + submit scoring; templates source from the"
                      << " embedded coin-state when seeded, else the retained"
                      << " dashd-RPC GBT fallback)\n";
            // ── REAL local (stratum) hashrate into the dashboard ───────
            // Same two callbacks WebServer wires for its own acceptor
            // (web_server.cpp:8730-8740), but sourced from the DASH
            // StratumServer that actually serves X11 miners. This is what
            // makes /local_stats report a truthful local hashrate + DOA
            // window instead of nothing.
            if (web_server) {
                auto* ss = stratum_server.get();
                auto* mi = web_server->get_mining_interface();
                mi->set_stratum_hashrate_fn(
                    [ss]() -> double { return ss->get_total_hashrate(); });
                mi->set_stratum_rate_stats_fn(
                    [ss]() -> core::MiningInterface::RateStats {
                        auto s = ss->get_rate_stats();
                        return {s.hashrate, s.effective_dt, s.total_datums,
                                s.dead_datums};
                    });
                // ── REAL per-worker registry into the dashboard ────────────
                // The DASH stratum acceptor's StratumSessions register/update
                // their per-connection hashrate + share/difficulty state into
                // DASHWorkSource (NOT the dashboard's own MiningInterface,
                // whose acceptor is disabled). Feed that live registry so
                // /local_stats + /stratum_stats report the true per-miner
                // hashrates, non-empty miner maps, and a correct connected-
                // miner count (no false "pool is idle"). Display only.
                mi->set_stratum_workers_fn(
                    [wsrc = work_source.get()]()
                        -> std::map<std::string, core::MiningInterface::WorkerInfo> {
                        return wsrc->get_stratum_workers();
                    });
                // ── REAL block value + network difficulty into the dashboard ─
                // c2pool-dash drives its own work pipeline, so WebServer's
                // m_cached_template stays empty. Expose the last-sourced dashd
                // GBT template so block_value / masternode payment split /
                // attempts_to_block read the live values. Non-fetching peek;
                // display only, never drives coinbase or consensus.
                mi->set_coin_work_fn(
                    [wsrc = work_source.get()]()
                        -> core::MiningInterface::CoinWorkInfo {
                        core::MiningInterface::CoinWorkInfo info;
                        auto t = wsrc->peek_template();
                        if (!t) return info;
                        info.valid              = true;
                        info.coinbase_value_sat = t->m_coinbase_value;
                        info.payment_amount_sat = t->m_payment_amount;
                        info.height             = t->m_height;
                        info.template_age_sec   = wsrc->peek_template_age_sec();
                        // ── EVERY non-miner output, not just the MN payee ─
                        // m_payment_amount rides in share serialization and
                        // on the embedded arm carries ONLY the projected MN
                        // payment — it must keep that meaning. The dashboard
                        // needs the ACCEPTED-coinbase truth: miner share =
                        // coinbasevalue − ALL protocol outputs. Measured on
                        // our own accepted h=2516911: MN 0.8304 + platform
                        // burn 0.4979 leave miners 0.4428 (25%), while the
                        // card computed 0.9404 (53%) by subtracting the MN
                        // payee alone. Summing m_packed_payments — which
                        // both the RPC and embedded builders fill in real
                        // coinbase-output order — closes that gap. Display
                        // only; no share/consensus field is touched.
                        uint64_t total = 0, burn = 0;
                        for (const auto& pp : t->m_packed_payments) {
                            total += pp.amount;
                            // "!6a" is the normalized OP_RETURN platform
                            // burn (rpc.cpp / embedded_gbt.hpp both use it).
                            if (pp.payee.rfind("!6a", 0) == 0)
                                burn += pp.amount;
                        }
                        info.payments_total_sat = total;
                        info.burn_sat           = burn;
                        if (t->m_bits != 0)
                            info.network_difficulty = chain::target_to_difficulty(
                                dash::coin::target_from_nbits(t->m_bits));
                        return info;
                    });
                std::cout << "[run] dashboard local-hashrate + per-worker "
                             "registry + block-value/net-diff bound to the DASH "
                             "stratum acceptor\n";
            }
        } else {
            std::cout << "[run] stratum FAILED to bind " << stratum_host << ":"
                      << stratum_port << " -- stratum disabled\n";
            stratum_server.reset();
        }
    } else {
        std::cout << "[run] stratum disabled (no --stratum flag)\n";
    }

    // ── Think loop: initial election + 15 s keep-fresh tick ───────────────
    // Share arrivals trigger run_think() themselves (add_verified_shares);
    // the periodic tick covers quiet stretches (retries deferred broadcasts,
    // re-elects after verify continuations) and now runs clean_tracker()
    // (btc/ltc parity: think + stale-head eat + drop-tails beyond
    // 2*CHAIN_LENGTH+10 + LevelDB prune — without it the raw chain grows
    // unbounded). clean_tracker runs think inline, so the tick still keeps
    // the election fresh; it no-ops (defers) when a think is in flight.
    boost::asio::post(ioc, [&p2p_node]() { p2p_node.run_think(); });
    auto think_timer = std::make_shared<io::steady_timer>(ioc);
    auto think_tick =
        std::make_shared<std::function<void(const boost::system::error_code&)>>();
    *think_tick = [&p2p_node, think_timer, think_tick](
                      const boost::system::error_code& ec) {
        if (ec) return;   // cancelled at shutdown
        p2p_node.clean_tracker();
        think_timer->expires_after(std::chrono::seconds(15));
        think_timer->async_wait(*think_tick);
    };
    think_timer->expires_after(std::chrono::seconds(15));
    think_timer->async_wait(*think_tick);

    // ── E2a: wire the LIVE coin-P2P feed into the maintainer -> populate ──
    // GUARANTEE: this whole block is gated on `coin_p2p` (i.e. --coin-p2p-connect
    // was supplied). With NO flag, coin_p2p is null, none of the header chain /
    // maintainer / ingest legs below are constructed, and run_node is byte-
    // identical to the released dashd-fallback prod path. The subscriptions are
    // REGISTERED here (before ioc.run()); no wire event can fire until the loop
    // below pumps the socket I/O, so wiring after the E1 connect() is race-free.
    //
    // These locals are declared LAST in run_node's scope so they are destroyed
    // FIRST at return (after ioc.run() has stopped and no further events fire):
    // subscription handles -> maintainer -> header_chain, all torn down before
    // node_coin_state / coin_state (declared earlier) they reference.
    std::unique_ptr<dash::coin::HeaderChain> header_chain;
    std::unique_ptr<dash::coin::CoinStateMaintainer> maintainer;
    // #91: the MN-CKPT bridge's resumable replay cursor. Declared BEFORE the
    // lane so it is destroyed AFTER it — the lane borrows a raw pointer and
    // writes through it from on_block_connected/publish, so the store must
    // outlive every path that can still call into the lane.
    std::unique_ptr<dash::coin::MnBridgeCursorStore> mn_bridge_cursor;
    // E2d: the daemonless MN-set bridge. Constructed for the whole embedded
    // arm so the tip-changed driver below can pump it unconditionally, but
    // only ARMED on the no-RPC path (an available `protx list` is strictly
    // better than a pinned anchor, so the hotel/RPC posture is unchanged).
    // Declared AFTER maintainer and BEFORE coin_feed_subs so teardown order is
    // subscriptions -> lane -> maintainer -> header_chain.
    std::unique_ptr<dash::coin::MnCheckpointLane> mn_ckpt_lane;
    std::vector<std::shared_ptr<EventDisposable>> coin_feed_subs;
    // ── W2 replay bulk-fetch locals (--replay-bulk; replay_bulk_fetch.hpp) ──
    // Declared AFTER header_chain (they read it) so they unwind FIRST at
    // return; the timer is last so its callbacks stop before the lane dies.
    // All null unless the flag armed them — zero construction otherwise.
    std::unique_ptr<dash::coin::replay::HeaderBackfill>        replay_backfill;
    std::unique_ptr<dash::coin::replay::CountingReplayConsumer> replay_counter;
    std::unique_ptr<dash::coin::replay::CaptureReplayConsumer> replay_capture;
    std::unique_ptr<dash::coin::replay::ReplayCursorStore>     replay_cursor;
    std::unique_ptr<dash::coin::replay::BulkFetchLane>         replay_lane;
    std::unique_ptr<core::Timer>                               replay_timer;
    // Phase-1 mempool-ingest telemetry (30s); constructed only under
    // --embedded-mempool-ingest.
    std::unique_ptr<core::Timer>                               mempool_ingest_timer;
    // #129 fresh-path header-sync stall watchdog (coin-p2p arm only).
    // Declared after header_chain/coin_p2p so it unwinds FIRST at return —
    // its callback reads both.
    std::unique_ptr<core::Timer>                               header_sync_watchdog_timer;
    // W5 integration: the fold engine the lane drives, and its consumer.
    std::unique_ptr<dash::coin::replay::DmlFoldEngine>         replay_fold_engine;
    std::unique_ptr<dash::coin::replay::FoldReplayConsumer>    replay_fold_consumer;
    // THE SEAM: W4's quorum lane and the bridge that closes the loop.
    std::unique_ptr<dash::coin::replay::QuorumReplayEngine>    replay_quorum_engine;
    std::unique_ptr<dash::coin::replay::ReplayQuorumBridge>    replay_quorum_bridge;
    // THE SERVE SEAM: the fold's proven-current list -> the payee queue that
    // gates serving, plus the live-tip tail that lets the fold actually REACH
    // the tip (the bulk lane idles at the height its peers announced).
    // Constructed only alongside the fold engine.
    std::unique_ptr<dash::coin::replay::FoldLiveTail>          replay_live_tail;
    std::unique_ptr<dash::coin::replay::ReplayPayeePublisher>  replay_payee_pub;
    // MN DIFF/SNAPSHOT STORE (dashd evodb dmn_D4/dmn_S3 port,
    // evo/deterministicmns.cpp:689-694): per-block list diffs + 576-cadence
    // snapshots written by the fold's per-block commit, read by the payee-
    // queue gap-repair seam. Constructed only alongside the fold engine.
    std::unique_ptr<dash::coin::replay::MnDiffStore>           mn_diff_store;
    std::unique_ptr<dash::coin::replay::MnDiffWriter>          mn_diff_writer;
    // DASHD-CUT ARM: the PARALLEL DML fold engine that feeds the diff store on
    // the COLD MN-CKPT bridge path (no --replay-bulk / --replay-fold-prestate).
    // The cold bridge folds an MnStateMachine (payee projection); this engine
    // folds the full ReplayMNState alongside it so the store writer has the
    // root+payee-checked per-block commit it needs. Seeded at the same anchor
    // the bridge stands on; sinks MnDiffWriter::on_folded off ITS OWN commit.
    std::unique_ptr<dash::coin::replay::DmlFoldEngine>         mn_bridge_fold_engine;
    // DASHD-CUT ARM (resolver wiring): the parallel store engine, like the
    // main replay-fold path, needs the W4 quorum-member resolver or its fold
    // FAILS CLOSED at the first punishing qfcommit (llmqType=5 @ h=2513130,
    // ~130 past the anchor) and the store caps there. Stand up a SECOND
    // QuorumReplayEngine + ReplayQuorumBridge whose ctor installs
    // set_members_fn onto mn_bridge_fold_engine, seeded at the SAME anchor.
    std::unique_ptr<dash::coin::replay::QuorumReplayEngine>    mn_bridge_quorum_engine;
    std::unique_ptr<dash::coin::replay::ReplayQuorumBridge>    mn_bridge_quorum_bridge;
    // PR-2 FORWARD: dashd's mined-commitment store, fed from the same replayed
    // bodies. shared_ptr because the qc-plan lambda (installed far above, on
    // the serve path) captures it by value and must see it appear later — it
    // stays null, and the lambda's guard stays false, when the flag is off or
    // the arm is refused.
    std::shared_ptr<dash::coin::MinedCommitmentIndex>          mined_commitment_index;
    if (coin_p2p) {
        const auto dash_params = testnet
            ? dash::coin::make_dash_chain_params_testnet()
            : dash::coin::make_dash_chain_params_mainnet();
        const auto hdr_db = (core::filesystem::config_path()
            / net_subdir / "dash_headers").string();
        header_chain = std::make_unique<dash::coin::HeaderChain>(dash_params, hdr_db);
        header_chain->init();

        // CROSS-LANE ASYMMETRY CLOSED: HeaderChain::is_synced() was DEFINED
        // AND NEVER CALLED on the DASH path (bch 13 callers, ltc 12, nmc 12,
        // btc 6, dgb 6, dash 0) -- a predicate nothing invokes is a lie about
        // what the code checks. Every other freshness gate on NodeCoinState is
        // relative to OUR OWN tip and so is satisfied by a node that is
        // thousands of blocks behind but internally consistent; this is the
        // only comparison against anything outside our own view. LTC's
        // template_builder.hpp:376 is the reference pattern (refuse, do not
        // serve). A refusal here is a template-SERVE refusal, never a
        // block-SUBMIT refusal, and it now NAMES itself as "chain-not-synced".
        node_coin_state.set_chain_synced_fn(
            [hc = header_chain.get()] { return hc && hc->is_synced(); });

        // ── Daemonless chain queries ──────────────────────────────────────
        // getbestblockhash / getblockhash / getblockchaininfo are answered
        // from the header chain we just opened — a PoW(X11)+DGW-validated,
        // height-indexed, on-disk chain — instead of from dashd. These three
        // and no more: the remaining six daemon RPCs (getblock, getpeerinfo,
        // getrawmempool, getnetworkinfo, getmininginfo, protx) need block
        // bodies, peer tables, a mempool or the masternode set, which a header
        // chain does not own. See impl/dash/coin/chain_rpc.hpp.
        //
        // Refusals are forwarded verbatim: a query the chain cannot answer
        // (no tip, stale tip, height below the fast-start anchor) returns the
        // named condition with its measured value and threshold, never a zero.
        if (web_server) {
            web_server->get_mining_interface()->set_coin_chain_query_fn(
                [hc = header_chain.get()](const std::string& method,
                                          const nlohmann::json& params,
                                          const std::string& chain) -> nlohmann::json {
                    if (chain != "dash")
                        return nlohmann::json{
                            {"error", "chain '" + chain + "' is not served by this "
                                      "node (owned chain: dash)"}};
                    return dash::coin::chain_rpc::chain_query(*hc, method, params);
                });
            std::cout << "[run] daemonless chain queries ARMED "
                         "(getbestblockhash/getblockhash/getblockchaininfo "
                         "answered from the header chain)\n";

            // ── DEFECT-3 operator surface: WHY the embedded arm is not serving ──
            // web-static/dashboard.html has read a per-coin `no_work_reason` since
            // 08-02 and test_web_honesty_regression pins the contract from both
            // sides -- but NOTHING in the tree ever produced one: main_dash never
            // called set_node_topology_fn at all, so the field was permanently
            // absent and the card rendered a declining node identically to a dead
            // one. This is the producer. The reason is the SAME DeclineReport the
            // arm-selection branch returned (DASHWorkSource::embedded_arm_status_json),
            // so the page and the journal cannot disagree.
            //
            // Lifetime: web_server is explicitly reset() after ioc.run() returns,
            // BEFORE header_chain / coin_p2p unwind at scope exit, so these raw
            // captures cannot outlive their targets.
            web_server->get_mining_interface()->set_node_topology_fn(
                [ws = work_source, hc = header_chain.get(),
                 cp = coin_p2p.get(), testnet]() -> nlohmann::json {
                    nlohmann::json c = nlohmann::json::object();
                    c["coin"]     = "DASH";
                    c["primary"]  = true;
                    c["embedded"] = true;
                    // MEASURED pool state, never guessed. Omitting it would make
                    // the dashboard default to 0 and mislabel every decline as
                    // "faulted". distinct_addrs is published alongside the count
                    // because "3 connections, 1 address" is exactly the failure
                    // the single-peer rotation produced unnoticed for 9h.
                    const bool connected = cp && cp->is_connected();
                    c["peers"] = cp ? static_cast<int>(cp->connected_peer_count()) : 0;
                    if (cp) {
                        c["peers_handshaked"] = static_cast<int>(cp->handshaked_peer_count());
                        c["peers_target"]     = static_cast<int>(cp->max_peers());
                        c["peers_distinct_addrs"] = static_cast<int>(cp->distinct_peer_addresses());
                    }
                    if (hc) {
                        const uint32_t hh = hc->height();
                        c["header_height"] = hh;
                        // The peer's advertised best height is the only target
                        // we actually observe; absent it we publish NO target
                        // and no synced flag rather than invent one.
                        const uint32_t target = connected ? cp->best_peer_height() : 0;
                        if (target > 0) {
                            c["target_height"] = target;
                            c["sync_percent"]  =
                                100.0 * static_cast<double>(hh) / static_cast<double>(target);
                            c["synced"] = (hh + 1 >= target);
                        }
                    }
                    // arm + the ONE named cause, with value and threshold.
                    nlohmann::json arm = ws->embedded_arm_status_json();
                    c["arm"]               = arm.value("arm", std::string("unknown"));
                    c["no_work_cause"]     = arm.value("no_work_reason", std::string());
                    c["no_work_value"]     = arm.value("no_work_value", std::string("n/a"));
                    c["no_work_threshold"] = arm.value("no_work_threshold", std::string("n/a"));
                    // The dashboard renders no_work_reason VERBATIM, so carry
                    // the value and threshold in it -- "declined" alone repeats
                    // the very defect this exists to fix.
                    const std::string cause = c["no_work_cause"].get<std::string>();
                    c["no_work_reason"] = cause.empty()
                        ? std::string()
                        : cause + " (value=" + c["no_work_value"].get<std::string>()
                                + " threshold=" + c["no_work_threshold"].get<std::string>() + ")";
                    // #119 follow-up, web leg: cumulative per-cause TIME
                    // roll-up ({observed_sec, off_embedded_sec, per_cause}),
                    // seconds beside the cause names above so the page can
                    // rank by TIME the way [EMBED-GATE-ROLLUP] does — the
                    // decline COUNT ranks the causes wrongly (the h=2518004
                    // trap). ABSENT, never zeroed, when the serve-gate lock
                    // was busy: a missing observation is not a claim of
                    // health, and the degrade reason already rides `arm`.
                    if (arm.contains("gate_rollup"))
                        c["serve_gate_rollup"] = arm["gate_rollup"];
                    // SERVE-STALENESS: the height we actually handed to a miner
                    // versus an independently observed one. header_height and
                    // target_height above are about the HEADER chain and are
                    // recomputed only when a browser asks; this block is about
                    // the SERVE path and carries the sentinel's standing
                    // verdict, so the page can state a fault instead of leaving
                    // it to a human to notice two numbers disagree.
                    //
                    // Read from serve_staleness_json() DIRECTLY, not out of
                    // `arm`. embedded_arm_status_json also touches
                    // serve_gate_mutex_ -- a lock the SERVE PATH holds -- so
                    // sourcing the staleness block from its result would make
                    // the one surface that reports serve-path saturation depend
                    // on the serve path. This call takes no lock at all.
                    c["serve_staleness"] = ws->serve_staleness_json();
                    return nlohmann::json{
                        {"node_symbol", "DASH"},
                        {"auto_detected", false},
                        {"testnet", testnet},
                        {"coins", nlohmann::json::array({c})}};
                });
        }

        maintainer = std::make_unique<dash::coin::CoinStateMaintainer>(node_coin_state);
        mn_ckpt_lane = std::make_unique<dash::coin::MnCheckpointLane>();
        mn_ckpt_lane->set_max_bridge_blocks(g_mn_bridge_max_blocks);

        // ANTI-MINT LATCH (E2d prerequisite). Without this, a cold daemonless
        // arm can arm MN-readiness off leg 3 ALONE: with no seed the payee set
        // starts empty, the first live block carrying a ProRegTx registers ONE
        // masternode into it, mnstates().size() != 0 flips m_have_mn, and
        // populated() serves a template whose "payment queue" is that single
        // accidental masternode. That is a guessed payee — a coinbase the
        // network rejects. Require an authoritative height-stamped snapshot
        // (the E2c RPC seed or the E2d bridge publish) before MN-readiness can
        // ever be true on the embedded arm.
        maintainer->set_require_seeded_mn_set(true);

        // Coin address versions for the embedded coinbase-payee encoding (the
        // TipAdvance carries them so build_embedded_workdata can encode the MN
        // payee); sourced from the oracle CoinParams, testnet/mainnet-aware.
        const core::CoinParams coin_params = dash::make_coin_params(testnet);
        const uint8_t addr_ver  = coin_params.address_version;
        const uint8_t p2sh_ver  = coin_params.address_p2sh_version;

        // Leg 1 (mempool relay): new_tx -> maintainer.on_mempool_tx. Optional
        // for viability; enriches the assembled template.
        coin_feed_subs.push_back(
            c2pool::dash::wire_mempool_ingest(coin_state, *maintainer));
        // Leg 1b (islock relay): new_islock -> maintainer.on_islock ->
        // Mempool::add_islock. Activates the ALREADY-MERGED G4
        // conflict-tx-lock selection guard (#1110, feed-less until now) and
        // the IS mining-safety hold's IsLocked short-circuit. Fee-affecting
        // only, never validity: an islock can only EXCLUDE a tx from the
        // embedded template / evict a conflicting pool entry.
        coin_feed_subs.push_back(
            c2pool::dash::wire_islock_ingest(coin_state, *maintainer));
        // Leg 2 (tip advance): Node::new_tip -> maintainer.on_new_tip. The
        // new_tip event is FIRED by the tip-changed callback below (off the
        // header chain), NOT the raw wire.
        coin_feed_subs.push_back(
            c2pool::dash::wire_tip_ingest(coin_state, *maintainer));

        // ── Embedded ORACLE-SHADOW: per-block dashd cross-check (OBSERVE-only) ─
        // Subscribed to the SAME new_tip event AFTER wire_tip_ingest, so the
        // maintainer has already republished the embedded bundle for this tip
        // before the shadow reads it. The shadow builds the embedded template
        // via node_coin_state.select_work (the SAME build path the serve arm
        // uses) and cross-checks it against a fresh dashd getblocktemplate,
        // gating divergence/graduation on the DETERMINISTIC field set only (the
        // two nodes have intentionally different mempools/peers). It NEVER
        // changes the serving decision. Requires the alongside dashd RPC arm.
        if (embedded_oracle_shadow) {
            if (!rpc) {
                std::cout << "[run] --embedded-oracle-shadow given but the dashd "
                             "RPC arm is UNARMED (need dash.conf creds / --coin-rpc); "
                             "the shadow has no oracle to cross-check against -- "
                             "disabled.\n";
            } else {
                dash::coin::EmbeddedOracleShadow::Config oc;
                oc.testnet = testnet;
                oc.grad.consecutive_clean_target  = oracle_grad_blocks;
                oc.grad.per_class_coverage_target = oracle_class_coverage;
#ifdef C2POOL_VERSION
                oc.c2pool_commit = C2POOL_VERSION;
#endif
                try { oc.dashd_version =
                    rpc->getnetworkinfo().value("subversion", std::string{}); }
                catch (...) { /* best-effort ledger identity */ }
                const auto oracle_dir =
                    (core::filesystem::config_path() / net_subdir).string();
                oc.divergence_ledger_path =
                    oracle_dir + "/embedded_oracle_divergence.jsonl";
                oc.graduation_state_path =
                    oracle_dir + "/embedded_oracle_graduation.json";

                // Proposal VERDICT leg: assemble the embedded block (pool-only
                // coinbase, no miner payout -- consensus-irrelevant to dashd
                // TestBlockValidity) with the SAME SSOTs the --mine-block path
                // uses, and submit getblocktemplate{mode:proposal}. "" = dashd
                // ACCEPTED; else the reject reason. This is the authoritative,
                // mempool-independent per-height verdict (§6 condition 2).
                auto proposal_fn =
                    [testnet, rp = rpc.get()](const dash::coin::DashWorkData& wd)
                        -> dash::coin::ProposalResult {
                    dash::coin::ProposalResult r;
                    r.attempted = true;
                    try {
                        const core::CoinParams params = dash::make_coin_params(testnet);
                        std::map<std::vector<unsigned char>, uint64_t> empty_weights;
                        uint160 zero_pkh;   // pool-only coinbase (no finder)
                        auto tx_outs = dash::coinbase::compute_dash_payouts(
                            wd.m_coinbase_value, wd.m_packed_payments, zero_pkh,
                            empty_weights, /*total_weight=*/0, params);
                        auto layout = dash::coinbase::build(
                            wd, tx_outs, /*pool_tag=*/"c2pool", params,
                            /*ref_hash=*/uint256::ZERO);
                        // nonce 0 + curtime: proposal mode skips PoW; validity is
                        // structure + payee + CbTx + tx-set (TestBlockValidity).
                        auto block = dash::coin::serialize_full_block(
                            wd, layout.bytes, /*nonce=*/0,
                            wd.m_curtime ? wd.m_curtime
                                         : static_cast<uint32_t>(std::time(nullptr)));
                        const std::string reason = rp->propose_block_hex(HexStr(block));
                        r.accepted = reason.empty();
                        r.reason = reason;
                    } catch (const std::exception& e) {
                        r.accepted = false; r.reason = std::string("assemble:") + e.what();
                    }
                    return r;
                };

                // creditPool INVARIANT base = the CONNECTED block N-1's committed
                // creditPoolBalance (dashd getblock verbosity 2 -> tx[0].cbTx),
                // not dashd's previous *template* projection (review nit d).
                auto base_cp_fn =
                    [rp = rpc.get()](const uint256& prev_hash)
                        -> std::optional<int64_t> {
                    try {
                        auto blk = rp->getblock(prev_hash, /*verbosity=*/2);
                        if (blk.contains("tx") && blk["tx"].is_array()
                            && !blk["tx"].empty()) {
                            const auto& cb = blk["tx"][0];
                            if (cb.contains("cbTx")
                                && cb["cbTx"].contains("creditPoolBalance"))
                                return cb["cbTx"]["creditPoolBalance"].get<int64_t>();
                        }
                    } catch (...) { /* nullopt -> fall back to template base */ }
                    return std::nullopt;
                };

                oracle_shadow = std::make_shared<dash::coin::EmbeddedOracleShadow>(
                    node_coin_state,
                    [rp = rpc.get()]() { return rp->getwork(); },
                    std::move(proposal_fn),
                    std::move(oc),
                    std::move(base_cp_fn));
                auto* shadow = oracle_shadow.get();
                coin_feed_subs.push_back(
                    coin_state.new_tip.subscribe(
                        [shadow](const ::dash::interfaces::TipAdvance& t) {
                            shadow->on_new_tip(t.prev_height + 1, t.prev_hash);
                        }));
                std::cout << "[run] --embedded-oracle-shadow ARMED: per-block dashd "
                             "PROPOSAL verdict + regime-aware field diagnosis (N="
                          << oracle_grad_blocks << " K=" << oracle_class_coverage
                          << "); ledger at " << oracle_dir
                          << "/embedded_oracle_*.{jsonl,json}; verdict at "
                             "/embedded_oracle\n";
            }
        }

        // Leg 3 (block connect): Node::block_connected -> maintainer
        // .on_block_connected (MnStateMachine::apply_block, folds DIP3 special
        // txs into the DMN set). block_connected is fired by the live-feed
        // bridge (full_block -> height lookup). The E2b UTXO lane is ALSO
        // subscribed to the same event (its connect_block + fee recompute).
        coin_feed_subs.push_back(
            c2pool::dash::wire_block_connect_ingest(coin_state, *maintainer));
        // Leg 4 (MN-set RESYNC): Node::mn_list_update -> maintainer
        // .on_mn_list_update. Dash's P2P Simplified MN List omits scriptPayout,
        // so the payout-bearing feed for this leg is the E2c RPC seed below
        // (startup baseline) + leg 3's apply_block folding special txs on top.
        coin_feed_subs.push_back(
            c2pool::dash::wire_mn_list_ingest(coin_state, *maintainer));

        // Leg 5 (SML axis — DAEMONLESS CCbTx, v0.2.4 critical path): the raw
        // mnlistdiff off the live coin-P2P feed advances the SML
        // (merkleRootMNList) + QuorumManager (merkleRootQuorums) + seeds
        // bestCL*/creditPool via CoinStateMaintainer::on_mnlistdiff. This is
        // what makes the embedded coinbase's DIP-0004 type-5 payload
        // MAINNET-VALID (review finding C1). Distinct from leg 4 (the RPC-seeded PAYEE
        // axis). The getmnlistd request driver below primes it.
        coin_feed_subs.push_back(
            c2pool::dash::wire_mnlistdiff_ingest(coin_state, *maintainer));

        // Legs 6-7 (E-SUPERBLOCK — DAEMONLESS SUPERBLOCK PAYEE SOURCING): the
        // governance-object + vote feed off the coin-P2P govsync leg. govobj
        // triggers advance the GovernanceStore (winning-trigger schedule);
        // govobjvote funding votes feed the tally (counted only when verified —
        // see the vote-verifier seam below). This is what lets the embedded arm
        // serve a SUPERBLOCK height daemonlessly instead of falling back.
        coin_feed_subs.push_back(
            c2pool::dash::wire_govobject_ingest(coin_state, *maintainer));
        coin_feed_subs.push_back(
            c2pool::dash::wire_govvote_ingest(coin_state, *maintainer));

        // getmnlistd base tracker: the block hash the local SML is current at.
        // Cold start = ZERO (full snapshot). Each accepted mnlistdiff advances
        // it to diff.blockHash so the NEXT request is an incremental diff off
        // the last synced point (avoids re-pulling the full ~450 kB list).
        auto sml_base = std::make_shared<uint256>(uint256::ZERO);
        coin_feed_subs.push_back(
            coin_state.new_mnlistdiff.subscribe(
                [sml_base](const dash::coin::vendor::CSimplifiedMNListDiff& d) {
                    *sml_base = d.blockHash;
                }));

        // ── SML + quorum PERSISTENCE (SMLDb/QuorumDb) ────────────────────────
        // Persist the applied SML (merkleRootMNList) + active quorum set
        // (merkleRootQuorums) under the per-net subdir so a restart resumes
        // INCREMENTALLY: load the last verified state, set the getmnlistd base
        // to the persisted tip, and apply only the delta from there instead of a
        // cold mnlistdiff(zero, tip). When the stores are empty/absent (first
        // run) or fail the on-load root-verify, sml_base stays ZERO and the arm
        // cold-syncs exactly as before — DEFAULT BEHAVIOUR UNCHANGED.
        auto sml_db = std::make_shared<dash::coin::SMLDb>(
            (core::filesystem::config_path() / net_subdir / "dash_sml_db").string());
        auto quorum_db = std::make_shared<dash::coin::QuorumDb>(
            (core::filesystem::config_path() / net_subdir / "dash_quorum_db").string());
        // E2: the DIP-0027 credit-pool tip is persisted alongside SML/quorum so a
        // warm restart resumes the pool at the SAME tip (matching best_hash),
        // rather than the arm falling back to dashd until the next mnlistdiff
        // re-seeds the credit pool for the restart tip.
        auto credit_pool_db = std::make_shared<dash::coin::CreditPoolDb>(
            (core::filesystem::config_path() / net_subdir / "dash_credit_pool_db").string());
        const bool cp_open_ok = credit_pool_db->open();
        const bool sml_persist_ok = sml_db->open() && quorum_db->open() && cp_open_ok;
        if (!sml_persist_ok) {
            LOG_WARNING << "[SML-DB] open failed -> persistence DISABLED "
                           "(cold mnlistdiff(zero,tip) each restart, as before)";
        } else {
            // Warm restart: load both stores, INDEPENDENTLY root-verified inside
            // load_verified() (a corrupt/stale store fails closed to cold sync).
            dash::coin::vendor::CSimplifiedMNList loaded_sml;
            const bool sml_warm = sml_db->load_verified(loaded_sml);
            const bool quo_warm = quorum_db->load_verified(node_coin_state.qmgr());
            const bool tips_match =
                sml_db->get_best_hash() == quorum_db->get_best_hash();
            const bool warm = sml_warm && quo_warm && tips_match
                              && !sml_db->get_best_hash().IsNull();
            if (warm) {
                node_coin_state.sml() = std::move(loaded_sml);
                node_coin_state.set_have_sml(node_coin_state.sml().size() != 0);
                node_coin_state.set_sml_current_hash(sml_db->get_best_hash());
                // F1: restore the HEIGHT the warm SML is current at, not just
                // the list. Without this m_sml_current_height stayed 0 while
                // have_sml() was true, and every freshness check keyed on it
                // passed vacuously — a masternode banned before the persisted
                // tip and revived after it could be permanently demoted at a
                // height the chain held it valid. Mirrors restore_credit_pool()
                // immediately below, which exists for the same reason.
                maintainer->restore_sml_height(sml_db->get_best_height());
                *sml_base = sml_db->get_best_hash();  // handshake -> incremental
                LOG_INFO << "[SML-DB] WARM restart: SML(" << node_coin_state.sml().size()
                         << ") + quorums(" << node_coin_state.qmgr().active_count()
                         << ") @ " << sml_db->get_best_hash().GetHex().substr(0, 16)
                         << " h=" << sml_db->get_best_height()
                         << " -> incremental mnlistdiff(persisted-tip, tip)";
                // E2: restore the credit-pool seed to the SAME tip. Sentinel: the
                // persisted credit-pool best_hash must match the SML tip (both are
                // written per accepted mnlistdiff for diff.blockHash). On match,
                // seed BOTH the NodeCoinState freshness seed (keyed on this height)
                // and the maintainer's running accrual, so the credit-pool
                // freshness gate passes at the restart tip and the first
                // post-restart block advances contiguously + verifies against its
                // own from-wire cbTx. On mismatch (partial/divergent), wipe the
                // credit-pool store and let it re-seed cold from the next block/diff.
                if (credit_pool_db->is_initialized()
                    && credit_pool_db->get_best_hash() == sml_db->get_best_hash()
                    && !credit_pool_db->get_best_hash().IsNull()) {
                    node_coin_state.set_credit_pool(
                        credit_pool_db->get_balance(),
                        credit_pool_db->get_best_hash(),
                        static_cast<int32_t>(credit_pool_db->get_best_height()));
                    maintainer->restore_credit_pool(
                        credit_pool_db->get_balance(),
                        credit_pool_db->get_best_height());
                    LOG_INFO << "[CP-DB] WARM restart: credit pool "
                             << credit_pool_db->get_balance() << " @ h="
                             << credit_pool_db->get_best_height()
                             << " (tip matches SML) -> freshness gate live at restart tip";
                } else {
                    LOG_WARNING << "[CP-DB] credit-pool tip "
                                << credit_pool_db->get_best_hash().GetHex().substr(0, 16)
                                << " != SML tip (or empty) -> wipe + cold re-seed";
                    credit_pool_db->clear();
                }
            } else {
                // Undo any partial warm (quorum load may have replaced qmgr state)
                // and drop divergent/one-sided persisted state so we cold-resync.
                node_coin_state.qmgr().clear();
                if (sml_warm || quo_warm) {
                    LOG_WARNING << "[SML-DB] partial/divergent persisted state "
                                   "(sml_warm=" << sml_warm << " quo_warm=" << quo_warm
                                << " tips_match=" << tips_match
                                << ") -> wipe + cold re-sync";
                    sml_db->clear();
                    quorum_db->clear();
                }
                // E2: the SML cold-resyncs, so any persisted credit-pool tip is
                // orphaned relative to the tip we will rebuild — wipe it so the
                // pool re-seeds cold from the next block/diff (never a stale carry).
                credit_pool_db->clear();
            }

            // Persist-on-apply: after each accepted mnlistdiff the maintainer
            // fires this with the block the SML/quorum state is now current at.
            maintainer->set_on_sml_persist(
                [&node_coin_state, sml_db, quorum_db, hc = header_chain.get()]
                (const uint256& cur_hash) {
                    uint32_t h = 0;
                    if (auto e = hc->get_header(cur_hash)) h = e->height;
                    sml_db->write_sml(node_coin_state.sml(), cur_hash, h);
                    quorum_db->write_quorums(node_coin_state.qmgr(), cur_hash, h);
                });
            // E2 credit-pool persist: written per accepted mnlistdiff with the SAME
            // (blockHash, height) the SML persist uses, so the CreditPoolDb tip
            // tracks the SML tip and the restart sentinel (cp_hash == sml_hash)
            // holds. balance is the authoritative cbTx creditPoolBalance the diff
            // re-anchored the pool to.
            maintainer->set_on_credit_pool_persist(
                [credit_pool_db]
                (const uint256& cur_hash, uint32_t h, int64_t balance) {
                    credit_pool_db->write_state(cur_hash, h, balance,
                                                /*initialized=*/true);
                });
            // Wipe-on-reorg/heal: the persisted state is now for an orphaned
            // branch (self-consistent, so the root-verify would pass) — clear it.
            // Extended to the credit-pool store (same orphaned-branch hazard).
            maintainer->set_on_sml_clear(
                [sml_db, quorum_db, credit_pool_db]() {
                    sml_db->clear();
                    quorum_db->clear();
                    credit_pool_db->clear();
                    LOG_INFO << "[SML-DB] reorg/heal -> persisted SML+quorum+creditpool "
                                "wiped (cold re-sync)";
                });
        }

        // review finding H3: the embedded arm must NOT serve a template without a valid
        // CCbTx (that block is consensus-invalid on mainnet). Gate embedded
        // viability on an applied SML — until the first mnlistdiff lands, and
        // after any reorg wipe, get_work stays on the retained dashd fallback.
        node_coin_state.set_require_sml(true);

        // Superblock guard: on a Dash superblock height the coinbase must pay the
        // governance/treasury outputs, which the embedded template does not
        // compute. Refuse the embedded arm on those heights and let the reward-
        // safe dashd fallback serve the correct superblock template. Cycle is
        // network-specific (mainnet 16616, testnet 24).
        {
            const int sb_cycle = testnet
                ? dash::coin::DASH_SUPERBLOCK_CYCLE_TESTNET
                : dash::coin::DASH_SUPERBLOCK_CYCLE_MAINNET;
            node_coin_state.set_is_superblock_fn(
                [sb_cycle](uint32_t next_height) {
                    return dash::coin::is_superblock_height(next_height, sb_cycle);
                });

            // E-SUPERBLOCK: daemonless superblock payee provider. At a superblock
            // height the provider resolves the winning governance trigger's
            // budget-valid (script, amount) schedule from the GovernanceStore the
            // govsync legs (6-7) feed, so the embedded arm can serve the correct
            // superblock coinbase WITHOUT dashd. superblock_schedule() returns
            // nullopt when there is no trigger-confident winner (unfunded OR
            // under-synced OR over-budget OR the R6 desync latch fired) — the
            // NodeCoinState guard then FAILS CLOSED to the reward-safe dashd
            // fallback (never guesses payees).
            //
            // Enabled ONLY under --embedded-superblock (opt-in, default OFF). With
            // it OFF, set_require_superblock_provider(false) preserves the prior
            // reward-safe behaviour EXACTLY (every superblock height falls back).
            //
            // FAIL-CLOSED BY CONSTRUCTION, in three independent layers:
            //   1. (R3, WIRED below) the funding tally counts only votes the
            //      maintainer's vote-verifier accepts — now the real BLS verify
            //      by the voting MN's OPERATOR key over govvote_signature_hash
            //      (dashcore verifies TRIGGER funding votes against
            //      pubKeyOperator, NOT the ECDSA/keyIDVoting path, which is
            //      proposal-only). Unverified/forged votes never count; when the
            //      BLS backend is absent the verifier fails closed (0 counted).
            //   2. (R3, WIRED below) the weighted tally uses the vote-weight/
            //      membership seam (GovernanceStore::set_vote_weight_fn) —
            //      resolved from the full DMN view (collateral outpoint ->
            //      operator key + type), EvoNode 4x, 0 only for an MN no
            //      longer in the DMN list at all (dashcore's UNFILTERED
            //      GetMNByCollateral — PoSe-banned MNs still count). The
            //      threshold itself reseeds from the weighted VALID SML count
            //      on every diff (reseed_funding_threshold — dashcore's own
            //      tally/denominator asymmetry).
            //   3. the R5 govsync-completeness gate IS wired
            //      (set_superblock_sync_complete_fn, below), so the guard is no
            //      longer a structural refusal: it is a RUNTIME predicate over
            //      GovernanceMaintainer::gov_sync_complete() (>= min peers,
            //      settled, quiesced). It still closes on its own whenever
            //      govsync has not completed, and R3 landing here does not by
            //      itself open it.
            // The parse/selection/template-emit logic is proven by the KATs;
            // flipping this fully live is still gated on R5 completeness + the
            // R6 desync latch + a funded-superblock soak.
            {
                const int64_t budget_cycle = sb_cycle;
                // Chain-strict trigger parsing + dashcore threshold inputs:
                // min-quorum is chainparams nGovernanceMinQuorum; the
                // threshold itself re-derives from the weighted SML count on
                // every accepted mnlistdiff (maintainer reseed — dashcore
                // nAbsVoteReq = max(minQuorum, weighted/10)). Cross-checkable
                // against dashd getgovernanceinfo.fundingthreshold.
                maintainer->set_gov_params(
                    testnet, testnet ? dash::coin::DASH_GOV_MIN_QUORUM_TESTNET
                                     : dash::coin::DASH_GOV_MIN_QUORUM_MAINNET);
                // Superblock ctx for the R6 coinbase cross-check + executed-
                // cycle pruning on the block-connect leg.
                maintainer->set_superblock_ctx(
                    [sb_cycle](uint32_t h) {
                        return dash::coin::is_superblock_height(h, sb_cycle);
                    },
                    [budget_cycle](uint32_t h) {
                        return dash::coin::superblock_budget(
                            h, static_cast<int>(budget_cycle));
                    });
                node_coin_state.set_superblock_provider(
                    [maint = maintainer.get()](uint32_t next_height)
                        -> std::optional<std::vector<dash::coin::SuperblockPayment>> {
                        return maint->superblock_schedule(next_height);
                    });
                node_coin_state.set_require_superblock_provider(embedded_superblock);
                // R5 GOVSYNC-COMPLETENESS GATE (production wiring). Model:
                // dashcore CMasternodeSync governance-phase completion — the
                // view is COMPLETE only when the governance set was requested
                // from >= min_peers distinct peers, a settle floor elapsed, and
                // no new object/vote arrived for the quiescence window (the
                // stream quiesced). Fed from the govobj/govobjvote reception
                // path + note_govsync_requested at the send site (below). This
                // is the gate that lets a VERIFIED-complete superblock actually
                // serve; a PARTIAL view (missing the higher-yes competing
                // trigger/votes) is the confidently-wrong-winner hazard, so the
                // default (nothing synced / under-covered / not quiesced) is
                // FALSE => reward-safe dashd fallback.
                maintainer->set_gov_sync_params(
                    dash::coin::DASH_GOVSYNC_MIN_PEERS_DEFAULT,
                    dash::coin::DASH_GOVSYNC_SETTLE_SECS_DEFAULT,
                    dash::coin::DASH_GOVSYNC_QUIESCE_SECS_DEFAULT);
                node_coin_state.set_superblock_sync_complete_fn(
                    [maint = maintainer.get()]() {
                        return maint->gov_sync_complete();
                    });

                // R3 — governance-vote BLS verify + vote-weight seam. This is
                // the piece that lets a funding tally count anything at all:
                // both closures resolve the voting masternode by its COLLATERAL
                // OUTPOINT in the node's live DMN view (node_coin_state
                // .mnstates(), seeded from protx info — the DIP-4 SML alone
                // carries neither collateral outpoints nor operator keys), via
                // the shared gov_mn_by_collateral / gov_vote_weight_for_key
                // parity helpers. Every step FAILS CLOSED: unknown MN,
                // unresolvable key, wrong sig size, stale/future time, or a
                // failed BLS verify => the vote is NOT tallied. NOTE dashcore
                // parity (v23.1.7): the resolve is UNFILTERED
                // (GetMNByCollateral) — a PoSe-BANNED MN's vote still verifies
                // and still counts at full weight, in BOTH paths; only the
                // funding THRESHOLD denominator is valid-weighted
                // (reseed_funding_threshold, reseeded from the weighted SML
                // count on every accepted diff — dashcore's own asymmetry).
                // The R5 completeness gate wired ABOVE still evaluates FALSE
                // in production (single peer / empty store), so landing
                // vote-verify here can never by itself open the serve path.
                {
                    auto* ncs = &node_coin_state;

                    // Vote-signature verifier — dashcore CGovernanceVote::
                    // CheckSignature over the MN's OPERATOR key (TRIGGER funding
                    // votes; the ECDSA voting-key path is PROPOSAL-only and NOT
                    // used here). Plus the IsValid time bound (nTime <= now+1h).
                    maintainer->set_vote_verifier(
                        [ncs](const dash::coin::CoinStateMaintainer::GovVoteContext& v)
                            -> bool {
                            // dashcore IsValid: reject a vote timestamped more
                            // than an hour into the future (clock-skew bound).
                            // KNOWN NIT (documented, not fixed): dashcore uses
                            // GetAdjustedTime() (network-adjusted); c2pool has
                            // no peer time-offset plumbing here, so this is the
                            // LOCAL clock. Divergence is bounded by our own
                            // clock skew and only matters for votes inside that
                            // skew of the +1h edge; NTP-disciplined hosts make
                            // it negligible. Revisit if soak shows drift.
                            if (v.time > static_cast<int64_t>(std::time(nullptr)) + 60 * 60)
                                return false;
                            // Resolve collateral outpoint -> DMN -> operator
                            // key. UNFILTERED (no PoSe-ban check) — dashcore
                            // CGovernanceVote::IsValid resolves via
                            // GetMNByCollateral, so a banned MN's vote still
                            // verifies in dashd and must here too (dropping a
                            // banned MN's NO inflates our yes−no vs dashd).
                            bitcoin_family::coin::TxPrevOut op;
                            op.hash  = v.mn_outpoint_hash;
                            op.index = v.mn_outpoint_index;
                            const dash::coin::MNState* mn =
                                dash::coin::gov_mn_by_collateral(
                                    ncs->mnstates(), op);
                            if (!mn) return false;           // MN not in DMN list
                            const bool legacy =
                                (mn->nVersion ==
                                 dash::coin::vendor::ProTxVersion::LEGACY_BLS);
                            return dash::coin::vendor::verify_govvote_operator_sig(
                                mn->pubKeyOperator, legacy,
                                v.vote_hash, v.vch_sig);
                        });

                    // Vote-weight + membership-at-tally — dashcore
                    // CountMatchingVotes: EvoNode 4x, Regular 1x, and 0 (vote
                    // dropped) ONLY when the outpoint is not in the DMN list
                    // at tally time (unfiltered GetMNByCollateral — banned MNs
                    // still count). Keyed by "<collateral-txid-hex>-<index>"
                    // (GovOutPoint::to_key()); gov_vote_weight_for_key
                    // reconstructs the outpoint and resolves it against the
                    // SAME live DMN view.
                    maintainer->gov_store().set_vote_weight_fn(
                        [ncs](const std::string& key) -> int {
                            return dash::coin::gov_vote_weight_for_key(
                                ncs->mnstates(), key);
                        });
                }

                // Reconciled log (R5 completeness gate + R3 vote-verify both wired).
                if (embedded_superblock)
                    LOG_INFO << "[E-SUPERBLOCK] daemonless superblock arm ENABLED "
                                "(--embedded-superblock). BOTH gates WIRED: the R5 "
                                "govsync-completeness gate (>= "
                             << dash::coin::DASH_GOVSYNC_MIN_PEERS_DEFAULT
                             << " peers, settled, quiesced) that lets a "
                                "trigger-confident superblock actually serve, AND the "
                                "R3 governance-vote BLS operator verify + vote-weight "
                                "seam ("
                             << (dash::coin::vendor::bls_backend_available()
                                     ? "BLS backend ON"
                                     : "BLS backend ABSENT => votes never verify")
                             << "). Serve stays CLOSED until the completeness "
                                "predicate proves complete (single peer / empty store "
                                "=> FALSE) and a funded soak clears -- R3 vote-verify "
                                "landing here cannot by itself open it.";
            }
        }

        // E4 re-soak fix (constant −66,966,830-duff creditPool bias): the
        // DIP-0027 platform-share accrual is gated on the NETWORK'S MN_RR
        // activation height (per-chainparams in dashcore: mainnet 2,128,896,
        // testnet 1,066,900 — buried, cross-checked live via getblockchaininfo
        // softforks). With the mainnet constant in force on testnet the
        // platform reward evaluated to 0 for every current testnet height, so
        // the embedded template committed creditPoolBalance(N-1) + 0 — exactly
        // one block's platform reward LOW, at every height, surviving restart
        // (the persisted seed was correct; the accrual term was the bias).
        // This threads the network's height into the template build, the
        // pre-emit value re-check, and the per-block credit-pool advance.
        node_coin_state.set_mn_rr_height(
            testnet ? dash::coin::DASH_MN_RR_HEIGHT_TESTNET
                    : dash::coin::DASH_MN_RR_HEIGHT_MAINNET);

        // confirmedHash rollover projection threshold (sml_projection.hpp):
        // the network's nMasternodeMinimumConfirmations (per-chainparams in
        // dashcore v23.1.7 chainparams.cpp — mainnet 15 at :177, testnet 1 at
        // :376). Gates the height-driven confirmation pass the template build
        // + viability + pre-emit gates replicate so the committed
        // merkleRootMNList matches the verifier's rebuilt list at an MN's
        // confirmation-crossing height (bad-cbtx-mnmerkleroot otherwise).
        node_coin_state.set_mn_min_confirmations(
            testnet ? dash::coin::DASH_MN_MIN_CONFIRMATIONS_TESTNET
                    : dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET);

        // review PR #780 BLOCKER-1 (CRITICAL): refuse the embedded arm on DKG
        // commitment-window heights. There the block MUST carry mandatory type-6
        // quorum-commitment txs (which the C-3 filter strips) and merkleRootQuorums
        // must include them (which the mnlistdiff-fed set omits) — the embedded
        // arm would produce a bad-qc-missing / wrong-root block. Fail closed to
        // the reward-safe dashd fallback at those heights (it builds the qc block).
        // With the E1 qc plan below installed this fn is the DORMANT fallback
        // posture (the plan supersedes it); it stays authoritative whenever the
        // plan is not installed.
        node_coin_state.set_commitment_window_fn(
            [](uint32_t next_height) {
                return dash::coin::is_dkg_commitment_window(next_height);
            });

        // E1 — daemonless DKG-window serving (dkg_commitments.hpp). Where the
        // embedded arm is enabled (testnet, or mainnet behind the explicit
        // --embedded-mainnet gate-lift; default OFF), DKG mining-window heights
        // are SERVED instead of refused: the mandatory type-6 commitment set is
        // derived from local state only — params-table math + quorum base
        // hashes off the embedded header chain + the mnlistdiff-fed
        // QuorumManager as dashd's HasMinedCommitment — and every mandatory
        // slot must carry a BLS-VERIFIED REAL commitment. Serving is PER-HEIGHT
        // ALL-OR-NOTHING: one unsatisfiable slot fails the WHOLE height closed
        // to the dashd fallback. Null commitments are NOT mined to fill the
        // shortfall (that arm is dashd's, and copying it diverged
        // merkleRootQuorums at block 1520106 — see dkg_commitments.hpp HEIGHT
        // COMPLETENESS). merkleRootQuorums stays the PROVEN active-set root.
        // The same nullopt/fail-closed result covers a set that cannot be
        // derived at all (header gap, below the per-network V19 serve floor —
        // which also covers --regtest chains riding the testnet flag), exactly
        // the old refusal. The emit gate re-derives this same plan and
        // hard-rejects any template whose type-6 set drifts from it.
        // #108: the member source is created inside the embedded-arm block
        // below, but the tip-advance callback that must PREFETCH from it is
        // installed further down at outer scope. Hold a handle out here so the
        // callback can reach it; stays null when the embedded arm is off, and
        // the callback checks.
        std::shared_ptr<dash::coin::QuorumMemberSource> qc_ms_prefetch_handle;
        if (run_arm.embedded_arm_enabled) {
            const auto qc_net = testnet ? dash::coin::LlmqNetwork::Testnet
                                        : dash::coin::LlmqNetwork::Mainnet;
            // Phase-L sourcing leg: collect REAL relayed DKG commitments off
            // the coin-P2P qfcommit stream (structural admission only). The
            // cache serves NOTHING into templates until a BLS12-381 verifier
            // is installed (MineableCommitmentCache::set_bls_verify_fn — done
            // by the VERIFY leg below, and inert unless the build actually
            // links dashbls).
            //
            // A required slot with no verified commitment is null-served ONLY
            // when --embedded-null-arm is armed AND the active-set view is
            // proven fresh to the tip (#127): dashd's own miner mines the null
            // commitment there (GetMineableCommitments, "null commitment
            // required" arm, llmq/blockprocessor.cpp:748-762), and a null is
            // consensus-valid + folds NOTHING into merkleRootQuorums, so it
            // reproduces the carried-forward active-set root exactly. The
            // 1520106 divergence was a STALE-active-set fault (null-serving a
            // view that MISSED a real commitment already mined <= pindexPrev),
            // which the same freshness obligation the arm already meets closes
            // — see dkg_commitments.hpp DkgNullEvidenceFn + "two reject doors".
            // With the flag OFF (default) the null_evidence argument at the
            // build_daemonless_qc_plan call below is literally nullptr, the
            // slot stays unsatisfiable, and the WHOLE height fails closed to
            // the dashd fallback, NAMED cause=qc-plan-underivable — exactly
            // master's behaviour. The refusal is BOUNDED either way: it ends
            // when any other miner mines the commitment (the slot then reads
            // already-mined off the mnlistdiff-fed QuorumManager) or when the
            // DKG mining window closes — both by cycleStart + dkgMiningWindowEnd.
            // [QC-MINEABLE] is the field-checkable signal that the sourcing leg
            // is live.
            auto qc_cache =
                std::make_shared<dash::coin::MineableCommitmentCache>();

            // Phase-L VERIFY leg: install the dashbls-backed verifier on the
            // cache. verified_for() will only yield a REAL commitment once this
            // passes dashcore's CFinalCommitment::Verify (membersSig aggregate
            // over the signers' operator keys + quorumSig against
            // quorumPublicKey, both over BuildCommitmentHash). The verifier
            // sources the ordered member operator key set via the provider
            // below; anything it cannot establish with certainty fails CLOSED
            // (verified_for -> nullopt -> the slot is unsatisfiable -> the
            // whole height falls back to dashd, exactly the pre-Phase-L
            // posture — reward-safe; the slot is NOT null-served).
            //
            // MEMBER-SET SOURCING (E1 Phase-L, the piece that ENABLES real-
            // commitment serving): the deterministic quorum member selection
            // (dashcore llmq/utils.cpp ComputeQuorumMembers: score = hash over
            // proRegTxHash/confirmedHash with the per-quorum V20 modifier,
            // taken over the SML AS OF the WORK block = base - 8, per v23.1.7
            // GetAllQuorumMembers — #814 review R2) needs the HISTORICAL SML +
            // the work block's own cbTx ChainLock. QuorumMemberSource sources
            // BOTH via ONE getmnlistd(ZERO, workBlock) full snapshot over the
            // SAME coin-P2P client, deduped by block hash across quorum types
            // sharing a cycle base (#814 R1), authenticates the snapshot with
            // DIP-4 client verification against the PoW-verified header chain
            // (#814 R3 — a lying peer must not supply the member-set root of
            // trust), computes the ordered member operator-key set (with the
            // per-MN SML nVersion populating MemberOperatorKey::legacy_scheme
            // — a mixed quorum needs the scheme flag; Evo-only for the
            // platform type, #814 R4), and caches it. The provider is a pure
            // cache lookup (never blocks the template path). ROTATED (DIP-24,
            // llmq_60_75) types source instead via ONE getqrinfo per CYCLE:
            // the reply carries the four cycle work-block lists + the three
            // quarter-rotation snapshots, is DIP-4 authenticated per cycle
            // diff, and yields all signingActiveQuorumCount member sets in one
            // go (each keyed by its own quorumHash = cycleBase + quorumIndex).
            // Anything uncertain -> nullopt -> fail-closed.
            auto qc_member_source =
                std::make_shared<dash::coin::QuorumMemberSource>(
                    qc_net,
                    [hc = header_chain.get()](uint32_t h)
                        -> std::optional<uint256> {
                        if (auto e = hc->get_header_by_height(h)) return e->hash;
                        return std::nullopt;
                    },
                    [hc = header_chain.get()](const uint256& qh)
                        -> std::optional<uint32_t> {
                        if (auto e = hc->get_header(qh)) return e->height;
                        return std::nullopt;
                    },
                    // DIP-4 trust anchor (R3): the PoW-verified header's
                    // hashMerkleRoot for the awaited work block.
                    [hc = header_chain.get()](const uint256& bh)
                        -> std::optional<uint256> {
                        if (auto e = hc->get_header(bh))
                            return e->header.m_merkle_root;
                        return std::nullopt;
                    },
                    [cp = coin_p2p.get()](const uint256& base, const uint256& tgt) {
                        if (cp) cp->send_getmnlistd(base, tgt);
                    });

            // ── ONE admission path for EVERY commitment transport ──────────
            // (qc-plan-underivable fix). The cache used to be fed from exactly
            // one source: the qfcommit push subscription below. Push requires
            // being connected at the instant of the inv — measured on the
            // 2026-08 soaks as a 14 s – 5 m 35 s arrival race after
            // window-open on a healthy-peer host (7.5% of wall-clock declined
            // qc-plan-underivable) and total cold-start starvation on a host
            // whose peers churn. But FULL commitments also arrive over
            // request/response — mnlistdiff `newQuorums` and qrinfo
            // `lastCommitmentPerIndex` carry the complete DIP-4
            // CFinalCommitment — and were dropped after existence
            // bookkeeping. Every transport now funnels through THIS ingest,
            // so the admission guarantees (structural checks + the BLS verify
            // hook behind verified_for) hold identically regardless of
            // arrival shape, and every ingest names its transport in the
            // [QC-MINEABLE] line — the soak-checkable evidence of which
            // transport actually supplied a commitment.
            //
            // SAY WHY on the reject path too: a dropped commitment that
            // leaves no trace makes a later "no-commitment-cached" refusal
            // indistinguishable from "never reached us" — opposite diagnoses
            // (our bug vs a relay hole).
            auto qc_ingest_from =
                [qc_cache, qc_net, qc_member_source](
                    const dash::coin::vendor::CFinalCommitment& c,
                    const char* source, bool kick_member_fetch)
                    -> dash::coin::MineableCommitmentCache::Admission {
                    using Adm = dash::coin::MineableCommitmentCache::Admission;
                    const auto adm = qc_cache->ingest_ex(qc_net, c);
                    if (adm == Adm::Accepted) {
                        LOG_INFO << "[QC-MINEABLE] cached commitment type="
                                 << static_cast<int>(c.llmqType)
                                 << " quorum="
                                 << c.quorumHash.GetHex().substr(0, 16)
                                 << "... signers=" << c.CountSigners()
                                 << " source=" << source
                                 << " cache=" << qc_cache->size();
                        // Proactively source the member set so it is READY by
                        // the DKG-window height that must serve it.
                        if (kick_member_fetch)
                            qc_member_source->request(c.llmqType, c.quorumHash);
                    } else if (adm == Adm::NotBetterThanCached) {
                        // EXPECTED steady-state overlap now that several
                        // transports carry the same commitment (push +
                        // mnlistdiff + qrinfo): an equal-or-better copy is
                        // already held, the arrival is a no-op and NEVER a
                        // downgrade. Same tag so a soak can still count
                        // arrivals per transport, but named as the duplicate
                        // it is, not a defect.
                        LOG_INFO << "[QC-MINEABLE] duplicate commitment type="
                                 << static_cast<int>(c.llmqType)
                                 << " quorum="
                                 << c.quorumHash.GetHex().substr(0, 16)
                                 << "... signers=" << c.CountSigners()
                                 << " source=" << source
                                 << " cache=" << qc_cache->size();
                    } else {
                        LOG_INFO << "[QC-MINEABLE] REJECTED relayed"
                                    " commitment type="
                                 << static_cast<int>(c.llmqType)
                                 << " quorum="
                                 << c.quorumHash.GetHex().substr(0, 16)
                                 << "... signers=" << c.CountSigners()
                                 << " reason="
                                 << dash::coin::MineableCommitmentCache
                                        ::admission_name(adm)
                                 << " source=" << source
                                 << " cache=" << qc_cache->size();
                    }
                    return adm;
                };

            // Member-set fetch amplification guard for the BATCH transports:
            // a cold full mnlistdiff snapshot re-carries EVERY active quorum
            // (~100-200 on mainnet), and kicking a historical getmnlistd
            // member-set fetch for each would fan out megabytes of wire
            // traffic for quorums whose DKG mining window closed long ago
            // (their slots cannot be required again short of a reorg wipe).
            // Only commitments whose mining window is still open at the
            // header tip get the proactive fetch; INGEST itself is
            // unconditional — the cache entry is cheap, and the case where a
            // closed-window commitment matters again (a reorg wiping the
            // QuorumManager near the tip) re-offers it inside a window this
            // filter passes.
            auto qc_member_fetch_worthwhile =
                [hc = header_chain.get(), qc_net](
                    const dash::coin::vendor::CFinalCommitment& c) -> bool {
                    auto tip = hc->tip();
                    if (!tip) return false;
                    auto base = hc->get_header(c.quorumHash);
                    if (!base) return false;
                    for (const auto& p : dash::coin::enabled_llmqs(qc_net)) {
                        if (p.type != c.llmqType) continue;
                        if (p.dkg_interval == 0) return false;
                        const auto wb =
                            dash::coin::qc_window_bound(p, base->height);
                        return tip->height <= wb.last_height;
                    }
                    return false;
                };

            // DIP-24 rotated lane: the getqrinfo send seam + the qrinfo reply
            // consumer. Both are OPTIONAL by construction — with neither wired
            // the rotated branch of request() simply cannot send, so no rotated
            // member set is ever sourced and every rotated slot stays
            // unsatisfiable: any height whose mandatory set contains one fails
            // closed to the dashd fallback (NOT null-served — dkg_commitments.hpp
            // HEIGHT COMPLETENESS). That is the pre-item-4 posture.
            if (coin_p2p) {
                // #108: publish the handle for the tip-advance prefetch.
                qc_ms_prefetch_handle = qc_member_source;
                qc_member_source->set_send_getqrinfo(
                    [cp = coin_p2p.get()](const std::vector<uint256>& bases,
                                          const uint256& req, bool extra) {
                        if (cp) cp->send_getqrinfo(bases, req, extra);
                    });
                // Unlike mnlistdiff there is no tip-feed hazard here: nothing
                // else consumes qrinfo, so this consumer needs no demux.
                coin_p2p->add_qrinfo_consumer(
                    [qc_member_source, qc_ingest_from,
                     qc_member_fetch_worthwhile]
                    (const dash::coin::vendor::CQuorumRotationInfo& info) {
                        // Rotated-quorum tee (DIP-24, type 5):
                        // lastCommitmentPerIndex carries the FULL final
                        // commitments per quorumIndex — same admission path
                        // as every other transport, source-tagged for the
                        // soak.
                        for (const auto& c : info.lastCommitmentPerIndex)
                            qc_ingest_from(c, "qrinfo",
                                           qc_member_fetch_worthwhile(c));
                        qc_member_source->on_qrinfo(info);
                    });
            }

            dash::coin::vendor::MemberKeysProvider qc_member_keys =
                [qc_member_source](uint8_t llmq_type, const uint256& quorum_hash)
                    -> std::optional<std::vector<dash::coin::vendor::MemberOperatorKey>> {
                    return qc_member_source->lookup(llmq_type, quorum_hash);
                };
            qc_cache->set_bls_verify_fn(
                dash::coin::vendor::make_commitment_bls_verifier(
                    std::move(qc_member_keys)));
            if (dash::coin::vendor::bls_backend_available()) {
                LOG_INFO << "[QC-PHASE-L] dashbls verifier + member-set sourcing "
                            "installed (real qc inclusion when the member set is "
                            "sourced; otherwise the slot is unsatisfiable and the "
                            "WHOLE height refuses with cause=qc-plan-underivable "
                            "and falls back to dashd -- never null-served)";
            }

            // REFUSAL-DIAGNOSIS seam (observability only, never gates a serve):
            // lets [QC-COMPLETENESS] tell "the member-set fetch is still in
            // flight" apart from "the BLS signature genuinely did not verify".
            // Reads the SAME cache the MemberKeysProvider above already reads
            // from the template thread — no new sharing, no new lock domain.
            qc_cache->set_members_ready_fn(
                [qc_member_source](uint8_t t, const uint256& qh) {
                    return qc_member_source->lookup(t, qh).has_value();
                });

            // PoSe-fold gate (the #1083 landmine ENFORCED — see
            // NodeCoinState::set_qc_pose_noop_fn and dkg_commitments.hpp
            // qc_pose_pass_provably_noop). A REAL in-block commitment makes
            // dashd's verifier PoSe-punish every member it marks invalid
            // (specialtxman.cpp:159-174), which can flip that MN's validity
            // in the SAME block's list — the template's committed
            // merkleRootMNList is then wrong (bad-cbtx-mnmerkleroot, a
            // silently lost block). No PoSe fold exists here, so the pre-emit
            // gate refuses any real commitment whose PoSe pass is not
            // PROVABLY a no-op: every listed member valid, judged against the
            // SAME deterministic member list the BLS verifier already sourced
            // (its size is the members.size() dashd's punish loop runs over).
            // Member set gone from cache => nullopt => refuse (fail-closed).
            // Null commitments are exempt (IsNull() guard, specialtxman.cpp
            // :432) — today's all-null plans are byte-unchanged.
            node_coin_state.set_qc_pose_noop_fn(
                [qc_member_source](
                    const dash::coin::vendor::CFinalCommitment& c)
                    -> std::optional<bool> {
                    auto members =
                        qc_member_source->lookup(c.llmqType, c.quorumHash);
                    if (!members) return std::nullopt;   // cannot prove
                    return dash::coin::qc_pose_pass_provably_noop(
                        c, members->size());
                });

            // DEMUX: route the source's HISTORICAL getmnlistd replies away from
            // the tip-SML maintainer (a base=ZERO snapshot would overwrite it).
            // ADDITIVE, not a slot: the MN-checkpoint lane registers its own
            // filter below for the per-height PoSe fold, and both consumers
            // must be offered every reply (a fold point can coincide with a
            // quorum work block, and then ONE reply answers BOTH awaits).
            if (coin_p2p) {
                coin_p2p->add_historical_mnlistdiff_filter(
                    [qc_member_source]
                    (const dash::coin::vendor::CSimplifiedMNListDiff& d) {
                        return qc_member_source->on_mnlistdiff(d);
                    });
            }

            // #127 INSTANT-UPGRADE wiring. The arm's "upgrade the template the
            // instant the real commitment arrives" needs a template REBUILD on
            // ingest — without one, stratum keeps handing out the cached NULL
            // job until an unrelated tip/state-dirty bump happens to fire. Drive
            // the same re-issue path tip-change/state-dirty use
            // (bump_work_generation + stratum notify_all), but ONLY when the
            // pure, KAT-tested predicate qc_ingest_triggers_work_bump says so:
            //   * flag OFF               => never (byte-unchanged when off);
            //   * duplicate/rejected adm => no upgrade owed (already cached);
            //   * quorum not a CURRENT required mining-window slot => no bump
            //     (the anti-bump-storm gate — same compute_required_qc_slots /
            //     phase schedule the arm null-serves by, same has_mined view).
            std::weak_ptr<dash::stratum::DASHWorkSource> qc_upgrade_ws =
                work_source;
            coin_feed_subs.push_back(
                coin_state.new_qfcommit.subscribe(
                    [qc_ingest_from, embedded_null_arm, qc_upgrade_ws,
                     &node_coin_state, hc = header_chain.get(), qc_net,
                     &stratum_server]
                    (const dash::coin::vendor::CFinalCommitment& c) {
                        // PUSH transport: relayed once at DKG finalize, so a
                        // live arrival is inside (or just ahead of) an open
                        // window by construction — kick the member fetch
                        // unconditionally, exactly the pre-fix behaviour.
                        const auto adm =
                            qc_ingest_from(c, "qfcommit-push",
                                           /*kick_member_fetch=*/true);
                        // Flag OFF => early-out before any upgrade work: the
                        // ingest above is byte-for-byte the pre-#127 path. (The
                        // predicate's own first conjunct also returns false when
                        // off — this guard just avoids the tip read entirely.)
                        if (!embedded_null_arm) return;
                        auto tip = hc->tip();
                        if (!tip) return;
                        // has_mined via the CONST accessor (the D2 root-memo
                        // epoch must not be re-chilled by a read) — the SAME
                        // active-set answer the plan's merkleRootQuorums fold
                        // reads (single-snapshot discipline).
                        const bool bump =
                            dash::coin::qc_ingest_triggers_work_bump(
                                qc_net, tip->height + 1u,
                                embedded_null_arm, adm,
                                c.llmqType, c.quorumHash,
                                [hc](uint32_t h) -> std::optional<uint256> {
                                    if (auto e = hc->get_header_by_height(h))
                                        return e->hash;
                                    return std::nullopt;
                                },
                                [&node_coin_state](uint8_t t,
                                                   const uint256& qh) {
                                    return std::as_const(node_coin_state)
                                               .qmgr().find(t, qh).has_value();
                                });
                        if (bump) {
                            if (auto ws = qc_upgrade_ws.lock())
                                ws->bump_work_generation();
                            if (stratum_server) stratum_server->notify_all();
                            LOG_INFO << "[QC-NULL-ARM] instant upgrade: real"
                                        " commitment for a required slot type="
                                     << static_cast<int>(c.llmqType)
                                     << " quorum="
                                     << c.quorumHash.GetHex().substr(0, 16)
                                     << "... admitted -> work bumped, template"
                                        " re-issued (was null-served)";
                        }
                    }));
            // ── qc-plan-underivable CLOSURE: the request/response tee ──────
            // mnlistdiff is the transport that measurably ALWAYS works
            // (277/277 per soak on both hosts, including the one whose peers
            // churn every 101 s) and is re-requested on every fresh
            // handshake, so feeding the cache from it removes the
            // be-connected-at-the-inv dependency the push-only feed had. The
            // maintainer hands over tail.newQuorums of every ACCEPTED diff
            // (its base-continuity / stale-snapshot R1 / malformed-tail H-1
            // guards have already run); admission is the SAME ingest as the
            // push path above, so verified_for's guarantees are
            // transport-independent.
            maintainer->set_on_new_quorum_commitments(
                [qc_ingest_from, qc_member_fetch_worthwhile]
                (const std::vector<dash::coin::vendor::CFinalCommitment>& qcs) {
                    for (const auto& c : qcs)
                        qc_ingest_from(c, "mnlistdiff",
                                       qc_member_fetch_worthwhile(c));
                });
            // COMPLETENESS GATE (definitive-soak block 1520106): the plan is
            // per-height all-or-nothing — any mandatory slot without a
            // BLS-verified real commitment (no attested-null evidence source
            // is wired in production) fails the WHOLE height closed to the
            // dashd fallback. Log the first gap once per height so the soak
            // can attribute the fallback (the hot path re-derives the plan
            // on every template build — do not log unthrottled).
            //
            // BOUNDING THE REFUSAL (mainnet 2026-08-03, h=2515381 type=1 qi=0,
            // 11 min / 14 serves dark): the commitment for a mandatory slot is
            // announced ONCE by inv relay at DKG finalize and is only servable
            // on getdata BY COMMITMENT HASH — a commitment relayed before this
            // process connected CANNOT be pulled back (see the COLD-START HOLE
            // note in dkg_commitments.hpp; verified against dashpay/dash
            // v21.1.0). So the refusal is not a bug to route around, it is a
            // wait — and a wait must say how long. Each refusal now names the
            // CLASSIFIED cause, the measured commitment state, and the DKG
            // mining window that bounds it. `qc_first_plan_h` is the first
            // height this process ever planned; a slot whose commitment must
            // have been relayed before that provably predates our wire
            // presence (before we have that datum the field prints n/a).
            auto qc_gap_logged_h  = std::make_shared<uint32_t>(0u);
            auto qc_first_plan_h  = std::make_shared<uint32_t>(0u);
            auto qc_cold_note_done = std::make_shared<bool>(false);
            // [QC-EPISODE] terminal-event classifier (null-arm design §8,
            // recommendation 1 — the measurement that decides whether the
            // null arm is ever worth building). Every qc-plan-underivable
            // episode ends real-arrived (the flood delivered), real-mined
            // (another miner mined it) or window-closed-null (the window
            // closed with no real commitment ever seen — the ONLY case the
            // null arm could ever help). One line per episode at RESUME,
            // derived from facts the caches already hold; no new state
            // machine, no new wire traffic.
            auto qc_episode =
                std::make_shared<dash::coin::QcEpisodeClassifier>();
            // NEGATIVE-CAPABLE BACKSTOP for the enabled-type table itself
            // (llmq_type_reconciler.hpp). The mainnet LLMQ_50_60 defect was
            // invisible because "required but NONEXISTENT" and "required but
            // NOT YET ARRIVED" print the same refusal — the second looks like
            // patience. This watches the mnlistdiff-fed mined set (already
            // current at every template build, so no new wire traffic) and
            // says the thing no per-height log can: which required type has
            // NEVER been mined while the others plainly were — and the
            // reverse, a mined type we do not require.
            auto qc_type_recon =
                std::make_shared<dash::coin::LlmqTypeReconciler>(qc_net);
            auto qc_recon_said = std::make_shared<std::string>();
            // 5-minute re-assert floor for a STANDING defect; a shape CHANGE
            // gets its own key so it is never held back by the floor.
            auto qc_recon_log =
                std::make_shared<dash::coin::diag::LogSuppressor>(300000);
            // ── #127 NULL ARM: the production DkgNullEvidenceFn ────────────
            // dashd's negative-and-chain-accurate rule, ported verbatim from
            // GetMineableCommitments (dashpay/dash llmq/blockprocessor.cpp
            // :748-762): a required, not-yet-mined slot may be served the
            // consensus-valid NULL commitment iff HasMinedCommitment==false
            // (:752). There is NO failed-DKG predicate in that path — the ONLY
            // test is has_mined==false on a slot the phase schedule requires
            // (that requirement is enforced upstream by
            // compute_required_qc_slots, so this fn is only ever CALLED for a
            // genuinely-required not-yet-mined slot). The one thing we add over
            // dashd is the freshness proof: may I TRUST has_mined==false, i.e.
            // is my mnlistdiff-fed active-set view current enough that
            // has_mined==false is authoritative, not merely un-synced? That is
            // the SAME require_sml freshness the embedded arm's viability gate
            // (node_coin_state.hpp) already enforced before build_daemonless_
            // qc_plan is even reached — re-asserted here for defence in depth,
            // so the null decision can never ride a view the arm would itself
            // refuse. The has_mined read goes through the SAME QuorumManager
            // the merkleRootQuorums fold reads (single-snapshot invariant),
            // via the CONST accessor so the D2 root-memo epoch is untouched.
            // Freshness unproven => FALSE => the whole height fails closed to
            // the dashd fallback (worst case = today's benign gap, never a
            // reject). Consulted ONLY when --embedded-null-arm is armed; off,
            // nullptr is passed at the call site and this fn is never invoked.
            dash::coin::DkgNullEvidenceFn qc_null_evidence =
                [&node_coin_state, m = maintainer.get()]
                (uint8_t llmq_type, const uint256& quorum_hash) -> bool {
                    // (a) !has_mined — redundant with compute_required_qc_slots
                    //     (:425 already skipped has_mined slots) but asserted.
                    const bool not_mined =
                        !std::as_const(node_coin_state).qmgr()
                             .find(llmq_type, quorum_hash).has_value();
                    // (b) SML DATABLE (#94 gate, coin_state_maintainer.hpp
                    //     sml_height_paired): an un-dateable list covers
                    //     NOTHING, so has_mined==false off it is not trusted.
                    const bool datable = (m != nullptr) && m->sml_height_paired();
                    // (c) SML CURRENT AT THE TIP we build on (== pindexPrev):
                    //     the require_sml freshness (m_sml_current_hash ==
                    //     m_prev_hash) the viability gate enforces.
                    const bool current = node_coin_state.sml_current_at_prev();
                    return not_mined && datable && current;
                };
            LOG_INFO << "[QC-NULL-ARM] " << (embedded_null_arm
                        ? "ARMED (--embedded-null-arm): a required, not-yet-mined"
                          " DKG slot on a fresh active-set view is served the"
                          " consensus-valid null commitment (dashd"
                          " GetMineableCommitments rule); the real commitment"
                          " upgrades the template via the normal work refresh"
                        : "OFF (default): unsatisfiable qc slots fail the whole"
                          " height closed to the dashd fallback, byte-identical"
                          " to master — pass --embedded-null-arm to enable");
            node_coin_state.set_qc_plan_fn(
                [&node_coin_state, hc = header_chain.get(), qc_net, qc_cache,
                 embedded_null_arm, qc_null_evidence,
                 qc_gap_logged_h, qc_first_plan_h, qc_cold_note_done,
                 qc_type_recon, qc_recon_said, qc_recon_log, qc_episode,
                 // PR-2 FORWARD. By REFERENCE: the index is constructed later
                 // in this same function (alongside the replay lane), so a
                 // by-value capture would freeze the null it holds today.
                 // Same lifetime class as &node_coin_state above.
                 &mined_commitment_index]
                (uint32_t next_h, dash::coin::QcPlanGap* plan_gap)
                    -> std::optional<dash::coin::QcBlockPlan> {
                    if (*qc_first_plan_h == 0u) *qc_first_plan_h = next_h;
                    // Observe the MINED set at the tip we are building on.
                    // D2 root memo: this lambda runs INSIDE emit_ok on the
                    // serve path. Reads of qmgr() here must go through the
                    // CONST accessor — the non-const one bumps the root-memo
                    // epoch (it hands out a mutable reference) and would
                    // re-chill the memo on every single gate evaluation,
                    // silently reinstating the recompute the memo removes.
                    if (next_h > 0)
                        qc_type_recon->observe(next_h - 1u,
                                               std::as_const(node_coin_state).qmgr());
                    // Log when the DEFECT SHAPE changes — a new offending
                    // type must never be swallowed by dedup on an old one —
                    // and otherwise at most once per 5 minutes, carrying the
                    // count it stood in for.
                    //
                    // THE FLOOD THIS FIXES (measured 2026-08-04): the dedup
                    // above compared the whole SENTENCE, and that sentence
                    // embeds observations=/span=/heights=/sightings=, every
                    // one of which moves on every template build. So "has it
                    // changed" was always true and the guard was inert:
                    // 205k+ identical-in-substance [LLMQ-TYPE-RECONCILE]
                    // lines in one run, burying everything else. Keying on
                    // defect_shape() (types + verdicts only) dedups on what
                    // an operator acts on, while the periodic re-assert keeps
                    // a standing defect from going silent.
                    if (auto shape = qc_type_recon->defect_shape();
                        !shape.empty()) {
                        const int64_t now_ms = dash::coin::diag::steady_now_ms();
                        const bool changed = (shape != *qc_recon_said);
                        if (changed) *qc_recon_said = shape;
                        if (qc_recon_log->allow(changed ? shape + "#new" : shape,
                                                now_ms)) {
                            LOG_WARNING
                                << qc_type_recon->format_defects()
                                << " suppressed="
                                << qc_recon_log->take_suppressed(
                                       changed ? shape + "#new" : shape);
                        }
                    }
                    dash::coin::RequiredQcSlot gap{};
                    auto plan = dash::coin::build_daemonless_qc_plan(
                        qc_net, next_h, std::as_const(node_coin_state).qmgr(),
                        [hc](uint32_t h) -> std::optional<uint256> {
                            if (auto e = hc->get_header_by_height(h))
                                return e->hash;
                            return std::nullopt;
                        },
                        [hc](const uint256& qh) -> std::optional<uint32_t> {
                            if (auto e = hc->get_header(qh)) return e->height;
                            return std::nullopt;
                        },
                        qc_cache.get(),
                        // #127: null arm. OFF => literally nullptr (the null
                        // branch never executes; byte-identical to master).
                        // ON => dashd's negative-and-chain-accurate rule.
                        (embedded_null_arm
                            ? qc_null_evidence
                            : dash::coin::DkgNullEvidenceFn(nullptr)),
                        &gap,
                        // ── PR-2 FORWARD: the SECOND already-mined source ──
                        // dashd answers HasMinedCommitment from the block it
                        // connected (v23.1.7 llmq/blockprocessor.cpp:502 over
                        // the DB_MINED_COMMITMENT record ProcessCommitment
                        // wrote at :359). We answered it only from the
                        // mnlistdiff/qrinfo-fed QuorumManager — a round trip
                        // that lands AFTER the block did, which is what turned
                        // "another miner already mined this slot" into
                        // qc-plan-underivable episodes of 512/302/283/249 s.
                        //
                        // Two gates deep: null unless the operator passed
                        // --replay-mined-commitment-index AND the index armed
                        // (it REFUSES on a live tip — the undo half is not
                        // ported). Both false => this is nullptr and the plan
                        // is byte-identical to before.
                        (mined_commitment_index
                         && mined_commitment_index->armed())
                            ? std::function<bool(uint8_t, const uint256&)>(
                                  [mi = mined_commitment_index](
                                      uint8_t t, const uint256& qh) {
                                      return mi->has_mined_commitment(t, qh);
                                  })
                            : std::function<bool(uint8_t, const uint256&)>(),
                        // The identity of what was missing, handed straight to
                        // the serve-gate refusal so its VALUE names a quorum
                        // instead of the word "nullopt".
                        plan_gap);
                    if (!plan && !gap.quorum_hash.IsNull()
                        && *qc_gap_logged_h != next_h) {
                        *qc_gap_logged_h = next_h;
                        const auto wb =
                            dash::coin::qc_window_bound(gap.params, next_h);
                        // "Could we ever have seen this commitment?" — the
                        // relay happens by the window's first height at the
                        // latest, so a window that opened before our first
                        // planned height provably predates our wire presence.
                        std::string predates = "n/a";
                        if (*qc_first_plan_h != 0u && *qc_first_plan_h != next_h)
                            predates = (wb.first_height < *qc_first_plan_h)
                                ? "yes" : "no";
                        std::string signers = "n/a";
                        if (gap.cached_signers >= 0)
                            signers = std::to_string(gap.cached_signers);
                        // Only meaningful once a commitment is actually held —
                        // with nothing cached the member set was never sought,
                        // so the honest value is n/a, not "no".
                        std::string members_ready = "n/a";
                        if (qc_cache->has_commitment(gap.params.type,
                                                     gap.quorum_hash)) {
                            if (auto mr = qc_cache->members_ready(
                                    gap.params.type, gap.quorum_hash))
                                members_ready = *mr ? "yes" : "no";
                        }
                        LOG_INFO << "[QC-COMPLETENESS] h=" << next_h
                                 << " mandatory slot type="
                                 << static_cast<int>(gap.params.type)
                                 << " qi=" << gap.quorum_index
                                 << " quorum="
                                 << gap.quorum_hash.GetHex().substr(0, 16)
                                 << "... reason="
                                 << dash::coin::qc_slot_gap_name(gap.gap)
                                 << " cached_signers=" << signers
                                 << "/" << gap.params.min_size << "(min)"
                                 << " cache=" << qc_cache->size()
                                 << " bls_verifier="
                                 << (qc_cache->has_bls_verifier() ? "yes" : "no")
                                 << " member_set_ready=" << members_ready
                                 << " window=[" << wb.first_height << ","
                                 << wb.last_height << "]"
                                 << " remaining=" << wb.heights_remaining
                                 << " first_planned_h=" << *qc_first_plan_h
                                 << " predates_our_wire=" << predates
                                 << " -> WHOLE height fails closed"
                                    " (arm=dashd-fallback)";
                        // ONE explainer per process, on the first cold-start
                        // shaped gap: the operator must not have to re-derive
                        // "why can't it just ask a peer?" from the source.
                        if (gap.gap == dash::coin::QcSlotGap::NoCommitmentCached
                            && !*qc_cold_note_done) {
                            *qc_cold_note_done = true;
                            LOG_INFO
                                << "[QC-COMPLETENESS] NOTE: a mineable quorum"
                                   " commitment is announced ONCE by inv relay"
                                   " at DKG finalize and is served on getdata BY"
                                   " COMMITMENT HASH only (dashcore"
                                   " llmq/blockprocessor.cpp"
                                   " AddMineableCommitment /"
                                   " GetMineableCommitmentByHash) — there is NO"
                                   " P2P request that pulls one for a"
                                   " (type,quorumHash) we did not witness live,"
                                   " and mnlistdiff/qrinfo carry MINED"
                                   " commitments only. dashd's own miner mines"
                                   " the NULL commitment here"
                                   " (GetMineableCommitments \"null commitment"
                                   " required\" arm); c2pool refuses instead"
                                   " because null-serving a SUCCEEDED DKG"
                                   " diverged merkleRootQuorums at block"
                                   " 1520106. The refusal clears when any miner"
                                   " mines the commitment or when the window"
                                   " above closes — whichever comes first.";
                        }
                    }
                    // ── [QC-EPISODE] terminal-event classification ────────
                    // A slot-shaped refusal starts (or re-slots) the episode;
                    // the first derivable plan afterwards is the RESUME, and
                    // the terminal class is read off facts the caches hold at
                    // that instant: the commitment cache (did the flood
                    // deliver it => real-arrived), the mnlistdiff-fed
                    // QuorumManager (did another miner mine it => real-mined),
                    // or neither past the window's last height
                    // (window-closed-null — the only case dashd's null arm
                    // would have recovered; its measured wall-clock is the
                    // standing input to the null-arm defer/build decision).
                    // Structural nullopts (header gap / below the serve
                    // floor: gap.quorum_hash null) are not commitment waits
                    // and neither start nor end an episode.
                    {
                        const int64_t ep_now_sec =
                            std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::steady_clock::now()
                                    .time_since_epoch())
                                .count();
                        if (!plan) {
                            if (!gap.quorum_hash.IsNull()) {
                                const auto ep_wb = dash::coin::qc_window_bound(
                                    gap.params, next_h);
                                qc_episode->observe_underivable(
                                    next_h, gap.params.type, gap.quorum_index,
                                    gap.quorum_hash, ep_wb.last_height,
                                    ep_now_sec);
                            }
                        } else if (auto slot = qc_episode->pending()) {
                            const bool ep_cache_has = qc_cache->has_commitment(
                                slot->llmq_type, slot->quorum_hash);
                            const bool ep_mined =
                                std::as_const(node_coin_state).qmgr()
                                    .find(slot->llmq_type, slot->quorum_hash)
                                    .has_value();
                            if (auto ended = qc_episode->observe_derivable(
                                    next_h, ep_cache_has, ep_mined,
                                    ep_now_sec)) {
                                LOG_INFO
                                    << "[QC-EPISODE] cause=qc-plan-underivable"
                                    << " dur=" << ended->duration_sec << "s"
                                    << " terminal="
                                    << dash::coin::QcEpisodeClassifier
                                           ::terminal_name(ended->terminal)
                                    << " type="
                                    << static_cast<int>(ended->llmq_type)
                                    << " quorum="
                                    << ended->quorum_hash.GetHex().substr(0, 16)
                                    << "... qi=" << ended->quorum_index
                                    << " h=[" << ended->first_height << ".."
                                    << ended->resumed_height << "]";
                            }
                        }
                    }
                    return plan;
                });
        }

        // review PR #780 BLOCKER-2 (HIGH): refuse the embedded arm on a stale or
        // absent bestCL (dashcore CheckCbTxBestChainlock rejects null/older CL).
        // Only meaningful when the embedded arm actually serves (testnet or
        // --embedded-mainnet); harmless otherwise (the arm is off, work_source
        // never consults viability).
        //
        // POLICY SELECTION (--bestcl-policy, DEFAULT freshness = unchanged).
        // The freshness predicate is a PROXY: dashcore constrains the committed
        // ChainLock only relative to what the PREVIOUS BLOCK committed, never
        // against the tip or wall-clock recency (dash v23.1.7
        // src/evo/specialtxman.cpp:129-141). `consensus-exact` enforces that
        // real rule instead — see NodeCoinState::set_bestcl_policy. Kept as a
        // runtime flag, not a rebuild, so the conservative posture is one
        // restart away if a soak ever disagrees.
        if (!run_arm.embedded_arm_enabled) {
            node_coin_state.set_bestcl_policy(dash::coin::BestClPolicy::Off);
        } else if (bestcl_policy == "consensus-exact") {
            node_coin_state.set_bestcl_policy(
                dash::coin::BestClPolicy::ConsensusExact);
            LOG_INFO << "[EMB-DASH] bestCL gate policy = CONSENSUS-EXACT"
                        " (dashcore CheckCbTxBestChainlock rule; requires the"
                        " tip block's own committed ChainLock)";
        } else {
            node_coin_state.set_bestcl_policy(dash::coin::BestClPolicy::Freshness);
            LOG_INFO << "[EMB-DASH] bestCL gate policy = FRESHNESS"
                        " (conservative proxy: best CL within one block of tip)";
        }

        // SOAK FIX (bad-cbtx-assetlocked-amount): the DIP-0027 credit-pool seed
        // rides a separate on_mnlistdiff step and can lag one block while the SML
        // hash is already at the tip; the accrual then commits a stale
        // creditPoolBalance. Refuse the embedded arm unless the credit-pool seed
        // is current AT the tip, same discipline as the SML axis.
        const bool require_fresh_credit_pool = run_arm.embedded_arm_enabled;
        node_coin_state.set_require_fresh_credit_pool(require_fresh_credit_pool);

        // E4 re-soak fix (bad-cb-payee at 1519827): the projected masternode
        // payee is only dashd-exact when the payee queue has folded EVERY
        // block through the tip the template builds on (dashd computes
        // GetMNPayee(pindexPrev) on the list that connected pindexPrev).
        // The soak's incident window — seed as-of 1519820, blocks
        // 1519821/1519822 mined during header sync and never folded — ran
        // the queue cursor 2 slots behind dashd's; the divergence stayed
        // invisible inside a shared-payoutAddress group and surfaced as a
        // served bad-cb-payee exactly at the address-group boundary. Refuse
        // the embedded arm while the queue lags the tip (same freshness
        // discipline as the SML hash and the credit-pool seed height); the
        // MnStateMachine's forward-contiguity guard + the maintainer's gap
        // fail-closed path (wipe + authoritative protx re-seed) close the
        // gap itself.
        const bool require_fresh_mn_payee = run_arm.embedded_arm_enabled;
        node_coin_state.set_require_fresh_mn_payee(require_fresh_mn_payee);

        // H-6: SML/quorum apply and bestCL adoption move ASYNCHRONOUSLY to the
        // header tip. When they advance (catching the SML up to a moved tip, or
        // adopting a fresher ChainLock) the served template changes but no tip
        // signal fires — so drive the same re-issue path the tip-change uses.
        // A reorg wipe also routes here so miners drop the orphaned-branch
        // template immediately. (weak_ptr so a late event can't resurrect a
        // torn-down work source during shutdown.)
        {
            std::weak_ptr<dash::stratum::DASHWorkSource> ws_dirty = work_source;
            maintainer->set_on_state_dirty(
                [ws_dirty, &stratum_server]() {
                    if (auto ws = ws_dirty.lock()) ws->bump_work_generation();
                    if (stratum_server) stratum_server->notify_all();
                });
        }

        // review PR #780 H-1 heal: on a malformed quorum tail the maintainer
        // wipes the base-relative SML/quorum state and asks for a FULL re-sync.
        // Reset the sml_base request tracker to ZERO and re-request a full
        // snapshot at the current tip, so the next mnlistdiff is base=ZERO (the
        // skipped delta cannot be silently ridden over by an incremental).
        maintainer->set_on_full_resync(
            [sml_base, cp = coin_p2p.get(), hc = header_chain.get()]() {
                *sml_base = uint256::ZERO;
                auto tip_entry = hc->tip();
                const uint256 tip = tip_entry ? tip_entry->hash : uint256::ZERO;
                if (cp) cp->send_getmnlistd(uint256::ZERO, tip);
            });

        // Fourth-axis conjunct companion (#1153 policy wired to the ordering
        // fix): when the serve-tip promotion is held because the SML currency
        // is stuck behind the header tip, re-drive the INCREMENTAL getmnlistd
        // the tip-change path already sends (base = where the SML is, target =
        // the header tip). This is what keeps the conjunct from turning a
        // dropped/lost diff into a silent doomed-tip window. Bounded inside the
        // maintainer's SmlResyncWatchdog; this closure only forwards.
        maintainer->set_on_sml_rerequest(
            [cp = coin_p2p.get()](const uint256& base, const uint256& target) {
                if (cp) cp->send_getmnlistd(base, target);
            });

        // ChainLock verifier: BLS-verify a relayed clsig against the quorum
        // dashcore's SelectQuorumForSigning says must have signed it, before
        // the maintainer may adopt its height as the CCbTx bestCL*. Candidate
        // quorums come from the mnlistdiff-sourced active set (llmqTypeChainLocks
        // = LLMQ_400_60 on mainnet, LLMQ_50_60 on testnet); each quorumHash is
        // itself a block hash, so the header chain supplies its base height.
        // Fail-closed at every step — see chainlock_verify.hpp.
        maintainer->set_chainlock_verify_fn(
            [st = &node_coin_state, hc = header_chain.get(),
             net = (testnet ? dash::coin::LlmqNetwork::Testnet
                            : dash::coin::LlmqNetwork::Mainnet)](
                int32_t height, const uint256& block_hash,
                const std::array<uint8_t, 96>& sig) -> bool {
                const auto* p = dash::coin::chainlock::chainlock_params(net);
                if (p == nullptr) return false;

                // Never adopt a ChainLock ABOVE our own header tip. Adoption is
                // monotonic, and embedded_gbt.hpp:496-503 clears bestCLHeightDiff
                // /bestCLSignature entirely whenever best_cl_height exceeds the
                // height we are building on — so adopting an over-tip ChainLock
                // would pin the CCbTx bestCL* fields to ZERO (diverging from
                // dashd, which would commit a real diff) until our tip caught up,
                // and we could never fall back to the older usable value. Holding
                // the previous ChainLock is strictly better. Self-correcting:
                // dashd re-announces its best ChainLock roughly every block.
                // This also bounds BLS work on a peer replaying junk heights.
                auto tip = hc->tip();
                if (!tip || height > static_cast<int32_t>(tip->height)) return false;

                // Collect the active quorums of the ChainLock-signing type,
                // each with the height of its base block (the quorumHash IS a
                // block hash, so the header chain resolves it directly — the
                // same lookup QuorumMemberSource's HeightOfHash seam uses).
                std::vector<dash::coin::chainlock::QuorumCandidate> cands;
                for (const auto& e : st->qmgr().active_entries()) {
                    if (e.key.llmqType != p->type) continue;
                    auto hdr = hc->get_header(e.key.quorumHash);
                    if (!hdr) continue;          // base header not held => skip
                    dash::coin::chainlock::QuorumCandidate c;
                    c.quorum_hash        = e.key.quorumHash;
                    c.base_height        = hdr->height;
                    c.quorum_public_key  = e.commitment.quorumPublicKey;
                    cands.push_back(c);
                }
                auto target = dash::coin::chainlock::build_sign_target(
                    *p, std::move(cands), height, block_hash);
                if (!target) return false;       // no quorum selectable => fail closed
                return dash::coin::vendor::verify_chainlock_sig(
                    target->quorum.quorum_public_key, target->sign_hash, sig);
            });

        // isdlock verifier (G4 conflict-tx-lock feed): BLS-verify a relayed
        // deterministic InstantSend lock against the ROTATED LLMQ_60_75
        // quorum dashcore's SelectQuorumForSigning designates, before the
        // maintainer may fold its outpoints into Mempool::add_islock. The one
        // divergence from the clsig verifier above: llmqTypeDIP0024InstantSend
        // is a rotated type, so selection is cycleHash + requestId-derived
        // quorumIndex (islock_verify.hpp), NOT the score-sort arm. Candidate
        // quorums come from the same qrinfo/mnlistdiff-sourced active set
        // (#1077 put rotated type-5 entries there); each quorumHash is a block
        // hash, so the header chain supplies base heights, and the isdlock's
        // cycleHash resolves the cycle base the same way. Fail-closed at every
        // step — unknown/over-tip cycleHash, unselectable quorum index,
        // missing pubkey, BLS fail => drop, no ban, no state change.
        maintainer->set_islock_verify_fn(
            [st = &node_coin_state, hc = header_chain.get(),
             net = (testnet ? dash::coin::LlmqNetwork::Testnet
                            : dash::coin::LlmqNetwork::Mainnet)](
                const std::vector<std::pair<uint256, uint32_t>>& inputs,
                const uint256& txid, const uint256& cycle_hash,
                const std::array<uint8_t, 96>& sig) -> bool {
                const auto* p = dash::coin::islock::islock_params(net);
                if (p == nullptr) return false;

                // The cycle base must be a block WE hold, at or below our own
                // header tip — a peer replaying junk cycle hashes gets a cheap
                // refusal before any BLS work (mirrors the clsig over-tip
                // guard; dashd's LookupBlockIndex(cycleHash) refusal is the
                // same shape, net_instantsend.cpp:106-110).
                auto cyc = hc->get_header(cycle_hash);
                if (!cyc) return false;
                auto tip = hc->tip();
                if (!tip || cyc->height > tip->height) return false;

                // Collect the active ROTATED type-5 quorums, each with the
                // height of its base block (rotated invariant: baseHeight ==
                // cycleHeight + quorumIndex; islock_verify.hpp filters on it).
                std::vector<dash::coin::islock::RotatedQuorumCandidate> cands;
                for (const auto& e : st->qmgr().active_entries()) {
                    if (e.key.llmqType != p->type) continue;
                    auto hdr = hc->get_header(e.key.quorumHash);
                    if (!hdr) continue;          // base header not held => skip
                    dash::coin::islock::RotatedQuorumCandidate c;
                    c.quorum_hash       = e.key.quorumHash;
                    c.base_height       = hdr->height;
                    c.quorum_index      = static_cast<uint16_t>(
                        e.commitment.quorumIndex < 0 ? 0xffff
                                                     : e.commitment.quorumIndex);
                    c.quorum_public_key = e.commitment.quorumPublicKey;
                    cands.push_back(c);
                }
                auto target = dash::coin::islock::build_islock_sign_target(
                    *p, cands, cyc->height, inputs, txid);
                if (!target) return false;       // no quorum selectable => fail closed
                return dash::coin::vendor::verify_chainlock_sig(
                    target->quorum.quorum_public_key, target->sign_hash, sig);
            });

        // Leg 6 (ChainLock sig): Node::new_chainlock_sig -> maintainer
        // .on_new_chainlock. The clsig message carries the recovered 96-byte
        // threshold sig (new_chainlock above drops it); the maintainer adopts
        // the freshest observed ChainLock height+sig as the CCbTx bestCL*
        // ONLY IF the verifier above accepts it.
        coin_feed_subs.push_back(
            coin_state.new_chainlock_sig.subscribe(
                [m = maintainer.get()]
                (const dash::interfaces::Node::ChainLockSigEvent& c) {
                    m->on_new_chainlock(c.height, c.block_hash, c.sig);
                }));

        // G4 leg (isdlock): Node::new_isdlock -> maintainer.on_new_isdlock.
        // The event only fires when --embedded-ingest-isdlock armed the pull;
        // the maintainer gate then BLS-verifies via the verifier above and
        // ONLY on pass folds the outpoints into Mempool::add_islock (arming
        // the already-merged G4 conflict-tx-lock selection guard). Both hops
        // fail closed, so subscribing unconditionally is inert without the
        // flag.
        coin_feed_subs.push_back(
            coin_state.new_isdlock.subscribe(
                [m = maintainer.get()]
                (const dash::interfaces::Node::IsdLockEvent& e) {
                    m->on_new_isdlock(e.inputs, e.txid, e.cycle_hash, e.sig);
                }));

        // Bridge: new_headers -> HeaderChain::add_headers (X11 PoW + DGW
        // validated). The tip authority for the embedded template.
        coin_feed_subs.push_back(
            dash::coin::wire_header_ingest(coin_state, *header_chain));
        // Bridge: full_block -> (X11 hash -> header-chain height) ->
        // Node::block_connected, driving leg 3 + the E2b UTXO lane.
        coin_feed_subs.push_back(
            dash::coin::wire_full_block_ingest(coin_state, *header_chain));

        // new_block(inv hash) -> pull the headers THEN the full block from the
        // peer. The getheaders-first ordering is the steady-state tip-follow
        // fix (E2c): dashd announces new blocks via inv (we never negotiate
        // sendheaders), so without an explicit getheaders here the header
        // chain stalls at the initial-sync tip forever and EVERY live block
        // hits wire_full_block_ingest's not-in-header-chain deferral — no
        // block_connected, no apply_block, no UTXO bootstrap trigger. Same
        // single ordered TCP stream to the same peer, so the headers response
        // (tip advance, header now known) lands BEFORE the block does and the
        // connect proceeds. Mirrors the PROVEN LTC new-block handler
        // (main_ltc.cpp ~2133: request_headers off the locator + block pull).
        coin_feed_subs.push_back(
            coin_state.new_block.subscribe(
                [cp = coin_p2p.get(), hc = header_chain.get()](const uint256& hash) {
                    // Route BOTH the header pull and the body pull to the peer
                    // that ANNOUNCED this block (#1082 pool: announcer != the
                    // primary). Sending them to an arbitrary primary that is
                    // behind/wedged is why a WARM node's tip-body never folded
                    // and body-first serve-tip stayed at have_tip=0.
                    cp->send_getheaders_from_block_source(
                        hash, 70230, hc->get_locator(), uint256::ZERO);
                    // TRACKED: this is the tip-body pull, the one request the
                    // serve tip now waits on (body-first). The lost-body
                    // watchdog re-requests it from a rotated peer after 10 s
                    // (`cause=body-rerequest` in the log) instead of waiting
                    // out the 600 s inv-dedup TTL — the #1089 208 s tail.
                    cp->request_block_tracked(hash);
                }));

        // new_chainlock -> record into the best-chainlock tracker (finalization
        // signal the block-find submit path can consult).
        coin_feed_subs.push_back(
            coin_state.new_chainlock.subscribe(
                [&coin_state](const std::pair<uint256, int32_t>& cl) {
                    coin_state.chainlocked_blocks[cl.first] = cl.second;
                }));

        // Header self-propel: after each accepted headers batch, request the
        // next batch off the updated locator so the chain catches up to tip.
        // Registered AFTER wire_header_ingest so add_headers runs first and the
        // locator reflects the new tip.
        coin_feed_subs.push_back(
            coin_state.new_headers.subscribe(
                [cp = coin_p2p.get(), hc = header_chain.get()]
                (const std::vector<dash::coin::BlockHeaderType>& batch) {
                    if (batch.empty()) return;
                    cp->send_getheaders(70230, hc->get_locator(), uint256::ZERO);
                }));

        // ── #129 FRESH-PATH HEADER-SYNC RE-ARM (stall watchdog) ──────────
        // The self-propel above is a ONE-TOKEN relay: exactly one getheaders
        // in flight, re-armed ONLY by its own response arriving as a
        // non-empty headers batch. Two ways the token dies on a FRESH
        // (empty-data-dir, no --coin-rpc) node:
        //   (a) the primary is busy computing the cold-start monsters the
        //       SAME handshake kick queued on it (null-base mnlistdiff for
        //       ~3200 MNs + qrinfo) — dashd answers a peer's requests
        //       sequentially, so the next headers reply sits minutes behind
        //       that computation; single-peer, effectively forever;
        //   (b) the reply is lost (disconnect, reorg race) — nothing re-asks.
        // Either way getheaders stops re-arming and the header chain parks
        // below tip (the h=2406000 fresh-bring-up wedge: anchor + 3 batches,
        // then silence). The per-block-inv rescue above cannot save a node
        // whose only/announcing peer is the starved one, and send_getheaders
        // is a silent no-op with a null primary. An EXISTING data-dir never
        // sees this: the warm deficit is small and the cold monsters absent.
        // This is the tip-lane analog of the bulk walker's
        // maybe_kick_backfill (replay_bulk_fetch.hpp) and the same
        // armed-once-never-re-armed class as #1151/#1162.
        //
        // Every 5 s: if the header chain is BEHIND the best peer-advertised
        // height AND has not advanced for kStallSec, re-issue getheaders off
        // the CURRENT locator, round-robining across ALL handshaked peers —
        // not pinned to the possibly-starved primary. Wire-conservative and
        // reward-safe by construction: it only re-sends an existing,
        // well-formed message (no wire/consensus change); a duplicate reply
        // de-dups as accepted==0; at/above the advertised tip the height
        // guard makes it inert; and NO serve gate reads it — the freshness /
        // is_synced gates that keep an incompletely-synced node from serving
        // are untouched, a re-request grants no serve authority.
        {
            struct HeaderSyncWatchdogState {
                uint32_t last_height{0};
                int64_t  last_change{0};   // steady seconds of last advance
                int64_t  last_kick{0};
                uint64_t rr{0};            // peer round-robin cursor
                uint64_t kicks{0};
            };
            constexpr int64_t kStallSec  = 20;  // no advance for this long
            constexpr int64_t kRekickSec = 10;  // min spacing between kicks
            header_sync_watchdog_timer =
                std::make_unique<core::Timer>(&ioc, /*repeat=*/true);
            header_sync_watchdog_timer->start(5,
                [cp = coin_p2p.get(), hc = header_chain.get(),
                 st = std::make_shared<HeaderSyncWatchdogState>()]() {
                    const int64_t now =
                        std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::steady_clock::now()
                                .time_since_epoch()).count();
                    const uint32_t h = hc->height();
                    if (st->last_change == 0 || h != st->last_height) {
                        st->last_height = h;
                        st->last_change = now;   // progress — watchdog quiet
                        return;
                    }
                    const uint32_t peer_tip = hc->peer_tip_height();
                    // peer_tip is stamped from version handshakes; once our
                    // height passes it in steady state the watchdog is inert
                    // (tip follow is inv-driven there, by design).
                    if (peer_tip == 0 || h >= peer_tip) return;
                    if ((now - st->last_change) < kStallSec) return;
                    if ((now - st->last_kick) < kRekickSec) return;
                    st->last_kick = now;
                    ++st->kicks;
                    const auto locator = hc->get_locator();
                    auto keys = cp->handshaked_peer_keys();
                    bool sent = false;
                    std::string target = "<primary>";
                    if (!keys.empty()) {
                        // Rotate so consecutive kicks reach DIFFERENT peers:
                        // the whole point is escaping a starved primary.
                        const std::string& key =
                            keys[st->rr++ % keys.size()];
                        sent = cp->send_getheaders_to(
                            key, 70230, locator, uint256::ZERO);
                        if (sent) target = key;
                    }
                    if (!sent)   // no named peer took it — primary fallback
                        cp->send_getheaders(70230, locator, uint256::ZERO);
                    LOG_INFO << "[COIN-P2P] header-sync stall watchdog:"
                                " re-armed getheaders h=" << h
                             << " peer_tip=" << peer_tip
                             << " stalled_s=" << (now - st->last_change)
                             << " peer=" << target
                             << " kick#" << st->kicks;
                });
        }

        // ── BODY-FIRST SERVE TIP + bounded full-block buffer (operator
        // direction off soak0804e; the follow-up the #1089 thread scopes).
        // Enabled ONLY here, on the coin-P2P daemonless arm, where full
        // bodies demonstrably flow (the dashd-RPC/ZMQ tip posture has no body
        // feed and stays header-first). From here on the header-chain tip
        // callback below keeps driving stale-work invalidation / job rebuild
        // / the mnlistdiff pull EXACTLY as before (header-tip consumers are
        // not delayed), while the maintainer's serve tip — the template
        // height and every freshness-gate threshold — advances only when the
        // tip block's inputs are parsed, atomically with the credit-pool
        // advance. `creditpool-stale` then ceases to exist as a class in
        // normal operation; the ~1-2 s window is named `tip-body-pending`.
        maintainer->set_body_first_serve_tip(true);
        // C-startup-invariant (gapless MN-list / daemonless re-seed): couple the
        // money-path freshness gates to body-first serving. The daemonless arm
        // sets body-first UNCONDITIONALLY one line up, so this can never
        // false-trip today; it exists so a FUTURE embedded wiring that adds an
        // arm with a freshness gate but forgets set_body_first_serve_tip(true)
        // fails LOUD at startup instead of silently regressing to
        // publish-at-header-tip (a payee / creditPool projected off a fold not
        // yet current at the serve tip = bad-cb-payee / bad-cbtx-assetlocked
        // = lost block). Read body-first back from the maintainer so a dropped
        // wiring is what actually trips it. Tightens only; relaxes no guard.
        dash::coin::require_body_first_when_fresh_gated(
            run_arm.embedded_arm_enabled,
            require_fresh_credit_pool,
            require_fresh_mn_payee,
            maintainer->body_first_serve_tip());
        // PR-5 publication height (default OFF; money path). With body-first
        // on, the credit pool derived for a block ABOVE the serve tip is held
        // and published atomically with the promotion that makes that block
        // the serve tip -- so the pool the template is built from is the pool
        // at the block it builds ON, which is what dashd does by construction
        // (GetCreditPool(pindexPrev)).
        maintainer->set_credit_pool_publish_at_serve_tip(
            embedded_creditpool_publish_at_serve_tip);
        std::cout << "[run] embedded credit-pool publication height: "
                  << (embedded_creditpool_publish_at_serve_tip
                          ? "SERVE TIP (--embedded-creditpool-publish-at-serve-tip)"
                          : "body height (default; creditpool-stale windows "
                            "possible while promotion is held)")
                  << "\n";
        maintainer->set_full_block_buffer(true);
        maintainer->set_chain_hash_at_height_fn(
            [hc = header_chain.get()](uint32_t h) -> std::optional<uint256> {
                auto e = hc->get_header_by_height(h);
                if (!e) return std::nullopt;
                return e->hash;
            });

        // Tip-changed callback: (a) fire Node::new_tip (leg 2 arms tip-readiness
        // -> the maintainer republishes once the MN list is ALSO seeded ->
        // populated() flips), and (b) #739 idle-notify: bump work-generation +
        // notify sessions on a real tip change so idle miners are not wedged on
        // stale work between job-push timer firings (event-driven notify).
        header_chain->set_on_tip_changed(
            [&coin_state, &stratum_server, hc = header_chain.get(),
             addr_ver, p2sh_ver, ws = work_source.get(),
             cp = coin_p2p.get(), sml_base, m = maintainer.get(),
             mnl = mn_ckpt_lane.get(), qcms = qc_ms_prefetch_handle]
            (const uint256&, uint32_t, const uint256& new_tip, uint32_t new_height,
             bool was_reorg) {
                // E2d bridge driver. Safe + REACHABLE here: HeaderChain fires
                // this callback with m_mutex RELEASED (add_header/add_headers
                // copy the pending tip-change out inside the lock scope, close
                // it, then invoke), so the lane's self-locking header-chain
                // reads below cannot self-deadlock. The pre-existing
                // tip_advance_from_chain(*hc, ...) call two lines down already
                // relies on exactly that property and is proven live.
                // No-op unless the lane was armed on the daemonless path.
                if (mnl) mnl->pump();
                // #108 QC-PREFETCH: ask for the member sets this DKG cycle
                // will need while the tip is still ~10 blocks short of the
                // mining window, instead of at the first qfcommit that needs
                // them. Same request paths, same authentication, same dedupe —
                // only the timing changes. Measured cost of asking late: 48
                // qc-plan-underivable declines on the daemonless soak.
                if (qcms) qcms->prefetch_cycle(new_height);
                auto ta = dash::coin::tip_advance_from_chain(
                    *hc, addr_ver, p2sh_ver);
                if (ta) {
                    coin_state.new_tip.happened(*ta);
                    LOG_INFO << "[EMB-DASH] tip advanced h=" << new_height
                             << " " << new_tip.GetHex().substr(0, 16)
                             << " bits=0x" << std::hex << ta->bits_for_next << std::dec
                             << " -> new_tip fired (maintainer arm)";
                }
                // C-2 reorg wiring: a branch switch invalidates the incremental
                // SML (its applied diffs were relative to the orphaned branch).
                // Wipe + drop have_sml so the embedded arm falls back to dashd,
                // reset the sync base to ZERO, and re-request a FULL cold-start
                // snapshot at the new tip (an incremental diff off the stale base
                // would be rejected by the base-continuity guard anyway).
                if (was_reorg && m) {
                    LOG_WARNING << "[SML] reorg to h=" << new_height
                                << " -> SML wipe + cold-resync";
                    m->on_sml_reorg();
                    *sml_base = uint256::ZERO;
                }
                // SML axis: pull the mnlistdiff current AT the new tip. dashcore
                // computes block (tip+1)'s CbTx merkleRootMNList/Quorums from the
                // DMN/quorum list as-of `tip` (GetListForBlock(pindexPrev)), so
                // targeting the diff at `new_tip` puts the local SML in exactly
                // the state needed to build tip+1. Incremental off the last
                // synced base (ZERO after a reorg = full snapshot); the
                // new_mnlistdiff subscription advances sml_base on acceptance.
                // A1: base = the APPLIED cursor (maintainer->sml_current_hash()),
                // the block the SML is actually current at — the single source of
                // truth. A prior overlapping/leaked/base-rejected reply can no
                // longer strand the request base ahead of the cursor (the
                // reception-time sml_base tracker's latch); the next advance
                // re-requests the same contiguous span and is accepted.
                if (cp && m) cp->send_getmnlistd(m->sml_current_hash(), new_tip);
                // #739 + stale-payee window close: event-driven stale-work
                // notify. INVALIDATE the template cache FIRST (mirrors the
                // #770/#772 fire_refresh trio: invalidate + bump + notify) so the
                // next served job is ALWAYS re-sourced with the fresh-tip payee,
                // regardless of refresh_executor_ state. Without the explicit
                // invalidate the window only stays closed IMPLICITLY (the coin-P2P
                // arm has no refresh_executor_, so cached_work() re-sources inline);
                // if io-decouple is ever extended to this arm, cached_work() would
                // serve the STALE cached template while refreshing async and a
                // stale-payee job would go out. Make it robust, not implicit.
                if (ws) {
                    ws->invalidate_template_cache(
                        "coin-P2P tip changed: fresh-payee re-source");
                    ws->bump_work_generation();
                }
                if (stratum_server) stratum_server->notify_all();
            });

        // E2b UTXO bootstrap window-refill seam: request historical block
        // bodies BY HEIGHT (header-chain hash lookup) so the UTXO view + the
        // MnStateMachine (apply_block) fill forward from the live feed.
        if (embedded_utxo && utxo_lane.live()) {
            utxo_lane.set_request_block_fn(
                [cp = coin_p2p.get(), hc = header_chain.get()](uint32_t h) {
                    auto e = hc->get_header_by_height(h);
                    if (e) cp->request_block(e->hash);
                });
        }

        // Peer's reported chain height -> header-chain sync-progress gauge.
        coin_p2p->set_on_peer_height(
            [hc = header_chain.get()](uint32_t h) { hc->set_peer_tip_height(h); });

        // ── PHASE-1 MEMPOOL INGEST: arm the MSG_TX pull ──────────────────
        // Every embedded template we build today is EMPTY, and the reason is
        // one line of policy: inv_type_is_pulled() admits only
        // quorum_final_commitment and clsig, so a peer's inv(MSG_TX) never
        // earned a getdata and the tx handler that feeds
        // Mempool::add_tx was unreachable from the network. Everything below
        // that handler already shipped in #1110.
        //
        // send_mempool() below has ALWAYS asked peers to announce their pool —
        // its own comment says "our inv handler currently only pulls block
        // invs" — so before this the prime was answered with announcements we
        // then threw away.
        //
        // OFF by default. Budgeted, and strictly lower priority than the tip
        // body. See the/docs/DASH-OWN-MEMPOOL-DESIGN.md.
        if (embedded_mempool_ingest) {
            coin_p2p->set_tx_pull(true, /*cap=*/64);
            // Say what the lane is doing on a cadence: what we were offered,
            // what we asked for, what arrived, and what the pool now holds.
            // received==0 with getdata>0 sustained is the signature of a peer
            // set that will not serve us transactions — a diagnosis nobody can
            // make from an empty template alone.
            mempool_ingest_timer =
                std::make_unique<core::Timer>(&ioc, /*repeat=*/true);
            mempool_ingest_timer->start(30,
                [cp = coin_p2p.get(), &node_coin_state]() {
                    LOG_INFO << cp->tx_ingest_status()
                             << " pool_txs=" << node_coin_state.mempool().size()
                             << " pool_bytes=" << node_coin_state.mempool().byte_size()
                             << " priced_fees="
                             << node_coin_state.mempool().total_known_fees()
                             << " duffs";
                });
            std::cout << "[run] --embedded-mempool-ingest: coin-P2P MSG_TX pull"
                         " ARMED (budget 64 in flight, yields to the tip body)."
                         " The mempool will now FILL from the DASH network.\n"
                      << "      This does NOT put transactions into served"
                         " templates: that stays --embedded-serve-mempool-txs"
                         " (default OFF), gated on the [MEMPOOL-VALIDITY]"
                         " testmempoolaccept series -- zero INVALID over "
                      << dash::coin::MempoolValidityGate::kCleanHeightsRequired
                      << " consecutive evidence-bearing DISTINCT heights.\n";
        }

        // ── G4 ISDLOCK INGEST: arm the MSG_ISDLOCK pull ──────────────────
        // Mempool::add_islock + the G4 conflict-tx-lock selection guard
        // shipped in #1110 fully inert: nothing acquired islocks, so the
        // outpoint map stayed empty and selection never excluded anything.
        // This is the acquire half; the verify half is the BLS gate installed
        // above (set_islock_verify_fn), and only its PASS ever reaches
        // add_islock. OFF by default — off, an inv(MSG_ISDLOCK=31) never
        // earns a getdata and the handler decodes-and-discards, wire and
        // template behaviour byte-identical to master.
        if (embedded_ingest_isdlock) {
            coin_p2p->set_isdlock_pull(true);
            std::cout << "[run] --embedded-ingest-isdlock: coin-P2P"
                         " MSG_ISDLOCK pull ARMED. Every isdlock is"
                         " individually BLS-verified against the rotated"
                         " LLMQ_60_75 signing quorum before its outpoints"
                         " reach the mempool's G4 conflict-tx-lock guard;"
                         " any verification failure is a drop (fail-closed,"
                         " no state change).\n";
        }

        // Kick the initial sync once the version/verack handshake completes:
        // getheaders off our current locator + a mempool prime.
        coin_p2p->set_on_handshake_complete(
            [cp = coin_p2p.get(), hc = header_chain.get(), sml_base,
             discover = coin_p2p_discover_eff, maint = maintainer.get()]() {
                LOG_INFO << "[EMB-DASH] handshake complete -> initial sync:"
                            " getheaders + mempool + mnlistdiff(cold)"
                         << (discover ? " + getaddr (peer crawl)" : "");
                cp->send_getheaders(70230, hc->get_locator(), uint256::ZERO);
                // ── BIP35 AND THE SOLE-INGESTION-PATH INVARIANT ──────────
                // mempool.hpp names "BIP35 sync drain" as one of the seams
                // that turns two ConnectBlock reject rows (bad-txns-nonfinal,
                // mandatory-script-verify-flag) from N/A into GAPs. Those rows
                // are argued N/A because every tx was RELAY-admitted: a peer
                // validated it against the current tip and chose to announce
                // it. A BIP35 drain is different in kind — it dumps the peer's
                // whole pool, including entries admitted long ago under
                // policy we cannot date.
                //
                // Before the MSG_TX pull existed this call was harmless: the
                // inv handler discarded the announcements, so the drain was a
                // no-op (its own comment said so). Arming the pull would make
                // it live, and would silently convert those two rows into gaps
                // without the re-audit the invariant demands.
                //
                // So when ingest is armed we do NOT drain: the pool fills from
                // relay only, exactly the path the invariant is written about.
                // The cost is cold-start latency (we learn a transaction when
                // it is next announced, not retroactively) — minutes on a
                // 2.5-minute chain, and it buys the audit staying true.
                if (!cp->tx_pull_enabled()) cp->send_mempool();
                // Peer-crawl: getaddr feeds set_addr_callback -> the isolated
                // peer manager (addr-crawl source, +50 scored) so the diverse
                // independent peer set grows off live wire discovery.
                if (discover) cp->send_getaddr();
                // Cold-start SML sync: full snapshot (base=ZERO) up to our best
                // known header tip. Steady-state incremental diffs then ride the
                // tip-changed driver. If the header chain is still empty at
                // handshake, target ZERO too — the first tip-change re-requests.
                auto tip_entry = hc->tip();
                const uint256 tip = tip_entry ? tip_entry->hash : uint256::ZERO;
                // A1: base = the APPLIED cursor (single source of truth). At
                // handshake the maintainer is cold (cursor == ZERO) so this is
                // the full cold snapshot; a reconnect after some sync re-requests
                // from exactly what the SML has applied, never a stranded base.
                cp->send_getmnlistd(maint ? maint->sml_current_hash() : uint256::ZERO, tip);
                // E-SUPERBLOCK: prime the governance object/vote sync (triggers
                // + funding votes) so a superblock height can be served
                // daemonlessly. Zero nProp + empty filter => request all.
                // Handshake-only today — there is NO tip-change re-prime yet.
                // KNOWN GAP (pre-enable requirement): dashcore answers govsync
                // with INVENTORY (MSG_GOVERNANCE_OBJECT/_VOTE invs), not
                // direct govobj/govobjvote messages, and our inv handler does
                // not getdata governance types — so this leg is currently
                // INERT (an extra fail-closed layer: the store stays empty).
                // The inv-driven getdata + per-object vote sync + periodic
                // re-prime co-land with vote-verify before any enable.
                cp->send_govsync();
                // R5: record govsync peer coverage + (re)arm the quiescence
                // window for the completeness determination. With the current
                // single-peer connection model this covers ONE peer, so the
                // default min_peers floor (>=2) keeps the completeness predicate
                // FALSE — reward-safe until multi-peer govsync lands.
                maint->note_govsync_requested(cp->peer_key());
            });

        std::cout << "[run] E2a live-feed wired: header-chain(" << hdr_db
                  << ") + CoinStateMaintainer + 6 ingest subscriptions;"
                     " populate flips get_work to the EMBEDDED arm once the tip"
                     " (headers) AND the DMN set (block-connect apply_block) are"
                     " present"
                  << (embedded_utxo
                          ? (embedded_utxo_immature_serve_empty
                                 ? " (UTXO immaturity serves coinbase-only --"
                                   " opt-in, not a refusal)"
                                 : " + UTXO maturity>=106")
                          : "")
                  << "\n";

        // The payee-desync re-seed answer this posture installs, kept in a
        // named variable so the replay serve seam (below, behind the replay
        // flags) can chain IN FRONT of it without replacing it: the replay
        // fold answers the ask when it is still proven current, otherwise the
        // node falls through to exactly the lane it had before.
        std::function<void()> mn_reseed_fallback;

        // ── E2c (#738): RPC MN-set SEED — flip the DMN half of populated() ──
        // E2a proved the TIP half populates live, but populated() ALSO needs a
        // payout-bearing DMN set, and no live leg can cold-start one: the P2P
        // Simplified MN List (leg 4's wire form) omits scriptPayout +
        // nLastPaidHeight, and leg 3's apply_block only folds special txs from
        // blocks we actually connect (a full DIP3-height replay = E2d). So when
        // the dashd-RPC arm is ARMED, fetch the full REGISTERED DMN set ONCE via
        // `protx list registered true` (payoutAddress + lastPaidHeight — everything
        // GetMNPayee ordering needs) and publish it through the EXISTING leg-4
        // event, so the maintainer takes it exactly like any other resync. The
        // parse FAILS CLOSED (mn_seed.hpp): any undecodable payoutAddress
        // aborts the whole seed rather than minting a wrong payee (the
        // bad-cb-payee class #746 fixed). Synchronous-before-ioc.run() is safe:
        // NodeRPC::Send self-connects via the blocking sync_reconnect fallback
        // (the same property --submit-block relies on).
        if (rpc && !g_no_dashd_mn_seed) {
            // Reusable authoritative seed fetch: invoked once at startup AND
            // re-invoked by the maintainer's payee-desync fail-closed path
            // (set_on_mn_reseed below) after it wiped a desynced payee queue.
            // Lifetime: rpc/coin_state are main()-scope and outlive ioc.run().
            auto seed_mn_set_from_rpc = [rpc_ptr = rpc.get(), addr_ver,
                                         p2sh_ver, &coin_state](const char* tag) {
            try {
                // Height-stable fetch: the snapshot must carry the exact
                // height it is current at (the maintainer fences off
                // re-application of blocks <= that height -- see
                // MnListUpdate::as_of_height). protx list is evaluated at
                // dashd's live tip, so bracket it with getblockcount and
                // refetch on a mid-flight tip move (bounded; a testnet block
                // race is rare, mainnet 2.5 min spacing makes it rarer).
                nlohmann::json protx_list;
                uint32_t as_of = 0;
                for (int attempt = 0; attempt < 3; ++attempt) {
                    const uint32_t h_before = static_cast<uint32_t>(
                        rpc_ptr->getblockchaininfo().value("blocks", 0));
                    protx_list = rpc_ptr->protx_list_registered_detailed();
                    const uint32_t h_after = static_cast<uint32_t>(
                        rpc_ptr->getblockchaininfo().value("blocks", 0));
                    if (h_before == h_after && h_after != 0) {
                        as_of = h_after;
                        break;
                    }
                }
                dash::coin::MnSeedStats seed_stats;
                auto seed = dash::coin::parse_protx_list_seed(
                    protx_list, addr_ver, p2sh_ver, &seed_stats);
                if (!seed.empty() && as_of != 0) {
                    dash::interfaces::MnListUpdate up;
                    up.mnstates     = std::move(seed);
                    up.as_of_height = as_of;
                    // NAME the lane: this snapshot came FROM DASHD. A run
                    // seeded here has not proven a daemonless serve, however
                    // daemonless the rest of it is.
                    up.source       = dash::coin::replay::kPayeeSourceDashdSeed;
                    coin_state.mn_list_update.happened(up);
                    std::cout << "[run] E2c MN-set seed LOADED (" << tag
                              << "): "
                              << seed_stats.seeded << "/" << seed_stats.total
                              << " registered MNs (" << seed_stats.evo
                              << " Evo; " << seed_stats.pose_banned
                              << " PoSe-banned, i.e. PRESENT but INELIGIBLE"
                                 " -> "
                              << (seed_stats.seeded - seed_stats.pose_banned)
                              << " payee-eligible)"
                                 " as-of h=" << as_of << " from dashd `protx"
                                 " list registered true` -> maintainer DMN half"
                                 " ARMED; populated() flips once the header"
                                 " tip syncs\n";
                    if (seed_stats.pose_banned == 0) {
                        // Not fatal — a chain can genuinely have none — but on
                        // mainnet it is the signature of a `valid`-filtered
                        // source, and a valid-filtered seed cannot ever
                        // reinstate a revived masternode. Say so at the seam
                        // rather than letting a later "REINSTATED: 0" be read
                        // as "none were needed".
                        std::cout << "[run] E2c MN-set seed NOTE (" << tag
                                  << "): the seeded set carries ZERO"
                                     " PoSe-banned masternodes. If this is"
                                     " mainnet that is the fingerprint of a"
                                     " `protx list valid`-filtered source: no"
                                     " ProUpServTx revive of a banned-at-seed"
                                     " masternode can be honoured, because"
                                     " there is no entry to revive.\n";
                    }
                } else if (as_of == 0) {
                    std::cout << "[run] E2c MN-set seed SKIPPED (" << tag
                              << ": dashd tip"
                                 " moved during every fetch attempt / height"
                                 " unavailable) -- populated() waits for the"
                                 " special-tx replay path; dashd fallback"
                                 " keeps serving\n";
                } else {
                    std::cout << "[run] E2c MN-set seed EMPTY/ABORTED (" << tag
                              << ": total="
                              << seed_stats.total << " decode_failed="
                              << seed_stats.payout_decode_failed
                              << " malformed=" << seed_stats.malformed
                              << ") -- populated() waits for the special-tx"
                                 " replay path; dashd fallback keeps serving\n";
                }
            } catch (const std::exception& e) {
                std::cout << "[run] E2c MN-set seed FAILED (" << tag
                          << ": protx list RPC: "
                          << e.what() << ") -- populated() waits for the"
                             " special-tx replay path; dashd fallback keeps"
                             " serving\n";
            }
            };
            seed_mn_set_from_rpc("startup");
            // Payee-desync heal (soak-found bad-cb-payee class): after the
            // maintainer wiped a desynced payee queue and demoted to the
            // dashd fallback, re-arm the embedded payee half from the
            // authoritative protx list. Until the re-seed lands, get_work
            // keeps serving the reward-safe fallback.
            mn_reseed_fallback = [seed_mn_set_from_rpc]() {
                seed_mn_set_from_rpc("payee-desync re-seed");
            };
            maintainer->set_on_mn_reseed(mn_reseed_fallback);
        } else if (rpc) {
            // ── --embedded-no-dashd-mn-seed: THE PROOF POSTURE ─────────────
            // A dashd RPC IS configured, but the payee axis is deliberately
            // cut off from it. Nothing else changes: the shadow-compare
            // diagnostic keeps asking dashd for its template so the two can
            // be diffed — which is the entire point. Without this switch a
            // parity run cannot separate "the replay serves correctly" from
            // "dashd seeded the queue and the replay watched": the LAN run on
            // .211 served in 7 minutes off
            //   [run] E2c MN-set seed LOADED (startup): 2971/2971 registered
            //         MNs as-of h=2516893 FROM DASHD `protx list registered
            //         true`
            // and that is NOT a daemonless serve, however daemonless the fold
            // beside it was.
            //
            // The E2d checkpoint bridge is skipped too: this posture exists to
            // leave the ROOT-CHECKED REPLAY FOLD as the only thing that can
            // populate the payee queue. If the fold does not get there, the
            // node does not serve — which is the honest outcome to measure.
            std::cout << "[run] --embedded-no-dashd-mn-seed: the E2c dashd"
                         " `protx list` MN-set seed is DISABLED and the E2d"
                         " checkpoint bridge is NOT armed.\n"
                         "      The PAYEE queue can now be populated by ONE"
                         " thing only: the root-checked replay fold"
                         " (source=replay-fold).\n"
                         "      The dashd RPC stays available to the"
                         " OBSERVE-only shadow-compare, which is what makes"
                         " this a parity measurement rather than a\n"
                         "      daemon-assisted serve. Until the fold"
                         " publishes, the embedded arm will not serve and no"
                         " masternode payee will be guessed.\n";
        } else {
            // ── E2d (#738): PURE DAEMONLESS MN-SET SEED ────────────────────
            // No dashd RPC, so no `protx list`. The set comes from a
            // RELEASE-PINNED CHECKPOINT compiled into this binary, replayed
            // forward to the tip through the SAME block-connect ingest leg 3
            // already uses. This is the last structurally daemon-dependent
            // input on the daemonless path.
            //
            // ⚠ THE CHECKPOINT IS A TRUST ANCHOR — the operator is trusting
            // this release build for the masternode set at the anchor height.
            // Nothing on the DASH P2P network can prove it (the Simplified MN
            // List omits scriptPayout/nLastPaidHeight and neither is committed
            // in merkleRootMNList). Locally verified: the anchor's chain
            // position against our PoW-validated header chain, its SHA-256
            // integrity digest, and every replayed block's real coinbase
            // against the payee our anchored set projects. Full trustless
            // DIP3-height replay stays a later opt-in verify-mode.
            // See src/impl/dash/coin/checkpoints/README.md.
            const char* payload = testnet ? kDashMnCheckpointTestnet
                                          : kDashMnCheckpointMainnet;
            const std::string net_name = testnet ? "testnet" : "mainnet";
            auto ckpt = dash::coin::parse_mn_checkpoint(payload, net_name);

            // ── #91: THE RESUMABLE REPLAY CURSOR ──────────────────────────
            //
            // Wired BEFORE arm(), because arm() is where the persisted record
            // is read. Rooted in the per-instance data dir alongside every
            // other piece of DASH state, so --data-dir isolates it exactly
            // like the header chain, the SML db and the credit pool.
            //
            // Without this the bridge threw away a COMPLETED replay on every
            // process start: "[MN-CKPT] bridge START: replaying
            // h=2513001..2516913 (3913 blocks)" after a restart that had
            // already finished that work. The lane is EVENT-BOUND — it
            // re-drives its window on tip changes, ~2.5 min apart — so that
            // discard cost ~26 of the ~34 minutes of a pure-daemonless cold
            // start, every time.
            //
            // The lane refuses to half-resume: see try_restore()'s R1..R7. A
            // record it cannot tie to THIS build's anchor, to our own header
            // chain at the persisted height, and to a contiguous span from the
            // anchor is discarded and the bridge starts COLD, naming the rule.
            if (!g_mn_bridge_no_cursor) {
                mn_bridge_cursor =
                    std::make_unique<dash::coin::MnBridgeCursorStore>(
                        (core::filesystem::config_path() / net_subdir
                         / "dash_mn_bridge_cursor.dat").string());
                mn_ckpt_lane->set_cursor_store(mn_bridge_cursor.get());
            } else {
                std::cout << "[run] --embedded-mn-bridge-no-cursor: the"
                             " MN-CKPT bridge will NOT persist or resume its"
                             " replay cursor. Every start replays the whole"
                             " window from the pinned anchor — the behaviour"
                             " before task #91. This exists so a cold-vs-warm"
                             " measurement has a control.\n";
            }

            // Fail CLOSED and LOUDLY. A wrong payee is a coinbase the network
            // rejects — direct revenue loss — so an unusable anchor must be
            // impossible to mistake for a working one. arm() latches the lane
            // terminally on a !ok checkpoint; populated() never flips, and
            // get_work keeps routing to the fallback arm.
            mn_ckpt_lane->arm(ckpt);
            if (!ckpt.ok) {
                std::cout << "\n"
                          << "  ============================================\n"
                          << "  E2d MN-set CHECKPOINT REFUSED -- FAIL CLOSED\n"
                          << "  ============================================\n"
                          << "  " << ckpt.error << "\n"
                          << "  The embedded DASH arm will NOT serve templates.\n"
                          << "  No masternode payee will be guessed.\n"
                          << "  Configure a dashd RPC (--coin-rpc-*) or run a\n"
                          << "  release that carries a " << net_name
                          << " masternode-set anchor.\n"
                          << "  ============================================\n\n";
            } else {
                std::cout << "[run] E2d MN-set checkpoint LOADED: "
                          << ckpt.entries.size() << " masternodes as-of h="
                          << ckpt.height << " ("
                          << ckpt.blockhash.GetHex().substr(0, 16) << ")\n"
                          << "      TRUST ANCHOR -- these masternode records are"
                             " asserted by this release build, not derived from"
                             " the chain.\n"
                          << "      provenance: " << ckpt.source << "\n"
                          << "      generated:  " << ckpt.generated << "\n"
                          << "      digest:     " << ckpt.digest << "\n"
                          << "      The anchor's chain position, its integrity"
                             " digest and every replayed block's coinbase ARE"
                             " verified locally;\n"
                          << "      the set contents at h=" << ckpt.height
                          << " are NOT (no consensus commitment exists). See"
                             " src/impl/dash/coin/checkpoints/README.md.\n"
                          << "      bridging forward to the tip (max "
                          << g_mn_bridge_max_blocks
                          << " blocks) before the embedded arm may serve.\n";
            }

            // Bridge seams. Each is REQUIRED: a missing one makes the lane
            // fail closed rather than stall silently (see the null checks in
            // MnCheckpointLane::request_window / publish).
            //
            // Block fetch by height — the same header-chain hash lookup +
            // request_block path the E2b UTXO lane's window refill uses.
            mn_ckpt_lane->set_request_block_fn(
                [cp = coin_p2p.get(), hc = header_chain.get()](uint32_t h) {
                    // #138: report the truth of the wire. BOTH local-death
                    // legs — the header for h not held yet (nothing to ask
                    // by), and request_block()'s block_source()==nullptr (no
                    // route to any peer) — must return false, so the lane's
                    // request ledger never counts a getdata that no peer
                    // heard. Fire-and-forget here is exactly the reseed-tail
                    // wedge: the ledger claims the tip body was requested,
                    // request_window() skips it forever, and the
                    // mn-needs-reseed latch holds the embedded arm down.
                    auto e = hc->get_header_by_height(h);
                    if (!e) return false;
                    // BULK + TAIL both TRACKED. The whole anchor->tip fold now
                    // rides the dashd-style lost-body watchdog
                    // (service_pending_bodies): the initial getdata is spread
                    // round-robin across the handshaked pool
                    // (request_block -> select_block_peer, dashd
                    // FindNextBlocksToDownload), a stalled window is re-requested
                    // from a DIFFERENT peer, and the chronic staller is
                    // disconnected so the pool churns to one that serves the
                    // body. The in-flight bound is dashd's per-peer window x pool
                    // size (effective_pending_cap = MAX_BLOCKS_IN_TRANSIT_PER_PEER
                    // x handshaked peers), so a full kWindow no longer defeats
                    // the tracker. This closes the deep (~9.5k-block) cut cold
                    // fold's single-primary wedge, where every body funnelled at
                    // m_primary and only that peer was re-asked — freezing at the
                    // first window when it churned or rate-limited. Reward-safe:
                    // getdata routing only; the derived MN/quorum/credit-pool
                    // bytes and every publish() hold are unchanged.
                    return cp->request_block_tracked(e->hash);
                });
            mn_ckpt_lane->set_tip_height_fn(
                [hc = header_chain.get()]() { return hc->height(); });
            // DIAGNOSTIC seam: wire byte size of each replayed block, so the
            // progress line can print `fetched=` instead of `fetched=n/a`.
            // Telemetry only — the lane never branches on it.
            mn_ckpt_lane->set_wire_size_fn(
                [](const dash::coin::BlockType& b) -> size_t {
                    return pack(b).size();
                });
            mn_ckpt_lane->set_header_hash_at_fn(
                [hc = header_chain.get()](uint32_t h) -> std::optional<uint256> {
                    auto e = hc->get_header_by_height(h);
                    if (!e) return std::nullopt;
                    return e->hash;
                });
            // SML validity attestation — the ONLY carrier of a post-anchor
            // PoSe ban. dashd applies those from consensus, never as a special
            // tx, so the bridge's block replay is structurally unable to see
            // one: a masternode banned after the anchor height stays eligible
            // in our projection, the coinbase pays somebody else, and the
            // bridge fail-closes forever — the daemonless arm then never
            // publishes a masternode set at all. With this seam the replay may
            // demote a projected payee the SML ATTESTS INVALID, and only onto a
            // candidate whose scriptPayout exactly matches this coinbase.
            // Three-state on purpose: absent-from-SML is nullopt, never "fine".
            // See mn_checkpoint_lane.hpp's residuals note.
            //
            // Same thread as everything else the lane touches: the SML is
            // updated on the mnlistdiff ingest leg and read here from the
            // block-connect / tip-changed callbacks, all on the single
            // io_context thread main_dash runs. No lock is taken or needed.
            mn_ckpt_lane->set_sml_validity_fn(
                [&node_coin_state](const uint256& proTxHash)
                    -> std::optional<bool> {
                    if (!node_coin_state.have_sml()) return std::nullopt;
                    for (const auto& e : node_coin_state.sml().mnList) {
                        if (e.proRegTxHash == proTxHash) return e.isValid;
                    }
                    return std::nullopt;
                });
            // WHOLESALE SML PoSe FOLD seam — the whole list PLUS the height
            // it is current at. The per-hash seam above can only answer a
            // question about a masternode the projection already surfaced,
            // and the walk behind it adjudicates ONE exclusion per height
            // with an exact coinbase script match required at every step.
            // That is proven to work for ISOLATED bans (mainnet 2026-08-02:
            // it succeeded five times during the replay) and proven NOT to
            // work for a BURST — the same chain put THREE masternodes out of
            // `protx list valid` inside 73 blocks (2062 -> 2059 over
            // 2514800..2514873) and the bridge fail-closed. A wholesale fold
            // removes all three in one pass, which is what makes a burst
            // indistinguishable from a single ban.
            //
            // The HEIGHT half is mandatory, not decoration: the lane folds
            // ONLY when its apply cursor equals this height (never earlier —
            // an early fold can silently publish a wrong queue inside a
            // shared-payoutAddress group), and it gates the walk's
            // attestations so a STALE SML cannot license a permanent
            // demotion of a since-revived masternode.
            //
            // Same thread as everything else the lane touches: the SML is
            // updated on the mnlistdiff ingest leg and read here from the
            // block-connect / tip-changed callbacks, all on the single
            // io_context thread main_dash runs. No lock is taken or needed,
            // and the returned pointer never escapes the call.
            // PER-HEIGHT PoSe FOLD seams. The lane asks for the masternode
            // list AS OF the height its replay cursor is standing on, using
            // the SAME getmnlistd primitive quorum_member_source.hpp already
            // uses for historical member sets. This is what makes
            // cursor == H_sml true BY CONSTRUCTION instead of by luck: the tip
            // SML runs ahead of a catching-up replay, so waiting for the two
            // to coincide loses the race at exactly the heights that matter.
            //
            // WIRED AS A PAIR OR NOT AT ALL. The request seam and the reply
            // demux are two halves of one round trip: a lane that can ask but
            // never be answered would PAUSE its replay on the first fold point
            // and never resume. So both are installed inside the same
            // `if (coin_p2p)` — with no coin-P2P client there is no request
            // seam either, and the lane degrades to the additions-only replay
            // plus the per-mismatch walk and says so in status().
            if (coin_p2p) {
                auto* cp = coin_p2p.get();
                mn_ckpt_lane->set_request_snapshot_fn(
                    [cp](const uint256& block_hash) {
                        // Rotate the fold snapshot's getmnlistd across the
                        // eligible pool so a slow/non-serving primary cannot
                        // wedge the anchor->tip fold (dashd rotate-on-stall).
                        cp->send_getmnlistd_rotating(uint256::ZERO, block_hash);
                    });
                // DEMUX (reward-critical): the reply comes back on the SAME
                // mnlistdiff message the tip sync uses. Routed here it is
                // consumed as historical and the LIVE tip SML is never
                // touched; routed to the maintainer it would silently rewrite
                // the tip SML to the replayed (past) height — on the money
                // path. See historical_sml.hpp.
                coin_p2p->add_historical_mnlistdiff_filter(
                    [mnl = mn_ckpt_lane.get()]
                    (const dash::coin::vendor::CSimplifiedMNListDiff& d) {
                        return mnl->on_historical_snapshot(d);
                    });
            }
            // The DIP-4 trust anchor: our own PoW-validated header's merkle
            // root. Without it a snapshot cannot be authenticated and the lane
            // refuses to fold at all.
            mn_ckpt_lane->set_merkle_root_at_fn(
                [hc = header_chain.get()](const uint256& block_hash)
                    -> std::optional<uint256> {
                    // The SAME lookup QuorumMemberSource's R3 anchor uses.
                    if (auto e = hc->get_header(block_hash))
                        return e->header.m_merkle_root;
                    return std::nullopt;
                });
            mn_ckpt_lane->set_sml_snapshot_fn(
                [&node_coin_state, m = maintainer.get()]()
                    -> dash::coin::MnCheckpointLane::SmlSnapshot {
                    dash::coin::MnCheckpointLane::SmlSnapshot snap;
                    if (!node_coin_state.have_sml()) return snap;
                    snap.list   = &node_coin_state.sml();
                    // F2: report the height ONLY while it is paired with the
                    // list actually held. A diff can advance the list without
                    // advancing the height (unparseable cbTx is not a
                    // rejection), and folding a list that describes H2 at
                    // cursor H1 is the EARLY case. Unpaired -> no height, which
                    // both suppresses the fold and downgrades every walk
                    // attestation to "no opinion".
                    snap.height = (m && m->sml_height_paired())
                                      ? m->sml_current_height() : 0;
                    return snap;
                });

            // Publish through the EXACT leg-4 event the E2c RPC seed uses, so
            // CoinStateMaintainer::on_mn_list_update takes the bridged set as
            // an ordinary authoritative resync — snapshot fence set to the
            // bridged height, apply cursor armed for the next live block.
            mn_ckpt_lane->set_publish_fn(
                [&coin_state](std::vector<std::pair<uint256,
                                                    dash::coin::MNState>> set,
                              uint32_t as_of) {
                    dash::interfaces::MnListUpdate up;
                    up.mnstates     = std::move(set);
                    up.as_of_height = as_of;
                    // NAME the lane: compiled-in trust anchor replayed
                    // forward — daemonless, but anchored on this build's
                    // assertion rather than on a per-block consensus check.
                    up.source       = dash::coin::replay::kPayeeSourceMnCkpt;
                    coin_state.mn_list_update.happened(up);
                    std::cout << "[run] E2d MN-set BRIDGE COMPLETE: "
                              << up.mnstates.size() << " masternodes as-of h="
                              << as_of << " -> maintainer DMN half ARMED;"
                                 " populated() flips once the header tip"
                                 " syncs\n";
                });

            // Bridge driver leg: every connected block advances the private
            // replay machine. Subscribed to the SAME Node::block_connected
            // event as leg 3 (and as the E2b UTXO lane) — the lane only folds
            // the exact next height it is waiting for, so live tip blocks
            // arriving mid-bridge are ignored rather than folded onto a stale
            // cursor.
            //
            // REACHABILITY (the #878/#881 caller-side-lock class): this fires
            // from the live-feed bridge's full_block handler on the io thread
            // with NO tracker/maintainer lock held; the lane itself takes no
            // lock. The pump() call added to the tip-changed callback below is
            // likewise dispatched by HeaderChain with m_mutex RELEASED, so the
            // lane's self-locking header-chain reads are reachable, not dead.
            coin_feed_subs.push_back(
                coin_state.block_connected.subscribe(
                    [mnl = mn_ckpt_lane.get()]
                    (const dash::interfaces::BlockConnected& bc) {
                        mnl->on_block_connected(bc.block, bc.height);
                    }));

            // ── THE RE-SEED SEAM, now WIRED (was the KNOWN GAP) ───────────
            // CoinStateMaintainer::on_block_connected, on a payee DESYNC or an
            // apply GAP, wipes the payee set, latches m_mn_needs_reseed,
            // demotes to the dashd fallback and calls m_on_mn_reseed(). The RPC
            // branch above answers it with a fresh `protx list registered`. This
            // branch used to answer it with NOTHING — the ask went into a void.
            //
            // MEASURED, contabo daemonless soak: the ask fired THREE times in
            // one run (h=2513168, 2513261, 2515266). The last is ABOVE the
            // bridge's own failure height, i.e. it fires on LIVE TIP ADVANCES,
            // independently of any bridge replay. Nothing answered, so the
            // payee set stayed wiped for the rest of the run and only a restart
            // recovered it.
            //
            // The answer is a bridge RE-ARM from the SAME release-pinned
            // anchor. NOT a newer one: an anchor cut AFTER a divergence began
            // replays cleanly over a shorter window and re-arms a queue that is
            // already wrong, which mints a coinbase the network rejects.
            // MnCheckpointLane::rearm() refuses a newer anchor terminally, caps
            // the re-arms, backs off in blocks between them, and names every
            // outcome. See its header block for the policy and for what a
            // genuine oldest-first LADDER would still need (a multi-anchor
            // store that does not exist in this build).
            //
            // ORDERING IS SAFE: m_on_mn_reseed fires AFTER the maintainer has
            // wiped the set, latched and demoted — so the embedded arm is
            // already down and stays down until this bridge PUBLISHES through
            // the leg-4 event, which is the only thing that clears the latch.
            // Same io thread, no lock held (the lane takes none). The anchor is
            // captured BY VALUE rather than re-parsed per ask: parsing is not
            // free and a deferred ask must stay cheap.
            mn_reseed_fallback =
                [mnl = mn_ckpt_lane.get(), anchor = ckpt]() {
                    using Lane    = dash::coin::MnCheckpointLane;
                    const auto out = mnl->rearm(
                        anchor,
                        "CoinStateMaintainer wiped a desynced/gapped payee"
                        " queue and asked for an authoritative re-seed");
                    std::cout << "[run] E2d MN-set RE-SEED ask -> bridge re-arm "
                              << Lane::rearm_outcome_name(out)
                              << " (" << mnl->rearms() << "/"
                              << mnl->rearm_cap() << " re-arms used, "
                              << mnl->rearm_asks() << " asks) — "
                              << mnl->last_rearm_reason() << "\n";
                    if (out != Lane::RearmOutcome::Armed) {
                        std::cout << "[run] the embedded DASH arm stays DEMOTED;"
                                     " templates keep routing to the dashd"
                                     " fallback arm (if configured). No"
                                     " masternode payee will be guessed.\n";
                        return;
                    }
                    // Drive it immediately: the header chain is already well
                    // past the anchor, so the replay starts on this call rather
                    // than waiting for the next tip change.
                    mnl->pump();
                };
            maintainer->set_on_mn_reseed(mn_reseed_fallback);

            // ── DASHD-CUT ARM: the MN DIFF/SNAPSHOT STORE on the COLD bridge ──
            // The store block below (dashd evodb dmn_D4/dmn_S3 port) was DORMANT
            // on the daemonless cold flags: its only construction site was gated
            // under --replay-bulk → --replay-fold-prestate. LIFT it onto the
            // cold MN-CKPT bridge arm so the ban-state probe / on-demand fold can
            // repair from a 0-RTT root+payee-verified store instead of a capped
            // network round trip (see begin_revive_probe / the payee-desync
            // store re-apply in mn_checkpoint_lane.hpp).
            //
            // The cold bridge folds an MnStateMachine (payee projection); the
            // store WRITER is bound to a DmlFoldEngine (full ReplayMNState). So
            // we stand up a PARALLEL DmlFoldEngine seeded at the SAME anchor the
            // bridge stands on, feed it every block the bridge folds CLEANLY
            // (set_on_block_applied), and sink MnDiffWriter::on_folded off THAT
            // engine's own root-checked commit.
            //
            // REWARD-SAFETY IS BY CONSTRUCTION and does NOT depend on the seed
            // being complete: MnDiffStore::reconstruct() REFUSES any row that
            // does not re-hash to the block's committed merkleRootMNList
            // (mn_diff_store.hpp:849-857). The trusted-anchor checkpoint carries
            // the DIP-3 PAYEE fields but NOT the SML fields the root commits
            // (confirmedHash, netInfo) — which a checkpoint-only seed cannot
            // supply. So rather than seed from the checkpoint alone (which would
            // poison at anchor+1), the seed is DEFERRED to the lane's own anchor
            // fold: it fetches getmnlistd(base=ZERO, target=anchor_hash) and
            // DIP-4-authenticates the FULL Simplified MN List against the anchor
            // block's committed merkleRootMNList, and set_on_anchor_snapshot()
            // merges those root-committing fields onto the checkpoint's forward
            // facets. The merged seed is SELF-CHECKED against the committed root
            // before forward folds arm; a seed that fails leaves the engine
            // UNSEEDED, the store empty, and the SOURCE callers on their unchanged
            // network path — never a wrong row, never a bad mint. When the seed
            // matches, the store COVERS heights and the ban-state probe /
            // on-demand fold source 0-RTT/uncapped from it.
            if (mn_ckpt_lane && header_chain && ckpt.ok
                && !mn_diff_store
                // UAF FIX (yield to the deep replay-fold): the cold MN-CKPT
                // store-bridge and the W5 replay-fold arm (main_dash.cpp ~7288)
                // both drive the SINGLE mn_diff_store/mn_diff_writer, but they
                // are MUTUALLY EXCLUSIVE by design -- this block's own header
                // comment names it "the COLD MN-CKPT bridge path (no
                // --replay-bulk / --replay-fold-prestate)". The guard never
                // actually enforced that: this arm runs FIRST (cold bridge),
                // creates store/writer A and installs set_on_anchor_snapshot()
                // whose lambda captures raw w=mn_diff_writer.get(); the later W5
                // make_unique then FREES writer A behind that lambda's back, and
                // the historical-snapshot callback dereferences the freed writer
                // -> MnDiffWriter::arm()->save_snapshot() UAF (SIGSEGV/SIGBUS).
                // When --replay-fold-prestate is set the deep replay owns the
                // store; the cold bridge YIELDS. Normal cold start (no prestate)
                // is UNCHANGED -- this predicate is true there.
                && g_replay_fold_prestate.empty()) {
                namespace rp = dash::coin::replay;
                mn_diff_store = std::make_unique<rp::MnDiffStore>(
                    (core::filesystem::config_path() / net_subdir
                        / "dash_mn_diff_db").string());
                if (!mn_diff_store->open()) {
                    LOG_WARNING << "[MN-DIFF-DB] cold-bridge open failed — diff"
                                   " store DISABLED (gap repair unavailable;"
                                   " probe/fold caps unchanged)";
                    mn_diff_store.reset();
                } else {
                    auto diff_hlookup =
                        [hc = header_chain.get()](const uint256& h)
                            -> std::optional<std::pair<uint32_t, uint256>> {
                        if (!hc) return std::nullopt;
                        auto e = hc->get_header(h);
                        if (!e) return std::nullopt;
                        return std::make_pair(e->height, e->prev_hash);
                    };
                    std::string vnote;
                    mn_diff_store->startup_verify(diff_hlookup, vnote);
                    if (!vnote.empty())
                        LOG_INFO << "[MN-DIFF-DB] cold-bridge startup verify: "
                                 << vnote;

                    // ── FULL-STATE ANCHOR SEED (dashd-parity, option A) ──────
                    // Stand up the parallel DmlFoldEngine here but DEFER its seed
                    // to the lane's own anchor fold. The payee-only compiled
                    // checkpoint omits the two fields the anchor merkleRootMNList
                    // commits to (confirmedHash, netInfo); a checkpoint-only seed
                    // therefore cannot reproduce the anchor+1 root and poisons at
                    // the first fold. set_on_anchor_snapshot() below receives the
                    // DIP-4-authenticated FULL SML the lane already fetches for its
                    // anchor fold, MERGES its root-committing fields onto the
                    // checkpoint's forward-fold facets, seeds, and SELF-CHECKS the
                    // merged state against the anchor's committed root BEFORE arming
                    // forward folds. A seed that fails the self-check leaves the
                    // engine UNSEEDED -> store never populates -> callers fall
                    // through unchanged (reward-safe: a wrong seed can never mint).
                    dash::coin::replay::FoldConfig fcfg;
                    fcfg.enabled = true;
                    mn_bridge_fold_engine =
                        std::make_unique<rp::DmlFoldEngine>(fcfg);
                    mn_diff_writer = std::make_unique<rp::MnDiffWriter>(
                        *mn_diff_store, *mn_bridge_fold_engine);

                    // ── RESOLVER WIRING (the fix) ────────────────────────
                    // The parallel store engine, like the main replay-fold
                    // path, needs the W4 quorum-member resolver or its fold
                    // fails closed at the first punishing qfcommit (llmqType=5
                    // @ h=2513130, only ~130 past the anchor): "no quorum-
                    // member resolver is installed -- PoSe punishes cannot be
                    // folded, failing closed". That cap is why the store
                    // covered only ~130 heights and the bridge fell back to the
                    // capped network getmnlistd probe (payee-desync).
                    //
                    // Mirror the main-path --replay-fold-quorums seam: a SECOND
                    // QuorumReplayEngine seeded at the SAME full-state anchor and
                    // a SECOND ReplayQuorumBridge whose ctor installs
                    // set_members_fn onto mn_bridge_fold_engine. The engine
                    // self-DERIVES rotated + non-rotated member sets from the
                    // SAME replayed blocks the store folds (dashd
                    // CalcQuorumMembers / GetAllQuorumMembers analog),
                    // self-checked vs each block's committed merkleRootQuorums --
                    // no qrinfo/P2P dependency. The fold then applies dashd
                    // HandleQuorumCommitment PoSe-punishes (already ported in
                    // replay_fold_engine.hpp) so the folded list re-hashes to the
                    // committed merkleRootMNList PAST the qfcommit and the store
                    // COVERS heights to tip. A WRONG member set -> root mismatch
                    // -> the writer's own root self-check REFUSES the row -> store
                    // stays empty -> callers fall through to the network path
                    // (reward-safe by construction).
                    {
                        namespace rq = dash::coin::replay;
                        rq::QuorumReplayConfig qcfg;
                        qcfg.enabled = true;
                        qcfg.network = testnet
                            ? dash::coin::LlmqNetwork::Testnet
                            : dash::coin::LlmqNetwork::Mainnet;
                        if (testnet) qcfg.v20_floor = 905'100u;
                        mn_bridge_quorum_engine =
                            std::make_unique<rq::QuorumReplayEngine>(qcfg);
                        mn_bridge_quorum_engine->seed_cursor(
                            ckpt.height, ckpt.blockhash);
                        rq::QuorumBridgeConfig bcfg;
                        bcfg.network = qcfg.network;
                        mn_bridge_quorum_bridge =
                            std::make_unique<rq::ReplayQuorumBridge>(
                                *mn_bridge_fold_engine,
                                *mn_bridge_quorum_engine, bcfg);
                        // Pre-anchor height->hash from the PoW-verified header
                        // chain: a commitment mined just after the anchor whose
                        // quorum BASE predates it still resolves instead of
                        // failing the lane on an unknown base (mirrors the main
                        // path's back = 3*576 + 64 window).
                        size_t qseeded = 0;
                        const uint32_t qback = 3u * 576u + 64u;
                        for (uint32_t hh = (ckpt.height > qback
                                                ? ckpt.height - qback : 1);
                             hh < ckpt.height; ++hh) {
                            auto he = header_chain->get_header_by_height(hh);
                            if (!he) continue;
                            mn_bridge_quorum_bridge->seed_block_hash(hh, he->hash);
                            ++qseeded;
                        }
                        LOG_INFO << "[MN-DIFF-DB] store-engine quorum resolver"
                                    " WIRED: second QuorumReplayEngine seeded at"
                                    " anchor h=" << ckpt.height
                                 << " (" << qseeded << " pre-anchor header"
                                    " hashes); set_members_fn installed on the"
                                    " parallel DML engine -- prime_at_anchor"
                                    " deferred to the anchor snapshot seed.";
                    }
                    mn_ckpt_lane->set_on_anchor_snapshot(
                        [eng = mn_bridge_fold_engine.get(),
                         w   = mn_diff_writer.get(),
                         qbr = mn_bridge_quorum_bridge.get(),
                         anchor = ckpt, net = net_name](
                            const dash::coin::vendor::CSimplifiedMNList& asml,
                            uint32_t /*anchor_h*/) {
                            if (eng->size() != 0) return;   // already seeded
                            // The DIP-4-authenticated anchor SML is the AUTHORITATIVE
                            // source for EVERY field the committed merkleRootMNList
                            // commits to (nVersion, confirmedHash, netInfo,
                            // pubKeyOperator, keyIDVoting, isValid, nType, platform
                            // HTTP port + node id). The payee-only checkpoint diverges
                            // from the committed list in MORE than confirmedHash+
                            // netInfo (proven live: a confirmedHash+netInfo-only merge
                            // still missed the anchor root), so iterate the SML and
                            // take those root fields from it -- the seeded set then IS
                            // the anchor set and the root reproduces BY CONSTRUCTION.
                            // The FORWARD-FOLD facets the SML does not carry
                            // (collateralOutpoint, nRegisteredHeight, nLastPaidHeight,
                            // nConsecutivePayments, nPoSeRevivedHeight, nOperatorReward,
                            // keyIDOwner, scriptPayout/scriptOperatorPayout,
                            // platformP2PPort, the ban HEIGHT magnitude) come from the
                            // compiled checkpoint when it holds the MN.
                            std::map<uint256, const dash::coin::MNState*> cp;
                            for (const auto& [protx, mn] : anchor.entries)
                                cp[protx] = &mn;
                            std::vector<std::pair<uint256, rp::ReplayMNState>> seed;
                            seed.reserve(asml.mnList.size());
                            uint64_t trc = 0;
                            size_t with_facets = 0, without_facets = 0;
                            for (const auto& e : asml.mnList) {
                                rp::ReplayMNState st;
                                // ROOT-COMMITTING fields -- SML authoritative.
                                st.nVersion         = e.nVersion;
                                st.nType            = e.nType;
                                st.pubKeyOperator   = e.pubKeyOperator;
                                st.keyIDVoting      = e.keyIDVoting;
                                st.netInfo.ip       = e.netAddress;
                                st.netInfo.port_be  = e.netPort;
                                st.platformHTTPPort = e.platformHTTPPort;
                                st.platformNodeID   = e.platformNodeID;
                                if (!e.confirmedHash.IsNull())
                                    st.UpdateConfirmedHash(e.proRegTxHash,
                                                           e.confirmedHash);
                                st.internalId       = trc++;   // ordering only; not root
                                // FORWARD-FOLD facets -- checkpoint when present.
                                auto cit = cp.find(e.proRegTxHash);
                                if (cit != cp.end()) {
                                    const auto& mn = *cit->second;
                                    st.collateralOutpoint   = mn.collateralOutpoint;
                                    st.nOperatorReward      = mn.nOperatorReward;
                                    st.nRegisteredHeight    = static_cast<int32_t>(mn.nRegisteredHeight);
                                    st.nLastPaidHeight      = static_cast<int32_t>(mn.nLastPaidHeight);
                                    st.nConsecutivePayments = static_cast<int32_t>(mn.nConsecutivePayments);
                                    st.nPoSeRevivedHeight   = mn.nPoSeRevivedHeight == 0
                                        ? rp::ReplayMNState::NEVER
                                        : static_cast<int32_t>(mn.nPoSeRevivedHeight);
                                    st.nRevocationReason    = mn.nRevocationReason;
                                    st.keyIDOwner           = mn.keyIDOwner;
                                    st.scriptPayout         = mn.scriptPayout;
                                    st.scriptOperatorPayout = mn.scriptOperatorPayout;
                                    st.platformP2PPort      = mn.platformP2PPort;
                                    ++with_facets;
                                } else {
                                    ++without_facets;
                                }
                                // BAN STATE: the SML isValid boolean is the root truth
                                // (isValid == !IsBanned()); reconcile the ban HEIGHT so
                                // IsBanned() matches it -- the checkpoint height when it
                                // agrees, else a sentinel at the anchor.
                                if (e.isValid) {
                                    st.nPoSeBanHeight = rp::ReplayMNState::NEVER;
                                } else {
                                    int32_t cpban = rp::ReplayMNState::NEVER;
                                    if (cit != cp.end() && cit->second->nPoSeBanHeight != 0)
                                        cpban = static_cast<int32_t>(cit->second->nPoSeBanHeight);
                                    st.nPoSeBanHeight = (cpban != rp::ReplayMNState::NEVER)
                                        ? cpban
                                        : static_cast<int32_t>(anchor.height);
                                }
                                seed.emplace_back(e.proRegTxHash, std::move(st));
                            }
                            eng->seed(std::move(seed), trc, anchor.height,
                                      anchor.blockhash, net);
                            // SEED SELF-CHECK: the merged state MUST reproduce the
                            // anchor's own committed merkleRootMNList (== the DIP-4
                            // authenticated SML's root). If not, UNSEED so the store
                            // never populates and every caller falls through.
                            const uint256 got  = eng->compute_sml_root();
                            const uint256 want = asml.CalcMerkleRoot();
                            if (got != want) {
                                LOG_ERROR
                                    << "[MN-DIFF-DB] FULL-STATE anchor seed SELF-CHECK"
                                       " FAILED at h=" << anchor.height
                                    << " (with_facets=" << with_facets
                                    << " without_facets=" << without_facets
                                    << "): computed root "
                                    << got.GetHex().substr(0, 16) << " != committed "
                                    << want.GetHex().substr(0, 16)
                                    << " -- engine left UNSEEDED, store stays empty,"
                                       " callers fall through to the network path"
                                       " unchanged (reward-safe).";
                                eng->seed({}, 0, 0, uint256::ZERO, net);   // UNSEED
                                return;
                            }
                            if (!w->arm()) {
                                LOG_WARNING
                                    << "[MN-DIFF-DB] writer arm FAILED after a"
                                       " root-matched full-state seed -- store"
                                       " inert, callers unchanged.";
                                return;
                            }
                            // Resolver lane: retain the anchor MN list in the
                            // quorum bridge's window now that the fold engine is
                            // seeded (m_dml.height()==anchor), so rotated member
                            // derivation has its base list. Mirrors the main path.
                            if (qbr) qbr->prime_at_anchor();
                            LOG_INFO
                                << "[MN-DIFF-DB] FULL-STATE anchor seed OK: "
                                << with_facets << " MNs seeded root-fields from the"
                                   " DIP-4 anchor SML (" << without_facets
                                << " without a checkpoint facet); reproduces the"
                                   " anchor's committed"
                                   " merkleRootMNList "
                                << want.GetHex().substr(0, 16)
                                << " -- the parallel DML engine now folds forward"
                                   " WITHOUT poisoning at anchor+1; the store will"
                                   " COVER heights and the ban-state probe /"
                                   " on-demand fold source 0-RTT/uncapped from it.";
                        });

                    // ── DIP-24 ROTATED-QUORUM STRADDLE BOOTSTRAP (getqrinfo) ─────
                    // The store engine is seeded at the anchor with ZERO
                    // pre-anchor quarter snapshots (only pre-anchor header
                    // hashes, above). The FIRST rotated (DIP-24, llmqType=5)
                    // cycle mined AFTER the anchor has a base B0 whose three
                    // quarter predecessors (B0-C/2C/3C) all sit BELOW the
                    // anchor, so the engine's self_contained_from is beyond it
                    // and it cannot self-derive that cycle's member set from
                    // the replayed post-anchor stream alone. Its first punishing
                    // qfcommit then hits fold_qfcommit with "resolver has no
                    // member set", the parallel fold fails closed only ~a
                    // window past the anchor, the store caps, and the payee lane
                    // falls to the capped network probe (the #149-class payee
                    // desync). FIX (dashd DIP-24 CGetQuorumRotationInfo /
                    // BuildQuorumSnapshot, the companion to the #1261 full-SML
                    // seed): fetch getqrinfo(B0) once at cold arm, DIP-4/merkle
                    // authenticate the returned quarter snapshots + work lists
                    // against the committed roots, and seed them so cycle B0 is
                    // derivable. A WRONG snapshot -> wrong members -> folded root
                    // mismatch -> the writer's own root self-check REFUSES the
                    // row -> store empty -> callers fall through (reward-safe by
                    // construction; never a bad mint).
                    struct StoreStraddleSeed {
                        bool     armed{false};
                        bool     sent{false};
                        bool     landed{false};
                        bool     exhausted{false};
                        uint8_t  llmq_type{5};
                        uint32_t C{0};
                        uint32_t cycle_base{0};     // B0 = first rotated cycle base > anchor
                        uint32_t first_need_h{0};   // hold straddle blocks at/after this height
                        uint32_t last_send_h{0};
                        uint256  cycle_base_hash;
                        std::vector<std::pair<uint32_t, dash::coin::BlockType>> hold;
                        // Pre-anchor header backfill (cold fast-start): leg (b)
                        // of the getqrinfo snapshot auth needs the FULL headers
                        // of the three rotated work blocks, all BELOW the anchor
                        // and absent from the lone-anchor cold chain. One-shot
                        // backward getheaders installs the span DOWN from the
                        // trusted anchor before the seed can authenticate.
                        bool     backfill_sent{false};
                        uint256  anchor_hash;      // trusted downward-link root
                        uint32_t anchor_height{0};
                    };
                    auto sseed = std::make_shared<StoreStraddleSeed>();
                    {
                        const uint32_t anchor_h = ckpt.height;
                        for (const auto& pv : dash::coin::enabled_llmqs(
                                 testnet ? dash::coin::LlmqNetwork::Testnet
                                         : dash::coin::LlmqNetwork::Mainnet)) {
                            if (!pv.use_rotation || pv.dkg_interval == 0) continue;
                            sseed->llmq_type   = pv.type;
                            sseed->C           = pv.dkg_interval;
                            sseed->cycle_base  = ((anchor_h / pv.dkg_interval) + 1u)
                                                 * pv.dkg_interval;
                            // Hold from the cycle base itself (conservative): the
                            // engine derives cycle B0's members no later than the
                            // block that carries B0's first punishing qfcommit, and
                            // no earlier than observing B0; gating at the base is
                            // correct for both and costs at most a few dozen buffered
                            // blocks in the rare case the reply is slow.
                            sseed->first_need_h = sseed->cycle_base;
                            sseed->anchor_hash  = ckpt.blockhash;
                            sseed->anchor_height= anchor_h;
                            sseed->armed        = true;
                            break;   // one rotated type on mainnet (type 5)
                        }
                        if (sseed->armed)
                            LOG_INFO << "[MN-DIFF-DB] store-engine rotated-quorum"
                                        " bootstrap ARMED: getqrinfo(cycle_base h="
                                     << sseed->cycle_base << ", type="
                                     << int(sseed->llmq_type) << ", C=" << sseed->C
                                     << ") will seed the pre-anchor quarter"
                                        " snapshots+work-lists for the cycle that"
                                        " STRADDLES anchor h=" << anchor_h
                                     << " (its H-C/2C/3C predecessors are all below"
                                        " the anchor; the store engine cannot"
                                        " self-derive them).";
                    }

                    // ── PRE-ANCHOR HEADER BACKFILL INSTALLER ─────────────────
                    // The one-shot backward getheaders issued by the qrinfo
                    // consumer below (when the work-block headers leg (b) needs
                    // are absent at cold fast-start) returns a `headers` batch
                    // spanning [h-4C .. anchor]. It arrives on the new_headers
                    // event, where the forward add_headers path orphan-rejects
                    // every pre-anchor header (parent not held). This installer
                    // instead links them DOWN from the trusted anchor via
                    // HeaderChain::install_preanchor_span (X11 prev-hash chain +
                    // PoW, reward-safe), then re-drives getqrinfo so leg (b)
                    // authenticates promptly. Self-guarding: it no-ops unless the
                    // backfill was issued and not yet landed, and a batch that
                    // does not reach the anchor installs nothing.
                    if (sseed->armed) {
                        coin_feed_subs.push_back(
                            coin_state.new_headers.subscribe(
                                [sseed, hc = header_chain.get(),
                                 cp = coin_p2p.get()](
                                    const std::vector<dash::coin::BlockHeaderType>&
                                        batch) {
                                    if (!sseed->armed || sseed->landed) return;
                                    if (!sseed->backfill_sent) return;
                                    if (batch.empty()) return;
                                    const size_t n = hc->install_preanchor_span(
                                        sseed->anchor_hash, batch);
                                    if (n == 0) return;
                                    // Re-drive getqrinfo now that the pre-anchor
                                    // work-block headers are held → leg (b)
                                    // authenticates on the next reply.
                                    if (cp && !sseed->cycle_base_hash.IsNull())
                                        cp->send_getqrinfo(
                                            {}, sseed->cycle_base_hash,
                                            /*extra=*/true);
                                }));
                    }

                    // The shared per-block fold drive. Both the live feed and the
                    // held-block drain call THIS, so a block folded from the hold
                    // buffer takes the exact same observe/fold/after_fold/writer
                    // path as a live one.
                    auto feed = std::make_shared<
                        std::function<void(const dash::coin::BlockType&, uint32_t)>>();
                    *feed = [eng = mn_bridge_fold_engine.get(),
                             w   = mn_diff_writer.get(),
                             qbr = mn_bridge_quorum_bridge.get(),
                             logged = std::make_shared<bool>(false)](
                                const dash::coin::BlockType& blk, uint32_t h) {
                        if (eng->poisoned()) return;
                        if (eng->size() == 0) return;   // seed deferred to the anchor fold
                        const uint256 bh = rp::DmlFoldEngine::block_header_hash(blk);
                        if (qbr) qbr->observe(h, bh, blk);
                        const auto fr = eng->fold_block(blk, h);
                        if (qbr) qbr->after_fold(h);
                        if (fr.ok) { w->on_folded(h, bh, blk, fr); return; }
                        if (!*logged) {
                            *logged = true;
                            LOG_WARNING
                                << "[MN-DIFF-DB] cold-bridge parallel fold could"
                                   " not extend the store at h=" << h << " ("
                                << fr.error << "). The store keeps only heights up"
                                   " to here; every height above REPAIR-REFUSES and"
                                   " the probe/on-demand paths fall through to the"
                                   " network unchanged (reward-safe).";
                        }
                    };

                    // The qrinfo reply consumer: authenticate the straddle-cycle
                    // snapshots + work lists and seed them into the store engine.
                    // Additive (coexists with the serve-path consumer at
                    // main_dash.cpp:4446); it filters by the reply's H so only OUR
                    // getqrinfo(B0) reply is consumed.
                    if (coin_p2p && sseed->armed) {
                        coin_p2p->add_qrinfo_consumer(
                            [sseed, feed,
                             qbr = mn_bridge_quorum_bridge.get(),
                             hc  = header_chain.get(),
                             cp  = coin_p2p.get(),
                             anchor_h = ckpt.height, net = net_name](
                                const dash::coin::vendor::CQuorumRotationInfo& info) {
                                if (!sseed->armed || sseed->landed) return;
                                namespace v  = dash::coin::vendor;
                                namespace rq = dash::coin::replay;
                                // Bind: OUR reply's mnListDiffH sits at B0-8.
                                v::CCbTx hcb;
                                if (info.mnListDiffH.cbTx.type != 5
                                    || !v::parse_cbtx(
                                           info.mnListDiffH.cbTx.extra_payload, hcb)
                                    || hcb.nHeight < 0) return;
                                if (static_cast<uint32_t>(hcb.nHeight)
                                    != sseed->cycle_base - 8u) return;   // not ours

                                // ── PRE-ANCHOR HEADER BACKFILL GATE ──────────
                                // leg (b) below needs the FULL headers of the
                                // three rotated work blocks (h-C/2C/3C), all
                                // BELOW the fast-start anchor. At cold start the
                                // header chain holds only the anchor, so the auth
                                // fails closed 'block header not held'. Fetch the
                                // pre-anchor span (once) and install it DOWN from
                                // the trusted anchor BEFORE authenticating.
                                {
                                    const uint256 wh_c  =
                                        info.mnListDiffAtHMinusC.blockHash;
                                    const uint256 wh_2c =
                                        info.mnListDiffAtHMinus2C.blockHash;
                                    const uint256 wh_3c =
                                        info.mnListDiffAtHMinus3C.blockHash;
                                    if (!hc->has_header(wh_c)
                                        || !hc->has_header(wh_2c)
                                        || !hc->has_header(wh_3c)) {
                                        // getheaders replies START at locator+1,
                                        // so to INCLUDE the deepest work block
                                        // (h-3C) the locator is seeded one rotated
                                        // cycle DEEPER — the h-4C block from the
                                        // extraShare leg. That hash is used ONLY
                                        // as a locator; it is never trusted (a bad
                                        // one yields no downward linkage from the
                                        // anchor → zero installs → fail closed).
                                        if (!sseed->backfill_sent && cp
                                            && info.extraShare
                                            && info.mnListDiffAtHMinus4C) {
                                            const uint256 loc =
                                                info.mnListDiffAtHMinus4C->blockHash;
                                            const std::string peer =
                                                cp->primary_peer_key();
                                            if (!peer.empty()
                                                && cp->send_getheaders_to(
                                                       peer, 70230, {loc},
                                                       sseed->anchor_hash)) {
                                                sseed->backfill_sent = true;
                                                LOG_INFO << "[MN-DIFF-DB] pre-anchor"
                                                    " header BACKFILL issued:"
                                                    " getheaders locator=h-4C "
                                                    << loc.GetHex().substr(0, 16)
                                                    << " stop=anchor "
                                                    << sseed->anchor_hash.GetHex()
                                                           .substr(0, 16)
                                                    << " — installs the h-C/2C/3C"
                                                       " work-block headers leg (b)"
                                                       " needs; getqrinfo retries"
                                                       " once the span lands.";
                                            }
                                        } else if (!info.extraShare
                                                   || !info.mnListDiffAtHMinus4C) {
                                            LOG_WARNING << "[MN-DIFF-DB] getqrinfo"
                                                " reply lacks the h-4C extraShare"
                                                " leg — cannot seed a locator below"
                                                " the deepest work block; rotated"
                                                " bootstrap fails closed"
                                                " (reward-safe), retry.";
                                        }
                                        return;   // headers absent → fail closed
                                    }
                                }
                                dash::coin::MerkleRootOfHashFn mroot =
                                    [hc](const uint256& b)
                                        -> std::optional<uint256> {
                                        if (auto e = hc->get_header(b))
                                            return e->header.m_merkle_root;
                                        return std::nullopt;
                                    };
                                const v::CSimplifiedMNListDiff* diffs[3] = {
                                    &info.mnListDiffAtHMinusC,
                                    &info.mnListDiffAtHMinus2C,
                                    &info.mnListDiffAtHMinus3C };
                                const v::CQuorumSnapshot* snaps[3] = {
                                    &info.quorumSnapshotAtHMinusC,
                                    &info.quorumSnapshotAtHMinus2C,
                                    &info.quorumSnapshotAtHMinus3C };
                                rq::QSnapshotSeed qs;  qs.network = net;
                                rq::WorkListSeed  wl;  wl.network = net;
                                wl.llmq_type  = sseed->llmq_type;
                                wl.cycle_base = sseed->cycle_base;
                                wl.interval   = sseed->C;
                                for (size_t i = 0; i < 3; ++i) {
                                    const uint32_t cyc = sseed->cycle_base
                                        - static_cast<uint32_t>(i + 1) * sseed->C;
                                    const uint32_t work_h = cyc - 8u;
                                    // A qrinfo cycle diff is a FULL list (applied
                                    // onto empty); a delete means it is not.
                                    if (!diffs[i]->deletedMNs.empty()) {
                                        LOG_WARNING << "[MN-DIFF-DB] getqrinfo cycle"
                                                       " diff " << i << " is not a"
                                                       " full list (deletes) — rotated"
                                                       " bootstrap fails closed, retry.";
                                        return;
                                    }
                                    v::CCbTx cbtx;
                                    auto sml = dash::coin::authenticate_historical_snapshot(
                                        *diffs[i], work_h, mroot, cbtx, "MN-DIFF-DB-QR");
                                    if (!sml) {
                                        LOG_WARNING << "[MN-DIFF-DB] getqrinfo cycle"
                                                       " diff " << i << " DIP-4 auth"
                                                       " FAILED at work h=" << work_h
                                                    << " — rotated bootstrap fails"
                                                       " closed, retry.";
                                        return;
                                    }
                                    rq::QSnapshotSeedEntry se;
                                    se.llmq_type  = sseed->llmq_type;
                                    se.cycle_base = cyc;
                                    se.snapshot   = *snaps[i];
                                    qs.entries.push_back(std::move(se));
                                    rq::WorkListSeedEntry we;
                                    we.work_height = work_h;
                                    we.cycle_base  = cyc;
                                    we.block_hash  = diffs[i]->blockHash;
                                    if (cbtx.nVersion >= v::CCbTx::VERSION_CLSIG_AND_BALANCE
                                        && cbtx.has_best_cl_signature()) {
                                        we.has_cl = true;
                                        std::memcpy(we.cl_sig.data(),
                                                    cbtx.bestCLSignature.data(),
                                                    we.cl_sig.size());
                                    }
                                    we.entries.reserve(sml->mnList.size());
                                    for (const auto& e : sml->mnList) {
                                        rq::QuorumMnEntry qe;
                                        qe.proTxHash      = e.proRegTxHash;
                                        qe.confirmedHash  = e.confirmedHash;
                                        qe.is_valid       = e.isValid;
                                        qe.n_type         = e.nType;
                                        qe.has_collateral = false;
                                        we.entries.push_back(std::move(qe));
                                    }
                                    wl.works.push_back(std::move(we));
                                }
                                qs.ok = true;  wl.ok = true;
                                std::string e1, e2;
                                const bool ok1 = qbr->seed_snapshots(qs, anchor_h, e1);
                                const bool ok2 = qbr->seed_work_lists(wl, anchor_h, e2);
                                if (!ok1 || !ok2) {
                                    LOG_ERROR << "[MN-DIFF-DB] getqrinfo rotated"
                                                 " bootstrap seed REJECTED (snapshots: "
                                              << (ok1 ? "ok" : e1) << "; work-lists: "
                                              << (ok2 ? "ok" : e2) << ") — store engine"
                                                 " stays without the straddle snapshots;"
                                                 " callers fall through (reward-safe).";
                                    return;
                                }
                                sseed->landed = true;
                                LOG_INFO << "[MN-DIFF-DB] getqrinfo rotated bootstrap"
                                            " SEEDED: " << qs.entries.size()
                                         << " pre-anchor quarter snapshots + "
                                         << wl.works.size() << " work-lists for cycle"
                                            " base h=" << sseed->cycle_base << " (type "
                                         << int(sseed->llmq_type) << "); cycle "
                                         << sseed->cycle_base << " is now derivable —"
                                            " fold_qfcommit past the anchor resolves its"
                                            " member set and the store extends toward"
                                            " tip.";
                                // ── ASSEMBLE + KEY the straddle cycle NOW ────
                                // The seed made the cycle DERIVABLE (snapshots +
                                // work-lists present); this drives dashd's
                                // ComputeQuorumMembersByQuarterRotation over them
                                // (the engine's compute_rotation_cycle, verbatim)
                                // and registers the ordered member set keyed by
                                // (llmqType, cycle_base+quorumIndex) — the exact
                                // key fold_qfcommit's m_members_fn(type,quorumHash)
                                // resolves a commitment quorumHash to. Done BEFORE
                                // draining the held blocks so the qfcommit at
                                // cycle_base+mining_window_start (the height the
                                // store used to cap at) resolves its member set
                                // and the fold folds THROUGH toward tip.
                                {
                                    auto dr = qbr->derive_members_for_cycle(
                                        sseed->llmq_type, sseed->cycle_base);
                                    if (dr.ok)
                                        LOG_INFO << "[MN-DIFF-DB] straddle cycle"
                                                    " base h=" << sseed->cycle_base
                                                 << " (type "
                                                 << int(sseed->llmq_type)
                                                 << ") rotated member sets"
                                                    " ASSEMBLED + KEYED: "
                                                 << dr.member_sets << "/"
                                                 << dr.expected_sets
                                                 << " quorumIndex lists (quorum"
                                                    " size " << dr.quorum_size
                                                 << ") — fold_qfcommit resolves"
                                                    " past the anchor.";
                                    else
                                        LOG_WARNING << "[MN-DIFF-DB] straddle cycle"
                                                       " base h="
                                                    << sseed->cycle_base
                                                    << " (type "
                                                    << int(sseed->llmq_type)
                                                    << ") member assembly"
                                                       " INCOMPLETE ("
                                                    << dr.member_sets << "/"
                                                    << dr.expected_sets << "): "
                                                    << dr.skip_reason
                                                    << " — store will cap at the"
                                                       " cycle's first punishing"
                                                       " qfcommit; callers fall"
                                                       " through (reward-safe).";
                                }
                                if (!sseed->hold.empty()) {
                                    for (auto& pr : sseed->hold)
                                        (*feed)(pr.second, pr.first);
                                    sseed->hold.clear();
                                }
                            });
                    }

                    // THE WRITE FEED: the SAME shared drive as the hold-buffer
                    // drain (feed), wrapped by the rotated-quorum ORDERING GATE.
                    // getqrinfo(B0) is a P2P round-trip that races the parallel
                    // fold advancing from the anchor; a straddle block folded
                    // BEFORE its snapshots are seeded fails closed and POISONS
                    // the engine. So: issue the fetch once a body-serving peer is
                    // certainly up, HOLD straddle blocks until the seed lands
                    // (then drain them in order), and — reward-safe fallback — if
                    // the reply never arrives within a bounded hold, cap the store
                    // below the straddle and let callers fall through unchanged
                    // rather than poison.
                    mn_ckpt_lane->set_on_block_applied(
                        [sseed, feed, cp = coin_p2p.get(),
                         hc = header_chain.get()](
                            const dash::coin::BlockType& blk, uint32_t h) {
                            // Lazy one-shot getqrinfo(B0): fire on the first folded
                            // block, when headers are synced and a body-serving
                            // peer exists.
                            if (sseed->armed && !sseed->sent) {
                                if (auto he = hc->get_header_by_height(
                                        sseed->cycle_base)) {
                                    sseed->cycle_base_hash = he->hash;
                                    // extra=true: the reply must carry the h-4C
                                    // leg, whose blockHash seeds a getheaders
                                    // locator BELOW the deepest work block so the
                                    // pre-anchor backfill span includes h-3C.
                                    if (cp) cp->send_getqrinfo(
                                        {}, he->hash, /*extra=*/true);
                                    sseed->sent        = true;
                                    sseed->last_send_h = h;
                                    LOG_INFO << "[MN-DIFF-DB] getqrinfo issued for"
                                                " straddling cycle base h="
                                             << sseed->cycle_base
                                             << " — bootstrap the store engine's"
                                                " rotated member derivation across"
                                                " the anchor.";
                                }
                            }
                            // Seed landed while blocks were held -> drain first.
                            if (sseed->landed && !sseed->hold.empty()) {
                                for (auto& pr : sseed->hold)
                                    (*feed)(pr.second, pr.first);
                                sseed->hold.clear();
                            }
                            // Hold blocks that would ask the resolver for the
                            // straddling cycle before its snapshots are seeded.
                            if (sseed->armed && !sseed->landed
                                && h >= sseed->first_need_h) {
                                if (sseed->exhausted) return;   // gave up: never fold unseeded
                                constexpr size_t kHoldCap = 2000;
                                if (sseed->hold.size() < kHoldCap) {
                                    sseed->hold.emplace_back(h, blk);
                                    if (sseed->sent
                                        && h >= sseed->last_send_h + 24u) {
                                        if (auto he = hc->get_header_by_height(
                                                sseed->cycle_base)) {
                                            if (cp) cp->send_getqrinfo(
                                                {}, he->hash, /*extra=*/true);
                                            sseed->last_send_h = h;
                                        }
                                    }
                                } else {
                                    sseed->exhausted = true;
                                    sseed->hold.clear();
                                    LOG_WARNING
                                        << "[MN-DIFF-DB] getqrinfo straddle seed did"
                                           " not arrive before the hold cap at h="
                                        << h << "; store caps below the straddling"
                                           " cycle and callers fall through to the"
                                           " network path (reward-safe, no bad mint).";
                                }
                                return;   // do not fold a straddle block unseeded
                            }
                            (*feed)(blk, h);
                        });

                    // THE READ SEAM: the 0-RTT gap-repair the SOURCE callers
                    // use, reconstructed from the store and cross-checked at
                    // every hop against OUR PoW-validated header chain.
                    dash::coin::MnGapRepairFn repair_fn =
                        [store = mn_diff_store.get(),
                         hc = header_chain.get()](uint32_t want)
                            -> dash::coin::MnGapRepairResult {
                        dash::coin::MnGapRepairResult out;
                        out.as_of = want;
                        if (store == nullptr || hc == nullptr) {
                            out.error = "diff store / header chain absent";
                            return out;
                        }
                        auto e = hc->get_header_by_height(want);
                        if (!e) {
                            out.error = "h=" + std::to_string(want)
                                      + " is not on our PoW-validated header"
                                        " chain";
                            return out;
                        }
                        auto hlookup = [hc](const uint256& h)
                            -> std::optional<std::pair<uint32_t, uint256>> {
                            auto ie = hc->get_header(h);
                            if (!ie) return std::nullopt;
                            return std::make_pair(ie->height, ie->prev_hash);
                        };
                        rp::DmlFoldEngine::Entries list;
                        uint64_t trc2 = 0;
                        std::string err;
                        if (!store->reconstruct(e->hash, hlookup, list, trc2,
                                                err)) {
                            out.error = err;
                            return out;
                        }
                        out.entries.reserve(list.size());
                        for (const auto& [protx, st] : list)
                            out.entries.emplace_back(protx,
                                                     rp::to_payee_state(st));
                        out.ok = true;
                        return out;
                    };
                    mn_ckpt_lane->set_gap_repair(repair_fn);

                    std::cout << "[run] MN DIFF STORE ARMED (cold bridge): the"
                                 " MN-CKPT bridge's clean folds feed a parallel"
                                 " root-checked DML engine; the ban-state probe"
                                 " and on-demand fold repair from it 0-RTT when"
                                 " it covers the height, else fall through to"
                                 " the network unchanged (reward-safe: a row"
                                 " that does not re-hash to the committed"
                                 " merkleRootMNList is REFUSED)\n";
                }
            }

            // Kick the lane once now in case the header chain is already past
            // the anchor from a previous run's persisted header DB.
            mn_ckpt_lane->pump();
        }

        // ── W2: FULL-HISTORY REPLAY bulk block-fetch lane (--replay-bulk) ──
        // OBSERVE-only transport slice: fetches DIP3→tip bodies across the
        // peer pool, verifies, hands them IN ORDER to the (W2 counting stub)
        // consumer and PRUNES them. Registers the two CoinClient demux
        // filters + the notfound seam; nothing here touches serving, gating
        // or the tip lane's request paths (priority invariants are in
        // replay_bulk_fetch.hpp's header comment).
        if (g_replay_bulk) {
            namespace rp = dash::coin::replay;
            const auto& rparams = header_chain->params();
            if (rparams.fast_start_checkpoint.has_value()) {
                // Extend the fast-start anchor to GENESIS: the backfill walks
                // genesis→anchor and must JOIN the anchor hash exactly
                // (fail-closed otherwise). Without a fast-start (testnet) the
                // main header chain already syncs from genesis — no backfill.
                const auto& cpk = rparams.fast_start_checkpoint.value();
                replay_backfill = std::make_unique<rp::HeaderBackfill>(
                    rparams.genesis_hash, cpk.height, cpk.hash,
                    rparams.pow_limit,
                    (core::filesystem::config_path() / net_subdir
                        / "dash_replay_headers").string());
            }
            replay_counter = std::make_unique<rp::CountingReplayConsumer>();
            rp::IReplayBlockConsumer* replay_consumer = replay_counter.get();

            // ── W5: seed the DML fold and let the lane DRIVE it ───────────
            // Without a prestate the lane keeps W2's counting stub (pure
            // OBSERVE). With one, every delivered body is folded and its
            // computed merkleRootMNList checked byte-exact against that
            // block's own committed cbTx root — the per-block proof.
            uint32_t replay_fold_anchor = 0;
            if (!g_replay_fold_prestate.empty()) {
                auto ps = rp::load_prestate_file(g_replay_fold_prestate);
                if (!ps.ok) {
                    std::cerr << "[run] FATAL: --replay-fold-prestate "
                              << g_replay_fold_prestate << ": " << ps.error
                              << "\n";
                    return 1;
                }
                dash::coin::replay::FoldConfig fcfg;
                fcfg.enabled = true;   // W1 feature flag, explicit opt-in
                replay_fold_engine =
                    std::make_unique<rp::DmlFoldEngine>(fcfg);
                const std::string serr =
                    rp::seed_engine_from_prestate(*replay_fold_engine, ps);
                if (!serr.empty()) {
                    std::cerr << "[run] FATAL: " << serr << "\n";
                    return 1;
                }
                replay_fold_anchor = ps.height;
                replay_fold_consumer =
                    std::make_unique<rp::FoldReplayConsumer>(
                        *replay_fold_engine);
                replay_consumer = replay_fold_consumer.get();
                std::cout << "[run] W5 REPLAY FOLD ARMED: anchor h="
                          << ps.height << " mns=" << replay_fold_engine->size()
                          << " root="
                          << replay_fold_engine->compute_sml_root().GetHex()
                          << " (reproduces the anchor block's committed cbTx"
                             " merkleRootMNList)\n";

                // ── THE SEAM ─────────────────────────────────────────────
                // W4's engine derives member sets from the SAME replayed
                // blocks the fold consumes; the bridge installs both
                // directions and nothing else is supplied.
                if (g_replay_fold_quorums) {
                    dash::coin::replay::QuorumReplayConfig qcfg;
                    qcfg.enabled = true;   // W4 feature flag, explicit opt-in
                    qcfg.network = testnet
                        ? dash::coin::LlmqNetwork::Testnet
                        : dash::coin::LlmqNetwork::Mainnet;
                    if (testnet) qcfg.v20_floor = 905'100u;
                    replay_quorum_engine =
                        std::make_unique<rp::QuorumReplayEngine>(qcfg);
                    replay_quorum_engine->seed_cursor(
                        ps.height, replay_fold_engine->block_hash());
                    dash::coin::replay::QuorumBridgeConfig bcfg;
                    bcfg.network = qcfg.network;
                    replay_quorum_bridge =
                        std::make_unique<rp::ReplayQuorumBridge>(
                            *replay_fold_engine, *replay_quorum_engine, bcfg);
                    // Pre-anchor height->hash from the PoW-verified header
                    // chain, so a commitment mined just after the anchor
                    // whose quorum BASE predates it still resolves instead
                    // of poisoning the lane on an "unknown base".
                    size_t seeded_hashes = 0;
                    const uint32_t back = 3u * 576u + 64u;
                    for (uint32_t h = (ps.height > back ? ps.height - back : 1);
                         h < ps.height; ++h) {
                        auto e = header_chain->get_header_by_height(h);
                        if (!e) continue;
                        replay_quorum_bridge->seed_block_hash(h, e->hash);
                        ++seeded_hashes;
                    }
                    size_t seeded_snaps = 0;
                    if (!g_replay_fold_qsnapshot.empty()) {
                        auto qs = rp::load_qsnapshot_seed_file(
                            g_replay_fold_qsnapshot);
                        std::string qerr;
                        if (!replay_quorum_bridge->seed_snapshots(
                                qs, ps.height, qerr)) {
                            std::cerr << "[run] FATAL: "
                                         "--replay-fold-qsnapshot "
                                      << g_replay_fold_qsnapshot << ": "
                                      << qerr << "\n";
                            return 1;
                        }
                        seeded_snaps =
                            replay_quorum_bridge->seeded_snapshot_count();
                    }
                    size_t seeded_works = 0;
                    if (!g_replay_fold_worklists.empty()) {
                        auto wl = rp::load_work_list_seed_file(
                            g_replay_fold_worklists);
                        std::string werr;
                        if (!replay_quorum_bridge->seed_work_lists(
                                wl, ps.height, werr)) {
                            std::cerr << "[run] FATAL: "
                                         "--replay-fold-worklists "
                                      << g_replay_fold_worklists << ": "
                                      << werr << "\n";
                            return 1;
                        }
                        seeded_works =
                            replay_quorum_bridge->seeded_work_list_count();
                    }
                    replay_quorum_bridge->prime_at_anchor();
                    replay_fold_consumer->set_pre_fold(
                        [br = replay_quorum_bridge.get()](
                            uint32_t h, const uint256& bh,
                            const dash::coin::BlockType& blk) {
                            return br->observe(h, bh, blk);
                        });
                    replay_fold_consumer->set_post_fold(
                        [br = replay_quorum_bridge.get()](uint32_t h) {
                            br->after_fold(h);
                        });
                    std::cout << "[run] REPLAY QUORUM SEAM ARMED: W4 member"
                                 " derivation feeds the W1 MembersFn"
                                 " (pre-anchor header hashes seeded="
                              << seeded_hashes
                              << ", pre-anchor cycle snapshots seeded="
                              << seeded_snaps
                              << ", pre-anchor work lists seeded="
                              << seeded_works
                              << "; rotated membership reads NOTHING seeded "
                                 "from cycle base h="
                              << replay_quorum_bridge->self_contained_from(
                                     5, ps.height)
                              << " onward)\n";
                } else {
                    std::cout << "[run] --replay-fold-quorums NOT given: the"
                                 " fold has no member resolver, so the first"
                                 " commitment that marks a member invalid"
                                 " will fail closed (by design).\n";
                }

                // ── THE SERVE SEAM: the fold FEEDS the payee queue ────────
                // Everything above proves a masternode list. Nothing above
                // ever handed it to the thing that gates serving.
                //
                // MEASURED on contabo (pure daemonless, no dashd, cold
                // start): the fold reconstructed the DML to tip in 264 s,
                // 4690/4690 byte-exact roots, DIVERGED=none — while the
                // serve gate sat on
                //   [EMBED-GATE] DECLINED cause=not-populated
                //                value=have_tip=1,have_mn=0
                // waiting for the MN-CKPT bridge's SECOND, independent
                // reconstruction to crawl the same range at ~0.8-1 blk/s
                // (40-60 min), because the payee axis had no third source.
                // With no dashd creds the fallback arm is unarmed, so the
                // node pushed ZERO mining.notify for that whole window.
                //
                // This publisher is that third source. It goes through the
                // EXACT leg-4 event the dashd seed and the checkpoint bridge
                // use, so the maintainer takes it as an ordinary
                // authoritative resync — snapshot fence at the folded height,
                // apply cursor armed for the next live block. Neither
                // existing lane is removed or bypassed; whichever is ready
                // first populates the queue, and the log NAMES it.
                //
                // FAIL-CLOSED: ReplayPayeePublisher::evaluate() must pass all
                // of G1..G8 — not poisoned, DIVERGED=none, roots_matched ==
                // folded, engine cursor == last root-checked height, the list
                // RE-HASHES right now to the merkleRootMNList that block
                // committed, the cursor is AT the header tip, and every entry
                // carries a payout script. A fold that diverged, is poisoned,
                // or is behind the tip can never become the authoritative
                // snapshot, and the refusal names which condition blocked.
                // ── DASHD-CUT: self-derived MN-set checkpoint DUMP ────────
                // One-shot: when the fold cursor reaches H, serialize the
                // registered set to FILE (mn_checkpoint_dump.hpp). SELF-DERIVED
                // — every field comes from the fold's own root-checked
                // ReplayMNState (scriptPayout verbatim from the ProRegTx it
                // replayed; nLastPaidHeight from the payee bookkeeping it
                // keeps), never a dashd protx snapshot. Serve-inert: it only
                // reads the engine and writes one file. The write self-verifies
                // through parse_mn_checkpoint() so it can never emit a file the
                // runtime cold-start would refuse.
                if (g_dump_mn_checkpoint_height != 0 && replay_fold_consumer) {
                    const uint32_t dump_h = g_dump_mn_checkpoint_height;
                    const std::string dump_file = g_dump_mn_checkpoint_file;
                    replay_fold_consumer->set_dump_hook(
                        dump_h,
                        [dump_file, dump_h](const rp::DmlFoldEngine& eng,
                                            uint32_t reached) {
                            const std::string source =
                                "self-derived from chain via c2pool"
                                " --replay-bulk at H=" + std::to_string(reached)
                                + " (blockhash " + eng.block_hash().GetHex()
                                + ")";
                            const std::string generated =
                                dash::coin::mn_dump_detail::iso8601_utc_now();
                            std::string err;
                            if (dash::coin::write_mn_checkpoint_inc(
                                    eng, dump_file, source, generated, err)) {
                                std::cout << "[run] --dump-mn-checkpoint: WROTE "
                                          << eng.size() << " registered"
                                             " masternodes at h=" << reached
                                          << " to " << dump_file
                                          << " (self-derived, no dashd) —"
                                             " verified through"
                                             " parse_mn_checkpoint()\n";
                            } else {
                                std::cerr << "[run] --dump-mn-checkpoint FAILED"
                                             " at h=" << reached << ": " << err
                                          << "\n";
                            }
                        });
                    std::cout << "[run] --dump-mn-checkpoint ARMED: the fold will"
                                 " serialize its registered MN set at h="
                              << dump_h << " to " << dump_file
                              << " (self-derived from chain; no dashd RPC)\n";
                }

                if (replay_fold_consumer) {
                    replay_payee_pub =
                        std::make_unique<rp::ReplayPayeePublisher>(
                            *replay_fold_engine, *replay_fold_consumer,
                            [hc = header_chain.get()]() -> uint32_t {
                                // OUR OWN PoW-validated header chain is the
                                // currency reference — not a peer's claim.
                                return hc ? hc->height() : 0u;
                            },
                            [&coin_state](
                                std::vector<std::pair<uint256,
                                                      dash::coin::MNState>> set,
                                uint32_t as_of, const char* source) {
                                dash::interfaces::MnListUpdate up;
                                up.mnstates     = std::move(set);
                                up.as_of_height = as_of;
                                up.source       = source;
                                coin_state.mn_list_update.happened(up);
                            });
                    // ── THE LAST MILE (found by the first live seam run) ──
                    // The W2 bulk lane fetches what its peers ANNOUNCED and
                    // then goes idle: on .211 it parked at
                    //   [BULK] delivered=2516911/2516911 inflight=0 hdr=joined
                    // while our own header chain had already advanced to
                    // h=2516923. The fold therefore sat 12 blocks short of the
                    // tip, permanently, and the currency guard (G7) could never
                    // flip — correctly refusing, and never publishing.
                    //
                    // The node is ALREADY receiving those blocks: the tip lane
                    // connects them and fires block_connected. Hand them to the
                    // fold. The consumer no-ops any height at or below the
                    // engine's cursor, so a body the bulk lane also delivers is
                    // counted once; both feeds run on the same io thread, so
                    // there is no interleaving to guard. And because the fold
                    // keeps root-checking live blocks after the handover, the
                    // proof does not stop at the tip — it continues.
                    //
                    // A live block that FAILS the fold behaves exactly as a
                    // replayed one: W1 poisons, the consumer records the
                    // divergence, and the guard's G1/G2 stop the seam from ever
                    // publishing again. It cannot un-publish an earlier
                    // snapshot — but it cannot mint a new one either.
                    replay_live_tail =
                        std::make_unique<rp::FoldLiveTail>(
                            *replay_fold_consumer, *replay_fold_engine,
                            // EXCLUSIVE floor: the bulk lane's DELIVERED
                            // high-water, and nothing more aspirational than
                            // that. The first attempt used
                            // max(delivered, target_end) and orphaned every
                            // height in between: the lane raises its ceiling
                            // as headers arrive, so live blocks 2516933..42
                            // were refused as "the lane's" and then never
                            // fetched, leaving the fold 12 short again with
                            //   [REPLAY-TAIL] held=2 lowest_held=2516943
                            //                 bulk_floor=2516932
                            // A ceiling is an intention; only `delivered` is a
                            // fact. Above it the tail may hold, and it still
                            // only ever folds engine.height()+1 — the exact
                            // height and order the lane itself would have
                            // delivered, with the same block hash — so the W4
                            // quorum lane sees no difference. Before the lane
                            // exists the floor is "everything".
                            [&replay_lane]() -> uint32_t {
                                if (!replay_lane) return UINT32_MAX;
                                return replay_lane->delivered();
                            });
                    coin_feed_subs.push_back(
                        coin_state.block_connected.subscribe(
                            [lt = replay_live_tail.get()]
                            (const dash::interfaces::BlockConnected& bc) {
                                lt->offer(bc.height, bc.block);
                            }));

                    std::cout << "[run] REPLAY SERVE SEAM ARMED: the fold's"
                                 " root-checked masternode list will populate"
                                 " the PAYEE queue (source=replay-fold) the"
                                 " moment it is proven current — G1..G8"
                                 " fail-closed guard; the dashd-seed and"
                                 " mn-ckpt lanes are UNCHANGED and keep"
                                 " whichever job they get to first\n";

                    // CHAIN, do not replace. The maintainer's payee-desync
                    // re-seed ask fired THREE times in one contabo daemonless
                    // run (h=2513168, 2513261, 2515266) — the last one on a
                    // LIVE tip advance, i.e. independently of any bridge
                    // replay. Answer it from the fold when the fold is still
                    // proven current (the queue was just wiped, so
                    // republishing the same height is precisely the repair);
                    // otherwise fall through to the EXACT handler this
                    // posture had installed a moment ago.
                    if (maintainer) {
                        maintainer->set_on_mn_reseed(
                            [pp = replay_payee_pub.get(),
                             fb = mn_reseed_fallback]() {
                                if (pp && pp->republish_for_reseed()) return;
                                if (fb) fb();
                            });
                    }
                }

                // ── MN DIFF/SNAPSHOT STORE (dashd evodb dmn_D4/dmn_S3 port,
                // evo/deterministicmns.cpp:689-694) ──────────────────────────
                // Written by the fold's per-block commit (post root-match, via
                // the consumer's diff sink); read ONLY by the gap-repair seam.
                // Opened next to dash_replay_headers. On open/verify failure
                // the store is simply absent and both repair callers keep
                // their historical wipe/demote fail-closed behavior — the
                // store is an accelerator, never consensus-required.
                if (replay_fold_consumer && mn_diff_store) {
                    // DEFENSIVE (named fail-closed, not a clobber): the cold
                    // MN-CKPT store-bridge (main_dash.cpp ~6182) must have YIELDED
                    // when a prestate is configured. If it did not, a make_unique
                    // here would FREE the cold bridge's live MnDiffWriter while
                    // its set_on_anchor_snapshot lambda still holds it raw -> UAF.
                    // Refuse instead. The deep replay then folds WITHOUT the
                    // accelerator store (reward-safe: the store is never
                    // consensus-required, only a gap-repair accelerator).
                    LOG_ERROR << "[MN-DIFF-DB] INVARIANT VIOLATED: cold-bridge"
                                 " store present while arming the W5 deep-replay"
                                 " store -- refusing to clobber a live writer"
                                 " (would UAF the cold-bridge anchor lambda);"
                                 " W5 accelerator store DISABLED (reward-safe).";
                }
                if (replay_fold_consumer && !mn_diff_store) {
                    mn_diff_store = std::make_unique<rp::MnDiffStore>(
                        (core::filesystem::config_path() / net_subdir
                            / "dash_mn_diff_db").string());
                    if (!mn_diff_store->open()) {
                        LOG_WARNING << "[MN-DIFF-DB] open failed — diff store"
                                       " DISABLED (gap repair unavailable;"
                                       " wipe/demote floor unchanged)";
                        mn_diff_store.reset();
                    } else {
                        // hash -> (height, prev_hash) off OUR PoW-validated
                        // header chain — the walk's cross-check at every hop.
                        auto diff_hlookup =
                            [hc = header_chain.get()](const uint256& h)
                                -> std::optional<std::pair<uint32_t, uint256>> {
                            if (!hc) return std::nullopt;
                            auto e = hc->get_header(h);
                            if (!e) return std::nullopt;
                            return std::make_pair(e->height, e->prev_hash);
                        };
                        // Startup: 'B' sentinel cross-check + newest snapshot
                        // pair verify (dashd VerifyBestBlock /
                        // VerifySnapshotPair posture, scope-reduced). A
                        // failure wipes THIS store alone; the live fold
                        // repopulates it.
                        std::string vnote;
                        mn_diff_store->startup_verify(diff_hlookup, vnote);
                        if (!vnote.empty())
                            LOG_INFO << "[MN-DIFF-DB] startup verify: "
                                     << vnote;
                        mn_diff_writer = std::make_unique<rp::MnDiffWriter>(
                            *mn_diff_store, *replay_fold_engine);
                        // Seed/anchor snapshot: the explicit grounding row
                        // every backward walk must reach (the fail-closed
                        // inversion of dashd's initial-empty-list default).
                        mn_diff_writer->arm();
                        replay_fold_consumer->set_diff_sink(
                            [w = mn_diff_writer.get()](
                                uint32_t h, const uint256& bh,
                                const dash::coin::BlockType& blk,
                                const rp::FoldResult& fr) {
                                w->on_folded(h, bh, blk, fr);
                            });
                        // DELIBERATELY NOT added to set_on_sml_clear's reorg
                        // wipe cascade: dashd's UndoBlock keeps disk rows too
                        // (deterministicmns.cpp:736-769) — hash-keyed rows
                        // for orphaned blocks are harmless residue, and
                        // wiping diff history on reorg would destroy exactly
                        // what repair depends on.

                        // ── The GAP-REPAIR seam, wired at BOTH callers ─────
                        // want_height -> reconstruct(hash(want)) -> MNState
                        // projection through the same to_payee_state boundary
                        // every other lane uses.
                        dash::coin::MnGapRepairFn repair_fn =
                            [store = mn_diff_store.get(),
                             hc = header_chain.get()](uint32_t want)
                                -> dash::coin::MnGapRepairResult {
                            dash::coin::MnGapRepairResult out;
                            out.as_of = want;
                            if (store == nullptr || hc == nullptr) {
                                out.error = "diff store / header chain absent";
                                return out;
                            }
                            auto e = hc->get_header_by_height(want);
                            if (!e) {
                                out.error = "h=" + std::to_string(want)
                                          + " is not on our PoW-validated"
                                            " header chain";
                                return out;
                            }
                            auto hlookup = [hc](const uint256& h)
                                -> std::optional<std::pair<uint32_t, uint256>> {
                                auto ie = hc->get_header(h);
                                if (!ie) return std::nullopt;
                                return std::make_pair(ie->height,
                                                      ie->prev_hash);
                            };
                            rp::DmlFoldEngine::Entries list;
                            uint64_t trc = 0;
                            std::string err;
                            if (!store->reconstruct(e->hash, hlookup, list,
                                                    trc, err)) {
                                out.error = err;
                                return out;
                            }
                            out.entries.reserve(list.size());
                            for (const auto& [protx, st] : list)
                                out.entries.emplace_back(
                                    protx, rp::to_payee_state(st));
                            out.ok = true;
                            return out;
                        };
                        if (maintainer)
                            maintainer->set_mn_gap_repair(repair_fn);
                        if (mn_ckpt_lane)
                            mn_ckpt_lane->set_gap_repair(repair_fn);
                        std::cout << "[run] MN DIFF STORE ARMED: per-block"
                                     " list diffs + 576-cadence snapshots"
                                     " (dashd dmn_D4/dmn_S3 mechanism);"
                                     " payee-queue gap repair wired at the"
                                     " maintainer and the checkpoint bridge\n";
                    }
                }
            }

            // ── PR-2 FORWARD: the mined-commitment store ──────────────────
            // Placed HERE, after replay_live_tail is (or is not) constructed,
            // because that pointer is the STRUCTURAL answer to "is this
            // node's tip live?". FoldLiveTail subscribes block_connected and
            // hands LIVE TIP blocks to the same fold consumer this index
            // rides — so its existence means a disconnect can reach us, and
            // the missing UndoBlock half would matter. The posture is read
            // off the wiring, never guessed from how old the tip looks.
            if (g_mined_commitment_index && replay_fold_consumer
                && replay_fold_engine) {
                dash::coin::MinedCommitmentIndexConfig micfg;
                micfg.enabled = true;   // the operator asked for it by name
                micfg.network = testnet ? dash::coin::LlmqNetwork::Testnet
                                        : dash::coin::LlmqNetwork::Mainnet;
                auto mi = std::make_shared<dash::coin::MinedCommitmentIndex>(
                    micfg);
                mi->seed_cursor(replay_fold_engine->height());
                dash::coin::TipPosture posture;
                posture.live = (replay_live_tail != nullptr);
                posture.declared_by =
                    replay_live_tail
                        ? "FoldLiveTail is wired (live tip blocks are folded "
                          "into this same consumer)"
                        : "no FoldLiveTail: this consumer sees only replayed "
                          "historical bodies";
                const auto verdict = mi->arm(posture);
                std::cout << "[run] " << verdict.reason << "\n";
                LOG_INFO << "[QC-MINED-INDEX] " << verdict.reason;
                if (verdict.armed) {
                    mined_commitment_index = mi;
                    // Chain onto whatever pre_fold the quorum seam installed:
                    // the index observes the block FIRST (it needs no folded
                    // state), then the quorum lane, then the DML fold. A
                    // refusal here is reported through the same channel the
                    // quorum lane uses and never stops the fold.
                    auto prev = replay_fold_consumer->take_pre_fold();
                    replay_fold_consumer->set_pre_fold(
                        [mi, prev, hc = header_chain.get()](
                            uint32_t h, const uint256& bh,
                            const dash::coin::BlockType& blk) -> std::string {
                            std::string err;
                            const auto r = mi->process_block(
                                h, bh, blk,
                                [hc](uint32_t q) -> std::optional<uint256> {
                                    if (auto e = hc->get_header_by_height(q))
                                        return e->hash;
                                    return std::nullopt;
                                },
                                &err);
                            std::string out;
                            if (r != dash::coin::MinedIngestResult::Applied)
                                out = "mined-commitment index refused: " + err;
                            if (prev) {
                                const std::string q = prev(h, bh, blk);
                                if (!q.empty())
                                    out = out.empty() ? q : (out + "; " + q);
                            }
                            return out;
                        });
                }
            } else if (g_mined_commitment_index) {
                std::cout << "[run] --replay-mined-commitment-index given but "
                             "no replay fold consumer (needs "
                             "--replay-fold-prestate) — mined-commitment "
                             "index NOT armed\n";
            }

            if (!g_replay_bulk_capture_dir.empty()) {
                replay_capture = std::make_unique<rp::CaptureReplayConsumer>(
                    g_replay_bulk_capture_dir, replay_consumer);
                replay_consumer = replay_capture.get();
            }
            replay_cursor = std::make_unique<rp::ReplayCursorStore>(
                (core::filesystem::config_path() / net_subdir
                    / "dash_replay_cursor").string());

            // ── cursor/fold reconciliation (found by the first live run) ──
            // The lane's cursor is PERSISTENT and the fold's anchor seed is
            // re-read at every start, so the two are independent: a restart
            // resumed the lane at the stored height (h=2513098) while the
            // fold sat at the anchor (h=2513000), and the forward-contiguous
            // fold refused the very first delivery. When a fold is armed the
            // FOLD's cursor is authoritative — it is the thing carrying
            // consensus state — so the lane is pinned back to it. Resuming a
            // fold mid-range needs a snapshot v3 at the cursor height, not a
            // prestate at the anchor; until that path exists this refuses to
            // half-resume rather than silently skipping blocks.
            if (replay_fold_anchor != 0) {
                const auto stored = replay_cursor->load();
                if (stored && stored->height != replay_fold_anchor) {
                    LOG_WARNING
                        << "[BULK] persisted replay cursor is at h="
                        << stored->height << " but the armed DML fold is "
                           "seeded at anchor h=" << replay_fold_anchor
                        << " — pinning the lane back to the anchor so the "
                           "forward-contiguous fold starts at h="
                        << (replay_fold_anchor + 1)
                        << " (a mid-range resume needs a snapshot v3 at the "
                           "cursor height, not a prestate at the anchor)";
                }
                if (!stored || stored->height != replay_fold_anchor) {
                    rp::ReplayCursorStore::Cursor c;
                    c.height = replay_fold_anchor;
                    c.hash   = replay_fold_engine->block_hash();
                    replay_cursor->store(c);
                }
            }

            rp::BulkFetchLane::Seams seams;
            // Height→hash: pre-anchor from the (join-checked) backfill,
            // anchor→tip from the main header chain.
            seams.hash_at = [bf = replay_backfill.get(),
                             hc = header_chain.get()]
                (uint32_t h) -> std::optional<uint256> {
                if (bf) { auto x = bf->hash_at(h); if (x) return x; }
                auto e = hc->get_header_by_height(h);
                if (!e) return std::nullopt;
                return e->hash;
            };
            seams.chain_height = [hc = header_chain.get()] {
                return hc->height();
            };
            // Priority invariant 1: the PRIMARY carries every stateful
            // request/response leg — bulk loads it only when it is the sole
            // handshaked peer.
            seams.eligible_peers = [cp = coin_p2p.get()] {
                auto keys = cp->handshaked_peer_keys();
                const auto prim = cp->primary_peer_key();
                if (keys.size() > 1 && !prim.empty())
                    keys.erase(std::remove(keys.begin(), keys.end(), prim),
                               keys.end());
                return keys;
            };
            seams.send_getdata = [cp = coin_p2p.get()](
                const std::string& peer, const std::vector<uint256>& hashes) {
                cp->request_blocks_from(peer, hashes);
            };
            seams.send_getheaders = [cp = coin_p2p.get()](
                const std::string& peer, const uint256& locator_hash,
                const uint256& stop) {
                cp->send_getheaders_to(peer, 70230, {locator_hash}, stop);
            };
            // Priority invariant 2: no new bulk getdata while a tracked tip
            // body is outstanding.
            seams.tip_busy = [cp = coin_p2p.get()] {
                return cp->pending_body_count() > 0;
            };
            // DECONFLICT the shared response demux: while the embedded
            // MN-checkpoint anchor->tip fold is still building the payee queue,
            // the bulk genesis->anchor lane yields (body pump AND header
            // backfill). The fold's block-body getdata rides the same coin-P2P
            // link as this lane's fetch, and it gates the money arm — it must
            // finish first. Once the lane publishes, bridging_active() goes
            // false and the bulk lane resumes at full rate. Reward-safe: this
            // only reorders WHO fetches WHEN, never what either derives.
            seams.defer_to_higher_priority = [mnl = mn_ckpt_lane.get()] {
                return mnl && mnl->bridging_active();
            };

            rp::BulkFetchLane::Config rcfg;
            // A seeded fold pins the lane to anchor+1: the fold is
            // forward-contiguous, so a gap or an out-of-order delivery
            // refuses the WHOLE fold rather than silently skipping state.
            rcfg.start_height = replay_fold_anchor != 0
                ? replay_fold_anchor + 1
                : (g_replay_bulk_start != 0
                       ? g_replay_bulk_start
                       : (testnet ? 1 : rp::MAINNET_DIP3_HEIGHT));
            // ── THE EXCLUSION BAND (found by the third live seam run) ──────
            // The lane's default fetch ceiling is tip − 12: the live edge
            // "belongs to the tip lane" (priority invariant 3). For an
            // OBSERVE-only throughput lane that is exactly right. For a fold
            // whose whole purpose is to BE current it is a permanent
            // 12-block deficit — and nobody else fetches that band, because
            // the tip lane only pulls the tip's own body. Three runs in a row
            // parked on it, to the block:
            //   [REPLAY-PAYEE] WITHHELD: G7 fold is BEHIND the tip:
            //                  fold h=2516939, tip h=2516951 (12 blocks to go)
            //
            // With the fold armed the band is closed. The priority invariant
            // that actually matters is preserved: the lane still issues no
            // request while a tracked tip body is outstanding (the tip_busy
            // guard in BulkFetchLane::tick), so the tip lane keeps winning
            // every race — it simply no longer wins a band it never enters.
            // Unarmed (--replay-bulk alone) the default 12 is untouched.
            if (replay_fold_consumer) rcfg.tip_exclusion = 0;
            replay_lane = std::make_unique<rp::BulkFetchLane>(
                std::move(seams), rcfg, replay_backfill.get(),
                replay_consumer, replay_cursor.get());

            coin_p2p->set_headers_filter(
                [ln = replay_lane.get()](const std::string& key,
                                         const std::vector<dash::coin::BlockType>& b) {
                    return ln->on_headers(key, b);
                });
            coin_p2p->set_block_body_filter(
                [ln = replay_lane.get()](const uint256& h,
                                         const dash::coin::BlockType& blk) {
                    return ln->on_block_body(h, blk);
                });
            coin_p2p->set_on_block_notfound(
                [ln = replay_lane.get()](const uint256& h) {
                    ln->on_notfound(h);
                });

            replay_timer = std::make_unique<core::Timer>(&ioc, /*repeat=*/true);
            replay_timer->start(1, [ln = replay_lane.get(),
                                    fc = replay_fold_consumer.get(),
                                    br = replay_quorum_bridge.get(),
                                    pp = replay_payee_pub.get(),
                                    lt = replay_live_tail.get(),
                                    mi = mined_commitment_index,
                                    tick = std::make_shared<uint64_t>(0)] {
                ln->tick(std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                        .count());
                // Drain any live tip block the fold could not take when it
                // arrived: the bulk lane advances the cursor on its own
                // schedule, so contiguity can become satisfiable with no new
                // arrival to trigger it.
                if (lt) lt->drain();
                // THE SERVE SEAM, evaluated once a second: the instant the
                // fold is proven current the payee queue is populated from it
                // and the gate's have_mn flips. One-shot; the guard is pure
                // and cheap, and it says out loud what is still blocking.
                if (pp) pp->maybe_publish();
                // The run's deliverable is a COUNT of byte-exact root checks;
                // print it on a cadence so a run that is killed, wedged or
                // watched from another terminal still reports what it proved.
                if (fc && ++*tick % 30 == 0) {
                    LOG_INFO << fc->summary();
                    // PR-2 FORWARD: the mined-commitment store's own line —
                    // cursor, how many mined records it holds, and (issue #90)
                    // which llmq type is still short of the full active quota.
                    if (mi) LOG_INFO << mi->summary();
                    if (br) {
                        const auto& bs = br->stats();
                        LOG_INFO << "[REPLAY-SEAM] member_cycles_derived="
                                 << bs.member_cycles_derived
                                 << " skipped=" << bs.member_cycles_skipped
                                 << " members_answered=" << bs.members_answered
                                 << " members_missing=" << bs.members_missing
                                 << " lists_retained=" << br->retained_lists()
                                 // ── SCOPED COUNTER (was mis-read) ──────
                                 // Printed as `quorum_root_match/differ`
                                 // this read as a 4684-block divergence. It
                                 // is not: arm_self_check() has NO production
                                 // caller, so the comparison runs UNARMED —
                                 // a Tier-A anchor seeds no active quorum
                                 // set, the folded root is a warm-up artefact
                                 // and differs at essentially every height by
                                 // construction, while the SERVED root was
                                 // correct (154/154 shadow matches). The name
                                 // now says which comparison it is and the
                                 // line states the arming, so the number can
                                 // no longer be read as divergence evidence.
                                 // Scoping the COUNTER itself stays with the
                                 // W4 task; this is the logging half.
                                 << " fold_root_vs_committed="
                                 << bs.quorum_roots_matched << "/"
                                 << bs.quorum_roots_differed
                                 << " self_check="
                                 << (br->self_check_armed()
                                        ? std::string("armed")
                                        : std::string("UNARMED"))
                                 // ── ISSUE #90 ─────────────────────────
                                 // The counter now NAMES ITS BLOCKING
                                 // CONDITION — which llmq type is short and
                                 // by how many — instead of reading `0/N`
                                 // with nothing to say. NOTHING IN THIS
                                 // BINARY ARMS THE SELF-CHECK: the arming
                                 // half of #90 is deliberately not in this
                                 // PR (see the ISSUE #90 note in
                                 // ReplayQuorumBridge::observe — armed, a
                                 // root differ is a hard stop that can stop
                                 // SERVING, so it needs its own default-OFF
                                 // flag and its own KAT). The armed branch
                                 // below reads the real state rather than
                                 // asserting a constant, so the line stays
                                 // truthful when #90 lands.
                                 << (br->self_check_armed()
                                        ? std::string()
                                        : std::string(
                                              " (unarmed: active set "
                                              "incomplete — ")
                                              + br->active_set_shortfall_text()
                                              + "; on mainnet type1"
                                                " (LLMQ_50_60) is short"
                                                " FOREVER: its last 24"
                                                " commitments were mined"
                                                " before DIP0024 (~h1738698)"
                                                " and no forward replay from"
                                                " a modern anchor can observe"
                                                " them — they must be SEEDED"
                                                " or reached by a genesis"
                                                " replay. Until then a differ"
                                                " here is warm-up, NOT"
                                                " divergence)")
                                 << (bs.last_skip_reason.empty()
                                        ? std::string()
                                        : " last_skip=\"" + bs.last_skip_reason + "\"");
                    }
                    if (lt && (lt->held() || lt->folded_live())) {
                        LOG_INFO << "[REPLAY-TAIL] live tip blocks folded="
                                 << lt->folded_live()
                                 << " held=" << lt->held()
                                 << (lt->held()
                                        ? " lowest_held=" + std::to_string(lt->lowest_held())
                                          + " (waiting for the bulk lane to close h="
                                          + std::to_string(lt->lowest_held() - 1) + ")"
                                        : std::string())
                                 << " offered=" << lt->offered()
                                 << " dropped=" << lt->dropped()
                                 << " bulk_floor=" << lt->bulk_floor();
                    }
                    if (pp) {
                        // The serve seam says its own state: either it has
                        // populated the payee queue and at what height, or it
                        // names the ONE guard condition still refusing.
                        LOG_INFO << "[REPLAY-PAYEE] serve seam: "
                                 << (pp->has_published()
                                        ? "PUBLISHED source=replay-fold as_of_h="
                                          + std::to_string(pp->published_height())
                                          + " publishes="
                                          + std::to_string(pp->publishes())
                                          + " reseeds="
                                          + std::to_string(pp->reseeds())
                                        : "WITHHELD — " + pp->last_blocker());
                    }
                }
            });

            std::cout << "[run] W2 REPLAY BULK lane ARMED: start_h="
                      << rcfg.start_height
                      << (replay_backfill
                              ? " backfill=genesis->"
                                + std::to_string(replay_backfill->anchor_height())
                                + (replay_backfill->complete() ? " (joined)" : "")
                              : " backfill=none")
                      << (g_replay_bulk_capture_dir.empty()
                              ? ""
                              : " capture=" + g_replay_bulk_capture_dir)
                      << " consumer="
                      << (replay_fold_consumer
                              ? (g_replay_bulk_capture_dir.empty()
                                     ? "W1-DML-FOLD(root-checked)"
                                     : "capture+W1-DML-FOLD(root-checked)")
                              : (g_replay_bulk_capture_dir.empty()
                                     ? "counting-stub(W1 seam)"
                                     : "capture+counting-stub"))
                      << (replay_quorum_bridge
                              ? " members=W4-DERIVED"
                              : " members=none")
                      << " (OBSERVE-only; tip lane strictly prioritized)\n";
        }
    }
    if (g_replay_bulk && !coin_p2p) {
        // Name the unmet dependency instead of silently not arming.
        std::cout << "[run] --replay-bulk given but no coin-P2P client "
                     "(needs --coin-p2p-connect/--coin-p2p-discover) — "
                     "replay bulk lane NOT armed\n";
    }

    // ── Fallback-arm event-driven tip refresh ────────────────────────────
    // On the dashd-fallback arm (no embedded coin-P2P tip source) the template
    // cache only re-sources on the 30 s staleness TTL (work_source.cpp
    // kStaleAfter) — there is NO tip-change signal like the embedded arm's
    // header_chain->set_on_tip_changed callback. DASH blocks arrive ~every
    // 150 s, so up to ~30 s of stale-tip mining can occur per block (accepted
    // pseudoshares that can no longer win the current block).
    //
    // TWO tip-notify paths, sharing ONE last-seen-tip dedup so a poll+ZMQ
    // double-fire on the same block coalesces to a single refresh:
    //   • BACKSTOP (always, #770): a 3 s getbestblockhash poll. When ZMQ is
    //     unconfigured/unreachable this is the sole active path.
    //   • PRIMARY (opt-in, --coin-zmq-hashblock): a dashd ZMQ `hashblock` SUB
    //     subscriber fires the INSTANT (~0 s) the daemon connects a new block.
    // On a genuine tip CHANGE either path drops the cached template + bumps
    // work-generation + notifies every session (clean_jobs) — the SAME refresh
    // pair the embedded arm fires. Gated on the fallback arm (coin_p2p null) AND
    // an armed rpc AND a live stratum acceptor. getbestblockhash is a trivial
    // RPC; failures are swallowed so a daemon hiccup never crashes the run-loop.
    // io-thread-decouple: dedicated single-thread pool for the fallback arm's
    // BLOCKING dashd RPC (getbestblockhash tip probe + the background template
    // re-source). Mirrors main_ltc.cpp hdr_pool ("keeps scrypt off io_context"):
    // synchronous beast I/O runs HERE, never on the stratum io_context, so 60+
    // sessions never starve while dashd is queried (or wedged -- the NodeRPC
    // socket timeout + m_rpc_mutex bound this thread). Declared here (after rpc /
    // work_source / stratum_server) so its explicit stop()+join() after the run
    // loop -- and its destructor -- happen BEFORE those objects unwind: no
    // background probe is ever mid-flight against freed state. Only created on
    // the fallback arm; null on the embedded arm (legacy inline path unchanged).
    // The opt-in ZMQ subscriber (declared here for the same teardown ordering)
    // only posts onto ioc; when unconfigured/uncompiled the poll is the whole
    // mechanism -- byte-identical to the poll-only #770/#781 behavior.
#ifdef C2POOL_ZMQ
    std::unique_ptr<dash::coin::ZmqHashblockSubscriber> zmq_sub;
#endif
    std::shared_ptr<boost::asio::thread_pool> rpc_pool;
    if (!coin_p2p && rpc && stratum_server) {
        rpc_pool = std::make_shared<boost::asio::thread_pool>(1);

        // Non-blocking template re-source: cached_work() hands the blocking
        // select_work()/GBT to rpc_pool as a single-flight background job
        // instead of blocking the io thread on every stale/generation miss (the
        // per-share ~15-30 s GBT block). The io thread serves the cached template
        // immediately; the pool updates it and the next notify picks it up.
        work_source->set_refresh_executor(
            [rpc_pool](std::function<void()> job) {
                boost::asio::post(*rpc_pool, std::move(job));
            });

        // Shared last-seen-tip dedup — the poll AND the ZMQ subscriber consult
        // it, so if both observe the same new block only the first fires the
        // refresh trio (the second is_new_tip() returns false → no-op).
        auto tip_dedup = std::make_shared<dash::coin::TipHashDedup>();

        // ── p2p `bestblock` announcement (canonical node.py:137-140) ────────
        // Canonical p2pool watches the coin daemon's best-block header and
        // pushes it to every pool peer:
        //     @self.node.best_block_header.changed.watch
        //     def _(header):
        //         for peer in self.peers.itervalues():
        //             peer.send_bestblock(header=header)
        // DASH never sent `bestblock` at all (it only HANDLED the inbound one,
        // protocol_actual.cpp:191). LTC/DGB/BCH/BTC each expose
        // broadcast_bestblock(); the DASH port is dash::NodeImpl::broadcast_bestblock.
        //
        // Trigger: the ALREADY-DEDUPED tip-notify choke point below
        // (fire_refresh), so exactly ONE announcement per genuinely new dashd
        // tip -- ~1 per 2.5 min -- and a poll+ZMQ double-observation of the same
        // block cannot double-send. The header itself is fetched with a single
        // `getblockheader <tip> false` on the dedicated rpc_pool thread (never
        // on the io thread), then parsed and broadcast back on ioc. Any failure
        // is swallowed: bestblock is advisory, and the next tip re-announces.
        //
        // REWARD-SAFETY: announcement only. It does not touch the template, the
        // share chain, the mint path, the coinbase/payee, or the won-block
        // dispatch -- it is a read of dashd's tip header plus a socket write.
        std::function<void(const std::string&)> announce_bestblock =
            [rpc = rpc.get(), rpc_pool, &ioc, &p2p_node](const std::string& tip_hex) {
                uint256 tip;
                tip.SetHex(tip_hex);
                if (tip.IsNull())
                    return;
                // DIAG(#1046, non-soak dev tree): the ENTER marker resolves the
                // "lambda never invoked" case -- if [Stratum] tip-poll logs a NEW
                // tip but this line is ABSENT, announce_bestblock was not called.
                LOG_INFO << "[Pool] bestblock DIAG(#1046): announce ENTER tip="
                         << tip_hex.substr(0, 16);
                boost::asio::post(*rpc_pool, [rpc, tip, tip_hex, &ioc, &p2p_node]() {
                    std::string hdr_hex;
                    try {
                        // BLOCKING -- BACKGROUND THREAD (never the io thread).
                        auto r = rpc->getblockheader(tip, /*verbose=*/false);
                        // DIAG(#1046): the three-way classify replaces the two
                        // formerly-silent returns. RpcNotString vs BadHexLen are
                        // now distinguishable in the log; Ok falls through.
                        auto cls =
                            dash::coin::classify_bestblock_header(r, hdr_hex);
                        if (cls != dash::coin::BestblockFetch::Ok) {
                            LOG_WARNING << "[Pool] bestblock DIAG(#1046): BAIL "
                                        << dash::coin::bestblock_fetch_name(cls)
                                        << " (r.type=" << r.type_name()
                                        << ", hex_len=" << hdr_hex.size()
                                        << ") tip=" << tip_hex.substr(0, 16);
                            return; // refuse to send a non-80-byte header
                        }
                    } catch (const std::exception& e) {
                        LOG_WARNING << "[Pool] bestblock: getblockheader failed "
                                       "(non-fatal, next tip re-announces): "
                                    << e.what();
                        return;
                    } catch (...) {
                        return; // never crash on an advisory announcement
                    }
                    // Classified Ok above (exactly 160 hex chars); broadcast.
                    LOG_INFO << "[Pool] bestblock DIAG(#1046): fetch Ok len=160 "
                                "-> broadcast tip=" << tip_hex.substr(0, 16);
                    boost::asio::post(ioc, [hdr_hex = std::move(hdr_hex), &p2p_node]() {
                        try {
                            dash::coin::BlockHeaderType hdr;
                            PackStream ps(ParseHex(hdr_hex));
                            ps >> hdr;
                            p2p_node.broadcast_bestblock(hdr);
                        } catch (const std::exception& e) {
                            LOG_WARNING << "[Pool] bestblock: header unpack failed: "
                                        << e.what();
                        }
                    });
                });
            };

        // The refresh trio, shared by both paths. Runs on the io_context thread
        // ONLY (the poll follow-up is posted back to ioc; the ZMQ callback posts
        // onto ioc), so ws/ss/dedup are never touched concurrently. `verb`
        // differentiates the instant (ZMQ) vs polled log line. Returns true iff
        // the refresh trio actually fired (a NEW tip vs the shared dedup); false
        // when the tip was unchanged and the call coalesced to a no-op -- the
        // reconnect observer below uses that to tell a real tip change apart from
        // a benign idle-timeout reconnect.
        std::function<bool(const std::string&, const char*, const char*)>
            fire_refresh = [ws = work_source.get(), ss = stratum_server.get(),
                            tip_dedup, announce_bestblock](const std::string& tip,
                                       const char* source, const char* verb) {
                if (!tip_dedup->is_new_tip(tip))
                    return false; // dedup: coalesce a poll+ZMQ double-fire on one tip
                ws->invalidate_template_cache(
                    "tip-notify: dashd best-block changed");
                ws->bump_work_generation();
                ss->notify_all();
                // Canonical node.py:137-140 — announce the new tip header to
                // every pool peer. Deduped by is_new_tip() above, so exactly
                // one announcement per genuinely new block.
                announce_bestblock(tip);
                LOG_INFO << "[Stratum] " << source << ": " << tip.substr(0, 16)
                         << " -> " << verb;
                std::cout << "[Stratum] " << source << ": " << tip.substr(0, 16)
                          << " -> " << verb << "\n";
                return true;
            };

        // #751 churn fix: refine the CoindRPC reconnect-churn observer on the
        // fallback arm. dashd closes an idle keep-alive connection on its
        // rpcservertimeout (default 30 s), so on an otherwise-idle pool c2pool
        // reconnects every ~30-90 s. The unconditional invalidate wired on the
        // main path (see "reconnect-churn observer" above) then fires clean_jobs
        // to every stratum session on EVERY such reconnect -> the endpoint flaps
        // and rigs waste work even though NOTHING changed on-chain. Here we
        // OVERRIDE that observer (this assignment runs after the main-path one,
        // still before the io loop starts) with a tip-aware version: on a
        // reconnect, probe dashd's best-block hash and invalidate ONLY if the tip
        // actually moved while we were disconnected.
        //
        //   INVARIANT (must NOT regress the stale-masternode-payee lost-block
        //   class): a tip change during the disconnect window MUST still
        //   invalidate -- a new tip means a new masternode payee, so any template
        //   cached from before the churn is stale and unsafe to serve or submit.
        //   We skip the invalidate ONLY when the tip is PROVABLY unchanged (probe
        //   succeeded AND equals the last-seen tip). If the probe itself fails
        //   (RPC not ready on the fresh socket) we FALL BACK to invalidating --
        //   never serve stale-payee work on an unproven tip.
        //
        // Deadlock note: m_on_reconnect fires from inside NodeRPC::sync_reconnect(),
        // which runs UNDER m_rpc_mutex from within Send(). A synchronous
        // getbestblockhash() here would re-enter Send() and self-deadlock on that
        // non-recursive mutex, so the probe is POSTED to rpc_pool (the RPC thread)
        // and runs after the triggering Send() releases the lock. The tip compare
        // + refresh trio then post BACK onto ioc, where fire_refresh / tip_dedup
        // are io-thread-confined -- identical threading to the 3 s tip poll below.
        rpc->set_on_reconnect(
            [rpc = rpc.get(), rpc_pool, fire_refresh, ws = work_source.get(),
             &ioc]() {
                boost::asio::post(*rpc_pool, [rpc, fire_refresh, ws, &ioc]() {
                    std::string tip;
                    bool ok = false;
                    try {
                        tip = rpc->getbestblockhash(); // BLOCKING -- background thread
                        ok = true;
                    } catch (...) {
                        // swallow -- treated as a probe failure (fail-safe below)
                    }
                    boost::asio::post(ioc,
                        [ok, tip = std::move(tip), fire_refresh, ws]() {
                            if (!ok || tip.empty()) {
                                // FAIL-SAFE: tip unproven -> conservatively drop
                                // the cache (the pre-#751 unconditional behaviour).
                                ws->invalidate_template_cache(
                                    "CoindRPC reconnect: tip probe failed "
                                    "(fail-safe invalidate)");
                                return;
                            }
                            // fire_refresh invalidates + bumps + notifies IFF the
                            // tip is NEW vs the shared last-seen dedup; an unchanged
                            // tip is a benign idle-timeout reconnect -> cache kept.
                            if (!fire_refresh(tip, "reconnect",
                                              "tip changed during disconnect -> "
                                              "refresh + notify")) {
                                LOG_INFO << "[Stratum] reconnect: benign idle-"
                                            "timeout, tip unchanged ("
                                         << tip.substr(0, 16)
                                         << ") -- template cache retained";
                            }
                        });
                });
            });

        // BACKSTOP: 3 s getbestblockhash poll (#770), io-decoupled (#781).
        auto tip_timer = std::make_shared<io::steady_timer>(ioc);
        auto tip_tick = std::make_shared<
            std::function<void(const boost::system::error_code&)>>();
        // tip_tick runs ON ioc when the 3 s timer fires. It does NOT call the
        // blocking RPC itself: it hands getbestblockhash to rpc_pool and posts
        // the tip-change follow-up + the timer re-arm BACK onto ioc (fire_refresh
        // / tip_timer are io-thread-confined), exactly like main_ltc.cpp's
        // post-to-pool -> post-back-to-ioc pattern. The timer is re-armed only
        // AFTER the RPC completes, so a slow dashd cannot pile up overlapping
        // polls. Lost-block-prevention is preserved: a real tip change still
        // fires the refresh trio -- only WHERE the probe runs has moved off the
        // stratum io thread.
        *tip_tick = [rpc = rpc.get(), tip_dedup, fire_refresh, tip_timer,
                     tip_tick, rpc_pool, &ioc](const boost::system::error_code& ec) {
            if (ec) return;   // cancelled at shutdown
            boost::asio::post(*rpc_pool,
                [rpc, tip_dedup, fire_refresh, tip_timer, tip_tick, &ioc]() {
                    std::string tip;
                    bool ok = false;
                    try {
                        tip = rpc->getbestblockhash();   // BLOCKING -- BACKGROUND THREAD
                        ok = true;
                    } catch (const std::exception& e) {
                        LOG_WARNING << "[Stratum] tip-poll getbestblockhash failed "
                                       "(non-fatal, retry next tick): " << e.what();
                    } catch (...) {
                        // swallow — never crash on a tip probe
                    }
                    // Follow-up + timer re-arm run BACK ON ioc (io-thread-confined
                    // state). If ioc is already stopped (shutdown) this handler
                    // simply never runs -> the poll stops cleanly.
                    boost::asio::post(ioc,
                        [ok, tip = std::move(tip), tip_dedup, fire_refresh,
                         tip_timer, tip_tick]() {
                            if (ok && !tip.empty()) {
                                if (tip_dedup->last().empty()) {
                                    // Startup baseline: this is the tip we are
                                    // already mining, not a change — seed the
                                    // dedup, do NOT notify.
                                    tip_dedup->set_last(tip);
                                } else {
                                    fire_refresh(tip, "tip-poll",
                                                 "template refresh + notify");
                                }
                            }
                            tip_timer->expires_after(std::chrono::seconds(3));
                            tip_timer->async_wait(*tip_tick);
                        });
                });
        };
        tip_timer->expires_after(std::chrono::seconds(3));
        tip_timer->async_wait(*tip_tick);
        std::cout << "[run] fallback-arm tip-poll ARMED (dashd getbestblockhash "
                     "every 3 s on a dedicated RPC thread -> event-driven template "
                     "refresh + clean_jobs notify on tip change; io thread never "
                     "blocks on dashd)\n";

        // PRIMARY: dashd ZMQ `hashblock` INSTANT tip-notify (opt-in). Absent or
        // uncompiled => the poll above is the sole active path (zero regression).
        if (coin_zmq_hashblock.empty()) {
            std::cout << "[run] ZMQ hashblock tip-notify NOT configured "
                         "(--coin-zmq-hashblock unset); the 3 s poll is the "
                         "active tip-notify path\n";
        } else {
#ifdef C2POOL_ZMQ
            // Every hashblock frame is a genuine new-block event. Hop onto the
            // io_context thread before touching ws/ss (fire_refresh contract);
            // the shared dedup coalesces it against the poll on the same block.
            zmq_sub = std::make_unique<dash::coin::ZmqHashblockSubscriber>(
                coin_zmq_hashblock,
                [&ioc, fire_refresh](const std::string& hash_hex) {
                    boost::asio::post(ioc, [fire_refresh, hash_hex]() {
                        fire_refresh(hash_hex, "zmq hashblock",
                                     "instant template refresh + notify");
                    });
                });
            zmq_sub->start();
            std::cout << "[run] ZMQ hashblock tip-notify ARMED at "
                      << coin_zmq_hashblock
                      << " (PRIMARY instant tip-notify; 3 s poll is the "
                         "backstop; reconnects if dashd ZMQ is down)\n";
#else
            std::cout << "[run] --coin-zmq-hashblock " << coin_zmq_hashblock
                      << " requested but this build has no libzmq (C2POOL_ZMQ "
                         "off); the 3 s poll is the active tip-notify path\n";
#endif
        }
    }

    // ── HTTP cache refresh timer (main_ltc.cpp:7343 parity) ──────────────
    // Every 2 s rebuild all zero-arg dashboard caches on the io_context thread
    // so the WebServer's HTTP thread reads pre-computed RCU snapshots instead of
    // racing think() on the live peer/tracker containers. Pairs with the
    // mi->set_io_context(&ioc) wired at web-server standup; only armed when the
    // dashboard is enabled (web_port != 0 → web_server present). The initial
    // populate gives the dashboard data on the first HTTP hit instead of the
    // CacheEntry default-constructed value. Display/liveness only — touches no
    // share/consensus/subsidy/payout path.
    if (web_server) {
        auto* cache_mi = web_server->get_mining_interface();
        auto cache_timer = std::make_shared<io::steady_timer>(ioc);
        auto cache_tick =
            std::make_shared<std::function<void(const boost::system::error_code&)>>();
        *cache_tick = [cache_timer, cache_tick, cache_mi](
                          const boost::system::error_code& ec) {
            if (ec) return;   // cancelled at shutdown
            cache_mi->refresh_http_caches();
            cache_timer->expires_after(std::chrono::seconds(2));
            cache_timer->async_wait(*cache_tick);
        };
        cache_mi->refresh_http_caches();   // initial populate
        cache_timer->expires_after(std::chrono::seconds(2));
        cache_timer->async_wait(*cache_tick);

        // ── Stats persistence timer (main_ltc.cpp:7429 parity) ───────────
        // Save the stat_log every 100 s (matches p2pool graph_db cadence) so a
        // hard kill loses at most ~100 s of history. Reuses cache_mi/ioc; the
        // timer self-cancels at shutdown. Display/history only.
        auto stats_timer = std::make_shared<io::steady_timer>(ioc);
        auto stats_tick =
            std::make_shared<std::function<void(const boost::system::error_code&)>>();
        *stats_tick = [stats_timer, stats_tick, cache_mi](
                          const boost::system::error_code& ec) {
            if (ec) return;   // cancelled at shutdown
            cache_mi->save_stat_log();
            stats_timer->expires_after(std::chrono::seconds(100));
            stats_timer->async_wait(*stats_tick);
        };
        stats_timer->expires_after(std::chrono::seconds(100));
        stats_timer->async_wait(*stats_tick);

        // ── Post-broadcast found-block confirmation / orphan lane ──────────
        // WHY: DASH wired NONE of set_block_verify_fn / schedule_block_
        // verification (LTC wires both, main_ltc.cpp:2105/3013/4258/6315), so a
        // DASH found block sat "pending" on the dashboard forever and orphans
        // (e.g. hotel 2508008) were found by humans, not the board. This arms
        // the poller: verify_found_block fires the verdict fn at +30/+150/… s
        // and flips the row to confirmed/orphaned.
        //
        // TELEMETRY ONLY. Runs strictly AFTER submission; touches no submit,
        // mint, target or payout path. The pre-broadcast payee guard
        // (work_source.cpp) remains the sole consensus gate — a wrong verdict
        // here can only mislabel a dashboard row, never a broadcast.
        //
        // DAEMONLESS-FIRST (rule 4): the embedded X11+DGW header chain answers
        // "which block won height h" from its own best branch, so orphan/confirm
        // resolve with NO dashd. dashd getblockheader is used only as a fallback
        // when the header chain is absent (pure --coin-rpc arm). The found block
        // height comes from our own record (get_found_blocks) — authoritative
        // even for an orphan whose header peers never relayed to us.
        cache_mi->set_block_verify_fn(
            [hc = header_chain.get(), rp = rpc.get(), mi = cache_mi](
                const std::string& hash_hex) -> int {
                uint256 h;
                h.SetHex(hash_hex);

                // Recorded mint height for this hash (authoritative for orphans).
                uint32_t found_height = 0;
                bool have_height = false;
                for (const auto& b : mi->get_found_blocks()) {
                    if (b.hash == hash_hex) {
                        found_height = static_cast<uint32_t>(b.height);
                        have_height = true;
                        break;
                    }
                }

                // Daemonless arm: resolve against the embedded header chain.
                if (hc) {
                    if (!have_height) {
                        if (auto e = hc->get_header(h)) {
                            found_height = e->height;
                            have_height = true;
                        }
                    }
                    if (have_height) {
                        auto winner_at =
                            [hc](uint32_t hh) -> std::optional<uint256> {
                                if (auto e = hc->get_header_by_height(hh))
                                    return e->hash;
                                return std::nullopt;
                            };
                        return dash::coin::block_confirm::resolve_status(
                            winner_at, hc->height(), h, found_height);
                    }
                    // header chain present but height unknown → still pending
                    return 0;
                }

                // Fallback arm (no embedded chain): dashd getblockheader.
                // dashd reports confirmations = -1 for a block off the active
                // chain (orphaned), >=1 while it is on the best chain.
                if (rp) {
                    try {
                        auto j = rp->getblockheader(h, /*verbose=*/true);
                        if (j.contains("confirmations") &&
                            j["confirmations"].is_number()) {
                            int c = j["confirmations"].get<int>();
                            if (c < 0) return -1;   // off active chain → orphaned
                            if (c >= static_cast<int>(
                                    dash::coin::block_confirm::kDefaultConfirmDepth))
                                return c;           // buried enough → confirmed
                        }
                    } catch (...) { /* unreachable/unknown → pending */ }
                }
                return 0;
            });
        std::cout << "[run] found-block confirmation/orphan lane ARMED "
                     "(daemonless header-chain verdict"
                  << (rpc ? " + dashd getblockheader fallback" : "")
                  << ")\n";
    }

    // ════════════════════════════════════════════════════════════════════════
    // DIAGNOSTIC TICK — telemetry only, no serve/arm/consensus effect
    // ════════════════════════════════════════════════════════════════════════
    //
    // Everything below exists because of a specific incident on 2026-08-04/05
    // where the answer was in the node's head and not in its log:
    //
    //   • [LANE-WATCHDOG] — the MN-CKPT bridge froze on BOTH .211 and contabo
    //     right after a completed on-demand PoSe fold (h=2514874, h=2516862)
    //     for 11-12 minutes with NO warning, because the stall probe lived
    //     inside pump() below its own early returns and was driven by tip
    //     changes. THIS timer is the independent path: it cannot be skipped by
    //     the condition it is watching.
    //   • [EMBED-STATUS] — "why is this node not serving?" took grepping four
    //     different markers. The gate names its cause when it DECLINES a
    //     template (#1038/#1039); this is the standing-state complement, so the
    //     question is answerable without provoking a decline.
    //   • [BLOCK-LEDGER] — block h=2516911 was won and accepted by the chain,
    //     and NEITHER hotel node's log showed it: the primary's log had been
    //     rotated that morning and the reserve had restarted. Counting our own
    //     blocks by grepping a rotated, restart-truncated log produced two
    //     wrong answers in ten minutes. This line is sourced from the found-
    //     blocks DB (persistent) instead of from log history, so a rotated log
    //     loses the scrollback and the NEXT line still prints the true totals.
    {
        namespace ddiag = dash::coin::diag;
        auto* diag_mi = web_server ? web_server->get_mining_interface() : nullptr;

        // ── WON-BLOCK VERDICT: ALREADY WIRED ON MASTER ─────────────────────
        // An earlier revision of this branch wired add_chain_verify_fn("DASH")
        // here, because main_dash had never called set_block_verify_fn /
        // schedule_block_verification and every DASH block ever won sat at
        // status=pending forever. That gap is now CLOSED ON MASTER by the
        // post-broadcast block-confirm lane (block_confirm::resolve_status +
        // its KAT), which resolves orphan/confirm off the embedded header
        // chain and falls back to dashd getblockheader. Re-adding a
        // per-chain verifier here would SHADOW it — verify_found_block
        // prefers m_chain_verify_fns[chain] over m_block_verify_fn — so this
        // branch deliberately wires NOTHING on that path and keeps only the
        // ledger telemetry below. The verdicts themselves are logged by that
        // lane; the periodic line here is the rotation-proof standing count.

        auto diag_timer = std::make_shared<io::steady_timer>(ioc);
        auto diag_tick =
            std::make_shared<std::function<void(const boost::system::error_code&)>>();
        auto ticks   = std::make_shared<uint64_t>(0);
        // Shape-keyed suppressor: [EMBED-STATUS] is emitted whenever the SHAPE
        // of the state changes (arm, cause, the precondition bits, the MN
        // source) and otherwise once per heartbeat, carrying suppressed=N. The
        // numeric cursors ride the line but are NOT part of the key — they move
        // every block, and keying on them would turn a status line into a
        // flood. Same policy the serve-gate journal (#1038) already applies.
        auto embed_shape = std::make_shared<std::string>();
        auto embed_since = std::make_shared<uint64_t>(0);
        auto embed_last  = std::make_shared<int64_t>(0);

        *diag_tick = [diag_timer, diag_tick, ticks, diag_mi, embed_shape,
                      embed_since, embed_last, &node_coin_state, &maintainer,
                      &header_chain, &mn_ckpt_lane](
                         const boost::system::error_code& ec) {
            if (ec) return;   // cancelled at shutdown
            ++*ticks;

            // ── 1. LANE WATCHDOG (every tick) ───────────────────────────
            if (mn_ckpt_lane) mn_ckpt_lane->watchdog_tick();

            // ── 2. EMBED-STATUS (every 2nd tick = 60 s) ─────────────────
            if ((*ticks % 2) == 0) {
                const auto d = node_coin_state.describe_decline();
                const int  ht = node_coin_state.have_tip_dbg();
                const int  hm = node_coin_state.have_mn_dbg();
                const char* src =
                    maintainer && !maintainer->mn_source().empty()
                        ? maintainer->mn_source().c_str()
                        : "n/a";
                const bool dmnless =
                    maintainer
                    && maintainer->mn_source_daemonless();
                const int32_t bcl = node_coin_state.best_cl_height();
                const int32_t cp  = node_coin_state.credit_pool_height();
                std::ostringstream shape;
                shape << (d.viable ? "serve" : "decline") << '|' << d.cause
                      << '|' << ht << hm << '|' << src << '|'
                      << (node_coin_state.have_sml() ? 1 : 0) << '|'
                      << (node_coin_state.mn_needs_reseed() ? 1 : 0) << '|'
                      << (node_coin_state.tip_body_pending_dbg() ? 1 : 0) << '|'
                      << (mn_ckpt_lane ? mn_ckpt_lane->state_name() : "none");
                const int64_t now = ddiag::steady_now_ms();
                const bool changed = shape.str() != *embed_shape;
                // 5-minute heartbeat: an UNCHANGED state must still prove it is
                // being observed, or "quiet" and "dead" look the same again.
                const bool heartbeat = (now - *embed_last) >= 300000;
                if (changed || heartbeat) {
                    LOG_INFO
                        << "[EMBED-STATUS]"
                        << " arm=" << (d.viable ? "would-serve" : "would-decline")
                        << " cause=" << (d.viable ? std::string("none") : d.cause)
                        << " value=" << d.value << " threshold=" << d.threshold
                        << " populated=" << (node_coin_state.populated() ? 1 : 0)
                        << " have_tip=" << (ht < 0 ? std::string("n/a")
                                                   : std::to_string(ht))
                        << " have_mn=" << (hm < 0 ? std::string("n/a")
                                                  : std::to_string(hm))
                        << " mn_source=" << src
                        << " mn_daemonless=" << (dmnless ? 1 : 0)
                        << " payee_cursor="
                        << node_coin_state.mnstates().last_applied_height() << "/"
                        << (header_chain ? header_chain->height() : 0)
                        << " mn_entries=" << node_coin_state.mnstates().size()
                        << " sml=" << (node_coin_state.have_sml() ? "ok" : "absent")
                        << " sml_h="
                        << (maintainer ? maintainer->sml_current_height() : 0)
                        << " quorums=" << node_coin_state.qmgr().active_count()
                        << " bestcl=" << (bcl > 0 ? std::to_string(bcl)
                                                  : std::string("n/a"))
                        << " creditpool=" << (cp >= 0 ? std::to_string(cp)
                                                      : std::string("n/a"))
                        << " reseed_latch="
                        << (node_coin_state.mn_needs_reseed() ? 1 : 0)
                        // Body-first transient (landed on master after this
                        // branch point): a known-newer header tip whose block
                        // body / tip-targeted cbTx has not been parsed yet. It
                        // is the normal ~1-2 s propagation window, and naming
                        // it here stops a refusal inside it reading as a
                        // header-sync fault.
                        << " tip_body_pending="
                        << (node_coin_state.tip_body_pending_dbg() ? 1 : 0)
                        << " bridge="
                        << (mn_ckpt_lane ? mn_ckpt_lane->state_name() : "none")
                        << " bridge_cursor="
                        << (mn_ckpt_lane ? mn_ckpt_lane->cursor_height() : 0)
                        // #91: is this process finishing a previous one's
                        // replay, or redoing it? It is the first thing worth
                        // knowing when a restart is slow, and before this the
                        // only way to tell was to time it.
                        << " bridge_cursor_src="
                        << (!mn_ckpt_lane
                                ? std::string("none")
                                : (mn_ckpt_lane->cursor_restored()
                                       ? "resumed@h="
                                             + std::to_string(
                                                   mn_ckpt_lane->restored_at())
                                       : std::string("cold")))
                        << " bridge_wait="
                        << (mn_ckpt_lane ? mn_ckpt_lane->waiting_for()
                                         : std::string("n/a"))
                        << " hdr_tip=" << (header_chain ? header_chain->height() : 0)
                        << " trigger=" << (changed ? "shape-change" : "heartbeat")
                        << " suppressed=" << *embed_since;
                    *embed_shape = shape.str();
                    *embed_last  = now;
                    *embed_since = 0;
                } else {
                    ++*embed_since;
                }
            }

            // ── 3. BLOCK-LEDGER (every 10th tick = 300 s) ───────────────
            if (diag_mi && (*ticks % 10) == 0) log_block_ledger(diag_mi);

            diag_timer->expires_after(std::chrono::seconds(30));
            diag_timer->async_wait(*diag_tick);
        };
        // ONE ledger line immediately at standup, so a freshly rotated or
        // freshly restarted log carries the true persistent totals from its
        // first minute rather than only after five.
        if (diag_mi) log_block_ledger(diag_mi);
        diag_timer->expires_after(std::chrono::seconds(30));
        diag_timer->async_wait(*diag_tick);
    }

    // ═════════════════════════════════════════════════════════════════════
    // MN-CKPT EVENT-DRIVEN BODY RE-REQUEST — a FAST timer, off the tip clock
    // ═════════════════════════════════════════════════════════════════════
    //
    // The anchor->tip fold self-drives at burst rate as long as bodies arrive
    // contiguously (on_block_connected tops up the window per applied block).
    // But once the header chain has caught the tip — which on a cut cold start
    // it does long before the fold finishes — pump() (HeaderChain::
    // on_tip_changed) fires only on a NEW block, ~2.5 min apart on mainnet. A
    // body dropped or starved mid-window then stalls the forward-contiguous
    // cursor for a whole tip interval before pump()'s stall probe re-asks it,
    // collapsing the fold onto ~1 block per tip. This 3 s timer re-drives the
    // request window FROM THE CURSOR the moment it sees no progress — the
    // cut-cold-path analog of #1162, recovering a starved window in seconds
    // instead of ~2.5 min. FETCH-timing only (see service_tick's contract): it
    // issues getdata and nothing else, so the derived MN/quorum/credit bytes
    // and every reward-safety hold on publish() are untouched. Dormant unless
    // the lane is armed on the daemonless path; a no-op while Waiting/Published.
    io::steady_timer mn_service_timer(ioc);
    auto mn_service_tick =
        std::make_shared<std::function<void(const boost::system::error_code&)>>();
    *mn_service_tick =
        [&mn_service_timer, mn_service_tick, &mn_ckpt_lane](
            const boost::system::error_code& ec) {
            if (ec) return;   // cancelled at shutdown
            if (mn_ckpt_lane) mn_ckpt_lane->service_tick();
            mn_service_timer.expires_after(std::chrono::seconds(3));
            mn_service_timer.async_wait(*mn_service_tick);
        };
    mn_service_timer.expires_after(std::chrono::seconds(3));
    mn_service_timer.async_wait(*mn_service_tick);

    // ═════════════════════════════════════════════════════════════════════
    // SERVE-STALENESS SENTINEL — REPORT-ONLY (2026-08-07 dead-height incident)
    // ═════════════════════════════════════════════════════════════════════
    //
    // On 2026-08-07 this node handed h=2518006 to 26 rigs for ONE HOUR while
    // dashd advanced to h=2518028, and nothing said so. The catalogue of why
    // every existing signal was structurally unable to fire lives at the top of
    // impl/dash/coin/serve_staleness.hpp; the short version is that all of them
    // compare the node against ITSELF, and the [EMBED-STATUS] line that would
    // have carried the news is a steady_timer on `ioc` — the very thread that
    // pegged, so it stopped printing.
    //
    // Two pieces stand up here:
    //
    //   1. A 1 s heartbeat timer ON `ioc`. Its only job is to prove the io
    //      thread can still write a number. It ALSO mirrors, from the io thread
    //      where those reads are safe, the two values the sentinel would
    //      otherwise have to race for: an independently observed height and the
    //      attached-session count. The sentinel then dereferences NOTHING but
    //      atomics.
    //
    //   2. A DEDICATED sentinel thread. Not an ioc timer, and this is the whole
    //      point — diag::StallWatchdog's own contract (coin/lane_diag.hpp:
    //      209-219) says a stall detector must not live on the path it watches,
    //      and half of what this detects is that path dying.
    //
    // REPORT-ONLY: the outputs are a LOG_ERROR line and a JSON field on the
    // existing /api/node_topology surface. There is no code path from an alarm
    // to a serve decision, an arm flip, or a template byte. A false positive
    // costs a page; a blocking detector's false positive would cost 26 rigs an
    // outage, which is strictly worse than the failure it guards.
    //
    // HEIGHT SOURCE — a deliberate deviation from the approved plan, stated
    // plainly. The plan called for `dashd getblockcount` on the sentinel's own
    // dedicated NodeRPC connection. That is NOT wired here, because:
    //   * reusing the SHARED NodeRPC is a data race, not merely contention:
    //     NodeRPC::CallAPIMethod takes no lock at all, and blockcount_cached()
    //     mutates the plain non-atomic members m_blockcount_cache /
    //     m_blockcount_cache_at (impl/dash/coin/rpc.hpp:110-111). Adding a race
    //     on the money path in order to detect a freeze is the wrong trade.
    //   * a SECOND dashd connection was already an open question in the plan
    //     (hotel auth / connection limits) and is not something to answer by
    //     assumption on a production node.
    // So the independent reference is the PEER-ADVERTISED height —
    // HeaderChain::peer_tip_height(), a relaxed atomic that already existed and
    // is already fed from the coin-p2p peer-height callback. It is genuinely
    // from outside this process, which is the property that matters.
    //
    // AND IT IS THE ONLY ELIGIBLE SOURCE. There is deliberately NO fallback to
    // our own header tip. set_peer_tip_height is wired only inside the coin_p2p
    // block below, and header_chain is only constructed when coin_p2p exists —
    // so on a node without coin-p2p there is no outside height at all, and an
    // `hdr` fallback would have quietly turned D2 into the node comparing
    // itself against itself. That is the exact class of check this lane's
    // catalogue condemns in (b), (c) and (d): it would have read "served ==
    // observed, healthy" for every minute of the incident. D2 REFUSES to run
    // instead, and /api/node_topology publishes
    // serve_staleness.d2 = "unavailable-no-independent-reference" so the refusal
    // is visible rather than indistinguishable from a clean bill of health.
    //
    // The honest consequence, recorded rather than hidden: BOTH mirrors are
    // written on `ioc`, so in a full io freeze they stop advancing and D2 goes
    // blind — D1 is the sub-check that fires in THIS incident, D2 is the
    // generalisation, and the status surface names which one raised.
    std::shared_ptr<std::atomic<int64_t>>  ss_beat;
    std::shared_ptr<std::atomic<uint32_t>> ss_obs_h;
    std::shared_ptr<std::atomic<int>>      ss_obs_src;
    std::shared_ptr<std::atomic<uint32_t>> ss_sessions;
    std::shared_ptr<std::atomic<bool>>     ss_stop;
    std::thread                            ss_thread;
    if (serve_staleness_sentinel && work_source) {
        namespace ddiag = dash::coin::diag;
        ss_beat     = std::make_shared<std::atomic<int64_t>>(ddiag::steady_now_ms());
        ss_obs_h    = std::make_shared<std::atomic<uint32_t>>(0);
        ss_obs_src  = std::make_shared<std::atomic<int>>(0);
        ss_sessions = std::make_shared<std::atomic<uint32_t>>(0);
        ss_stop     = std::make_shared<std::atomic<bool>>(false);

        auto hb_timer = std::make_shared<io::steady_timer>(ioc);
        auto hb_tick  =
            std::make_shared<std::function<void(const boost::system::error_code&)>>();
        *hb_tick = [hb_timer, hb_tick, ss_beat, ss_obs_h, ss_obs_src, ss_sessions,
                    hc = header_chain.get(), ssrv = stratum_server.get()](
                       const boost::system::error_code& ec) {
            if (ec) return;   // cancelled at shutdown
            // The liveness proof itself. Deliberately the FIRST thing the
            // handler does: if the queue is drained late, the beat is late, and
            // that lateness is exactly the measurement.
            ss_beat->store(ddiag::steady_now_ms(), std::memory_order_relaxed);

            // Mirrors, taken here because THIS is the thread on which reading
            // them is safe.
            //
            // THE ONLY ELIGIBLE SOURCE IS peer_tip_height() — a height that
            // came from OUTSIDE this process. Our own header tip is NOT a
            // fallback and must never be one: hc->peer_tip_height() is fed only
            // from the coin-p2p peer-height callback (set_peer_tip_height,
            // below in the coin_p2p block) and header_chain itself is only
            // constructed when coin_p2p exists, so on a node without coin-p2p
            // there is no outside height at all. Falling back to hc->height()
            // there would have made D2 compare the node against ITSELF — the
            // exact defect this lane's own header condemns, and it would have
            // reported "served == observed, healthy" for the whole incident
            // hour. 0/none means D2 does not run, and the surface says so.
            uint32_t obs = 0;
            int      src = 0;
            if (hc) {
                const uint32_t peer = hc->peer_tip_height();
                if (peer > 0) { obs = peer; src = 2; }          // "peer"
            }
            ss_obs_h->store(obs, std::memory_order_relaxed);
            ss_obs_src->store(src, std::memory_order_relaxed);
            if (ssrv)
                ss_sessions->store(
                    static_cast<uint32_t>(ssrv->get_session_count()),
                    std::memory_order_relaxed);

            hb_timer->expires_after(std::chrono::seconds(1));
            hb_timer->async_wait(*hb_tick);
        };
        hb_timer->expires_after(std::chrono::seconds(1));
        hb_timer->async_wait(*hb_tick);

        ss_thread = std::thread(
            [ss_beat, ss_obs_h, ss_obs_src, ss_sessions, ss_stop,
             ws = work_source]() {
                dash::coin::ServeStalenessSentinel sen{
                    dash::coin::ServeStalenessConfig{}};
                const auto src_name = [](int i) {
                    switch (i) {
                        case 1:  return "rpc";
                        case 2:  return "peer";
                        case 3:  return "hdr";
                        default: return "none";
                    }
                };
                // INDEPENDENT means "not from inside this process". Only the
                // peer-advertised height qualifies today; "hdr" is our own tip
                // and is listed here solely so that if a future source is
                // wired it has to declare which side of this line it is on.
                const auto src_independent = [](int i) {
                    return i == 1 || i == 2;   // rpc (separate daemon) | peer
                };
                while (!ss_stop->load(std::memory_order_relaxed)) {
                    // ~15 s poll, slept in 100 ms slices so shutdown is prompt
                    // rather than up to a poll-period late.
                    for (int i = 0;
                         i < 150 && !ss_stop->load(std::memory_order_relaxed);
                         ++i)
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    if (ss_stop->load(std::memory_order_relaxed)) break;

                    dash::coin::ServeStalenessSample s;
                    s.now_ms          = dash::coin::diag::steady_now_ms();
                    s.io_heartbeat_ms = ss_beat->load(std::memory_order_relaxed);
                    s.served_height   = ws->last_served_height();
                    s.served_at_ms    = ws->last_served_at_ms();
                    const int obs_src_i =
                        ss_obs_src->load(std::memory_order_relaxed);
                    s.observed_height = ss_obs_h->load(std::memory_order_relaxed);
                    s.observed_src    = src_name(obs_src_i);
                    s.observed_independent = src_independent(obs_src_i);
                    s.sessions        = ss_sessions->load(std::memory_order_relaxed);

                    const auto v = sen.poll(s);

                    // Publish EVERY poll, not only the alarming ones: the
                    // status surface must be able to say "checked N seconds
                    // ago and it was fine", because "quiet" and "dead" looking
                    // identical is the defect this whole lane exists to close.
                    //
                    // And publish the STANDING verdict, not just D2's. In the
                    // incident as it truly presented, the io thread was pegged,
                    // so BOTH ioc-written mirrors froze and D2 went blind while
                    // D1 raised correctly every minute. A surface carrying D2
                    // alone reported `stale: false` for the entire hour that the
                    // log was printing [STALE-SERVE] check=io-silence.
                    dash::stratum::DASHWorkSource::ServeStalenessReport rep;
                    rep.observed_height = s.observed_height;
                    rep.observed_at_ms  = s.io_heartbeat_ms;
                    rep.observed_src    = s.observed_src;
                    rep.d2_armed        = v.d2_armed;
                    rep.stale           = v.stale;
                    rep.stale_check =
                        dash::coin::stale_serve_check_name(v.stale_check);
                    rep.stale_age_ms    = v.stale_age_ms;
                    rep.io_silent_ms    = v.io_silent_ms;
                    rep.skew_age_ms     = v.skew_age_ms;
                    rep.serve_quiet_ms  = v.serve_quiet_ms;
                    ws->note_serve_observation(rep);
                    if (v.fired) LOG_ERROR << v.line;
                }
            });
        std::cout << "[run] serve-staleness sentinel ARMED (report-only, "
                     "dedicated poller, --serve-staleness-sentinel=off to "
                     "disable)\n";
    } else if (!serve_staleness_sentinel) {
        std::cout << "[run] serve-staleness sentinel DISABLED by flag — a dead "
                     "height served to miners will NOT be alarmed\n";
    }

    std::cout << "[run] run-loop up (Ctrl-C to stop); won blocks relay DUAL-PATH:\n"
                 "[run]   ARM A embedded coin-P2P relay (primary, daemonless) = "
              << (p2p_relay ? "ARMED" : (no_p2p_relay ? "SUPPRESSED (--no-p2p-relay)"
                                                       : "off (no --coin-p2p-connect peer)"))
              << "\n[run]   ARM B dashd submitblock RPC backup = "
              << (rpc_submit ? "ARMED" : "off (no dashd creds)") << "\n";
    // #755 guard (btc main_btc.cpp:1309-1315 parity): an exception escaping an
    // io handler must NOT terminate the node (Exit 134 core-dump — e.g. a
    // chain-walk throw over unrooted persisted shares after a partial join).
    // Log + resume; after an escaped exception the io_context is NOT stopped,
    // so run() continues with the remaining handlers. Ctrl-C still exits via
    // the signal handler's ioc.stop() → run() returns normally → break.
    for (;;) {
        try {
            ioc.run();
            break;
        } catch (const std::exception& e) {
            LOG_ERROR << "[run] io handler exception (non-fatal, #755 guard): "
                      << e.what();
            std::cout << "[run] io handler exception (non-fatal): " << e.what()
                      << "\n";
        } catch (...) {
            LOG_ERROR << "[run] io handler exception (non-fatal, #755 guard): "
                         "unknown error";
        }
    }

    // W2 replay lane: force-persist the delivered high-water cursor so a
    // clean shutdown resumes exactly where it stopped (a crash costs at most
    // cursor_persist_every blocks of re-fetch). Timer callbacks no longer
    // fire — ioc.run() has returned.
    // Serve-staleness sentinel: stop and JOIN its thread FIRST, before anything
    // it can touch unwinds. It holds a shared_ptr to work_source (so the
    // pointer cannot dangle) and otherwise reads only shared_ptr'd atomics, but
    // joining here also guarantees no [STALE-SERVE] line is emitted after the
    // log surface starts tearing down. The 100 ms sleep slices bound this wait
    // at ~100 ms, not at a full 15 s poll period. Its ioc heartbeat timer is
    // already dead: ioc.run() has returned.
    if (ss_stop) ss_stop->store(true, std::memory_order_relaxed);
    if (ss_thread.joinable()) ss_thread.join();

    if (replay_timer) replay_timer->stop();
    if (replay_lane) replay_lane->flush();

    // Save stats on shutdown (main_ltc.cpp:7457 parity): flush the final
    // stat_log so the last window survives the restart. mi still valid here —
    // run() has returned but web_server/mining-interface teardown is below.
    if (web_server) web_server->get_mining_interface()->save_stat_log();

    // Stop the ZMQ hashblock subscriber (joins its thread) BEFORE the stratum
    // acceptor + work source it refreshes are torn down. Its callback only posts
    // onto the now-stopped ioc, so no refresh can run past here.
#ifdef C2POOL_ZMQ
    if (zmq_sub) {
        zmq_sub->stop();
        zmq_sub.reset();
    }
#endif

    // io-thread-decouple: join the background RPC pool, before any of the
    // objects it dereferences (rpc / work_source / stratum_server) unwind. run()
    // has returned (ioc stopped), so no NEW work is posted; stop()+join() waits
    // out any in-flight getbestblockhash/GBT re-source (bounded by the NodeRPC
    // socket timeout) so no pool thread ever touches freed state. Any post-back
    // to the stopped ioc simply never executes.
    if (rpc_pool) {
        rpc_pool->stop();
        rpc_pool->join();
    }

    // #1133 teardown-order fix (fault 2): drain the sharechain node's OWN compute
    // pools (m_verify_pool X11 share-verify + m_think_pool run_think/clean
    // election) HERE — right after ioc.run() returns and BEFORE stratum_server /
    // oracle_shadow / web_server unwind — for the SAME reason rpc_pool is joined
    // just above. p2p_node is declared FIRST (:998) so ~Node would otherwise run
    // LAST, joining these pools only after every object a still-in-flight
    // verify/think task can reach (the tracker's callback targets, the work
    // refresh bound off m_on_best_share_changed) is already freed. run() has
    // returned (ioc stopped) so no NEW task is posted; stop()+join() waits out
    // the in-flight tail against still-live state. Any post-back to the stopped
    // ioc simply never executes. Idempotent with the ~NodeImpl belt below.
    p2p_node.join_compute_pools();

    // Tear the acceptor + sessions down while the work source and node_coin_state
    // it references are still alive -- explicit reset keeps destruction order safe
    // (stratum_server was declared before them, so it would otherwise outlive them).
    stratum_server.reset();

    // Join the oracle-shadow worker thread BEFORE node_coin_state / rpc unwind:
    // the worker dereferences both (select_work + getwork/proposal), and
    // oracle_shadow is declared earlier than node_coin_state so it would
    // otherwise outlive it. ioc.run() has returned, so no further new_tip fires.
    if (oracle_shadow) oracle_shadow.reset();

    // Join the shadow-compare worker BEFORE rpc unwinds: its worker thread
    // dereferences rpc (getwork oracle). Dropping work_source's ref here runs the
    // probe's dtor (which joins the worker) while rpc is still alive. ioc.run()
    // has returned, so no further template re-source can enqueue a new job.
    if (work_source) work_source->set_shadow_compare(nullptr);

    // Stop the dashboard BEFORE p2p_node unwinds: its callbacks hold a raw
    // dash::Node* and the HTTP thread must be joined while that is still valid.
    if (web_server) {
        web_server->stop();
        web_server.reset();
    }

    // Flush pending sharechain persistence buffers (verified marks + removals).
    p2p_node.shutdown_persistence();

    std::cout << "[run] run-loop stopped cleanly\n";
    return 0;
}

// --mine-block: the slice-5 PRODUCER one-shot. Pull a block template (dashd
// getblocktemplate via NodeRPC::getwork), build the coinbase, X11-mine the
// 80-byte header over the nonce until it meets the compact-bits target,
// serialize the FULL block to hex, and feed it into the EXISTING submit arm
// (NodeRPC::submit_block_hex). This is the "c2pool-dash builds and wins the
// block itself" lever -- slice-4 only re-submitted a pre-built hex.
//
// Creds posture is IDENTICAL to --submit-block: endpoint via --coin-rpc, creds
// from dash.conf (never argv). The optional --payout-pubkey-hash HEX (40 hex =
// 20 bytes) names the block-finder P2PKH payout; default all-zero placeholder
// (genesis-style: empty PPLNS weights, total_weight 0). max_nonce is bounded;
// regtest bits (0x207fffff) make the target trivial so a winner is found fast.
int run_mine_block(bool testnet, const std::string& rpc_endpoint,
                   const std::string& rpc_conf_path,
                   const std::string& payout_pkh_hex,
                   uint64_t max_nonce)
{
    namespace io = boost::asio;

    dash::coin::RpcConf conf;
    std::string conf_path = rpc_conf_path;
    if (conf_path.empty()) {
        const char* home = std::getenv("HOME");
        conf_path = std::string(home ? home : ".") + "/.dashcore/dash.conf";
    }
    dash::coin::load_rpc_conf(conf_path, conf);
    dash::coin::apply_endpoint_override(rpc_endpoint, conf);
    if (conf.port == 0)
        conf.port = testnet ? 19998 : 9998;

    if (!conf.armed()) {
        std::cout << "[mine] submit arm UNARMED (no dash.conf creds / no port); "
                     "supply dashd creds via dash.conf or --coin-rpc-auth PATH\n";
        return 2;
    }

    io::io_context ioc;
    dash::interfaces::Node coin_state;
    dash::coin::NodeRPC rpc(&ioc, &coin_state, testnet);
    rpc.connect(NetService(conf.host, conf.port), conf.userpass());
    std::cout << "[mine] producer ARMED: NodeRPC -> " << conf.host << ":"
              << conf.port << " (creds from dash.conf)\n";

    // 1) Pull the template.
    std::cout << "[mine] fetching block template (getblocktemplate)...\n";
    // Work source (S8 embedded_gbt live-wire capstone): PREFER the locally
    // assembled embedded template via build_embedded_workdata, fall back to
    // dashd getblocktemplate. The dashd arm is RETAINED as fallback + the
    // [GBT-XCHECK] cross-check -- never removed.
    //
    // NOTE: NodeImpl does not yet hold the embedded coin-state (masternode
    // list + mempool + header tip) that build_embedded_workdata consumes, so
    // emb.has_state stays false here and the selector routes to the dashd
    // fallback today. Populating that in-process state is the flagged next
    // sub-slice; once it lands, set emb.has_state=true and the embedded arm
    // goes live with zero change to this call site.
    dash::coin::EmbeddedWorkInputs emb;   // has_state=false until node-held coin-state lands
    dash::coin::WorkSelection sel =
        dash::coin::select_dash_work(emb, [&]{ return rpc.getwork(); });
    dash::coin::DashWorkData work = std::move(sel.work);
    std::cout << "[mine] work source: "
              << (sel.source == dash::coin::WorkSource::Embedded
                      ? "EMBEDDED (build_embedded_workdata)"
                      : "dashd getblocktemplate (fallback)") << "\n";
    std::cout << "[mine] template: height=" << work.m_height
              << " bits=0x" << std::hex << work.m_bits << std::dec
              << " prev=" << work.m_previous_block.GetHex().substr(0, 16) << "..."
              << " ntx(gbt)=" << work.m_tx_data_hex.size()
              << " coinbase_value=" << work.m_coinbase_value << "\n";

    // 2) Build the coinbase. Genesis-style payout (no prior shares): empty
    //    weights, total_weight 0 -> all of worker_payout goes to the finder
    //    (this_script, 2% rule) + donation remainder.
    uint160 payout_pkh;   // default all-zero
    if (!payout_pkh_hex.empty()) {
        if (payout_pkh_hex.size() != 40) {
            std::cout << "[mine] --payout-pubkey-hash must be 40 hex chars (20 bytes)\n";
            return 2;
        }
        payout_pkh.SetHex(payout_pkh_hex);
    }
    const core::CoinParams params = dash::make_coin_params(testnet);
    std::map<std::vector<unsigned char>, uint64_t> empty_weights;
    auto tx_outs = dash::coinbase::compute_dash_payouts(
        work.m_coinbase_value, work.m_packed_payments, payout_pkh,
        empty_weights, /*total_weight=*/0, params);
    // ref_hash is the PPLNS commitment; for a standalone producer block we use
    // zero (no sharechain commitment) -- consensus-irrelevant to dashd validity.
    auto layout = dash::coinbase::build(
        work, tx_outs,
        /*coinbase_text=*/dash::SharechainConfig::coinbase_text(params.is_testnet),
        params, /*ref_hash=*/uint256::ZERO);
    std::cout << "[mine] coinbase built: " << layout.bytes.size()
              << " bytes, " << tx_outs.size() << " outputs\n";

    // 3) X11-mine.
    std::cout << "[mine] X11-mining header (max_nonce=" << max_nonce << ")...\n";
    dash::coin::MineResult mr =
        dash::coin::mine_block(work, layout.bytes, max_nonce);
    if (!mr.found) {
        std::cout << "[mine] NO winning nonce in [0, " << max_nonce
                  << "] -- raise --max-nonce or check bits\n";
        return 1;
    }
    std::cout << "[mine] WON: nonce=" << mr.nonce
              << " powhash=" << mr.block_hash.GetHex()
              << " block=" << (mr.block_hex.size() / 2) << " bytes\n";

    // 4) Submit via the EXISTING arm.
    const int64_t before = static_cast<int64_t>(
        rpc.getblockchaininfo().value("blocks", -1));
    std::cout << "[mine] getblockcount(before)=" << before << "\n";
    std::cout << "[mine] submitting mined block to dashd "
              << conf.host << ":" << conf.port << "...\n";
    const bool accepted = rpc.submit_block_hex(mr.block_hex, /*ignore_failure=*/false);
    const int64_t after = static_cast<int64_t>(
        rpc.getblockchaininfo().value("blocks", -1));
    std::cout << "[mine] submitblock " << (accepted ? "ACCEPTED" : "REJECTED")
              << " by dashd; block_hash=" << mr.block_hash.GetHex()
              << " getblockcount(after)=" << after
              << (after > before ? " (+1, tip advanced)\n" : "\n");
    return accepted ? 0 : 1;
}

} // namespace

int main(int argc, char** argv)
{
    // Mining-hotel interim fix #4: raise RLIMIT_NOFILE to 65536 at startup
    // (one fd per stratum/miner session + RPC + sharechain P2P; distro-default
    // 1024 starves the accept loop). Report the effective soft limit.
    {
        const uint64_t nofile = core::raise_nofile_limit(65536);
        if (nofile == 0)
            std::cout << "[init] RLIMIT_NOFILE: unsupported on this platform (or query failed)\n";
        else
            std::cout << "[init] RLIMIT_NOFILE soft limit: " << nofile
                      << (nofile < 65536 ? " (< 65536; hard limit too low)" : "") << "\n";
    }

    // Name the BLS backend unconditionally at startup: a stub (BLS-dark) node
    // is otherwise indistinguishable from an armed one until a DKG-window
    // height silently fails closed to the dashd fallback (no verifier => no
    // slot can ever be satisfied) -- which is how this fleet ran BLS-dark for
    // months without anyone noticing.
    std::cout << "[init] DASH BLS backend: "
              << (dash::coin::vendor::bls_backend_available()
                      ? "REAL (dashbls linked; quorum-commitment verify armed)"
                      : "STUB (fail-closed; commitment verify inert / BLS-dark)")
              << "\n";

    bool want_help = false;
    bool want_run  = false;
    bool want_mine = false;
    bool testnet   = false;
    std::string payout_pkh_hex;   // --payout-pubkey-hash HEX (20-byte P2PKH finder)
    uint64_t    max_nonce = 0xffffffffull;  // --max-nonce N (producer search bound)
    std::string rpc_endpoint;     // --coin-rpc / --coin-daemon HOST:PORT (endpoint only)
    std::string rpc_conf_path;    // --coin-rpc-auth PATH (creds; default ~/.dashcore/dash.conf)
    std::string submit_hex;       // --submit-block HEX (one-shot won-block submit)
    std::string submit_file;      // --submit-block-file PATH
    std::string listen_raw;                    // --listen [HOST:]PORT (sharechain bind)
    std::vector<std::string> addnode_raw;      // --addnode HOST:PORT (persistent outbound)
    std::vector<std::string> connect_raw;      // --connect HOST:PORT (connect-only)
    std::vector<std::string> coin_p2p_raw;     // --coin-p2p-connect HOST:PORT (repeatable; E1 opt-in coin-network dial)
    bool coin_p2p_discover = false;            // --coin-p2p-discover: DASH-isolated scored/diverse peer discovery (network-standalone arm; independent of local dashd)
    bool no_p2p_relay = false;                 // --no-p2p-relay: suppress the embedded P2P-relay won-block arm (A/B isolation; RPC backup stays live)
    bool embedded_mainnet = false;             // --embedded-mainnet: gate-lift, allow the daemonless embedded template arm on MAINNET (byte-parity proven; default OFF = dashd fallback)
    std::string coin_p2p_magic = "";           // --coin-p2p-magic HEX: override the embedded CoinClient wire magic (e.g. regtest fcc1b7dc); default mainnet/testnet
    // --coin-p2p-peers N: CONCURRENT embedded coin-P2P peers (default 8, cap 16).
    // EVIDENCE knob, not bandwidth: a DKG final commitment is announced exactly
    // ONCE and served only by commitment hash, so "we never heard it" is only
    // trustworthy in proportion to how many peers we were holding at the time.
    std::size_t coin_p2p_peers =
        dash::coin::p2p::CoinClient<dash::Config>::DEFAULT_POOL_PEERS;
    bool force_won_block = false;              // --regtest-force-won-block: fail-closed regtest E5 harness (drive one real won block through the run-path dual-path)
    bool embedded_superblock = false;          // --embedded-superblock: OPT-IN daemonless superblock payee sourcing via govsync (E-SUPERBLOCK); default OFF = superblock heights fall back to dashd (reward-safe)
    std::string stratum_host = "0.0.0.0";      // --stratum [HOST:]PORT bind interface (default all)
    uint16_t    stratum_port = 0;              // 0 disables the Stratum accept-loop; --stratum sets it
    bool embedded_utxo = false;                // --embedded-utxo: arm the E2b UTXO/fee lane (opt-in)
    // --embedded-utxo-immature-serve-empty: pure-daemonless OPT-IN. Default
    // OFF refuses every embedded template until the UTXO lane reaches
    // blocks_connected >= 106 (p2pool semantics: an unsynced node does not
    // serve templates; the dashd fallback serves full ones where armed).
    // With the flag, the immature window is served with a coinbase-only
    // body instead -- consensus-valid, fees exactly 0, nothing to overstate
    // (see NodeCoinState::set_utxo_immature_policy).
    bool embedded_utxo_immature_serve_empty = false;
    // --embedded-serve-mempool-txs: OPT-IN fee-carrying embedded templates.
    // Default OFF = coinbase-only serving (values exact, fees forgone); the
    // mempool-tx body path with its G1-G4 guards (mempool.hpp; audit
    // DASH_CONNECTBLOCK_REJECT_SURFACE_AUDIT.md) arms only on explicit
    // operator decision, and only once the MEMPOOL VALIDITY GATE
    // (mempool_validity_gate.hpp) reports zero transactions refused by dashd's
    // testmempoolaccept over its sustained window.
    bool embedded_serve_mempool_txs = false;
    bool embedded_accrue_asset_locks = false;  // #107 PHASE 2, default OFF
    bool embedded_accrue_asset_unlocks = false;  // #143 Variant B (type-9), default OFF
    // --embedded-creditpool-publish-at-serve-tip: publish the derived credit
    // pool AT THE SERVE TIP rather than at the folded body height (PR-5,
    // dashd GetCreditPool(pindexPrev) parity). MONEY PATH -> default OFF: it
    // makes the body-first arm SERVE serve-tip-based work in windows where it
    // currently refuses with `creditpool-stale`.
    bool embedded_creditpool_publish_at_serve_tip = false;
    std::string pin_local_tx_hex_path;
    bool pin_splice_xcheck_arm = false;
    bool pin_splice_block_budget = false;
    // --embedded-mempool-ingest: arm the coin-P2P MSG_TX pull (phase 1).
    // SEPARATE from --embedded-serve-mempool-txs on purpose: this only makes
    // the mempool FILL. Whether its contents ever reach a served template is
    // still the other flag's decision, and that one stays default-OFF until
    // the [MEMPOOL-VALIDITY] series says it is safe: ZERO transactions that
    // dashd's testmempoolaccept refuses, over a sustained window
    // (mempool_validity_gate.hpp). NOT the [SHADOW-TXSET] ours_only number --
    // that is a coverage statistic and gates nothing.
    bool embedded_mempool_ingest = false;
    // --embedded-null-arm (#127): optimistic null commitment at fresh
    // window-open slots + template upgrade to the real commitment. DEFAULT
    // OFF, money/consensus path; byte-unchanged when off (nullptr null_evidence).
    bool embedded_null_arm = false;
    // --embedded-ingest-isdlock: arm the coin-P2P MSG_ISDLOCK pull (G4
    // conflict-tx-lock feed). DEFAULT OFF — off, no getdata for inv type 31
    // and the handler decodes-and-discards (wire + template behaviour
    // byte-identical); on, every isdlock is still individually BLS-gated
    // before Mempool::add_islock (fail-closed at every hop).
    bool embedded_ingest_isdlock = false;
    std::string bestcl_policy = "freshness";   // --bestcl-policy: freshness (default, conservative proxy) | consensus-exact (dashcore's actual CheckCbTxBestChainlock rule)
    bool embedded_oracle_shadow = false;       // --embedded-oracle-shadow: per-block dashd cross-check (OBSERVE-only)
    bool embedded_shadow_compare = false;      // --embedded-shadow-compare: serve-vs-dashd template diff (OBSERVE-only, NOT a gate)
    // Serve-staleness sentinel (2026-08-07 dead-height incident): DEFAULT ON.
    // Report-only -- log line + JSON field, no serve effect -- so the kill flag
    // is ops hygiene, not a safety gate.
    bool serve_staleness_sentinel = true;
    uint64_t oracle_grad_blocks = 5000;        // --oracle-graduation-blocks N (consecutive clean)
    uint64_t oracle_class_coverage = 20;       // --oracle-class-coverage K (per height class)
    double dev_donation = 0.1;                 // --give-author (donation_percentage; README default 0.1%)
    std::string coinbase_text;                 // --coinbase-text (empty => network default from the SSOT)
    double node_owner_fee = 0.0;               // -f / --fee (node_owner_fee; default 0)
    std::string node_owner_address;            // --node-owner-address (fee destination)
    // Web dashboard (the EXISTING c2pool dashboard, same defaults as main_ltc.cpp:
    // http_port 8080, dashboard_dir "web-static"). Default-ON for --run.
    std::string web_host      = "0.0.0.0";     // --web-host bind interface
    uint16_t    web_port      = 8080;          // --web-port / --http-port (0 disables)
    std::string dashboard_dir = "web-static";  // --dashboard-dir static asset root
    std::string redistribute_mode = "pplns";   // --redistribute pplns|fee|boost|donate
    std::string coin_zmq_hashblock;             // --coin-zmq-hashblock ENDPOINT (opt-in dashd ZMQ hashblock instant tip-notify, e.g. tcp://127.0.0.1:28332)
    // Operator-supplied miner-facing host for the dashboard Stratum URL.
    // Empty => auto-detect the outbound public IP (current behaviour).
    std::string external_ip;                   // --external-ip / --stratum-advertise / --public-host
    // Optional encrypted authority message_data blob for local v36 shares +
    // dashboard transition-notice display (EMIT side, mirror of main_ltc.cpp).
    std::string operator_message_blob_hex;     // --message-blob-hex / --transition-message
    // ── FULL-HISTORY REPLAY W3: standalone UTXO fold utility surface ──────
    // Feature-flagged and serve-path-inert: when --replay-utxo-db is absent
    // nothing constructs the fold. Present, the process runs the standalone
    // status/hash utility and EXITS before any node/serve path starts (the
    // fold's block feed is the W2 bulk lane; wiring them is W5).
    std::string replay_utxo_db;        // --replay-utxo-db PATH (fold store)
    bool replay_utxo_hash = false;     // --replay-utxo-hash: compute hash_serialized_2
    std::string replay_utxo_expect;    // --replay-utxo-expect HEX (gate compare, exit code)
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            std::cout << "c2pool-dash " << C2POOL_VERSION << "\n";
            return 0;
        }
        else if (std::strcmp(argv[i], "--help") == 0)    want_help = true;
        else if (std::strcmp(argv[i], "--data-dir") == 0) {
            // Root all per-instance state (LevelDB sharechain, mn_state_db,
            // addr store, logs, ...) under PATH so co-located instances don't
            // contend the LevelDB LOCK. Default keeps ~/.c2pool. See #722.
            if (i + 1 >= argc || argv[i + 1][0] == '\0' || argv[i + 1][0] == '-') {
                std::cerr << "error: --data-dir requires a PATH argument\n";
                return 1;
            }
            core::filesystem::set_data_dir(argv[++i]);
        }
        else if (std::strcmp(argv[i], "--run") == 0)     want_run  = true;
        else if (std::strcmp(argv[i], "--mine-block") == 0) want_mine = true;
        else if (std::strcmp(argv[i], "--payout-pubkey-hash") == 0 && i + 1 < argc)
            payout_pkh_hex = argv[++i];
        else if (std::strcmp(argv[i], "--max-nonce") == 0 && i + 1 < argc)
            max_nonce = std::strtoull(argv[++i], nullptr, 0);
        else if (std::strcmp(argv[i], "--testnet") == 0 ||
                 std::strcmp(argv[i], "--regtest") == 0)  testnet = true;
        else if ((std::strcmp(argv[i], "--coin-rpc") == 0 ||
                  std::strcmp(argv[i], "--coin-daemon") == 0) && i + 1 < argc)
            rpc_endpoint = argv[++i];
        else if (std::strcmp(argv[i], "--coin-rpc-auth") == 0 && i + 1 < argc)
            rpc_conf_path = argv[++i];
        else if (std::strcmp(argv[i], "--submit-block") == 0 && i + 1 < argc)
            submit_hex = argv[++i];
        else if (std::strcmp(argv[i], "--submit-block-file") == 0 && i + 1 < argc)
            submit_file = argv[++i];
        else if (std::strcmp(argv[i], "--listen") == 0 && i + 1 < argc)
            listen_raw = argv[++i];
        else if (std::strcmp(argv[i], "--addnode") == 0 && i + 1 < argc)
            addnode_raw.emplace_back(argv[++i]);
        else if (std::strcmp(argv[i], "--connect") == 0 && i + 1 < argc)
            connect_raw.emplace_back(argv[++i]);
        else if (std::strcmp(argv[i], "--coin-p2p-connect") == 0 && i + 1 < argc)
            coin_p2p_raw.emplace_back(argv[++i]);
        else if (std::strcmp(argv[i], "--coin-p2p-discover") == 0)
            coin_p2p_discover = true;
        else if (std::strcmp(argv[i], "--no-p2p-relay") == 0)
            no_p2p_relay = true;
        else if (std::strcmp(argv[i], "--embedded-mainnet") == 0)
            embedded_mainnet = true;
        else if (std::strcmp(argv[i], "--coin-p2p-magic") == 0 && i + 1 < argc)
            coin_p2p_magic = argv[++i];
        else if (std::strcmp(argv[i], "--coin-p2p-peers") == 0 && i + 1 < argc)
            coin_p2p_peers = static_cast<std::size_t>(std::strtoul(argv[++i], nullptr, 10));
        else if (std::strcmp(argv[i], "--regtest-force-won-block") == 0)
            force_won_block = true;
        else if (std::strcmp(argv[i], "--embedded-superblock") == 0)
            embedded_superblock = true;
        else if (std::strcmp(argv[i], "--embedded-utxo") == 0)
            embedded_utxo = true;
        else if (std::strcmp(argv[i], "--embedded-utxo-immature-serve-empty") == 0)
            embedded_utxo_immature_serve_empty = true;
        else if (std::strcmp(argv[i], "--embedded-serve-mempool-txs") == 0)
            embedded_serve_mempool_txs = true;
        else if (std::strcmp(argv[i], "--embedded-accrue-asset-locks") == 0)
            embedded_accrue_asset_locks = true;   // #107 PHASE 2
        else if (std::strcmp(argv[i], "--embedded-accrue-asset-unlocks") == 0)
            embedded_accrue_asset_unlocks = true; // #143 Variant B (type-9)
        else if (std::strcmp(argv[i], "--embedded-mempool-ingest") == 0)
            embedded_mempool_ingest = true;
        else if (std::strcmp(argv[i], "--embedded-null-arm") == 0)
            embedded_null_arm = true;   // #127
        else if (std::strcmp(argv[i], "--embedded-null-arm=false") == 0)
            embedded_null_arm = false;  // #127: explicit OFF (OFF-equivalence)
        else if (std::strcmp(argv[i], "--embedded-ingest-isdlock") == 0)
            embedded_ingest_isdlock = true;   // G4 conflict-tx-lock feed
        else if (std::strcmp(argv[i],
                             "--embedded-creditpool-publish-at-serve-tip") == 0)
            embedded_creditpool_publish_at_serve_tip = true;
        else if (std::strcmp(argv[i], "--pin-local-tx-hex") == 0 && i + 1 < argc)
            pin_local_tx_hex_path = argv[++i];
        else if (std::strcmp(argv[i], "--pin-splice-xcheck-arm") == 0)
            pin_splice_xcheck_arm = true;
        else if (std::strcmp(argv[i], "--pin-splice-block-budget") == 0)
            pin_splice_block_budget = true;
        else if (std::strcmp(argv[i], "--replay-utxo-db") == 0 && i + 1 < argc)
            replay_utxo_db = argv[++i];
        else if (std::strcmp(argv[i], "--replay-utxo-hash") == 0)
            replay_utxo_hash = true;
        else if (std::strcmp(argv[i], "--replay-utxo-expect") == 0 && i + 1 < argc)
            replay_utxo_expect = argv[++i];
        else if (std::strcmp(argv[i], "--bestcl-policy") == 0 && i + 1 < argc)
            bestcl_policy = argv[++i];
        else if (std::strcmp(argv[i], "--coinbase-text") == 0 && i + 1 < argc)
            coinbase_text = argv[++i];
        else if (std::strcmp(argv[i], "--embedded-oracle-shadow") == 0)
            embedded_oracle_shadow = true;
        else if (std::strcmp(argv[i], "--embedded-shadow-compare") == 0)
            embedded_shadow_compare = true;
        // Serve-staleness sentinel kill switch. Accepts the bare flag (= on,
        // already the default) and an explicit `=off` / `=on`, because an ops
        // kill switch that needs the operator to remember which polarity the
        // bare flag means is a kill switch that gets typed wrong at 04:00.
        else if (std::strncmp(argv[i], "--serve-staleness-sentinel", 26) == 0) {
            const char* eq = std::strchr(argv[i], '=');
            serve_staleness_sentinel =
                !(eq && (std::strcmp(eq + 1, "off") == 0 ||
                         std::strcmp(eq + 1, "0")   == 0 ||
                         std::strcmp(eq + 1, "false") == 0));
        }
        // W2 full-history replay bulk-fetch lane (replay_bulk_fetch.hpp).
        else if (std::strcmp(argv[i], "--replay-bulk") == 0)
            g_replay_bulk = true;
        else if (std::strcmp(argv[i], "--replay-bulk-capture") == 0 && i + 1 < argc) {
            g_replay_bulk_capture_dir = argv[++i];
            g_replay_bulk = true;   // capture is a decoration of the lane
        }
        else if (std::strcmp(argv[i], "--replay-bulk-start") == 0 && i + 1 < argc)
            g_replay_bulk_start = static_cast<uint32_t>(
                std::strtoul(argv[++i], nullptr, 10));
        // DASHD-CUT: dump the fold's registered MN set at H to a checkpoint
        // .inc (self-derived; no dashd). Takes two args: H and FILE.
        else if (std::strcmp(argv[i], "--dump-mn-checkpoint") == 0 && i + 2 < argc) {
            g_dump_mn_checkpoint_height = static_cast<uint32_t>(
                std::strtoul(argv[++i], nullptr, 10));
            g_dump_mn_checkpoint_file = argv[++i];
        }
        // W5: anchor-seeded DML fold driven by the bulk lane.
        else if (std::strcmp(argv[i], "--replay-fold-prestate") == 0 && i + 1 < argc) {
            g_replay_fold_prestate = argv[++i];
            g_replay_bulk = true;   // the fold has nothing to fold without it
        }
        // THE SEAM: W4 member derivation feeds the fold's MembersFn.
        else if (std::strcmp(argv[i], "--replay-fold-quorums") == 0)
            g_replay_fold_quorums = true;
        else if (std::strcmp(argv[i], "--replay-fold-qsnapshot") == 0 && i + 1 < argc)
            g_replay_fold_qsnapshot = argv[++i];
        else if (std::strcmp(argv[i], "--replay-fold-worklists") == 0 && i + 1 < argc)
            g_replay_fold_worklists = argv[++i];
        // PR-2 FORWARD: the mined-commitment store, fed from our own replay.
        else if (std::strcmp(argv[i], "--replay-mined-commitment-index") == 0)
            g_mined_commitment_index = true;
        // THE PROOF POSTURE: keep the dashd RPC (shadow-compare) but cut the
        // PAYEE axis off from it — see g_no_dashd_mn_seed.
        else if (std::strcmp(argv[i], "--embedded-no-dashd-mn-seed") == 0)
            g_no_dashd_mn_seed = true;
        else if (std::strcmp(argv[i], "--oracle-graduation-blocks") == 0 && i + 1 < argc)
            oracle_grad_blocks = std::strtoull(argv[++i], nullptr, 10);
        else if (std::strcmp(argv[i], "--oracle-class-coverage") == 0 && i + 1 < argc)
            oracle_class_coverage = std::strtoull(argv[++i], nullptr, 10);
        // E2d: how far back the pinned masternode-set anchor may be before the
        // daemonless bridge refuses it as STALE. Raising this is an explicit
        // operator decision to wait through a longer replay -- it never
        // weakens a correctness check, only the "how long is too long" bound.
        else if (std::strcmp(argv[i], "--embedded-mn-bridge-max") == 0
                 && i + 1 < argc)
            g_mn_bridge_max_blocks = static_cast<uint32_t>(
                std::strtoul(argv[++i], nullptr, 10));
        // #91: the A/B control for the resumable replay cursor.
        else if (std::strcmp(argv[i], "--embedded-mn-bridge-no-cursor") == 0)
            g_mn_bridge_no_cursor = true;
        else if ((std::strcmp(argv[i], "--give-author") == 0 ||
                  std::strcmp(argv[i], "--dev-donation") == 0) && i + 1 < argc)
            dev_donation = std::strtod(argv[++i], nullptr);
        else if ((std::strcmp(argv[i], "-f") == 0 ||
                  std::strcmp(argv[i], "--fee") == 0) && i + 1 < argc)
            node_owner_fee = std::strtod(argv[++i], nullptr);
        else if (std::strcmp(argv[i], "--node-owner-address") == 0 && i + 1 < argc)
            node_owner_address = argv[++i];
        else if (std::strcmp(argv[i], "--redistribute") == 0 && i + 1 < argc)
            redistribute_mode = argv[++i];
        else if (std::strcmp(argv[i], "--coin-zmq-hashblock") == 0 && i + 1 < argc)
            coin_zmq_hashblock = argv[++i];   // opt-in dashd ZMQ hashblock endpoint
        else if ((std::strcmp(argv[i], "--message-blob-hex") == 0 ||
                  std::strcmp(argv[i], "--transition-message") == 0) && i + 1 < argc)
            operator_message_blob_hex = argv[++i];  // encrypted authority message_data blob (EMIT side)
        else if ((std::strcmp(argv[i], "--web-port") == 0 ||
                  std::strcmp(argv[i], "--http-port") == 0) && i + 1 < argc) {
            const long p = std::strtol(argv[++i], nullptr, 10);
            if (p < 0 || p > 65535) {
                std::cout << "c2pool-dash: --web-port out of range: " << argv[i] << "\n";
                return 2;
            }
            web_port = static_cast<uint16_t>(p);
        }
        else if (std::strcmp(argv[i], "--web-host") == 0 && i + 1 < argc)
            web_host = argv[++i];
        // Miner-facing host override for the dashboard Stratum URL. Both hotel
        // nodes NAT out through one gateway, so the auto-detected outbound IP
        // is NOT the address miners reach; the operator advertises the real
        // external-mapped host here. Aliases match how the flag is referenced.
        else if ((std::strcmp(argv[i], "--external-ip") == 0 ||
                  std::strcmp(argv[i], "--stratum-advertise") == 0 ||
                  std::strcmp(argv[i], "--public-host") == 0) && i + 1 < argc)
            external_ip = argv[++i];
        else if (std::strcmp(argv[i], "--dashboard-dir") == 0 && i + 1 < argc)
            dashboard_dir = argv[++i];
        else if (std::strcmp(argv[i], "--stratum") == 0 && i + 1 < argc) {
            // --stratum [HOST:]PORT -- bind a Stratum TCP listener for miners.
            // Bare PORT keeps the default 0.0.0.0 bind host (parse_listen SSOT).
            if (!parse_listen(argv[++i], stratum_host, stratum_port)) {
                std::cout << "[run] --stratum malformed (want [HOST:]PORT): "
                          << argv[i] << "\n";
                return 2;
            }
        }
        // --selftest is the default; accepted explicitly for symmetry.
    }

    // ── FULL-HISTORY REPLAY W3: --replay-utxo-* standalone utility ──────────
    // Runs and EXITS: opens the fold store, names its resume cursor, and with
    // --replay-utxo-hash computes the dashd-compatible hash_serialized_2 over
    // the whole set (the Tier-B gate: expect
    // 3d14913768a9d492bfa7a42fe9b111cff625b80e35bb4133e1d60cf3991c2319 at
    // h=2,516,758 once a genesis→tip replay has been folded). Never touches
    // the serve path — no node, no stratum, no RPC is constructed here.
    if (!replay_utxo_db.empty()) {
        dash::coin::replay::ReplayUtxoFold fold;
        if (!fold.open(replay_utxo_db)) {
            std::cout << "[REPLAY-UTXO] FAILED to open fold store at "
                      << replay_utxo_db << " (see log; version mismatch is"
                         " fail-loud by design)\n";
            return 1;
        }
        if (fold.have_cursor()) {
            std::cout << "[REPLAY-UTXO] db=" << replay_utxo_db
                      << " format=v" << dash::coin::replay::REPLAY_UTXO_FORMAT_VERSION
                      << " best_height=" << fold.best_height()
                      << " best_block=" << fold.best_hash().GetHex()
                      << " resume_height=" << fold.resume_height()
                      << " undo_window=" << fold.undo_window() << "\n";
        } else {
            std::cout << "[REPLAY-UTXO] db=" << replay_utxo_db
                      << " EMPTY (no cursor; the fold expects height 0 or 1"
                         " first — a UTXO fold starts at genesis)\n";
        }
        if (replay_utxo_hash) {
            std::cout << "[REPLAY-UTXO] computing hash_serialized_2 (full set"
                         " scan; ~4.5M coins at mainnet tip takes a few"
                         " minutes)...\n";
            auto res = fold.hash_serialized_2();
            if (!res) {
                std::cout << "[REPLAY-UTXO] hash REFUSED: " << fold.refusal()
                          << "\n";
                return 1;
            }
            std::cout << "[REPLAY-UTXO] hash_serialized_2=" << res->hash.GetHex()
                      << " height=" << res->best_height
                      << " best_block=" << res->best_block.GetHex()
                      << " coins=" << res->coins
                      << " tx_groups=" << res->tx_groups << "\n";
            if (!replay_utxo_expect.empty()) {
                std::string want = replay_utxo_expect;
                for (auto& c : want) c = static_cast<char>(std::tolower(c));
                if (res->hash.GetHex() == want) {
                    std::cout << "[REPLAY-UTXO] GATE PASS: set matches the"
                                 " expected dashd hash_serialized_2\n";
                    return 0;
                }
                std::cout << "[REPLAY-UTXO] GATE MISMATCH: got "
                          << res->hash.GetHex() << " want " << want
                          << " — fold state MUST NOT feed any serving"
                             " decision\n";
                return 1;
            }
        } else if (!replay_utxo_expect.empty()) {
            std::cout << "[REPLAY-UTXO] --replay-utxo-expect given without"
                         " --replay-utxo-hash — nothing was compared\n";
            return 2;
        }
        return 0;
    }
    if (replay_utxo_hash || !replay_utxo_expect.empty()) {
        std::cout << "[REPLAY-UTXO] --replay-utxo-hash/--replay-utxo-expect"
                     " require --replay-utxo-db PATH\n";
        return 2;
    }

    // ── --coinbase-text: resolve ONCE, here, before any coinbase is built ────
    // DASH has no merged mining and writes no THE state-root/metadata tail, so
    // the operator slot is bounded by MAX_OPERATOR_TEXT_SOLO (README "Coinbase
    // structure"); the BIP34 height push (<=5 B) plus 64 B stays well inside the
    // 100-byte scriptSig limit. Stored on the coin SSOT rather than threaded
    // through every call so the stratum job path and the share-mint path cannot
    // disagree -- a one-byte divergence between them would make the node
    // self-reject its own shares.
    if (!coinbase_text.empty()) {
        if (coinbase_text.size() > c2pool::MAX_OPERATOR_TEXT_SOLO) {
            std::cout << "[args] --coinbase-text too long: " << coinbase_text.size()
                      << " bytes (max " << c2pool::MAX_OPERATOR_TEXT_SOLO << ")\n";
            return 2;
        }
        dash::SharechainConfig::coinbase_text_override = coinbase_text;
    }

    print_banner(argv[0]);
    if (want_help)
        return 0;
    if (want_mine)
        return run_mine_block(testnet, rpc_endpoint, rpc_conf_path,
                              payout_pkh_hex, max_nonce);
    if (want_run) {
        if (!submit_file.empty() && submit_hex.empty()) {
            std::ifstream bf(submit_file);
            if (!bf) {
                std::cout << "[run] cannot open --submit-block-file " << submit_file << "\n";
                return 2;
            }
            std::getline(bf, submit_hex, '\0');   // whole-file slurp
            while (!submit_hex.empty() &&
                   (submit_hex.back() == '\n' || submit_hex.back() == '\r' ||
                    submit_hex.back() == ' '  || submit_hex.back() == '\t'))
                submit_hex.pop_back();
        }
        PeeringConfig peer;
        for (const auto& raw : addnode_raw) {
            NetService ns;
            if (!parse_hostport(raw, ns)) {
                std::cout << "[run] --addnode malformed (want HOST:PORT): " << raw << "\n";
                return 2;
            }
            peer.addnodes.push_back(ns);
        }
        for (const auto& raw : connect_raw) {
            NetService ns;
            if (!parse_hostport(raw, ns)) {
                std::cout << "[run] --connect malformed (want HOST:PORT): " << raw << "\n";
                return 2;
            }
            peer.connects.push_back(ns);
        }
        if (!listen_raw.empty()) {
            if (!parse_listen(listen_raw, peer.listen_host, peer.listen_port)) {
                std::cout << "[run] --listen malformed (want [HOST:]PORT): " << listen_raw << "\n";
                return 2;
            }
            peer.listen_set = true;
        }
        std::vector<NetService> coin_p2p_targets;
        for (const auto& raw : coin_p2p_raw) {
            NetService ns;
            if (!parse_hostport(raw, ns)) {
                std::cout << "[run] --coin-p2p-connect malformed (want HOST:PORT): "
                          << raw << "\n";
                return 2;
            }
            coin_p2p_targets.push_back(ns);
        }
        // Guard against port conflicts between stratum and the web dashboard
        // (main_ltc.cpp:1480, same posture and same +1 resolution).
        if (stratum_port != 0 && web_port != 0 && stratum_port == web_port) {
            std::cout << "[run] stratum port " << stratum_port
                      << " conflicts with web dashboard port, moving dashboard to "
                      << (stratum_port + 1) << "\n";
            web_port = static_cast<uint16_t>(stratum_port + 1);
        }
        return run_node(testnet, rpc_endpoint, rpc_conf_path, submit_hex, peer,
                        stratum_host, stratum_port, web_host, web_port,
                        dashboard_dir, coin_p2p_targets, coin_p2p_discover,
                        embedded_utxo, dev_donation, node_owner_fee,
                        node_owner_address, redistribute_mode, no_p2p_relay,
                        embedded_mainnet,
                        coin_zmq_hashblock,
                        external_ip,
                        coin_p2p_magic, force_won_block,
                        operator_message_blob_hex, embedded_superblock,
                        embedded_oracle_shadow, oracle_grad_blocks,
                        oracle_class_coverage, coin_p2p_peers, bestcl_policy,
                        embedded_utxo_immature_serve_empty,
                        embedded_serve_mempool_txs,
                        embedded_shadow_compare,
                        embedded_mempool_ingest,
                        pin_local_tx_hex_path,
                        serve_staleness_sentinel,
                        embedded_creditpool_publish_at_serve_tip,
                        pin_splice_xcheck_arm,
                        pin_splice_block_budget,
                        embedded_accrue_asset_locks,   // #107 PHASE 2
                        embedded_null_arm,             // #127
                        embedded_accrue_asset_unlocks, // #143 Variant B
                        embedded_ingest_isdlock);      // G4 isdlock feed
    }
    return run_selftest();
}