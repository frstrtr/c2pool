// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BCH pool run-loop ENTRYPOINT standup -- broadcaster-gate leg C, pool side
// (integrator 2026-06-18: "NodeImpl + EmbeddedDaemon constructed,
// bch::wire_won_block_sink called live").
//
// This is the single production call site the c2pool-bch binary main invokes to
// bring the pool node up WITH its embedded coin daemon and the won-block sink
// already bound. It owns both objects for the lifetime of the run-loop (they
// outlive io_context.run(), so the wire_won_block_sink lambda -- which captures
// the daemon by reference -- never dangles) and enforces the structural half of
// broadcaster-gate criterion C: the won-block sink MUST be live before the
// run-loop accepts shares, or a verified block-meeting share would fire
// m_on_block_found into a null sink and the win would be silently dropped.
//
// G3-slice-b (integrator 2026-06-27): this entrypoint now also stands up the
// miner-facing IWorkSource + Stratum front-end, closing the M5 "no BCH
// IWorkSource served" gap. BCHWorkSource bridges the coin-agnostic
// core::StratumServer to BCH work generation off the embedded daemon's
// HeaderChain + Mempool, and routes a mainnet-hit (share-author) block down the
// SAME dual-path broadcaster the won-block sink uses (embedded P2P primary +
// BCHN submitblock fallback). So the coinbase a genuine share assembles is what
// reaches the network -- not a synthetic solo-cb leg-C block (the slice-a
// caveat). standup_pool_run is the production caller the work_source.hpp Stage-a
// TODO names ("wire StratumServer into standup_pool_run + main_bch.cpp --pool").
//
// Construction + wiring order (matches EmbeddedDaemon::run() contract):
//   1. EmbeddedDaemon(ctx, config, anchor) -- cold-start floor-anchored ABLA.
//   2. daemon.run() -- external BCHN-RPC fallback (init_rpc) + assemble() +
//      ABLA loop + operator-approved cold-start anchor pin. Embedded-primary
//      work source live, external fallback retained (external_fallback law).
//   3. NodeImpl(ctx, config) -- the pool node (sharechain, storage, P2P).
//   4. wire_won_block_sink(node, daemon) -- bind tracker().m_on_block_found ->
//      daemon.broadcast_won_block (dual path: embedded P2P PRIMARY + external
//      BCHN submitblock FALLBACK).
//   5. ASSERT node.has_block_broadcaster() -- the sink is LIVE. This is the
//      structural criterion-C check; throwing here is correct (a missing sink
//      at the production entrypoint is a wiring bug, not a runtime condition).
//   6. BCHWorkSource + core::StratumServer -- miner-facing front-end; a hit
//      block routes through the SAME daemon.broadcast_won_block dual path.
//
// The sink being live is NECESSARY but NOT SUFFICIENT to declare BCH
// block-viable: reconstruct_won_block() still gates on full gentx (coinbase)
// reconstruction, and the dual paths must be proven to FIRE+ACCEPT against a
// live BCHN peer -- the behavioural half of criterion C, a separate e2e slice
// (code-exists != fires).
//
// PER-COIN ISOLATION: src/impl/bch only. p2pool-merged-v36 surface: NONE
// (block dispatch + run-loop bring-up, not share/PPLNS/coinbase/AuxPoW bytes).
// BCH = SHA256d standalone parent.

#include "node.hpp"
#include "pool_standup.hpp"
#include "coin/embedded_daemon.hpp"
#include "stratum/work_source.hpp"
#include "config_pool.hpp"      // bch::PoolConfig::get_donation_script
#include "share_check.hpp"      // bch::create_local_share (transitive via node.hpp)
#include "share_types.hpp"      // bch::StaleInfo
#include "coin/block.hpp"       // bch::coin::SmallBlockHeaderType

#include <core/pack_types.hpp>    // BaseScript

#include <core/log.hpp>
#include <core/stratum_server.hpp>
#include <functional>

#include <btclibs/util/strencodings.h>   // HexStr

#include <boost/asio/io_context.hpp>

#include <cstdint>
#include <cstring>
#include <cstdlib>   // std::getenv (BCH_DEMO_SHARE_BITS demo floor)
#include <shared_mutex>
#include <type_traits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace bch
{

// Stand up the BCH pool node + embedded coin daemon on a shared io_context,
// bind the won-block sink, assert it is live, stand up the miner-facing
// IWorkSource + Stratum front-end, then drive the run-loop.
// `config` and `ioc` outlive this call (owned by the binary entrypoint); the
// daemon, node, work source and stratum server are owned here for the run-loop
// lifetime. `anchor_height` is the cold-start ABLA floor anchor (operator-
// approved VM300 record, floor-equivalent). `stratum_addr`/`stratum_port` are
// the miner-facing bind (port 0 == stratum disabled); `is_testnet` selects the
// BCH network params the work source stamps onto generated work. Returns when
// the io_context stops.
inline void standup_pool_run(boost::asio::io_context& ioc,
                             Config& config,
                             uint32_t anchor_height,
                             const std::string& stratum_addr = "0.0.0.0",
                             uint16_t stratum_port = 0,
                             bool is_testnet = false,
                             bool is_regtest = false)
{
    // 1+2: embedded daemon up first -- it owns the work source + RPC fallback
    // the pool node consumes, and is the broadcast sink the node wires into.
    coin::EmbeddedDaemon<Config> daemon(&ioc, &config, anchor_height, is_regtest);
    daemon.run();

    // 3: the pool node (sharechain, LevelDB, P2P, Stratum).
    Node node(&ioc, &config);  // concrete NodeBridge<NodeImpl,Legacy,Actual> -- NodeImpl alone is abstract (ICommunicator::handle lives in NodeBridge)

    // 4: bind the in-operation won-block fire path to the dual-path broadcaster.
    wire_won_block_sink(node, daemon);

    // 5: structural criterion-C gate -- refuse to run shares without a live sink.
    if (!node.has_block_broadcaster()) {
        LOG_FATAL << "[BCH-POOL] won-block sink NOT live after wire_won_block_sink"
                  << " -- refusing to start run-loop (a won block would be dropped).";
        throw std::runtime_error("bch::standup_pool_run: won-block broadcaster sink not wired");
    }

    LOG_INFO << "[BCH-POOL] pool run-loop standup complete: embedded daemon up,"
             << " won-block sink LIVE (dual-path: embedded P2P primary + BCHN"
             << " submitblock fallback). Structural broadcaster-gate criterion-C"
             << " satisfied; live VM300 e2e is the behavioural half.";

    // 6: miner-facing IWorkSource + Stratum front-end. BCHWorkSource generates
    // work off the embedded daemon's HeaderChain + Mempool (SHA256d, no-segwit,
    // CashTokens transparent-carry), and routes a mainnet-hit block through the
    // SAME dual-path broadcaster (embedded P2P primary + BCHN submitblock
    // fallback) the won-block sink uses -- so the share-author coinbase reaches
    // the network down both legs. Held here so the shared_ptr + server outlive
    // ioc.run() alongside the daemon they reference.
    auto work_source = std::make_shared<stratum::BCHWorkSource>(
        daemon.chain(),
        daemon.mempool(),
        is_testnet,
        [&daemon](const std::vector<unsigned char>& block_bytes,
                  uint32_t /*height*/) -> bool {
            // Genuine share-author block -> dual-path broadcaster. block_hex for
            // the BCHN submitblock fallback is HexStr(block_bytes). True iff at
            // least one sink accepted (embedded P2P relay OR external RPC).
            coin::BlockBroadcast r =
                daemon.broadcast_won_block(block_bytes, HexStr(block_bytes));
            return r.any();
        });

    // ── Sharechain WRITE path: local-share author wiring ─────────────────
    // Without these callbacks BCHWorkSource accepts miner submissions that
    // clear the sharechain target but DROPS them ("accepted (no-tracker)",
    // work_source.cpp:686) because create_share_fn_ is null -- c2pool-bch runs
    // as a bare stratum proxy and Stored shares stay stuck at 0. This block
    // closes that gap (mirrors main_btc.cpp:863/1118), wiring the three
    // callbacks the local-author path needs:
    //   - best_share_hash_fn : new-job prev_share = our sharechain tip
    //   - donation_script    : version-gated coinbase residual recipient
    //   - create_share_fn    : mining_submit -> bch::create_local_share ->
    //                          tracker.add -> broadcast_share + notify_local_share
    // BCH is a STANDALONE SHA256d parent: no segwit, no merged/aux dimension
    // (merged_addrs = {}, segwit_active=false, witness_* empty). ref_hash_fn /
    // pplns_fn are a FOLLOW-UP slice -- they gate peer-verifiable ref_hash +
    // PPLNS payout distribution, NOT local Stored accumulation; until wired,
    // build_connection_coinbase falls back to a single-output coinbase and
    // create_local_share computes its own share target via
    // tracker.compute_share_target (has_frozen=false).
    work_source->set_best_share_hash_fn(
        [&node]() -> uint256 { return node.best_share_hash(); });

    // Work-source donation MUST match the authored share version, and both must
    // match the LIVE jtoomim-BCH net -- BCH is a CROSSING coin. Shares author at
    // CROSSING_FLOOR_VERSION (what the live net mints), and the donation served
    // in the miner-hashed template is the floor script (sub-36 -> forrestv P2PK).
    // generate_share_transaction rebuilds the coinbase donation under the SAME
    // authored version, so template-donation and verify-rebuild are byte-identical
    // -- closing the byte-offset-104 recompute/GENTX divergence WITHOUT forking
    // off the live net (authoring v36 from genesis would). The 60%-by-work auto-
    // ratchet (#326/#577) advances author + donation together once the tip>=36.
    work_source->set_donation_script(PoolConfig::get_donation_script(PoolConfig::CROSSING_FLOOR_VERSION));

    // -- ref_hash_fn: peer-verifiable share commitment (G2 conform) --------
    // Without this the local-author coinbase carries NO p2pool OP_RETURN
    // ref_hash (build_connection_coinbase gates the OP_RETURN on ref_hash_fn
    // being set) and create_local_share runs has_frozen=false -- so every
    // share we author is systematically non-peer-verifiable: the recomputed
    // ref_hash never equals the stored one (100% verify_share mismatch).
    // This lambda produces the ref_hash AND the chain-walked snapshot
    // (bits/max_bits from compute_share_target, absheight/abswork/
    // far_share_hash off the prev walk, clipped timestamp) that populates
    // snap.frozen_ref; mining_submit threads it back into create_local_share
    // (has_frozen=true) so the create-side reconstruction is byte-exact.
    // Mirrors main_btc.cpp:920 and the chain-position math of
    // create_local_share_v35 (share_check.hpp:2724); BCH is standalone
    // SHA256d -- no segwit, no merged dimension.
    work_source->set_ref_hash_fn(
        [&node](const uint256& prev_share_hash,
                const std::vector<unsigned char>& scriptSig,
                const std::vector<unsigned char>& payout_script,
                uint64_t subsidy, uint32_t block_bits, uint32_t timestamp)
        -> core::stratum::RefHashResult
        {
            core::stratum::RefHashResult result;
            result.share_version   = PoolConfig::CROSSING_FLOOR_VERSION;   // crossing-floor SSOT (ratchet-current genesis default)
            result.desired_version = core::version_gate::V36_ACTIVATION_VERSION;   // vote to ratchet toward v36

            bch::RefHashParams p;
            p.share_version      = PoolConfig::CROSSING_FLOOR_VERSION;   // crossing-floor author version (SSOT)
            p.prev_share         = prev_share_hash;
            p.coinbase_scriptSig = scriptSig;
            p.share_nonce        = 0;
            p.subsidy            = subsidy;
            p.donation           = 50;      // 0.5% finder fee (matches create side)
            p.stale_info         = 0;
            p.desired_version    = core::version_gate::V36_ACTIVATION_VERSION;   // vote to ratchet toward v36
            p.has_segwit         = false;   // BCH: never segwit
            p.timestamp          = timestamp;

            // Pubkey extract mirrors create_local_share_v35 (share_check.hpp
            // ~2600): P2PKH / P2SH / P2WPKH, so p.pubkey_hash + p.pubkey_type
            // feed the ref-stream identically on both sides.
            if (payout_script.size() == 25 && payout_script[0] == 0x76 &&
                payout_script[1] == 0xa9 && payout_script[2] == 0x14 &&
                payout_script[23] == 0x88 && payout_script[24] == 0xac) {
                std::memcpy(p.pubkey_hash.begin(), payout_script.data() + 3, 20);
                p.pubkey_type = 0;
            } else if (payout_script.size() == 23 && payout_script[0] == 0xa9 &&
                       payout_script[1] == 0x14 && payout_script[22] == 0x87) {
                std::memcpy(p.pubkey_hash.begin(), payout_script.data() + 2, 20);
                p.pubkey_type = 2;
            } else if (payout_script.size() == 22 && payout_script[0] == 0x00 &&
                       payout_script[1] == 0x14) {
                std::memcpy(p.pubkey_hash.begin(), payout_script.data() + 2, 20);
                p.pubkey_type = 1;
            }

            auto block_bits_fallback = [&] {
                p.bits = block_bits;  p.max_bits = block_bits;
            };

            // Read-only chain walk (shared lock; the compute thread holds the
            // exclusive lock and never runs on this stratum thread).
            {
                std::shared_lock<std::shared_mutex> lk(node.tracker_mutex());
                auto& tracker = node.tracker();

                const bool have_prev = !prev_share_hash.IsNull() &&
                                       tracker.chain.contains(prev_share_hash);

                // share_version off the prev tip (matches create_ver); cold
                // start stays v35 voting v36.
                if (have_prev) {
                    tracker.chain.get(prev_share_hash).share.invoke([&](auto* s) {
                        using ST = std::remove_pointer_t<decltype(s)>;
                        p.share_version = ST::version;
                    });
                }

                // absheight + clipped timestamp off prev.
                if (have_prev) {
                    tracker.chain.get(prev_share_hash).share.invoke([&](auto* prev) {
                        p.absheight = prev->m_absheight + 1;
                        if (p.timestamp <= prev->m_timestamp)
                            p.timestamp = prev->m_timestamp + 1;
                    });
                } else {
                    p.absheight = 1;   // genesis
                }

                // share_target with the clipped timestamp (same call
                // create_local_share_v35 makes).
                try {
                    auto st = tracker.compute_share_target(
                        prev_share_hash, p.timestamp,
                        chain::bits_to_target(block_bits));
                    p.bits = st.bits;  p.max_bits = st.max_bits;
                } catch (const std::exception&) {
                    block_bits_fallback();
                }
                // Cold start: compute_share_target's genesis branch yields
                // bits==0 while max_bits carries the MAX_TARGET floor. Pin
                // p.bits to the floor so the ref_hash, the frozen field, and
                // share_bits_ all agree (else recomputed != stored).
                if (p.bits == 0 && p.max_bits != 0)
                    p.bits = p.max_bits;

                // [ISOLATED-NET DEMO / G2] Mirror work_source's
                // BCH_DEMO_SHARE_BITS floor here so the ref_hash, the frozen
                // field, and the core pool_difficulty gate all read ONE share
                // target on a CPU-grind isolated net. Without it ref_hash_fn
                // reports compute_share_target's ~diff-1 floor -- unclearable
                // by a CPU grinder -- so no submission is ever promoted to a
                // STORED share and recomputed==stored can't be observed.
                // OFF unless the env var is set; never active on normal or
                // mainnet runs. BCH-local (fenced to the BCH tree).
                if (const char* e = std::getenv("BCH_DEMO_SHARE_BITS"); e && *e) {
                    uint32_t demo = static_cast<uint32_t>(std::strtoul(e, nullptr, 16));
                    if (demo) { p.bits = demo; p.max_bits = demo; }
                }

                // abswork = prev_abswork + attempts(this share's bits).
                {
                    auto att = chain::target_to_average_attempts(
                        chain::bits_to_target(p.bits));
                    if (have_prev) {
                        uint128 prev_abswork;
                        tracker.chain.get(prev_share_hash).share.invoke(
                            [&](auto* prev) { prev_abswork = prev->m_abswork; });
                        p.abswork = prev_abswork + uint128(att.GetLow64());
                    } else {
                        p.abswork = uint128(att.GetLow64());
                    }
                }

                // far_share_hash: 99th ancestor, mirroring create_local_share
                // _v35's get_height_and_last rule exactly.
                if (have_prev) {
                    auto [prev_height, last] =
                        tracker.chain.get_height_and_last(prev_share_hash);
                    if (last.IsNull() && prev_height < 99) {
                        p.far_share_hash = uint256();
                    } else {
                        try {
                            p.far_share_hash =
                                tracker.chain.get_nth_parent_key(prev_share_hash, 99);
                        } catch (const std::exception&) {
                            // Bootstrap short chain: degrade to far=None instead of
                            // throwing out of ref_hash_fn (which would zero frozen_ref
                            // and force the create-side into its own unguarded walk).
                            p.far_share_hash = uint256();
                        }
                    }
                } else {
                    p.far_share_hash = uint256();
                }
            }

            // Mirror the walked values into the result for snap.frozen_ref.
            result.share_version   = p.share_version;
            result.desired_version = p.desired_version;
            result.bits            = p.bits;
            result.max_bits        = p.max_bits;
            result.timestamp       = p.timestamp;
            result.absheight       = p.absheight;
            result.abswork         = p.abswork;
            result.far_share_hash  = p.far_share_hash;

            try {
                auto [rh, nn] = bch::compute_ref_hash_for_work(p);
                result.ref_hash         = rh;
                result.last_txout_nonce = nn;
            } catch (const std::exception& e) {
                LOG_WARNING << "[BCH-STRATUM] compute_ref_hash_for_work threw: "
                            << e.what() << " -- coinbase will lack OP_RETURN";
            }
            return result;
        });

    LOG_INFO << "[BCH-STRATUM] ref_hash_fn wired (walks share tracker for"
             << " share_target/absheight/abswork/far_share; emits p2pool"
             << " OP_RETURN ref_hash + freezes the snapshot for byte-exact"
             << " create-side reconstruction).";

    // Local-share -> stratum work-refresh bridge (BCH-side wiring; the refresh
    // mechanism itself lives unchanged in core StratumServer::notify_all(),
    // which re-polls best_share_hash_fn and pushes a clean mining.notify with
    // the NEW sharechain tip as prev_share). Without ringing it after each
    // authored share, every miner keeps grinding the job frozen at pool start
    // (prev=genesis), so shares bootstrap off 0000... as orphan siblings and
    // the chain never links past height 1.
    auto stratum_notify = std::make_shared<std::function<void()>>();

    // --- Version-aware PPLNS payout + author-version wiring (finder-fee gate) ---
    // The height-2 verified-tip stall was a share-version vs coinbase-author
    // mismatch: shares stamp at the tip version (35 through a short grind, the
    // ratchet never flips) while the coinbase author produced a v36-pure,
    // finder-fee-less gentx -- so generate_share_transaction (v35 verify path)
    // rejected every non-genesis share. Fix: select the PPLNS shape at the tip
    // version and (in build_connection_coinbase) apply the sub-36 finder fee.
    // The v35 walk (flat weights, grandparent start, 199/200) and the v36 walk
    // (decayed, exponential window, pure) yield DIFFERENT integer amounts
    // (division order), so shape must be chosen at weight->amount time, never
    // haircut afterward. Ref: share_check.hpp use_v36_pplns.
    auto derive_author_version = [&node]() -> int64_t {
        int64_t ver = 35;
        uint256 tip = node.best_share_hash();
        std::shared_lock<std::shared_mutex> lk(node.tracker_mutex());
        if (!tip.IsNull() && node.tracker().chain.contains(tip)) {
            node.tracker().chain.get_share(tip).invoke(
                [&](auto* s) {
                    using ST = std::remove_pointer_t<decltype(s)>;
                    ver = ST::version;
                });
        }
        return ver;
    };
    work_source->set_author_version_fn(derive_author_version);

    work_source->set_pplns_fn(
        [&node](const uint256& best_share_hash,
                const uint256& block_target,
                uint64_t subsidy,
                const std::vector<unsigned char>& donation_script)
            -> std::map<std::vector<unsigned char>, double>
        {
            // Single read guard: derive the tip version AND walk under the same
            // lock (do NOT call derive_author_version here -- that would take a
            // second shared_lock on the same thread == UB under a waiting writer).
            std::shared_lock<std::shared_mutex> lk(node.tracker_mutex());
            int64_t ver = 35;
            uint256 tip = node.best_share_hash();
            if (!tip.IsNull() && node.tracker().chain.contains(tip)) {
                node.tracker().chain.get_share(tip).invoke(
                    [&](auto* s) {
                        using ST = std::remove_pointer_t<decltype(s)>;
                        ver = ST::version;
                    });
            }
            if (ver < 36)
                return node.tracker().get_v35_expected_payouts(
                    best_share_hash, block_target, subsidy, donation_script);
            return node.tracker().get_expected_payouts(
                best_share_hash, block_target, subsidy, donation_script);
        });

    work_source->set_create_share_fn(
        [&node, stratum_notify](const std::vector<unsigned char>& full_coinbase,
                const std::vector<uint8_t>&        header_80b,
                const core::stratum::JobSnapshot&  job,
                const std::vector<unsigned char>& payout_script) -> uint256
        {
            if (header_80b.size() != 80) {
                LOG_WARNING << "[BCH-CREATE-SHARE] bad header size=" << header_80b.size();
                return uint256::ZERO;
            }

            // Parse the 80-byte BCH block header -> SmallBlockHeaderType. The
            // merkle_root (bytes 36..67) is reconstructible from coinbase +
            // frozen branches, so it is not stored in min_header.
            auto read_le32 = [](const uint8_t* p) -> uint32_t {
                return uint32_t(p[0]) | (uint32_t(p[1]) << 8)
                     | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
            };
            coin::SmallBlockHeaderType min_header;
            min_header.m_version = read_le32(header_80b.data() + 0);
            std::memcpy(min_header.m_previous_block.data(), header_80b.data() + 4, 32);
            min_header.m_timestamp = read_le32(header_80b.data() + 68);
            min_header.m_bits      = read_le32(header_80b.data() + 72);
            min_header.m_nonce     = read_le32(header_80b.data() + 76);

            // full_coinbase is the fully serialized coinbase TRANSACTION, but a
            // share's m_coinbase field must be ONLY the coinbase INPUT scriptSig
            // (BIP34 height + pool marker) -- share_init_verify enforces the
            // consensus 2..100 byte bound. Feeding the whole tx tripped
            // "bad coinbase size" and left every G2 share unverified. Extract the
            // input scriptSig here; the full tx still rides via actual_coinbase_bytes
            // for gentx byte-parity (extranonce lives in an OP_RETURN output, not
            // the scriptSig, so this slice is complete on its own).
            std::vector<unsigned char> coinbase_scriptSig;
            {
                size_t p = 0;
                bool ok = true;
                auto need = [&](size_t n) { return p + n <= full_coinbase.size(); };
                auto rd_varint = [&](uint64_t& out) -> bool {
                    if (!need(1)) return false;
                    uint8_t ch = full_coinbase[p++];
                    if (ch < 253) { out = ch; return true; }
                    size_t n = (ch == 253) ? 2 : (ch == 254) ? 4 : 8;
                    if (!need(n)) return false;
                    out = 0;
                    for (size_t i = 0; i < n; ++i)
                        out |= uint64_t(full_coinbase[p++]) << (8 * i);
                    return true;
                };
                uint64_t vin = 0, slen = 0;
                if (need(4)) p += 4; else ok = false;            // version
                ok = ok && rd_varint(vin) && vin >= 1;           // tx_in count
                if (ok && need(36)) p += 36; else ok = false;    // prevout (32+4)
                ok = ok && rd_varint(slen);                      // scriptSig length
                if (ok && need(slen)) {
                    coinbase_scriptSig.assign(full_coinbase.begin() + p,
                                              full_coinbase.begin() + p + slen);
                } else {
                    LOG_WARNING << "[BCH-CREATE-SHARE] cannot parse coinbase scriptSig from "
                                << full_coinbase.size() << "B tx -- share skipped";
                    return uint256::ZERO;
                }
            }
            BaseScript coinbase_bs(coinbase_scriptSig);

            // Stratum branches are hex of LE-internal bytes -> ParseHex+memcpy
            // (SetHex would byte-reverse and break the merkle root the miner used).
            std::vector<uint256> merkle_branches;
            merkle_branches.reserve(job.merkle_branches.size());
            for (const auto& bhex : job.merkle_branches) {
                uint256 b;
                auto bb = ParseHex(bhex);
                if (bb.size() == 32) std::memcpy(b.begin(), bb.data(), 32);
                merkle_branches.push_back(b);
            }

            // Exclusive tracker lock (non-blocking): defer to the next submit if
            // the compute thread is mid-think rather than freezing the io_context.
            std::unique_lock<std::shared_mutex> lk(node.tracker_mutex(), std::try_to_lock);
            if (!lk.owns_lock()) {
                LOG_INFO << "[BCH-CREATE-SHARE] tracker busy -- share deferred";
                return uint256::ZERO;
            }

            // Author at the current tip's version (35 on an empty chain), voting
            // desired=36. Same-version authoring never trips the 60%-by-work
            // accept gate; the ratchet-driven upgrade to v36 is a follow-up slice.
            // Author at the frozen share_version the ref_hash was computed
            // under (job.frozen_ref.share_version) so the create-side ref
            // reconstruction is byte-exact; fall back to the prev-tip version
            // (cold start: v35 voting v36) when ref_hash_fn produced no frozen
            // data (bits == 0).
            int64_t create_ver = PoolConfig::CROSSING_FLOOR_VERSION;   // crossing-floor default; tip version overrides below (ratchet-current)
            if (job.frozen_ref.bits != 0) {
                create_ver = job.frozen_ref.share_version;
            } else if (!job.prev_share_hash.IsNull() &&
                node.tracker().chain.contains(job.prev_share_hash)) {
                node.tracker().chain.get_share(job.prev_share_hash).invoke(
                    [&](auto* s) {
                        using ST = std::remove_pointer_t<decltype(s)>;
                        create_ver = ST::version;
                    });
            }

            uint256 share_hash;
            try {
                share_hash = bch::create_local_share(
                    node.tracker(), min_header, coinbase_bs,
                    /* subsidy */               job.subsidy,
                    /* prev_share */            job.prev_share_hash,
                    merkle_branches, payout_script,
                    /* donation bps */          50,
                    /* merged_addrs */          {},
                    /* stale_info */            StaleInfo::none,
                    /* segwit_active */         false,        // BCH: no segwit
                    /* witness_commitment */    {},
                    /* message_data */          {},
                    /* actual_coinbase_bytes */ full_coinbase,
                    /* witness_root */          uint256(),
                    /* override_max_bits */     job.share_max_bits,  // pin share target to
                    /* override_bits */         job.share_bits,      // what the miner was issued
                    /* frozen_absheight */      job.frozen_ref.absheight,
                    /* frozen_abswork */        job.frozen_ref.abswork,
                    /* frozen_far_share_hash */ job.frozen_ref.far_share_hash,
                    /* frozen_timestamp */      job.frozen_ref.timestamp,
                    /* frozen_merged_payout */  job.frozen_ref.merged_payout_hash,
                    /* has_frozen */            (job.frozen_ref.bits != 0),
                    /* frozen_merkle_branches*/ job.frozen_ref.frozen_merkle_branches,
                    /* frozen_witness_root */   uint256(),   // BCH: never segwit
                    /* frozen_merged_cb_info */ {},          // BCH: standalone, no merged
                    /* share_version */         create_ver,
                    /* desired_version */       36);
            } catch (const std::exception& e) {
                LOG_WARNING << "[BCH-CREATE-SHARE] threw: " << e.what();
                return uint256::ZERO;
            }

            // Drop the exclusive lock BEFORE broadcast/notify (they take their
            // own locks / post to the io_context).
            lk.unlock();
            if (!share_hash.IsNull()) {
                node.broadcast_share(share_hash);
                node.notify_local_share(share_hash);
                // Ring the stratum work-refresh so the next mining.notify carries
                // the new sharechain tip as prev_share (chain links past height 1).
                if (*stratum_notify) (*stratum_notify)();
                LOG_INFO << "[BCH-CREATE-SHARE] OK + broadcast v" << create_ver
                         << " hash=" << share_hash.GetHex().substr(0, 16);
            }
            return share_hash;
        });

    LOG_INFO << "[BCH-POOL] sharechain WRITE path wired (mining_submit ->"
             << " create_local_share -> broadcast_share + notify_local_share);"
             << " ref_hash/pplns are a follow-up slice.";

    std::unique_ptr<core::StratumServer> stratum_server;
    if (stratum_port != 0) {
        stratum_server = std::make_unique<core::StratumServer>(
            ioc, stratum_addr, stratum_port, work_source);
        if (stratum_server->start()) {
            // Wire the local-share bridge to the now-constructed stratum server.
            *stratum_notify = [srv = stratum_server.get()]() { srv->notify_all(); };
            LOG_INFO << "[BCH-POOL] stratum listening on " << stratum_addr << ":"
                     << stratum_port << " (BCHWorkSource: SHA256d, no-segwit,"
                     << " CashTokens transparent-carry; hit block routes the"
                     << " dual-path broadcaster).";
        } else {
            LOG_ERROR << "[BCH-POOL] stratum FAILED to bind " << stratum_addr << ":"
                      << stratum_port << " -- stratum disabled, daemon run-loop continues.";
            stratum_server.reset();
        }
    } else {
        LOG_INFO << "[BCH-POOL] stratum disabled (no --stratum bind given);"
                 << " embedded daemon run-loop only.";
    }

    // Drive the shared io_context: pool node + embedded daemon + stratum run together.
    ioc.run();
}

} // namespace bch