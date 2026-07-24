// SPDX-License-Identifier: AGPL-3.0-or-later
// dash::stratum::DASHWorkSource -- Stage 4c/4d bodies (issue #732).
//
// 4c (template serving): bridges the armed get_work() seam (#726 -- embedded
// coin-state when seeded, retained dashd GBT fallback otherwise) into the
// template trio the coin-agnostic StratumSession consumes in
// send_notify_work(): get_current_work_template() / get_stratum_merkle_
// branches() / build_connection_coinbase() (coinb1/coinb2 split around the
// 8-byte nonce64 extranonce slot). The DashWorkData snapshot is cached under
// template_mutex_, keyed on work_generation_ + a 30 s staleness TTL, so the
// per-session 1 s notify timers never turn into a dashd RPC storm.
//
// 4d (submit scoring): mining_submit() reconstructs the 80-byte header from
// the frozen JobSnapshot + miner inputs, runs the DASH X11 chained-hash PoW
// (the --selftest-pinned dash::crypto::hash_x11), and classifies: WonBlock ->
// full-block assembly (the same serialization the --mine-block leg uses,
// coin/block_producer.hpp idiom) -> submit_block_fn_ (dual-path won-block
// broadcaster bound in main_dash.cpp); ShareAccept -> mint_share_fn_ seam
// (accept-for-vardiff + LOUD log while unbound); else low-difficulty reject.
// compute_share_difficulty() is the same reconstruction ending in
// diff1 / x11(header), so the coin-agnostic vardiff gate engages.
//
// Coinbase byte-compatibility: the payout split + tx layout reuse the
// EXISTING SSOTs the verifier and the --mine-block producer already share --
// dash::coinbase::compute_dash_payouts (worker_tx || packed_payments ||
// donation tail, the share_check.hpp gentx order) and dash::coinbase::build /
// split_coinb (ref_hash + nonce64 OP_RETURN tail). No second payout or
// serialization implementation exists in this TU by construction.
//
// Embedded / fallback duality (MUST PERSIST): get_work() sources the base
// template through dash::stratum::get_work(), which picks the EMBEDDED arm when
// the node-held NodeCoinState bundle is populated and otherwise falls back to
// the always-reachable dashd GBT RPC arm. The dashd-RPC fallback is never
// removed -- it is the safety + [GBT-XCHECK] cross-check path (operator rule).

#include <impl/dash/stratum/work_source.hpp>

#include <impl/dash/stratum/submit_payee_guard.hpp>  // check_submit_payee (won-block stale-payee gate)
#include <impl/dash/coinbase_builder.hpp>     // compute_dash_payouts, build, split_coinb, merkle helpers
#include <impl/dash/coin/block_producer.hpp>  // compute_merkle_root, append_compact_size, target_from_nbits
#include <impl/dash/crypto/hash_x11.hpp>      // dash::crypto::hash_x11 (X11 PoW SSOT)
#include <impl/dash/params.hpp>               // dash::make_coin_params
#include <impl/dash/coin/vendor/cbtx.hpp>     // vendor::parse_cbtx (GBT-xcheck creditPool)

#include <core/address_utils.hpp>             // core::address_to_script (mint payout from username)
#include <core/log.hpp>
#include <core/target_utils.hpp>              // chain::target_to_difficulty

#include <btclibs/util/strencodings.h>        // ParseHex, HexStr

#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <span>
#include <utility>

namespace dash::stratum {

namespace {

// Template staleness TTL: even without a work_generation bump (tip signal),
// re-source the template so ntime/mempool drift is bounded. Mirrors the ~30 s
// GBT re-poll every stratum sibling uses.
constexpr auto kStaleAfter = std::chrono::seconds(30);
// Negative-cache window after a failed sourcing attempt (set-gap / dashd
// down): sessions retry notify every 1 s -- don't turn that into an RPC storm.
constexpr auto kRetryAfter = std::chrono::seconds(5);

// Stratum sends ntime/nonce/nbits as big-endian hex; sscanf(%x) decodes them.
inline uint32_t parse_be_hex_u32(const std::string& s)
{
    uint32_t v = 0;
    std::sscanf(s.c_str(), "%x", &v);
    return v;
}

// One merkle ascent step: sha256d(left||right) over the two LE-internal
// 32-byte node hashes (per-coin isolation: the dash-local pair fold, same
// idiom as coin/block_producer.hpp's compute_merkle_root inner step).
inline uint256 merkle_pair(const uint256& left, const uint256& right)
{
    unsigned char buf[64];
    std::memcpy(buf,      left.data(),  32);
    std::memcpy(buf + 32, right.data(), 32);
    return dash::coinbase::sha256d(std::span<const unsigned char>(buf, 64));
}

// Extract the 20-byte pubkey hash from a canonical P2PKH scriptPubKey
// (76 a9 14 <20B> 88 ac). DASH sharechain payouts are pubkey-hash keyed
// (share_check.hpp: pubkey_hash_to_script2), so this is the address shape a
// miner must authorize with to earn credit. Returns false for any other shape.
inline bool p2pkh_pubkey_hash(const std::vector<unsigned char>& script, uint160& out)
{
    if (script.size() != 25) return false;
    if (script[0] != 0x76 || script[1] != 0xa9 || script[2] != 0x14
        || script[23] != 0x88 || script[24] != 0xac) return false;
    std::memcpy(out.begin(), script.data() + 3, 20);
    return true;
}

}  // namespace

DASHWorkSource::DASHWorkSource(const coin::NodeCoinState& coin_state,
                               std::function<coin::DashWorkData()> dashd_fallback,
                               SubmitBlockFn submit_fn,
                               core::stratum::StratumConfig config,
                               bool is_testnet)
    : coin_state_(coin_state)
    , dashd_fallback_(std::move(dashd_fallback))
    , submit_block_fn_(std::move(submit_fn))
    , config_(std::move(config))
    , is_testnet_(is_testnet)
{
    // X11 uses the standard Bitcoin diff-1 scale (p2pool-dash net
    // DUMB_SCRYPT_DIFF = 1) -- override the StratumConfig default (65536, the
    // scrypt convention) exactly as the SHA256d BTC work source does. Without
    // this the advertised mining.set_difficulty is inflated 65536x and X11
    // miners self-throttle into never submitting.
    config_.set_difficulty_multiplier = 1.0;
    // Runtime coin tag for the coin-agnostic core log lines (#732 secondary
    // defect: the core hardcoded "[LTC]" and a DASH binary logged LTC).
    if (config_.coin_symbol.empty())
        config_.coin_symbol = "DASH";
    // Stale-payee fix: DASH's coinbase validity is height-bound (the
    // masternode payee rotates EVERY block), so the stratum session must
    // NEVER assemble a job from mixed template fetches — it requires the
    // atomic header+coinbase snapshot build_connection_coinbase() returns
    // (WorkSnapshot::has_header) and suppresses the job otherwise. This also
    // makes the core's legacy stub-coinbase fallback unreachable for DASH.
    config_.require_job_snapshot = true;
    // Vardiff target share rate: adopt p2pool-dash's FIELD-TUNED default of 10s
    // per pseudoshare (p2pool-dash/p2pool/main.py:1153 default=10., dest='share_rate'),
    // not the 3s jtoomim/BTC default (stratum_types.hpp:40). DASH's variable X11
    // hashrate at 3s recomputes vardiff 3.3x as often and chases the variance,
    // producing the observed oscillation (1170->2264->1405->2041 in minutes) and
    // the ~28% "Low difficulty share" reject storm. 10s cuts retarget frequency
    // 3.3x and stabilises vardiff at the source. DASH-only; other coins keep the
    // 3s StratumConfig default. Pairs with the per-job issued_difficulty grace.
    config_.target_time = 10.0;
    // Use the stable-by-construction hashrate-based vardiff (D = H_est*target/2^32)
    // instead of the ratio-feedback loop, which still limit-cycles ~2-3x even at
    // 10s for variable X11 hashrate — the residual "Low difficulty share" rejects.
    // Derived directly from a smoothed hashrate, so it cannot oscillate. DASH-only;
    // other coins keep the legacy ratio path (use_hashrate_vardiff=false).
    config_.use_hashrate_vardiff = true;
    // ── Zombie-session leak fix (mining-hotel): OPT DASH IN to the live-session
    // hygiene knobs (default-off in StratumConfig so other coins are unchanged).
    // A NAT-dropped rig's TCP session is never FIN/RST'd, so socket_.is_open()
    // stays true forever and the session is never reaped -- every failed retry
    // minted an immortal subscribed session drawing full per-notify job builds
    // (66 sockets for ~23 rigs). Transport/liveness only; consensus-neutral.
    config_.tcp_keepalive_enabled    = true;   // kernel probes dead NAT paths (root fix)
    config_.tcp_keepalive_idle_sec   = 60;
    config_.tcp_keepalive_interval_sec = 10;
    config_.tcp_keepalive_count      = 3;       // ~90 s to detect a dead peer
    config_.handshake_timeout_sec    = 30;      // drop never-authorize probes
    // Idle reaper is a BACKSTOP to TCP keepalive (the real liveness authority),
    // not the primary zombie killer. 1800 s + the keepalive-aware skip in
    // start_idle_reaper() means an authorized rig on a high fixed-diff suffix
    // (e.g. ADDR+4096 at modest X11 hashrate -> multi-minute share intervals) is
    // NEVER reaped for idleness while its socket is keepalive-validated; only
    // genuinely dead / never-authorized sessions are reclaimed.
    config_.session_idle_timeout_sec = 1800;
    config_.max_write_queue_depth    = 256;     // drop a stuck-write dead peer
    // Idle keepalive-notify (coupled with the #751 idle-reconnect churn fix):
    // measured Antminer D9 rigs DROP a pool connection that receives no
    // mining.notify for 60.0 s (then retry after 30 s). Until the #751 fix, the
    // CoindRPC idle-reconnect churn re-broadcast work every ~30 s and was the
    // ONLY thing keeping idle BACKUP pool connections alive; reducing that churn
    // without feeding idle sessions would make every idle backup flap every
    // ~90 s. Re-notify the CURRENT job (non-clean, so no ASIC work reset) every
    // 25 s -- comfortably under the 60 s watchdog -- so any node is a stable
    // backup regardless of slot/path/RPC-timeout settings.
    config_.keepalive_notify_sec     = 25;
    LOG_INFO << "[DASH-STRATUM] DASHWorkSource constructed"
             << " (min_diff=" << config_.min_difficulty
             << " max_diff=" << config_.max_difficulty
             << " target_time=" << config_.target_time
             << "s vardiff=" << (config_.vardiff_enabled ? "on" : "off")
             << " dashd_fallback=" << (dashd_fallback_ ? "wired" : "UNSET")
             << " submit_fn=" << (submit_block_fn_ ? "wired" : "UNSET") << ")";
    if (!dashd_fallback_) {
        // The fallback is the always-reachable safety arm; an unbound one means
        // a set-gap (unpopulated bundle) would have NOTHING to source from.
        LOG_WARNING << "[DASH-STRATUM] dashd_fallback UNSET -- get_work() on a "
                       "coin-state set-gap has no template source (embedded arm "
                       "only). Bind the dashd GBT RPC fallback in main_dash.cpp.";
    }
}

DASHWorkSource::~DASHWorkSource() = default;

// ─────────────────────────────────────────────────────────────────────────────
// Fused get_work(): the single miner-facing entry point. Thin node-bound
// adapter over the free dash::stratum::get_work() capstone (#698) -- source the
// base template off the node-held coin-state (embedded when populated, retained
// dashd fallback on a set-gap) and assemble the per-miner job targets over it.
// ─────────────────────────────────────────────────────────────────────────────
GetWork DASHWorkSource::get_work(const WorkJobTargetInputs& job_in) const
{
    // Mainnet embedded gate (see resource_template_now): default OFF keeps an
    // unconfigured mainnet node on the reward-safe dashd fallback (fail-closed);
    // testnet/regtest and the --embedded-mainnet opt-in run the embedded arm.
    if (!is_testnet_ && !embedded_mainnet_) {
        coin::DashWorkData w =
            dashd_fallback_ ? dashd_fallback_() : coin::DashWorkData{};
        return GetWork{ coin::WorkSource::DashdFallback, std::move(w),
                        assemble_work_job_targets(job_in) };
    }
    // Qualify the free function explicitly: unqualified `get_work` in this
    // member body resolves to THIS member (class scope shadows the namespace),
    // so name the capstone by its namespace to avoid a self-call.
    return ::dash::stratum::get_work(coin_state_, dashd_fallback_, job_in);
}

// ─────────────────────────────────────────────────────────────────────────────
// IWorkSource: config + read-only state -- real now.
// ─────────────────────────────────────────────────────────────────────────────

std::function<uint256()> DASHWorkSource::get_best_share_hash_fn() const
{
    std::lock_guard<std::mutex> lk(best_share_mutex_);
    return best_share_hash_fn_;  // empty until set_best_share_hash_fn() wires it
}

std::string DASHWorkSource::get_current_gbt_prevhash() const
{
    // GBT-conventional BE display hex of the tip the pool mines on, drawn from
    // the SAME cached DashWorkData get_current_work_template() serves -- one
    // truthful source, so the dedicated getter and the assembled template can
    // never silently diverge. Empty on a set-gap (no template source armed) --
    // a truthful absence, never a fabricated tip id.
    auto wd = cached_work();
    if (!wd) return {};
    return wd->m_previous_block.GetHex();
}

bool DASHWorkSource::has_merged_chain(uint32_t /*chain_id*/) const
{
    // DASH V36: standalone X11 parent, no merged mining. (Any future
    // merged-mining seam folds in at v37; never fabricated here.)
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// IWorkSource: per-connection bookkeeping -- minimal but real now.
// ─────────────────────────────────────────────────────────────────────────────

void DASHWorkSource::register_stratum_worker(const std::string& session_id,
                                             const core::stratum::WorkerInfo& info)
{
    std::lock_guard<std::mutex> lk(workers_mutex_);
    workers_[session_id] = info;
    LOG_INFO << "[DASH-STRATUM] worker registered: session=" << session_id
             << " user=" << info.username;
}

void DASHWorkSource::unregister_stratum_worker(const std::string& session_id)
{
    std::lock_guard<std::mutex> lk(workers_mutex_);
    auto it = workers_.find(session_id);
    if (it != workers_.end()) {
        LOG_INFO << "[DASH-STRATUM] worker unregistered: session=" << session_id
                 << " user=" << it->second.username
                 << " accepted=" << it->second.accepted
                 << " rejected=" << it->second.rejected
                 << " stale=" << it->second.stale;
        workers_.erase(it);
    }
    // Unknown session_id: idempotent no-op (the server may double-unregister on
    // a racing disconnect) -- never a crash.
}

void DASHWorkSource::update_stratum_worker(const std::string& session_id,
                                           double hashrate, double dead_hashrate,
                                           double difficulty,
                                           uint64_t accepted, uint64_t rejected,
                                           uint64_t stale)
{
    std::lock_guard<std::mutex> lk(workers_mutex_);
    auto it = workers_.find(session_id);
    if (it == workers_.end()) return;  // update for an unregistered session: drop.
    it->second.hashrate      = hashrate;
    it->second.dead_hashrate = dead_hashrate;
    it->second.difficulty    = difficulty;
    it->second.accepted      = accepted;
    it->second.rejected      = rejected;
    it->second.stale         = stale;
}

std::map<std::string, core::stratum::WorkerInfo>
DASHWorkSource::get_stratum_workers() const
{
    std::lock_guard<std::mutex> lk(workers_mutex_);
    return workers_;   // copy under lock -- dashboard stats seam
}

std::shared_ptr<const coin::DashWorkData> DASHWorkSource::peek_template() const
{
    std::lock_guard<std::mutex> lk(template_mutex_);
    return template_cache_;   // last-sourced snapshot; no refresh triggered
}

// ─────────────────────────────────────────────────────────────────────────────
// IWorkSource: work generation -- Stage 4c (the template trio).
// ─────────────────────────────────────────────────────────────────────────────

void DASHWorkSource::resource_template_now() const
{
    // The blocking select_work()/dashd-GBT re-source + cache update. Runs either
    // inline on the caller (legacy blocking path) OR on the background rpc_pool
    // thread (io-thread-decouple, via refresh_executor_). select_work() is done
    // OUTSIDE the lock (the fallback arm is a blocking dashd RPC); the cache is
    // then updated under template_mutex_.

    // ── Mainnet embedded gate (v0.2.4 trigger) ──────────────────────────────
    // The SML/QuorumManager wiring emits a real DIP-0004 type-5 CCbTx, and its
    // byte-parity against a real dashd getblocktemplate is PROVEN (from the raw
    // mnlistdiff wire: both merkle roots + bestCL + creditPool accrual). The
    // mainnet gate LIFTS behind the explicit set_embedded_mainnet opt-in
    // (--embedded-mainnet). Default OFF => unconfigured mainnet nodes stay
    // FAIL-CLOSED on the reward-safe dashd-RPC fallback. Testnet/regtest always
    // run the embedded arm. Even when enabled, the NodeCoinState viability gate
    // (SML+quorum fresh at the tip, non-superblock, credit-pool seed height at
    // tip, bestCL fresh) fails safe to the fallback, so no invalid template mines.
    const bool embedded_arm_enabled = is_testnet_ || embedded_mainnet_;
    if (!embedded_arm_enabled && coin_state_.populated()) {
        static std::once_flag mainnet_gate_logged;
        std::call_once(mainnet_gate_logged, [] {
            LOG_WARNING << "[DASH-STRATUM-GBT] embedded template arm disabled on "
                           "mainnet (byte-parity proven; enable with --embedded-mainnet) "
                           "— using dashd-RPC fallback";
        });
    }

    coin::DashWorkData work;
    bool work_is_embedded = false;   // tracks the FINAL sourced arm for the cache tag
    const bool try_embedded = embedded_arm_enabled && coin_state_.populated();
    if (try_embedded || dashd_fallback_) {
        try {
            // Mainnet-gated: bypass select_work and source the reward-safe dashd
            // fallback directly; testnet/regtest picks embedded-when-viable.
            coin::WorkSelection sel = try_embedded
                ? coin_state_.select_work(dashd_fallback_)
                : coin::WorkSelection{
                      dashd_fallback_ ? dashd_fallback_() : coin::DashWorkData{},
                      coin::WorkSource::DashdFallback };
            // BLOCKER-3 pre-emit HARD GATE (PR #780): re-validate an EMBEDDED
            // template's CbTx against consensus invariants (both roots recomputed,
            // DKG/superblock/bestCL/credit-pool-height guards) before it can be
            // served; on any failure DISCARD it for the reward-safe dashd arm.
            if (sel.source == coin::WorkSource::Embedded
                && !coin_state_.embedded_template_emit_ok(sel.work)) {
                LOG_WARNING << "[DASH-STRATUM-GBT] embedded CbTx pre-emit check "
                               "FAILED at h=" << sel.work.m_height
                            << " — discarding, using dashd fallback";
                sel = coin::WorkSelection{
                    dashd_fallback_ ? dashd_fallback_() : coin::DashWorkData{},
                    coin::WorkSource::DashdFallback };
            }
            // GBT-xcheck reward-safety BACKSTOP (soak): when enabled and a dashd
            // is reachable, cross-check the embedded CbTx creditPoolBalance
            // against dashd getblocktemplate; on a same-height mismatch serve
            // dashd's template. Catches ANY seed bug the daemonless self-checks
            // miss. Opt-in (--embedded-mainnet-with-dashd), not pure-daemonless.
            if (sel.source == coin::WorkSource::Embedded && gbt_xcheck_ && dashd_fallback_) {
                coin::DashWorkData dref = dashd_fallback_();
                coin::vendor::CCbTx emb_cb, dref_cb;
                const bool emb_ok  = coin::vendor::parse_cbtx(sel.work.m_coinbase_payload, emb_cb);
                const bool dref_ok = coin::vendor::parse_cbtx(dref.m_coinbase_payload, dref_cb);
                if (emb_ok && dref_ok
                    && dref.m_height == sel.work.m_height
                    && emb_cb.creditPoolBalance != dref_cb.creditPoolBalance) {
                    LOG_WARNING << "[DASH-STRATUM-GBT] GBT-xcheck MISMATCH at h="
                                << sel.work.m_height << " embedded creditPool="
                                << emb_cb.creditPoolBalance << " dashd="
                                << dref_cb.creditPoolBalance
                                << " — serving dashd template (reward-safety backstop)";
                    sel = coin::WorkSelection{ std::move(dref),
                                               coin::WorkSource::DashdFallback };
                }
            }
            // E2c observability: WHICH arm served this template + the MN payee
            // it carries (the payee-correctness axis of the embedded arm). One
            // line per re-source (cache-TTL cadence), INFO -- the field-
            // checkable "embedded arm is live and paying the right MN" signal
            // the E2c smoke gate and prod diagnosis both read.
            std::string mn_payee = "(none)";
            for (const auto& pp : sel.work.m_packed_payments)
                if (pp.payee != "!6a") { mn_payee = pp.payee; break; }
            LOG_INFO << "[DASH-STRATUM-GBT] template sourced: arm="
                     << (sel.source == coin::WorkSource::Embedded
                             ? "EMBEDDED" : "dashd-fallback")
                     << " h=" << sel.work.m_height
                     << " mn_payee=" << mn_payee;
            work_is_embedded = (sel.source == coin::WorkSource::Embedded);
            work = std::move(sel.work);
        } catch (const std::exception& e) {
            LOG_WARNING << "[DASH-STRATUM] template sourcing threw: " << e.what();
            work = coin::DashWorkData{};
        }
    }

    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lk(template_mutex_);
    if (work.m_bits == 0 || work.m_previous_block.IsNull()) {
        // Set-gap (unarmed fallback / empty GBT) OR a zero-prev template (the
        // pre-auth zero-hash job_0 defect: a zeroed prev is not mineable work
        // on any chain): an honest absence. Keep any previous cache DROPPED --
        // serving a stale tip is worse than waiting.
        template_cache_.reset();
        template_last_fail_at_ = now;
        return;
    }
    // Tip moved since the last snapshot? Bump work_generation_ so sessions
    // detect stale work between their timer firings and re-push.
    if (template_cache_ && template_cache_->m_previous_block != work.m_previous_block)
        work_generation_.fetch_add(1, std::memory_order_relaxed);
    template_cache_ = std::make_shared<const coin::DashWorkData>(std::move(work));
    template_cache_gen_ = work_generation_.load(std::memory_order_relaxed);
    template_cache_at_  = now;
    template_cache_is_embedded_ = work_is_embedded;
    template_last_fail_at_ = {};
}

std::shared_ptr<const coin::DashWorkData> DASHWorkSource::cached_work() const
{
    const uint64_t gen = work_generation_.load(std::memory_order_relaxed);
    const auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lk(template_mutex_);
        // FRESH cache (same generation, inside the TTL) -> serve it. The
        // generation key is load-bearing: bump_work_generation() is the "the tip
        // may have rotated, re-source" signal (double-fetch-race fix), so it must
        // still trigger a refresh -- but io-thread-decouple moves WHERE that
        // refresh runs off the stratum io thread (below).
        if (template_cache_ && template_cache_gen_ == gen
            && now - template_cache_at_ < kStaleAfter) {
            // Serve-time re-check (soak build-vs-serve skew): an EMBEDDED cached
            // template is re-validated against the CURRENT coin-state before it
            // is served. The credit-pool seed can advance without a
            // work_generation bump reaching here first, leaving a cached CbTx
            // that commits a stale creditPoolBalance (bad-cbtx-assetlocked-amount)
            // — the pre-emit gate's value/height re-check catches it. If it no
            // longer validates, drop the cache and re-source (below). A dashd
            // fallback cached template is served as-is.
            if (!template_cache_is_embedded_
                || coin_state_.embedded_template_emit_ok(*template_cache_))
                return template_cache_;
            LOG_WARNING << "[DASH-STRATUM-GBT] cached EMBEDDED template failed "
                           "serve-time re-check (stale creditPool/roots) — re-sourcing";
            template_cache_.reset();
        }

        if (refresh_executor_) {
            // NON-BLOCKING scale path (the fix for 60+ sessions freezing on each
            // re-source): the io thread NEVER runs the blocking select_work()/
            // dashd-GBT. Hand it to the background rpc_pool as a SINGLE-FLIGHT
            // job and serve the CURRENT cache (possibly stale, or null on a
            // set-gap) immediately. A minted share bumps the generation ~every
            // 15-30 s; before, that blocked the io thread on a full GBT -- now it
            // costs one background fetch, coalesced. A stale serve is bounded by
            // the bg refresh latency AND the 3 s tip-poll invalidation (which
            // RESETS the cache on a real tip change, so a rotated tip is served
            // as a set-gap until the fresh template lands, never as stale work).
            const bool recently_failed =
                !template_cache_
                && template_last_fail_at_.time_since_epoch().count() != 0
                && now - template_last_fail_at_ < kRetryAfter;
            if (!recently_failed && !template_refresh_inflight_.exchange(true)) {
                refresh_executor_([this]() {
                    resource_template_now();
                    template_refresh_inflight_.store(false);
                });
            }
            return template_cache_;   // stale-or-null; null == honest set-gap
        }

        // Legacy inline-blocking path (executor not wired: embedded/tests) --
        // BYTE-IDENTICAL to the pre-decouple behaviour. Negative cache: a recent
        // failed sourcing attempt -> don't re-poll yet.
        if (!template_cache_ && template_last_fail_at_.time_since_epoch().count() != 0
            && now - template_last_fail_at_ < kRetryAfter)
            return nullptr;
    }

    // Legacy path only: re-source inline (blocks the caller) then serve.
    resource_template_now();
    std::lock_guard<std::mutex> lk(template_mutex_);
    return template_cache_;
}

nlohmann::json DASHWorkSource::get_current_work_template() const
{
    // GBT-shaped template with exactly the fields StratumSession::
    // send_notify_work() consumes: previousblockhash (BE display hex),
    // version (int), bits (8-char BE hex string), curtime, height. Empty
    // object on a set-gap -- the session skips the push and retries.
    auto wd = cached_work();
    if (!wd) return nlohmann::json::object();

    nlohmann::json tmpl;
    tmpl["previousblockhash"] = wd->m_previous_block.GetHex();
    tmpl["version"]           = wd->m_version;
    tmpl["bits"]              = dash::coinbase::be_hex_u32(wd->m_bits);
    tmpl["height"]            = wd->m_height;
    tmpl["coinbasevalue"]     = wd->m_coinbase_value;
    tmpl["curtime"]           = static_cast<uint64_t>(
        wd->m_curtime ? wd->m_curtime
                      : static_cast<uint32_t>(std::time(nullptr)));
    if (wd->m_mintime)
        tmpl["mintime"] = wd->m_mintime;
    return tmpl;
}

std::vector<std::string> DASHWorkSource::get_stratum_merkle_branches() const
{
    // Stratum merkle branches over [coinbase placeholder, tx1..txN]: the
    // sibling list a miner ascends from its own coinbase txid. Wire encoding
    // = hex of the LE-internal bytes (dash::coinbase::merkle_branches_hex --
    // NOT the reversed display form; see that helper's cpuminer note).
    auto wd = cached_work();
    if (!wd || wd->m_tx_hashes.empty()) return {};

    std::vector<uint256> leaves;
    leaves.reserve(1 + wd->m_tx_hashes.size());
    leaves.push_back(uint256::ZERO);   // coinbase placeholder at leaf 0
    leaves.insert(leaves.end(), wd->m_tx_hashes.begin(), wd->m_tx_hashes.end());
    return dash::coinbase::merkle_branches_hex(
        dash::coinbase::merkle_branches_raw(leaves));
}

std::pair<std::string, std::string> DASHWorkSource::get_coinbase_parts() const
{
    // Session fallback when the per-connection builder yields nothing (e.g. a
    // pre-authorize notify): a pool coinbase with NO miner payout (worker
    // portion falls to the donation tail) but the correct masternode outputs
    // + nonce64 extranonce slot. Keeps the core's hardcoded legacy default
    // coinbase (an LTC-shaped stub) unreachable for DASH.
    auto cbr = build_connection_coinbase(uint256::ZERO, "", {}, {});
    return { cbr.coinb1, cbr.coinb2 };
}

core::stratum::CoinbaseResult DASHWorkSource::build_connection_coinbase(
    const uint256& prev_share_hash,
    const std::string& /*extranonce1_hex*/,
    const std::vector<unsigned char>& payout_script,
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& /*merged_addrs*/) const
{
    // 4c per-connection coinbase. Payout split + serialization go through the
    // EXISTING verifier-shared SSOTs (compute_dash_payouts -> build ->
    // split_coinb) so the coinbase a miner hashes is byte-identical to the
    // gentx shape share_check.hpp / pplns.hpp enforce -- no second payout
    // implementation to drift.
    //
    // PPLNS weights come from the set_pplns_weights_fn seam (ShareTracker
    // walk, bound by the run-loop). Genesis / unbound degradation: a fresh
    // pool's sharechain is EMPTY, so the single connecting miner carries the
    // whole worker_payout -- weights {payout_script: 1}, total 1 -- plus the
    // GBT-mandated masternode/superblock outputs and the donation tail.
    auto wd = cached_work();
    if (!wd) return {};   // no template -> no job (session retries)

    // Shared frozen-snapshot tail: branches + tx set from the SAME wd the
    // coinbase was built over, so the session's job merkle always matches the
    // block body assembled at submit time. Used by BOTH coinbase paths below.
    auto freeze_snapshot = [&](core::stratum::CoinbaseResult& out,
                               const uint256& ref_hash) {
        // Freeze the header fields ATOMICALLY with the coinbase: prevhash /
        // version / nbits / ntime come from the SAME wd the coinbase was
        // built over, so the session's issued job and the block body
        // assembled at submit time can never mix template generations. This
        // is the stale-payee root-cause fix: the masternode payee inside
        // THIS coinbase is only valid at THIS wd's height — a job carrying a
        // different fetch's prevhash with this coinbase is a guaranteed
        // dashd bad-cb-payee reject (hex-confirmed @h1517420).
        out.snapshot.has_header      = true;
        out.snapshot.gbt_prevhash    = wd->m_previous_block.GetHex();
        out.snapshot.header_version  = static_cast<uint32_t>(wd->m_version);
        out.snapshot.block_nbits_hex = dash::coinbase::be_hex_u32(wd->m_bits);
        out.snapshot.curtime         = wd->m_curtime
            ? wd->m_curtime : static_cast<uint32_t>(std::time(nullptr));
        out.snapshot.height          = wd->m_height;
        out.snapshot.subsidy             = wd->m_coinbase_value;
        out.snapshot.frozen_ref.ref_hash = ref_hash;
        if (!wd->m_tx_hashes.empty()) {
            std::vector<uint256> leaves;
            leaves.reserve(1 + wd->m_tx_hashes.size());
            leaves.push_back(uint256::ZERO);
            leaves.insert(leaves.end(), wd->m_tx_hashes.begin(), wd->m_tx_hashes.end());
            auto raw = dash::coinbase::merkle_branches_raw(leaves);
            out.snapshot.frozen_ref.frozen_merkle_branches = raw;
            out.snapshot.merkle_branches = dash::coinbase::merkle_branches_hex(raw);
        }
        out.snapshot.tx_data = std::make_shared<const std::vector<std::string>>(
            wd->m_tx_data_hex);
    };

    // ── Producer path (slice 3/3, run-loop mint) ─────────────────────────
    // When bound, the stratum coinbase IS the producer share gentx: split
    // verbatim around the zeroed nonce64 slot. Byte-parity with the mint-time
    // rebuild holds by construction — there is exactly ONE gentx serializer
    // on this path (producer::build_gentx). On nullopt/throw the non-producer
    // path below serves a block-valid coinbase (mint declines fail-closed).
    {
        ProducerJobFn pfn;
        {
            std::lock_guard<std::mutex> lk(producer_job_mutex_);
            pfn = producer_job_fn_;
        }
        if (pfn) {
            try {
                if (auto pj = pfn(prev_share_hash, payout_script, *wd)) {
                    if (pj->nonce64_offset + 8 <= pj->gentx_bytes.size()) {
                        core::stratum::CoinbaseResult out;
                        std::span<const unsigned char> b1(
                            pj->gentx_bytes.data(), pj->nonce64_offset);
                        std::span<const unsigned char> b2(
                            pj->gentx_bytes.data() + pj->nonce64_offset + 8,
                            pj->gentx_bytes.size() - pj->nonce64_offset - 8);
                        out.coinb1 = HexStr(b1);
                        out.coinb2 = HexStr(b2);
                        freeze_snapshot(out, pj->ref_hash);
                        // Publish the share_info-committed target so the
                        // mining_submit share gate matches the minted share's
                        // own m_bits (the ban-safety alignment).
                        // set_share_target only stores atomics; const_cast is
                        // safe here (build_connection_coinbase is const by
                        // interface contract, the target publish is a relaxed
                        // atomic store).
                        if (pj->share_bits != 0)
                            const_cast<DASHWorkSource*>(this)->set_share_target(
                                pj->share_bits, pj->share_max_bits);
                        return out;
                    }
                    LOG_ERROR << "[DASH-STRATUM] producer job nonce64 offset out of "
                                 "range -- falling back to non-producer coinbase";
                } else {
                    static int degrade_log = 0;
                    if (degrade_log++ % 50 == 0)
                        LOG_INFO << "[DASH-STRATUM] producer job unavailable "
                                    "(tracker busy / non-P2PKH payout / no template) "
                                    "-- serving non-producer coinbase (mint disabled "
                                    "for this job)";
                }
            } catch (const std::exception& e) {
                LOG_WARNING << "[DASH-STRATUM] producer job threw: " << e.what()
                            << " -- serving non-producer coinbase";
            }
        }
    }

    try {
        const core::CoinParams params = dash::make_coin_params(is_testnet_);

        PplnsWeightsFn pplns_fn;
        {
            std::lock_guard<std::mutex> lk(pplns_mutex_);
            pplns_fn = pplns_weights_fn_;
        }

        std::map<std::vector<unsigned char>, uint64_t> weights;
        uint64_t total_weight = 0;
        uint256  ref_hash     = uint256::ZERO;  // no sharechain commitment yet
        if (pplns_fn) {
            if (auto res = pplns_fn(prev_share_hash)) {
                weights      = std::move(res->weights);
                total_weight = res->total_weight;
                ref_hash     = res->ref_hash;
            }
        }

        // DASH sharechain payouts are P2PKH-keyed (share_check.hpp
        // pubkey_hash_to_script2); the finder pkh routes the pre-v36 2%
        // finder fee back to this miner's own output.
        uint160 finder_pkh;   // zero unless the payout script is P2PKH
        const bool have_pkh = p2pkh_pubkey_hash(payout_script, finder_pkh);

        if (weights.empty() || total_weight == 0) {
            if (have_pkh) {
                weights[payout_script] = 1;
                total_weight = 1;
            } else if (!payout_script.empty()) {
                LOG_WARNING << "[DASH-STRATUM] payout script is not P2PKH ("
                            << payout_script.size() << "B) -- genesis coinbase "
                               "routes worker payout to the donation tail "
                               "(authorize with a P2PKH DASH address)";
            }
            // No usable miner script: all-to-donation (still a valid block).
        }

        auto tx_outs = dash::coinbase::compute_dash_payouts(
            wd->m_coinbase_value, wd->m_packed_payments, finder_pkh,
            weights, total_weight, params);

        dash::coinbase::CoinbaseLayout layout = dash::coinbase::build(
            *wd, tx_outs, /*pool_tag=*/"c2pool", params, ref_hash);
        dash::coinbase::CoinbSplit split = dash::coinbase::split_coinb(layout);

        core::stratum::CoinbaseResult out;
        out.coinb1 = std::move(split.coinb1_hex);
        out.coinb2 = std::move(split.coinb2_hex);

        // Freeze the snapshot ATOMICALLY with the coinbase (shared helper:
        // header fields + branches + tx set from the SAME wd).
        freeze_snapshot(out, ref_hash);
        return out;
    } catch (const std::exception& e) {
        // Builder invariant tripped (logged): serve no job rather than a
        // malformed coinbase.
        LOG_ERROR << "[DASH-STRATUM] build_connection_coinbase failed: " << e.what();
        return {};
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IWorkSource: share submission -- Stage 4d (the X11 hot path).
// ─────────────────────────────────────────────────────────────────────────────

nlohmann::json DASHWorkSource::mining_submit(
    const std::string& username, const std::string& job_id,
    const std::string& extranonce1, const std::string& extranonce2,
    const std::string& ntime, const std::string& nonce,
    const std::string& /*request_id*/,
    const std::map<uint32_t, std::vector<unsigned char>>& /*merged_addresses*/,
    const core::stratum::JobSnapshot* job)
{
    // Stage 4d -- the hot path. Reconstruct the 80-byte header from the frozen
    // JobSnapshot + miner inputs, run the DASH X11 chained-hash PoW, and place
    // the result in EXACTLY ONE of three classes: WonBlock -> full-block
    // assembly (the --mine-block serialization idiom) -> submit_block_fn_
    // (dual-path broadcaster bound in main_dash.cpp); ShareAccept ->
    // mint_share_fn_ seam; else low-difficulty reject.

    // Stratum JSON-RPC error payload (false + [code, message, null]).
    auto reject = [](int code, const char* msg) {
        return nlohmann::json::array({
            false, nlohmann::json::array({code, msg, nullptr})
        });
    };

    if (!job) {
        LOG_WARNING << "[DASH-STRATUM] submit reject (no JobSnapshot): user="
                    << username << " job=" << job_id;
        return reject(21, "Job not found");
    }

    // 1. coinbase = coinb1 || extranonce1 || extranonce2 || coinb2
    //    (en1(4B) + en2(4B) fill the 8-byte nonce64 slot in the OP_RETURN tail).
    auto coinb1_bytes = ParseHex(job->coinb1);
    auto en1_bytes    = ParseHex(extranonce1);
    auto en2_bytes    = ParseHex(extranonce2);
    auto coinb2_bytes = ParseHex(job->coinb2);

    std::vector<unsigned char> coinbase;
    coinbase.reserve(coinb1_bytes.size() + en1_bytes.size()
                     + en2_bytes.size() + coinb2_bytes.size());
    coinbase.insert(coinbase.end(), coinb1_bytes.begin(), coinb1_bytes.end());
    coinbase.insert(coinbase.end(), en1_bytes.begin(),    en1_bytes.end());
    coinbase.insert(coinbase.end(), en2_bytes.begin(),    en2_bytes.end());
    coinbase.insert(coinbase.end(), coinb2_bytes.begin(), coinb2_bytes.end());

    // 2. coinbase txid = sha256d (DASH non-witness canonical serialization).
    const uint256 coinbase_txid = dash::coin::coinbase_txid(coinbase);

    // 3. Ascend the frozen stratum merkle branches (LE-internal bytes --
    //    ParseHex+memcpy, NOT SetHex which reverses). Keep the parsed hashes
    //    for the mint seam.
    std::vector<uint256> branch_hashes;
    branch_hashes.reserve(job->merkle_branches.size());
    uint256 merkle_root = coinbase_txid;
    for (const auto& branch_hex : job->merkle_branches) {
        uint256 b;
        auto bb = ParseHex(branch_hex);
        if (bb.size() == 32) std::memcpy(b.begin(), bb.data(), 32);
        branch_hashes.push_back(b);
        merkle_root = merkle_pair(merkle_root, b);
    }

    // 4. 80-byte header via the block_producer SSOT serializer. prevhash
    //    arrives BE-display -> SetHex converts to internal LE.
    uint256 prev_block;
    prev_block.SetHex(job->gbt_prevhash.c_str());

    unsigned char header[80];
    dash::coin::serialize_header80(header,
        static_cast<int32_t>(job->version), prev_block, merkle_root,
        parse_be_hex_u32(ntime), parse_be_hex_u32(job->nbits),
        parse_be_hex_u32(nonce));

    // 5. X11 PoW (the --selftest-pinned dash::crypto::hash_x11 entry).
    const uint256 pow_hash = dash::crypto::hash_x11(header, sizeof(header));

    // Expand targets. Block target = the original GBT block bits; share
    // target = the frozen share_bits, permissive diff-1 fallback for jobs
    // frozen before a share target was set (never silently reject-everything).
    const uint256 block_target = dash::coin::target_from_nbits(parse_be_hex_u32(
        job->block_nbits.empty() ? job->nbits : job->block_nbits));
    const uint256 share_target = dash::coin::target_from_nbits(
        job->share_bits != 0 ? job->share_bits : 0x1d00ffffu);

    auto bump = [&](bool accepted) {
        std::lock_guard<std::mutex> lk(workers_mutex_);
        for (auto& kv : workers_) {
            if (kv.second.username == username) {
                accepted ? kv.second.accepted++ : kv.second.rejected++;
                break;
            }
        }
    };

    // NOTE: the dashboard "Best Share" feed is NOT recorded here — mining_submit
    // only runs for pool-quality shares / block solutions (the stratum session
    // gates it), so it would miss ordinary pseudoshares. Every accepted
    // pseudoshare is instead recorded via record_best_pseudoshare(), which the
    // core stratum session calls on the vardiff-accept path.

    // 6. Classify (tighten-first: block target before share target).
    if (pow_hash <= block_target) {
        // A full network block. NEVER drop it.
        auto wd = cached_work();
        const uint32_t height = wd ? wd->m_height : 0;
        LOG_WARNING << "[DASH-STRATUM-BLOCK] *** BLOCK FOUND *** user=" << username
                    << " height~=" << height
                    << " pow_hash=" << pow_hash.GetHex().substr(0, 16)
                    << " job=" << job_id;

        // Full block = header || CompactSize(1+ntx) || coinbase || txs -- the
        // exact --mine-block serialization (coin/block_producer.hpp; DASH has
        // no segwit so the coinbase bytes go in verbatim).
        static const std::vector<std::string> kEmptyTxData;
        const std::vector<std::string>& txs =
            job->tx_data ? *job->tx_data : kEmptyTxData;

        std::vector<unsigned char> block_bytes;
        block_bytes.reserve(80 + 9 + coinbase.size() + txs.size() * 256);
        block_bytes.insert(block_bytes.end(), header, header + 80);
        dash::coin::append_compact_size(block_bytes, 1 + txs.size());
        block_bytes.insert(block_bytes.end(), coinbase.begin(), coinbase.end());
        for (const auto& tx_hex : txs) {
            auto tx_bytes = ParseHex(tx_hex);
            block_bytes.insert(block_bytes.end(), tx_bytes.begin(), tx_bytes.end());
        }

        // ── SUBMIT-TIME PAYEE GUARD (payee-script set-membership) ────────
        // Last line of defense before dispatch. REWARD INVARIANT: never refuse
        // a block dashd would ACCEPT (a false refusal forfeits ~0.44 DASH),
        // while still refusing one dashd would deterministically reject for
        // bad-cb-payee. The guard verifies the job's frozen coinbase pays every
        // GBT-mandated payee SCRIPT by SET MEMBERSHIP — it does NOT compare
        // amounts against the current template (the masternode amount is
        // subsidy + fees and drifts with the mempool on every re-pull; dashd
        // checks it against the block's OWN fees). Refuse only when a mandated
        // payee SCRIPT is genuinely absent (PayeeMissing); a moved-tip block is
        // a HeightRace and IS submitted (dashd is the authority at the block's
        // real height), and a guard-side parse failure never blocks a submit.
        // A HeightRace submit is dispatched RPC-FIRST (the is_height_race flag
        // threaded to submit_block_fn_ below): the local dashd validates the
        // block before we relay it to any coin-P2P peer, so an invalid race
        // block is rejected locally for free and never risks a coin-P2P ban.
        bool payee_guard_reject = false;
        bool is_height_race     = false;
        if (wd) {
            const auto guard = check_submit_payee(
                coinbase, job->gbt_prevhash, *wd,
                dash::make_coin_params(is_testnet_));
            switch (guard.verdict) {
            case PayeeGuardVerdict::PayeeMissing:
                payee_guard_reject = true;
                LOG_ERROR << "[DASH-STRATUM-PAYEE-GUARD] WON BLOCK LOCALLY "
                             "REJECTED, NOT submitted: " << guard.detail
                          << " user=" << username << " job=" << job_id
                          << " -- a coinbase that omits a mandated payee script "
                             "is a guaranteed bad-cb-payee network reject; the "
                             "job/template pipeline served stale work "
                             "(investigate!)";
                break;
            case PayeeGuardVerdict::HeightRace:
                // Parent moved since the job was issued -- but "parent moved"
                // is NOT "unwinnable". A chain-extend leaves us a valid
                // same-height competitor (dashd accepts, we race); a 1-block
                // reorg leaves us one above the tip (submitting reorgs the
                // network to us); only a 2+ deep bury is unwinnable, and even
                // then submitting is free (dashd stores a dead orphan). Per the
                // reward invariant we SUBMIT and let dashd decide -- dropping
                // would be a guaranteed, irreversible loss. NOT a reject. Flag
                // it so the broadcaster dispatches RPC-FIRST: the local dashd
                // validates the block before any coin-P2P relay, so an invalid
                // race block is rejected for free and never risks a peer-ban.
                is_height_race = true;
                LOG_WARNING << "[DASH-STRATUM-PAYEE-GUARD] WON BLOCK is a HEIGHT "
                               "RACE: " << guard.detail
                            << " user=" << username << " job=" << job_id
                            << " -- submitting anyway (RPC-first: dashd validates "
                               "before any coin-P2P relay); dashd is the authority "
                               "at the block's real height and will accept if "
                               "valid, reject for free if not";
                break;
            case PayeeGuardVerdict::Unverifiable:
                LOG_WARNING << "[DASH-STRATUM-PAYEE-GUARD] guard could not "
                               "verify (" << guard.detail
                            << ") -- submitting unblocked";
                break;
            case PayeeGuardVerdict::Ok:
                LOG_INFO << "[DASH-STRATUM-PAYEE-GUARD] coinbase pays all "
                            "mandated payee scripts at the current height ("
                         << guard.detail
                         << ") -- amount drift (if any) is validated by dashd "
                            "against the block's own fees; submitting";
                break;
            }
        }

        // Dual-path won-block dispatch: submit_block_fn_ (bound in
        // main_dash.cpp) relays via the dashd submitblock RPC arm + the
        // embedded P2P relay leg when armed; true iff >=1 sink reached. A won
        // block reaching NEITHER is a lost subsidy -- scream, never drop.
        bool reached_network = false;
        if (payee_guard_reject) {
            // Loud local reject: nothing dispatched. The share still counts
            // for the miner below — the miner's work was honest; the stale
            // template was ours.
        } else if (submit_block_fn_) {
            try {
                reached_network = submit_block_fn_(block_bytes, height, is_height_race);
            } catch (const std::exception& e) {
                LOG_ERROR << "[DASH-STRATUM-BLOCK] submit_block_fn threw: " << e.what();
            }
            if (!reached_network) {
                LOG_ERROR << "[DASH-STRATUM-BLOCK] WON BLOCK height=" << height
                          << " reached NEITHER the P2P relay NOR the submitblock "
                             "RPC -- lost subsidy!";
            }
        } else {
            LOG_ERROR << "[DASH-STRATUM-BLOCK] no submit_block_fn wired -- WON "
                         "BLOCK height=" << height << " not broadcast -- lost subsidy!";
        }

        // Recent-blocks dashboard record: a genuine block solution we
        // dispatched to the network. A local payee-guard reject was never sent
        // (not a won block) so it is skipped. Display only; fired after the
        // dispatch decision, never gates it.
        if (!payee_guard_reject) {
            FoundBlockFn fb_fn;
            {
                std::lock_guard<std::mutex> lk(found_block_mutex_);
                fb_fn = on_found_block_fn_;
            }
            if (fb_fn) fb_fn(height, pow_hash, username, reached_network);
        }

        bump(true);
        return nlohmann::json(true);
    }

    if (pow_hash <= share_target) {
        // Meets the sharechain target but not the full block: hand the found-
        // share fields to the mint seam. While the DASH node-side share-
        // creation seam is unbound, accept for vardiff + LOUD log (documented
        // 4d follow-up) -- never a silent drop, never a false reject.
        MintShareFn mint_fn;
        {
            std::lock_guard<std::mutex> lk(mint_share_mutex_);
            mint_fn = mint_share_fn_;
        }

        uint256 share_hash;
        if (mint_fn) {
            MintShareInputs in;
            in.header_bytes.assign(header, header + 80);
            in.subsidy         = job->subsidy;
            in.prev_share_hash = job->prev_share_hash;
            in.merkle_branches = std::move(branch_hashes);
            in.payout_script   = core::address_to_script(username);
            in.pow_hash        = pow_hash;
            // ref_hash: the coinb1/coinb2 split sits immediately after the
            // 32-byte OP_RETURN ref_hash (before the 8B nonce64 slot), so the
            // commitment is the coinb1 tail. Raw LE-internal bytes — embedded
            // via ref_hash.data() at build time, recovered the same way.
            if (coinb1_bytes.size() >= 32)
                std::memcpy(in.ref_hash.begin(),
                            coinb1_bytes.data() + coinb1_bytes.size() - 32, 32);
            // nonce64 = LE u64 of extranonce1 || extranonce2 (4+4 bytes).
            if (en1_bytes.size() + en2_bytes.size() == 8) {
                unsigned char n64[8];
                std::memcpy(n64, en1_bytes.data(), en1_bytes.size());
                std::memcpy(n64 + en1_bytes.size(), en2_bytes.data(), en2_bytes.size());
                uint64_t v = 0;
                for (int i = 7; i >= 0; --i) v = (v << 8) | n64[i];
                in.last_txout_nonce = v;
            }
            in.tx_data         = job->tx_data;
            in.coinbase_bytes  = std::move(coinbase);
            try {
                share_hash = mint_fn(in);
            } catch (const std::exception& e) {
                LOG_WARNING << "[DASH-STRATUM-SHARE] mint_share_fn threw: "
                            << e.what() << " -- share not minted";
            }
        }

        if (!share_hash.IsNull()) {
            LOG_INFO << "[DASH-STRATUM-SHARE] ACCEPTED + MINTED user=" << username
                     << " share_hash=" << share_hash.GetHex().substr(0, 16)
                     << " job=" << job_id;
        } else if (mint_fn) {
            LOG_INFO << "[DASH-STRATUM-SHARE] accepted (mint deferred/declined) "
                        "user=" << username << " job=" << job_id;
        } else {
            LOG_WARNING << "[DASH-STRATUM-SHARE] accepted WITHOUT sharechain "
                           "credit (mint seam unbound -- set_mint_share_fn): user="
                        << username << " job=" << job_id;
        }

        bump(true);
        return nlohmann::json(true);
    }

    bump(false);
    return reject(23, "Low difficulty share");
}

// Shared header reconstruction → X11 pow-hash. Used by BOTH the vardiff-gate
// difficulty (compute_share_difficulty) and the best-share dashboard feed
// (record_best_pseudoshare) so the two never diverge. Returns a null uint256
// on any malformed input.
static uint256 dash_reconstruct_pow_hash(
    const std::string& coinb1, const std::string& coinb2,
    const std::string& extranonce1, const std::string& extranonce2,
    const std::string& ntime, const std::string& nonce,
    uint32_t version, const std::string& prevhash_hex,
    const std::string& nbits_hex,
    const std::vector<std::string>& merkle_branches)
{
    auto coinb1_bytes = ParseHex(coinb1);
    auto en1_bytes    = ParseHex(extranonce1);
    auto en2_bytes    = ParseHex(extranonce2);
    auto coinb2_bytes = ParseHex(coinb2);
    if (coinb1_bytes.empty() || coinb2_bytes.empty()) return uint256();

    std::vector<unsigned char> coinbase;
    coinbase.reserve(coinb1_bytes.size() + en1_bytes.size()
                     + en2_bytes.size() + coinb2_bytes.size());
    coinbase.insert(coinbase.end(), coinb1_bytes.begin(), coinb1_bytes.end());
    coinbase.insert(coinbase.end(), en1_bytes.begin(),    en1_bytes.end());
    coinbase.insert(coinbase.end(), en2_bytes.begin(),    en2_bytes.end());
    coinbase.insert(coinbase.end(), coinb2_bytes.begin(), coinb2_bytes.end());
    uint256 merkle_root = dash::coin::coinbase_txid(coinbase);

    for (const auto& branch_hex : merkle_branches) {
        uint256 b;
        auto bb = ParseHex(branch_hex);
        if (bb.size() == 32) std::memcpy(b.begin(), bb.data(), 32);
        merkle_root = merkle_pair(merkle_root, b);
    }

    auto prevhash_be = ParseHex(prevhash_hex);
    if (prevhash_be.size() != 32) return uint256();
    uint256 prev_block;
    prev_block.SetHex(prevhash_hex.c_str());

    unsigned char header[80];
    dash::coin::serialize_header80(header,
        static_cast<int32_t>(version), prev_block, merkle_root,
        parse_be_hex_u32(ntime), parse_be_hex_u32(nbits_hex),
        parse_be_hex_u32(nonce));

    return dash::crypto::hash_x11(header, sizeof(header));
}

double DASHWorkSource::compute_share_difficulty(
    const std::string& coinb1, const std::string& coinb2,
    const std::string& extranonce1, const std::string& extranonce2,
    const std::string& ntime, const std::string& nonce,
    uint32_t version, const std::string& prevhash_hex,
    const std::string& nbits_hex,
    const std::vector<std::string>& merkle_branches) const
{
    // Per-coin PoW difficulty for the vardiff gate: the SAME header
    // reconstruction as mining_submit, ending in diff1 / x11(header). 0.0 on
    // any malformed input (the documented parse-error sentinel the vardiff
    // gate treats as a hard reject).
    const uint256 pow_hash = dash_reconstruct_pow_hash(
        coinb1, coinb2, extranonce1, extranonce2, ntime, nonce,
        version, prevhash_hex, nbits_hex, merkle_branches);
    if (pow_hash.IsNull()) return 0.0;
    return chain::target_to_difficulty(pow_hash);
}

void DASHWorkSource::record_best_pseudoshare(
    double share_difficulty, const std::string& miner,
    const std::string& coinb1, const std::string& coinb2,
    const std::string& extranonce1, const std::string& extranonce2,
    const std::string& ntime, const std::string& nonce,
    uint32_t version, const std::string& prevhash_hex,
    const std::string& nbits_hex,
    const std::vector<std::string>& merkle_branches)
{
    ShareDifficultyFn fn;
    {
        std::lock_guard<std::mutex> lk(share_difficulty_mutex_);
        fn = on_share_difficulty_fn_;
    }
    if (!fn) return;
    const uint256 pow_hash = dash_reconstruct_pow_hash(
        coinb1, coinb2, extranonce1, extranonce2, ntime, nonce,
        version, prevhash_hex, nbits_hex, merkle_branches);
    // Prefer the difficulty the stratum session already computed; fall back to
    // the reconstructed hash if the caller passed 0.
    double diff = share_difficulty > 0.0
                      ? share_difficulty
                      : (pow_hash.IsNull() ? 0.0 : chain::target_to_difficulty(pow_hash));
    if (diff > 0.0)
        fn(diff, miner, pow_hash);
}

// ─────────────────────────────────────────────────────────────────────────────
// DASH-specific control surface.
// ─────────────────────────────────────────────────────────────────────────────

void DASHWorkSource::set_best_share_hash_fn(std::function<uint256()> fn)
{
    std::lock_guard<std::mutex> lk(best_share_mutex_);
    best_share_hash_fn_ = std::move(fn);
}

void DASHWorkSource::set_on_share_difficulty_fn(ShareDifficultyFn fn)
{
    std::lock_guard<std::mutex> lk(share_difficulty_mutex_);
    on_share_difficulty_fn_ = std::move(fn);
}

void DASHWorkSource::set_on_found_block_fn(FoundBlockFn fn)
{
    std::lock_guard<std::mutex> lk(found_block_mutex_);
    on_found_block_fn_ = std::move(fn);
}

void DASHWorkSource::set_mint_share_fn(MintShareFn fn)
{
    std::lock_guard<std::mutex> lk(mint_share_mutex_);
    mint_share_fn_ = std::move(fn);
}

void DASHWorkSource::set_pplns_weights_fn(PplnsWeightsFn fn)
{
    std::lock_guard<std::mutex> lk(pplns_mutex_);
    pplns_weights_fn_ = std::move(fn);
}

void DASHWorkSource::set_producer_job_fn(ProducerJobFn fn)
{
    std::lock_guard<std::mutex> lk(producer_job_mutex_);
    producer_job_fn_ = std::move(fn);
}

void DASHWorkSource::invalidate_template_cache(const char* reason)
{
    // Stale-payee fix (defect 3): a CoindRPC reconnect churn means the cached
    // template — and the masternode payee frozen inside it — may predate the
    // reconnect. Drop the cache (next cached_work() re-sources through the
    // embedded/fallback selector) and bump work_generation so EVERY stratum
    // session re-pushes fresh work on its next heartbeat instead of letting
    // miners keep hashing jobs whose payee may already have rotated.
    {
        std::lock_guard<std::mutex> lk(template_mutex_);
        template_cache_.reset();
        template_last_fail_at_ = {};   // allow an immediate re-source
    }
    work_generation_.fetch_add(1, std::memory_order_relaxed);
    LOG_WARNING << "[DASH-STRATUM] template cache INVALIDATED (" << reason
                << ") -- cached GBT/masternode-payee snapshot dropped; all "
                   "sessions will re-pull fresh work (generation="
                << work_generation_.load(std::memory_order_relaxed) << ")";
}

}  // namespace dash::stratum
