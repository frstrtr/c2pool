// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Variant B (#143, workflow wtrv69elc) — the provably-gap-free CreditPool
/// INDEX follower: the sister lane to mn_checkpoint_lane.hpp for the DIP-0027
/// type-9 (asset-unlock) state the chain does NOT commit to.
///
/// WHY A SISTER LANE, NOT A PATCH ON THE SCALAR MACHINE. credit_pool.hpp
/// tracks ONE int64 (the balance) and can re-seed from any cbTx because the
/// balance IS committed per block. The unlock-index CRangesSet and the
/// 576-block latelyUnlocked window have NO commitment anywhere on the chain
/// (the confirmed asymmetry, task #140) — the only way to KNOW them is to have
/// ingested every block since their trustless floor with zero gaps. So this
/// follower mirrors the MN lane's discipline (arm / replay-forward / persist
/// cursor; a dead send never advances the ledger) with one decisive
/// simplification: the anchor needs NO external trust, because dashd's own
/// ConstructCreditPool (evo/creditpool.cpp:151-224) defines the set as EMPTY
/// below v20 activation — arm() is a compiled-in constant, not a DIP-4
/// checkpoint.
///
/// STATE — dashd's exact construction (creditpool.cpp:151-224):
///   * CRangesSet of every mined unlock index; duplicate ⇒ HARD FAIL,
///     mirroring the dashd throw at :174-177 ("failed-getcreditpool-index-
///     duplicated").
///   * per-block gross-unlocked rows for the sliding CreditPoolPeriodBlocks
///     (=576) latelyUnlocked window (:180-189).
///   * the era ladder — pre-v22 / WITHDRAWALS(2000 DASH) / V24(4000 DASH),
///     :192-203, constants creditpool.h:124-127 — gated on the buried
///     chainparams deployment heights ported below.
///
/// CROSS-CHECK — after EVERY applied block the scalar balance is recomputed
/// (type-8 adds total_credit, type-9 subtracts Σvout+fee — exactly
/// credit_pool.hpp:67-130, reused as a member, not re-derived) and compared
/// against the cbTx-committed creditPoolBalance: the ONLY commitment the
/// chain gives us. Mismatch ⇒ fail closed and WIPE — the index set has no
/// commitment of its own, so a balance divergence must be treated as total
/// loss of provenance, never patched around.
///
/// FAIL-CLOSED PREDICATE (one-way sticky): type-9 accrual into a template at
/// height H is permitted IFF ALL of
///   (a) --embedded-accrue-asset-unlocks is ON (caller-supplied flag);
///   (b) the build has real BLS (vendor::bls_backend_available() — the stub
///       makes quorumSig unverifiable, so accrual is structurally OFF);
///   (c) proven_complete AND cursor.height == H-1 AND cursor.block_hash ==
///       the template's hashPrevBlock (fresh through the exact parent);
///   (d) contiguity never broke since seed (any gap/lineage mismatch already
///       forced proven_complete := false + wipe);
///   (e) the per-block balance cross-check held at every applied block;
///   (f) the specific candidate passes: index ∉ set, quorumSig verifies
///       against the platform quorum, expiry window holds, cumulative amount
///       fits the era-correct limit.
/// Failure of ANY conjunct ⇒ the template excludes ALL type-9 — exactly
/// today's exclude_special behavior, consensus-valid by design. NOTHING
/// restores proven_complete except a full wipe-and-reseed from the v20 floor
/// that reaches the tip cleanly.
///
/// INGEST SEAM: on_replay_block matches replay_bulk_fetch.hpp's
/// IReplayBlockConsumer contract signature so the follower rides the shared
/// 30-40 GB bulk fetch through the TeeReplayConsumer — it must see each body
/// BEFORE drain_buffer() prunes it (the type-9 payloads are unrecoverable
/// after the prune without re-fetching). The same apply_block() is the tip
/// lane's hook, so seed and steady-state share ONE ingest function.

#include <impl/dash/coin/credit_pool.hpp>
#include <impl/dash/coin/credit_pool_idx_db.hpp>
#include <impl/dash/coin/asset_unlock_admission.hpp>
#include <impl/dash/coin/asset_unlock_verify.hpp>
#include <impl/dash/coin/asset_lock_fold.hpp>     // money_in_range
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/subsidy.hpp>

#include <core/uint256.hpp>
#include <core/log.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

// ── CRangesSet: verbatim port of dashd util/ranges_set.{h,cpp} ─────────────
// Numbers kept as sorted disjoint half-open ranges [begin, end). Add() returns
// false on duplicate — the caller (the follower) treats that as the dashd
// throw. Remove() is ported for completeness (reorg support is a later pass).
class CRangesSet
{
    struct Range {
        uint64_t begin;
        uint64_t end;
        bool operator<(const Range& other) const
        {
            if (begin != other.begin) return begin < other.begin;
            return end < other.end;
        }
    };
    std::set<Range> ranges;

public:
    [[nodiscard]] bool Add(uint64_t value)
    {
        if (Contains(value)) return false;
        Range new_range{value, value + 1};
        auto it = ranges.lower_bound({value, value});
        if (it != ranges.begin()) {
            auto prev = it;
            --prev;
            if (prev->end == value) {
                new_range.begin = prev->begin;
                it = ranges.erase(prev);
            }
        }
        if (it != ranges.end() && it->begin == value + 1) {
            new_range.end = it->end;
            ranges.erase(it);
        }
        return ranges.insert(new_range).second;
    }

    [[nodiscard]] bool Contains(uint64_t value) const noexcept
    {
        const auto it = ranges.lower_bound({value, value});
        if (it != ranges.end() && it->begin == value) return true;
        if (it == ranges.begin()) return false;
        auto prev = it;
        --prev;
        return prev->begin <= value && prev->end > value;
    }

    [[nodiscard]] bool IsEmpty() const noexcept { return ranges.empty(); }

    [[nodiscard]] size_t Size() const noexcept
    {
        size_t result = 0;
        for (const auto& r : ranges) result += r.end - r.begin;
        return result;
    }

    void clear() { ranges.clear(); }

    /// The canonical compact form for the 'R' record: sorted, disjoint,
    /// non-adjacent (Add() merges adjacency, so the invariant holds).
    std::vector<std::pair<uint64_t, uint64_t>> export_ranges() const
    {
        std::vector<std::pair<uint64_t, uint64_t>> out;
        out.reserve(ranges.size());
        for (const auto& r : ranges) out.emplace_back(r.begin, r.end);
        return out;
    }

    /// Rebuild from a decoded 'R' record. False on a malformed list (the DB
    /// decoder already enforces sorted/disjoint/non-adjacent; this re-checks).
    bool import_ranges(const std::vector<std::pair<uint64_t, uint64_t>>& in)
    {
        clear();
        uint64_t prev_end = 0;
        bool first = true;
        for (const auto& [b, e] : in) {
            if (e <= b) return false;
            if (!first && b <= prev_end) return false;
            first = false;
            prev_end = e;
            ranges.insert(Range{b, e});
        }
        return true;
    }
};

// ── era ladder + deployment schedule ────────────────────────────────────────

/// dashd evo/creditpool.h:124-127.
inline constexpr int64_t kCpLimitAmountLow  = 100  * COIN_SAT;
inline constexpr int64_t kCpLimitAmountHigh = 1000 * COIN_SAT;
inline constexpr int64_t kCpLimitAmountV22  = 2000 * COIN_SAT;
inline constexpr int64_t kCpLimitAmountV24  = 4000 * COIN_SAT;

/// "Not activated" sentinel for a deployment with no buried height yet
/// (DEPLOYMENT_V24 is versionbits NEVER_ACTIVE on mainnet/testnet at this
/// dashd pin — chainparams.cpp:213/:412). Fail-safe direction: treating an
/// actually-active era as inactive only makes OUR limit stricter (a smaller
/// template), never an invalid block.
inline constexpr uint32_t kCpIdxNeverActive = 0xFFFFFFFFu;

struct CpIdxDeploySchedule {
    uint32_t v20_floor_height;     // trustless seed floor (set empty below it)
    uint32_t withdrawals_height;   // DEPLOYMENT_WITHDRAWALS buried height (v22)
    uint32_t v24_height;           // DEPLOYMENT_V24 (kCpIdxNeverActive = not yet)
    uint32_t window_blocks{576};   // Params().CreditPoolPeriodBlocks()
};

/// Mainnet: V20 buried @1,987,776 (block 000000000000001bf41cff06b76780
/// 050682ca29e61a91c391893d4745579777, subsidy.hpp:45); WITHDRAWALS buried
/// @2,201,472 (dashd chainparams.cpp:196); V24 not activated.
inline constexpr CpIdxDeploySchedule kCpIdxScheduleMainnet{
    1'987'776u, 2'201'472u, kCpIdxNeverActive, 576u};

/// Testnet: V20 @905,100 (subsidy.hpp:55); WITHDRAWALS @1,148,500
/// (chainparams.cpp:395); V24 not activated.
inline constexpr CpIdxDeploySchedule kCpIdxScheduleTestnet{
    905'100u, 1'148'500u, kCpIdxNeverActive, 576u};

enum class CpIdxEra : uint8_t { PreV22 = 0, V22 = 1, V24 = 2 };

inline CpIdxEra cp_idx_era_at(const CpIdxDeploySchedule& s, uint32_t height)
{
    if (height >= s.v24_height)         return CpIdxEra::V24;
    if (height >= s.withdrawals_height) return CpIdxEra::V22;
    return CpIdxEra::PreV22;
}

/// dashd ConstructCreditPool's era-laddered withdrawal limit
/// (evo/creditpool.cpp:192-212), verbatim arithmetic:
///   V24 active:          max(0, min(pool, 4000 − lately))
///   WITHDRAWALS active:  min(pool, 2000)
///   pre-v22:             "max(100, min(.10 · pool, 1000)) inside window":
///                        if pool + lately > 100:
///                            limit = max(100, pool/10) − lately, floored at 0
///                        limit = min(limit, 1000 − lately)
/// A NEGATIVE result mirrors the dashd throw ("Negative limit for
/// CreditPool") — returned as nullopt so the caller fails closed.
inline std::optional<int64_t>
cp_idx_current_limit(int64_t pool_balance, int64_t lately_unlocked, CpIdxEra era)
{
    int64_t limit = pool_balance;
    switch (era) {
    case CpIdxEra::V24:
        limit = std::max<int64_t>(0, std::min(limit, kCpLimitAmountV24 - lately_unlocked));
        break;
    case CpIdxEra::V22:
        limit = std::min(limit, kCpLimitAmountV22);
        break;
    case CpIdxEra::PreV22:
        if (limit + lately_unlocked > kCpLimitAmountLow) {
            limit = std::max(kCpLimitAmountLow, pool_balance / 10) - lately_unlocked;
            if (limit < 0) limit = 0;
        }
        limit = std::min(limit, kCpLimitAmountHigh - lately_unlocked);
        break;
    }
    if (limit < 0) return std::nullopt;   // dashd throws here — we fail closed
    return limit;
}

// ── the follower ────────────────────────────────────────────────────────────

class CreditPoolIdxFollower
{
public:
    struct WindowRow { int64_t gross_unlocked{0}; uint32_t n_type9{0}; };

    /// Platform-share accrual per height (the reward term the scalar balance
    /// needs — credit_pool.hpp apply_block's reward_accrual). Injectable for
    /// KATs; production default is the mainnet subsidy schedule.
    using RewardFn = std::function<int64_t(uint32_t height)>;

    explicit CreditPoolIdxFollower(const CpIdxDeploySchedule& sched = kCpIdxScheduleMainnet)
        : m_sched(sched)
        , m_reward_fn([](uint32_t h) {
              return compute_dash_platform_reward_post_v20_mn_rr(h);
          })
    {}

    void set_reward_fn(RewardFn fn) { m_reward_fn = std::move(fn); }
    void attach_db(CreditPoolIdxDb* db) { m_db = db; }

    /// ARM at the trustless floor: empty CRangesSet, latelyUnlocked = 0,
    /// balance = the floor block's own cbTx creditPoolBalance (0 at v20
    /// activation: no locks could exist and MN_RR — the platform-reward
    /// accrual — activates later on both networks). No external trust: dashd
    /// itself defines the set as empty below v20 (creditpool.cpp:120 —
    /// !DeploymentActiveAt(V20) ⇒ CCreditPool{}).
    void arm(const uint256& floor_hash, int64_t floor_balance = 0,
             int64_t seed_wallclock = 0)
    {
        wipe_memory();
        m_height = m_sched.v20_floor_height;
        m_hash   = floor_hash;
        m_scalar.seed(floor_balance, m_height);
        m_armed = true;
        m_proven_complete = false;
        m_fail_cause.clear();
        if (m_db != nullptr) {
            CpIdxSeedProvenance seed;
            seed.v20_floor_height = m_sched.v20_floor_height;
            seed.v20_block_hash   = floor_hash;
            seed.seed_wallclock   = seed_wallclock;
            m_db->write_seed(seed);
            m_db->write_cursor(make_cursor());
        }
        LOG_INFO << "[CP-IDX] armed at v20 floor h=" << m_height
                 << " hash=" << floor_hash.GetHex().substr(0, 16)
                 << " balance=" << floor_balance << " (empty set, lately=0)";
    }

    /// Resume from the persisted namespace. Returns true when a complete,
    /// well-formed state was restored (cursor NOT yet bridged to the live
    /// chain — the lane must re-verify lineage before advancing; a resume
    /// that cannot bridge wipes and re-arms from the floor). Any decode
    /// failure or internal inconsistency adjudicates ABSENT: wipe + false.
    bool try_restore()
    {
        if (m_db == nullptr) return false;
        std::vector<std::pair<uint64_t, uint64_t>> ranges;
        std::map<uint32_t, CpIdxWindowRowRec> rows;
        CpIdxCursor cursor;
        CpIdxSeedProvenance seed;
        bool corrupt = false;
        if (!m_db->load(ranges, rows, cursor, seed, corrupt)) {
            if (corrupt) m_db->wipe();
            return false;
        }
        // Lineage floor must be OUR floor — a namespace seeded against a
        // different network/schedule is not provenance.
        if (seed.v20_floor_height != m_sched.v20_floor_height ||
            cursor.height < m_sched.v20_floor_height) {
            LOG_WARNING << "[CP-IDX] restore REFUSED: seed floor "
                        << seed.v20_floor_height << " != schedule floor "
                        << m_sched.v20_floor_height << " — wipe";
            m_db->wipe();
            return false;
        }
        if (!m_indexes.import_ranges(ranges)) {
            m_db->wipe();
            return false;
        }
        // Window rows: must cover (cursor − window, cursor] where above the
        // floor; a missing row inside the window = broken provenance.
        m_window.clear();
        int64_t lately = 0;
        const uint32_t lo = cursor.height > m_sched.window_blocks
                          ? cursor.height - m_sched.window_blocks + 1
                          : m_sched.v20_floor_height + 1;
        for (uint32_t h = lo; h <= cursor.height && cursor.height != 0; ++h) {
            auto it = rows.find(h);
            if (it == rows.end()) {
                if (h <= m_sched.v20_floor_height) continue;
                LOG_WARNING << "[CP-IDX] restore REFUSED: window row h=" << h
                            << " missing inside (" << lo << ".." << cursor.height
                            << "] — wipe";
                wipe_memory();
                m_db->wipe();
                return false;
            }
            m_window[h] = WindowRow{it->second.gross_unlocked, it->second.n_type9};
            lately += it->second.gross_unlocked;
        }
        m_lately_unlocked = lately;
        m_height = cursor.height;
        m_hash   = cursor.block_hash;
        m_scalar.seed(cursor.computed_balance, cursor.height);
        m_armed = true;
        // proven_complete does NOT survive a restart by itself: the ledger is
        // only proven through the persisted cursor; the lane must re-bridge
        // to the live tip before mark_proven_complete() may flip it back.
        m_proven_complete = false;
        LOG_INFO << "[CP-IDX] restored cursor h=" << m_height
                 << " hash=" << m_hash.GetHex().substr(0, 16)
                 << " balance=" << m_scalar.balance()
                 << " indexes=" << m_indexes.Size()
                 << " lately=" << m_lately_unlocked
                 << " (proven_complete reset pending re-bridge)";
        return true;
    }

    /// Fold ONE block. The block must be the cursor's direct child (height
    /// AND hashPrevBlock — the #138 honest-ledger rule: only a truly
    /// delivered, lineage-verified body advances the cursor; a refused or
    /// out-of-order body leaves the ledger unmoved OR, if it names a breach
    /// of provenance, wipes it).
    ///
    /// Returns false and FAILS CLOSED (proven_complete := false, memory +
    /// namespace wiped) on: lineage/contiguity breach, unparseable cbTx or
    /// unlock payload, duplicate unlock index, missing window row, or the
    /// balance cross-check missing the cbTx-committed value.
    bool apply_block(uint32_t height, const uint256& hash, const BlockType& block)
    {
        if (!m_armed) return false;

        // Contiguity + lineage (conjunct d).
        if (height != m_height + 1) {
            return fail_closed(height, "gap: expected h=" + std::to_string(m_height + 1)
                                         + " got h=" + std::to_string(height));
        }
        if (!m_hash.IsNull() && !block.m_previous_block.IsNull() &&
            block.m_previous_block != m_hash) {
            return fail_closed(height, "lineage: hashPrevBlock "
                                         + block.m_previous_block.GetHex().substr(0, 16)
                                         + " != cursor " + m_hash.GetHex().substr(0, 16));
        }

        // cbTx — the block's own committed balance (the ONLY commitment).
        if (block.m_txs.empty()) return fail_closed(height, "empty block body");
        vendor::CCbTx cbtx;
        if (!vendor::parse_cbtx(block.m_txs[0].extra_payload, cbtx) ||
            cbtx.nVersion < vendor::CCbTx::VERSION_CLSIG_AND_BALANCE) {
            return fail_closed(height, "cbTx below v3 / unparseable — no committed "
                                         "creditPoolBalance to cross-check against");
        }

        // Per-block type-9 extraction — dashd GetCreditDataFromBlock
        // (creditpool.cpp:60-112): gross = payload.fee + Σ vout (each vout
        // MoneyRange-checked), indexes collected; an unparseable payload is
        // the dashd throw ⇒ fail closed.
        int64_t gross = 0;
        uint32_t n_type9 = 0;
        std::unordered_set<uint64_t> block_indexes;
        for (size_t i = 1; i < block.m_txs.size(); ++i) {
            const auto& tx = block.m_txs[i];
            if (tx.version != 3 ||
                tx.type != vendor::CAssetUnlockPayload::SPECIALTX_TYPE) continue;
            vendor::CAssetUnlockPayload pl;
            if (!vendor::parse_assetunlock_payload(tx.extra_payload, pl)) {
                return fail_closed(height, "type-9 payload unparseable at tx["
                                             + std::to_string(i) + "]");
            }
            int64_t to_unlock = static_cast<int64_t>(pl.fee);
            for (const auto& v : tx.vout) {
                if (!money_in_range(v.value))
                    return fail_closed(height, "type-9 vout out of MoneyRange");
                to_unlock += v.value;
            }
            gross += to_unlock;
            ++n_type9;
            block_indexes.insert(pl.index);
        }

        // Duplicate ⇒ hard fail (dashd creditpool.cpp:174-177).
        for (uint64_t idx : block_indexes) {
            if (!m_indexes.Add(idx)) {
                return fail_closed(height, "failed-getcreditpool-index-duplicated: "
                                             + std::to_string(idx));
            }
        }

        // Sliding window: lately += this block − the row that slid out.
        int64_t out_gross = 0;
        if (height > m_sched.window_blocks) {
            const uint32_t out_h = height - m_sched.window_blocks;
            if (out_h > m_sched.v20_floor_height) {
                auto it = m_window.find(out_h);
                if (it == m_window.end()) {
                    return fail_closed(height, "window row missing at h="
                                                 + std::to_string(out_h));
                }
                out_gross = it->second.gross_unlocked;
            }
        }
        m_window[height] = WindowRow{gross, n_type9};
        m_lately_unlocked += gross - out_gross;

        // Scalar recompute — EXACTLY credit_pool.hpp:67-130 (reused member).
        m_scalar.apply_block(block, height, m_reward_fn(height));

        // THE cross-check (conjunct e): computed == committed, every block.
        if (m_scalar.balance() != cbtx.creditPoolBalance) {
            return fail_closed(height, "balance cross-check MISMATCH: computed="
                                         + std::to_string(m_scalar.balance())
                                         + " cbTx=" + std::to_string(cbtx.creditPoolBalance));
        }

        // Advance + prune + persist (persisted == delivered + folded +
        // balance-verified; never before).
        m_height = height;
        m_hash   = hash;
        const uint32_t prune_below = height > m_sched.window_blocks
                                   ? height - m_sched.window_blocks : 0;
        for (auto it = m_window.begin();
             it != m_window.end() && it->first < prune_below;)
            it = m_window.erase(it);
        if (m_db != nullptr) {
            m_db->write_apply(m_indexes.export_ranges(), height,
                              CpIdxWindowRowRec{gross, n_type9},
                              make_cursor(), prune_below);
        }
        return true;
    }

    /// IReplayBlockConsumer-shaped entry (replay_bulk_fetch.hpp TEE seam):
    /// same signature, same refuse-means-stop contract. A refusal here means
    /// the follower's provenance broke; the bulk lane keeps ITS OWN fold
    /// correct by failing the lane closed with a named cause.
    bool on_replay_block(uint32_t height, const uint256& hash, const BlockType& block)
    {
        return apply_block(height, hash, block);
    }

    /// The lane flips this ONLY when the follower's cursor has met the live
    /// tip lane's verified tip (seed complete + fresh). One-way in the other
    /// direction: any fail_closed() clears it and only a full wipe-and-reseed
    /// can earn it back.
    void mark_proven_complete()
    {
        if (!m_armed) return;
        m_proven_complete = true;
        if (m_db != nullptr) m_db->write_cursor(make_cursor());
    }

    // ── the fail-closed predicate (conjuncts a..e) ─────────────────────────
    /// True IFF a template at height H building on prev_hash may consult the
    /// index at all. Conjunct (f) is per-candidate, in try_admit_unlocks.
    bool accrual_permitted(bool flag_on, uint32_t template_height,
                           const uint256& template_prev_hash) const
    {
        if (!flag_on) return false;                                    // (a)
        if (!vendor::bls_backend_available()) return false;            // (b)
        if (!m_armed || !m_proven_complete) return false;              // (c,d,e latch)
        if (m_height != template_height - 1) return false;             // (c) fresh
        if (m_hash != template_prev_hash) return false;                // (c) exact parent
        return true;
    }

    /// ARM-3 admission: produce the verified type-9 set for a template at
    /// height H. Returns true when the admission is USABLE (the predicate
    /// held; `out` may still be empty if no candidate passed). Returns false
    /// — and `out` stays empty — when ANY predicate conjunct fails: the
    /// template then excludes ALL type-9, never a partial best-effort set.
    ///
    /// Per candidate (conjunct f), in dashd order:
    ///   structural CheckAssetUnlockTx (assetlocktx.cpp:157-188): type 9,
    ///     NO vin, ≤ MAXIMUM_WITHDRAWALS vouts, payload parses, version==1,
    ///     each vout in MoneyRange;
    ///   index ∉ CRangesSet and ∉ this session (CCreditPoolDiff::Unlock
    ///     :277-297 duplicate check);
    ///   quorum activity + expiry window + quorumSig BLS verify
    ///     (asset_unlock_verify.hpp — VerifySig :114-157);
    ///   cumulative sessionUnlocked + toUnlock ≤ era-correct LimitAmount
    ///     (currentLimit port; Unlock :287-289).
    bool try_admit_unlocks(bool flag_on, uint32_t template_height,
                           const uint256& template_prev_hash,
                           const std::vector<MutableTransaction>& candidates,
                           const std::vector<chainlock::QuorumCandidate>& quorums,
                           const LlmqParamsView& platform_params,
                           AssetUnlockAdmission& out) const
    {
        out = AssetUnlockAdmission{};
        if (!accrual_permitted(flag_on, template_height, template_prev_hash))
            return false;

        // Era + limit are functions of the PREVIOUS block (dashd: "limits
        // should stay same and depends only on the previous block",
        // creditpool.h:66-71) — i.e. of the cursor, which conjunct (c) just
        // pinned to the template's parent.
        const CpIdxEra era = cp_idx_era_at(m_sched, m_height);
        const auto limit = cp_idx_current_limit(m_scalar.balance(),
                                                m_lately_unlocked, era);
        if (!limit) {
            LOG_WARNING << "[CP-IDX] negative era limit at h=" << m_height
                        << " — fail closed, exclude-all";
            return false;
        }

        const int32_t tip_height = static_cast<int32_t>(template_height) - 1;
        int64_t session_unlocked = 0;
        std::unordered_set<uint64_t> session_indexes;

        for (const auto& tx : candidates) {
            if (tx.version != 3 ||
                tx.type != vendor::CAssetUnlockPayload::SPECIALTX_TYPE) continue;
            if (!tx.vin.empty()) continue;                    // bad-assetunlocktx-have-input
            if (tx.vout.size() > unlockverify::kMaximumWithdrawals) continue;
            vendor::CAssetUnlockPayload pl;
            if (!vendor::parse_assetunlock_payload(tx.extra_payload, pl)) continue;
            if (pl.nVersion == 0 ||
                pl.nVersion > vendor::CAssetUnlockPayload::CURRENT_VERSION) continue;

            int64_t to_unlock = static_cast<int64_t>(pl.fee);
            bool money_ok = pl.fee > 0;                       // bad-txns-assetunlock-fee-outofrange
            for (const auto& v : tx.vout) {
                if (!money_in_range(v.value)) { money_ok = false; break; }
                to_unlock += v.value;
            }
            if (!money_ok || !money_in_range(to_unlock)) continue;

            // Duplicate index — mined OR earlier in this session.
            if (m_indexes.Contains(pl.index) || session_indexes.count(pl.index)) {
                LOG_INFO << "[CP-IDX] EXCLUDING unlock index=" << pl.index
                         << ": duplicated (failed-creditpool-unlock-duplicated-index)";
                continue;
            }

            // Withdrawal limit (sessionUnlocked + toUnlock > currentLimit ⇒
            // failed-creditpool-unlock-too-much).
            if (session_unlocked + to_unlock > *limit) {
                LOG_INFO << "[CP-IDX] EXCLUDING unlock index=" << pl.index
                         << ": limit (session=" << session_unlocked
                         << " + " << to_unlock << " > " << *limit << ")";
                continue;
            }

            // Quorum signature + activity + expiry (fail-closed BLS).
            const uint256 msg_hash = unlockverify::unlock_msg_hash(tx, pl);
            if (!unlockverify::verify_asset_unlock_sig(
                    pl, msg_hash, tip_height, quorums, platform_params)) {
                continue;   // cause already logged by the verifier
            }

            session_indexes.insert(pl.index);
            session_unlocked += to_unlock;
            out.txs.push_back(tx);
            out.gross_unlocked     += to_unlock;
            out.total_payload_fees += static_cast<int64_t>(pl.fee);
        }
        if (!out.txs.empty()) {
            LOG_INFO << "[CP-IDX] ADMITTING " << out.txs.size()
                     << " verified type-9 unlock(s) into template h="
                     << template_height << " gross=" << out.gross_unlocked
                     << " fees=" << out.total_payload_fees
                     << " limit=" << *limit << " era=" << static_cast<int>(era);
        }
        return true;
    }

    // ── accessors ───────────────────────────────────────────────────────────
    bool     armed()            const { return m_armed; }
    bool     proven_complete()  const { return m_proven_complete; }
    uint32_t height()           const { return m_height; }
    const uint256& block_hash() const { return m_hash; }
    int64_t  balance()          const { return m_scalar.balance(); }
    int64_t  lately_unlocked()  const { return m_lately_unlocked; }
    const CRangesSet& indexes() const { return m_indexes; }
    const std::string& fail_cause() const { return m_fail_cause; }
    const CpIdxDeploySchedule& schedule() const { return m_sched; }

private:
    CpIdxDeploySchedule m_sched;
    RewardFn            m_reward_fn;
    CreditPoolIdxDb*    m_db{nullptr};      // borrowed, optional

    CRangesSet                    m_indexes;
    std::map<uint32_t, WindowRow> m_window;
    int64_t                       m_lately_unlocked{0};
    CreditPool                    m_scalar;   // credit_pool.hpp — the exact arithmetic
    uint32_t                      m_height{0};
    uint256                       m_hash;
    bool                          m_armed{false};
    bool                          m_proven_complete{false};
    std::string                   m_fail_cause;

    CpIdxCursor make_cursor() const
    {
        CpIdxCursor c;
        c.height           = m_height;
        c.block_hash       = m_hash;
        c.computed_balance = m_scalar.balance();
        c.proven_complete  = m_proven_complete;
        c.era              = static_cast<uint8_t>(cp_idx_era_at(m_sched, m_height));
        return c;
    }

    /// Total loss of provenance: latch proven_complete := false, wipe memory
    /// AND the persisted namespace. The only way back is a fresh floor seed
    /// that reaches the tip cleanly. Named cause, loudly.
    bool fail_closed(uint32_t at_height, const std::string& cause)
    {
        m_fail_cause = "h=" + std::to_string(at_height) + ": " + cause;
        LOG_ERROR << "[CP-IDX] FAIL CLOSED (" << m_fail_cause
                  << ") — proven_complete=0, wiping index namespace; template "
                     "path collapses to exclude-all (consensus-valid)";
        wipe_memory();
        if (m_db != nullptr) m_db->wipe();
        return false;
    }

    void wipe_memory()
    {
        m_indexes.clear();
        m_window.clear();
        m_lately_unlocked = 0;
        m_scalar.clear();
        m_height = 0;
        m_hash.SetNull();
        m_armed = false;
        m_proven_complete = false;
    }
};

} // namespace coin
} // namespace dash
