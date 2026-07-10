// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// BCH ABLA size-feed tracker (CHIP-2023-01) -- M5 slice C.
//
// This is the FULL-BLOCK / EMBEDDED-DAEMON-LAYER home of the live block-size
// feed that drives ABLA. It exists because of a structural constraint pinned
// in M4 s3: ABLA is advanced by each block's *actual serialized size*, which
// the headers-only SPV `header_chain` does not carry (it stores headers, not
// block bodies / sizes). So the running ABLA State cannot be derived from the
// header chain; it must be fed real per-block sizes as full blocks arrive at
// the daemon layer. That feed re-homes HERE, not in the share layer and not in
// the header chain (M5 PINNED acceptance item).
//
// Relationship to the rest of the size path:
//   abla.hpp                -- the consensus algorithm (State/Config/replay),
//                              a 1:1 BCHN v29 port. CONSENSUS-CRITICAL, frozen.
//   AblaTracker (this file) -- a thin LOCAL bookkeeping wrapper: it keeps the
//                              running State at the chain tip by folding live
//                              block sizes through abla::State::NextBlockState,
//                              and hands a tip State* to the template builder.
//   template_builder.hpp    -- consumes the tip State* as a dynamic build-time
//                              byte budget (build_template's `tip_state` arg).
//
// p2pool-merged-v36 SURFACE: NONE. Like abla.hpp, this governs only the LOCAL
// block-size build budget (how large a template we may assemble). It never
// touches PoW hash, share format, coinbase commitment, or PPLNS math, so there
// is zero interop risk. The hard floor below guarantees the budget can only
// ever EQUAL-OR-EXCEED the 32 MB activation/floor limit -- ABLA only raises it,
// and when the feed is absent or has a gap we fall back to the floor outright.
//
// Build-INERT / source-only: header-only, no impl_bch CMake registration
// (bch stays skip-green; don't race ci-steward).

#include "abla.hpp"

#include <cstdint>

namespace bch {
namespace coin {

/// Keeps the running ABLA State at the chain tip by folding live full-block
/// sizes (oldest-first, contiguous) through the consensus control function.
///
/// Lifecycle / ownership: lives at the embedded-daemon / full-block layer
/// (alongside the block-download path). On each fully-received best-chain block
/// the daemon calls record_block_size(height, serialized_size); the template
/// builder asks state_for_tip(tip_height) when assembling work. Single-threaded
/// use from the daemon's block-processing context is assumed (mirrors how the
/// header chain advances); add external synchronisation if that changes.
class AblaTracker {
public:
    /// Construct from a known-good anchor: the ABLA State of `anchor_height`
    /// and the matching per-network Config. The natural BCH anchor is a
    /// BCHN-pinned {height, State} captured at daemon start; absent that, use
    /// floor_anchored() below, which anchors at the activation/floor State.
    AblaTracker(bool is_testnet, uint32_t anchor_height, abla::State anchor_state)
        : m_config(is_testnet ? abla::testnet_config() : abla::mainnet_config()),
          m_is_testnet(is_testnet),
          m_cursor_height(anchor_height),
          m_cursor(anchor_state),
          m_valid(true) {}

    /// Anchor at the activation/floor State for `anchor_height`. This is the
    /// safe cold-start: the floor State's limit is exactly the 32 MB floor, and
    /// folding live sizes forward can only raise it (ABLA never drops below the
    /// floor). Use when no BCHN-pinned anchor is available yet.
    static AblaTracker floor_anchored(bool is_testnet, uint32_t anchor_height) {
        const abla::Config cfg =
            is_testnet ? abla::testnet_config() : abla::mainnet_config();
        return AblaTracker(is_testnet, anchor_height, abla::State(cfg, 0));
    }

    /// Live feed: record the serialized size of the best-chain block at
    /// `height`. Sizes MUST arrive contiguously (each height one greater than
    /// the last); ABLA cannot skip blocks. Behaviour:
    ///   height == cursor+1 : fold it in, advance the tip State (the hot path).
    ///   height <= cursor   : already incorporated -> ignored (idempotent).
    ///   height >  cursor+1 : a GAP -> the running State is no longer trustable;
    ///                        mark stale so the builder falls back to the floor
    ///                        until reanchor() supplies a fresh known-good State.
    /// While stale, further records are ignored until reanchor().
    void record_block_size(uint32_t height, uint64_t serialized_size) {
        if (!m_valid)
            return;  // awaiting reanchor() after a gap/reorg
        if (height <= m_cursor_height)
            return;  // duplicate / out-of-order replay of an old block
        if (height != m_cursor_height + 1) {
            m_valid = false;  // gap: cannot fold non-contiguous sizes
            return;
        }
        m_cursor = m_cursor.NextBlockState(m_config, serialized_size);
        m_cursor_height = height;
    }

    /// Re-establish a known-good anchor (after a gap, reorg, or initial BCHN
    /// pin). Clears the stale flag and resumes folding from `height`.
    void reanchor(uint32_t height, abla::State state) {
        m_cursor_height = height;
        m_cursor        = state;
        m_valid         = true;
    }

    /// State governing the block we are about to build on top of `tip_height`.
    /// That is the running State AFTER the tip block's size has been folded in,
    /// i.e. cursor must sit exactly at the tip. Returns nullptr -- so the
    /// template builder uses the floor fallback -- when the feed is stale (a
    /// gap occurred) or has not yet caught up to (or has overrun) the tip.
    /// The returned pointer is valid until the next record/reanchor call.
    const abla::State* state_for_tip(uint32_t tip_height) const {
        if (!m_valid || m_cursor_height != tip_height)
            return nullptr;
        return &m_cursor;
    }

    /// The dynamic build budget the builder would use right now for `tip_height`
    /// -- the live ABLA limit when the feed is current, else the floor. This is
    /// the SAME value build_template computes from state_for_tip(); exposed for
    /// logging/monitoring. By the ABLA invariant (control >= epsilon0, buffer >=
    /// beta0) the live limit is always >= the floor, so this never undercuts the
    /// 32 MB floor regardless of feed state.
    uint64_t budget_for_tip(uint32_t tip_height) const {
        const abla::State* s = state_for_tip(tip_height);
        const uint64_t live  = s ? s->GetBlockSizeLimit()
                                 : abla::floor_block_size_limit(m_is_testnet);
        const uint64_t floor = abla::floor_block_size_limit(m_is_testnet);
        return live < floor ? floor : live;  // hard floor guard (belt + braces)
    }

    bool     is_current(uint32_t tip_height) const { return m_valid && m_cursor_height == tip_height; }
    bool     is_stale()       const { return !m_valid; }
    uint32_t cursor_height()  const { return m_cursor_height; }

private:
    abla::Config m_config;
    bool         m_is_testnet;
    uint32_t     m_cursor_height;
    abla::State  m_cursor;
    bool         m_valid;
};

} // namespace coin
} // namespace bch