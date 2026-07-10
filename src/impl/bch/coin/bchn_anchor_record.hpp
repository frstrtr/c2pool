// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BCHN cold-start anchor record (VM300 bchn-bch, operator-approved read-only
// capture @ height 955700; see the/docs/c2pool-bch-embedded-divergence-set.md
// section 4, recorded under frstrtr/the @0d55c4d2). This is a STATIC record of
// the values read once from VM300 -- the daemon reads THIS record, never the
// live VM (VM300 stays read-only, no qm op). apply_bchn_anchor() pins the
// {height, abla::State} from here; everything else (hash/chainwork/time) just
// documents provenance + lets a future SPV cold-start trust a header origin
// instead of climbing from genesis.
//
// Embedded-internal only: ABLA / cold-start anchoring is NOT part of the
// p2pool-merged-v36 share/sharechain surface (BCH is a SHA256d standalone
// parent). Zero p2pool-v36 / bitcoin_family surface.

#include <cstdint>
#include <string_view>

#include "abla.hpp"   // abla::Config / abla::State

namespace bch {
namespace coin {

/// The VM300 BCHN cold-start anchor, captured read-only @ height 955700.
/// Values are verbatim from the recorded divergence-set section-4 block.
struct BchnAnchorRecord {
    static constexpr uint32_t         height          = 955700u;
    static constexpr std::string_view hash            =
        "000000000000000002065e870dae738e8d5a5ee26fe6e2969f0581e4076d8493";
    static constexpr std::string_view chainwork       =
        "000000000000000000000000000000000000000002f722c9abbcbe29d5eacea0";
    static constexpr std::string_view merkleroot      =
        "b1d174425bd0478fed3b07d16f0c262fdc32ca95f36ec565874ceaf10115edf6";
    static constexpr uint32_t         time            = 1781698703u;
    static constexpr uint32_t         mediantime      = 1781697829u;
    static constexpr uint32_t         bits            = 18025987u;   // nBits (0x???)
    static constexpr uint32_t         version         = 0x200ce000u;

    // Recorded ABLA control state @ 955700. blocksize is the captured block's
    // serialized size; control/elastic are the running ABLA state fields.
    static constexpr uint64_t         abla_blocksize          = 1069u;
    static constexpr uint64_t         abla_control_size       = 16000000u;  // epsilon
    static constexpr uint64_t         abla_elastic_buffer     = 16000000u;  // beta
    static constexpr uint64_t         abla_blocksizelimit     = 32000000u;
    static constexpr uint64_t         abla_nextblocksizelimit = 32000000u;

    /// Rebuild the recorded ABLA State for the daemon's network. The capture
    /// shows the control state still at the 32 MB floor (control+elastic ==
    /// 32000000, i.e. epsilon == beta == 16000000), so the floor State and the
    /// recorded State are byte-identical -- which is exactly why the M4
    /// safe-floor budget (slice 3, 6336679a) is correct against live mainnet.
    /// We build via abla::State(Config, blkSize) so any future non-floor
    /// capture would surface as a control/elastic mismatch in is_floor().
    static abla::State state(bool is_testnet) {
        // Mirror AblaTracker::floor_anchored() per-network Config selection.
        const abla::Config cfg =
            is_testnet ? abla::testnet_config() : abla::mainnet_config();
        return abla::State(cfg, abla_blocksize);
    }

    /// True iff the recorded control state is still at the 32 MB floor. When
    /// this holds, pinning the anchor changes nothing vs the cold-start floor
    /// (it only sharpens chainwork/height provenance); when it ever goes false
    /// the dry-run logs a real, non-floor budget to pin.
    static bool is_floor() {
        return abla_control_size + abla_elastic_buffer == abla::DEFAULT_CONSENSUS_BLOCK_SIZE;
    }
};

} // namespace coin
} // namespace bch