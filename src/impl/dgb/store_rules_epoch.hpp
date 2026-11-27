// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// The DGB sharechain store is wiped once when the share rules it was written
// under change (review 906a0e5e3 #5).
//
// The store keeps each share's "verified" flag, and a restart reloads it
// without verifying again (p2pool known_verified). After the V35 rule changes
// (address decode, segwit_data and the P2Pool commitment, PPLNS by address
// string, share_info), a store written by an older build holds shares
// verified under the old rules, this node's own commitment-less V35 shares
// among them, which the python network and this build reject. Such a store is
// emptied once (its shares come back from peers, verified by these rules);
// a marker file next to it records the rules epoch it was written under.
// ---------------------------------------------------------------------------

#include <core/log.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

namespace dgb {

/// Bump whenever a change makes shares verified by an older build untrustworthy.
inline constexpr const char* kDgbShareRulesEpoch = "dgb-v35-python-exact-1";

/// Empties `storage` (get_shares_by_height_range / remove_shares_batch) unless
/// `marker` names kDgbShareRulesEpoch, then writes it. Returns the number of
/// shares removed.
template <typename StorageT>
size_t wipe_store_if_rules_changed(StorageT& storage, const std::filesystem::path& marker)
{
    std::string epoch;
    {
        std::ifstream in(marker);
        std::getline(in, epoch);
    }
    if (epoch == kDgbShareRulesEpoch)
        return 0;
    size_t removed = 0;
    const std::vector<uint256> all = storage.get_shares_by_height_range(0, UINT64_MAX);
    if (!all.empty()) {
        LOG_WARNING << "[Pool] the DGB sharechain store was written under older share rules ("
                    << (epoch.empty() ? std::string("no epoch") : epoch) << "): its " << all.size()
                    << " shares are removed once and downloaded again from peers (rules "
                    << kDgbShareRulesEpoch << ")";
        storage.remove_shares_batch(all);
        removed = all.size();
    }
    std::error_code ec;
    std::filesystem::create_directories(marker.parent_path(), ec);
    std::ofstream out(marker, std::ios::trunc);
    out << kDgbShareRulesEpoch << "\n";
    return removed;
}

} // namespace dgb
