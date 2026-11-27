// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// The DGB sharechain store is verified again once when the share rules it was
// written under change (reviews 906a0e5e3 #5, dd1248abd REQUIRED 1-2).
//
// The store keeps each share's "verified" flag, and a restart reloads it
// without verifying again (p2pool known_verified). After the V35 rule changes
// (address decode, segwit_data and the P2Pool commitment, PPLNS by address
// string, share_info), a store written by an older build holds shares
// verified under the old rules, this node's own commitment-less V35 shares
// among them. Such a store has every verified flag cleared once: the shares
// are KEPT (the dormant chain may exist only here, and the revive starts from
// it) and are verified again under these rules; the ones that fail (our old
// commitment-less shares, V36 shares while held) are not verified.
//
// A marker next to the store records the rules epoch. It is written only
// after a re-scan of the index records confirms no share is still flagged
// verified (the clear is a synced batch, the marker a durable write), and
// read back. On any failure the marker is not written (the
// clear runs again on the next start) and this run trusts no stored flag.
// ---------------------------------------------------------------------------

#include <core/durable_file.hpp>
#include <core/leveldb_store.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

namespace dgb {

/// Bump whenever a change makes shares verified by an older build untrustworthy.
inline constexpr const char* kDgbShareRulesEpoch = "dgb-v35-python-exact-1";

inline std::string read_rules_epoch(const std::filesystem::path& marker)
{
    std::string epoch;
    std::ifstream in(marker);
    std::getline(in, epoch);
    return epoch;
}

/// Returns true when the store's verified flags may be trusted on this load:
/// the marker names kDgbShareRulesEpoch, or every flag was cleared (confirmed
/// by a re-scan) and the marker written. False: load without trusting any
/// stored flag. `storage`: scan_share_index / mark_shares_unverified.
template <typename StorageT>
bool reverify_store_if_rules_changed(StorageT& storage, const std::filesystem::path& marker)
{
    const std::string epoch = read_rules_epoch(marker);
    if (epoch == kDgbShareRulesEpoch)
        return true;
    const std::string was = epoch.empty() ? std::string("no epoch") : epoch;

    auto flagged = [&](std::vector<uint256>& out) -> bool {
        std::vector<core::SharechainLevelDBStore::IndexEntry> idx;
        if (!storage.scan_share_index(idx))
            return false;
        out.clear();
        for (const auto& e : idx)
            if (e.is_verified)
                out.push_back(e.hash);
        return true;
    };
    std::vector<uint256> verified;
    if (!flagged(verified)) {
        LOG_ERROR << "[Pool] the DGB sharechain store was written under older share rules (" << was
                  << ") and its index cannot be read: no stored share is trusted as verified this run;"
                     " the store is checked again on the next start";
        return false;
    }
    if (!verified.empty()) {
        LOG_WARNING << "[Pool] the DGB sharechain store was written under older share rules (" << was
                    << "): the verified flag of its " << verified.size()
                    << " shares is cleared once; the shares are kept and verified again (rules "
                    << kDgbShareRulesEpoch << ")";
        std::vector<uint256> still;
        if (!storage.mark_shares_unverified(verified) || !flagged(still) || !still.empty()) {
            LOG_ERROR << "[Pool] clearing the DGB store's verified flags FAILED ("
                      << (still.empty() ? std::string("write") : std::to_string(still.size()) + " still flagged")
                      << "): no stored share is trusted as verified this run; retried on the next start";
            return false;
        }
    }
    // The cleared flags are committed synced (mark_shares_unverified); the
    // marker is written durably after them (tmp, fsync, rename), so a power
    // loss cannot keep the marker without the cleared flags.
    std::error_code ec;
    std::filesystem::create_directories(marker.parent_path(), ec);
    core::durable_file::replace(marker.string(), std::string(kDgbShareRulesEpoch) + "\n");
    if (read_rules_epoch(marker) != kDgbShareRulesEpoch)
        LOG_ERROR << "[Pool] the DGB share rules marker " << marker.string()
                  << " cannot be written: the store's flags are cleared, and are checked again on the next start";
    // The flags are clear either way: nothing stored is trusted beyond them.
    return true;
}

} // namespace dgb
