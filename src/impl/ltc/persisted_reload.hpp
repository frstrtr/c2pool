#pragma once

// persisted_reload.hpp — which persisted shares a restart reloads
// (node.cpp load_persisted_shares), as a pure function so a KAT pins it.
//
// The loader used to walk the store's height index. That index held ONE hash
// per absheight, and removing ANY share of a height deleted the key: every
// pruned fork share took the main-chain share of its height out of the index.
// A production store (2026-11-13) held 18,478 contiguous verified main-chain
// shares, of which 4,172 were reachable through the height index; the node
// reloaded ~23 % of its window, in fragments, could not connect its saved tip
// to the live share chain, and stalled for hours. The ungraceful-shutdown
// rebuild repaired the index, but a graceful stop clears the dirty flag, so
// it never ran.
//
// The loader now reads every share's own index record and reloads by
// absheight:
//   keep   = 2*CHAIN_LENGTH+10, the depth clean_tracker keeps below a head;
//   anchor = the highest VERIFIED share: its absheight was checked against its
//            parent's when it was verified, whereas an unverified share's
//            absheight is whatever the peer that sent it claimed. With no
//            verified share at all, the highest share;
//   window = the `keep` absheights ending at the anchor, plus everything above
//            it (shares received after the last verified one); every share of
//            those heights is loaded, forks included — the tracker sorts them
//            out as it does live;
//   prune  = shares below the window are deleted from the store, and only when
//            the anchor is a verified share: a claimed absheight never decides
//            what is deleted.
//
// Pure: no c2pool types, no consensus surface, no reward surface. Entry is any
// type with `uint64_t height` and `bool is_verified`.

#include <algorithm>
#include <cstdint>
#include <vector>

namespace ltc {

struct ReloadWindow {
    std::uint64_t low = 0;             // lowest absheight reloaded
    std::uint64_t anchor = 0;          // the height the window ends at
    bool anchored_on_verified = false;
    bool prune_below = false;          // shares under `low` may be deleted
};

template <typename Entry>
ReloadWindow reload_window(const std::vector<Entry>& entries, std::uint64_t keep)
{
    ReloadWindow w;
    if (entries.empty())
        return w;
    std::uint64_t max_all = 0;
    std::uint64_t max_verified = 0;
    bool any_verified = false;
    for (const auto& e : entries) {
        max_all = std::max<std::uint64_t>(max_all, e.height);
        if (e.is_verified) {
            any_verified = true;
            max_verified = std::max<std::uint64_t>(max_verified, e.height);
        }
    }
    w.anchored_on_verified = any_verified;
    w.anchor = any_verified ? max_verified : max_all;
    w.low = (keep > 0 && w.anchor + 1 > keep) ? w.anchor + 1 - keep : 0;
    w.prune_below = any_verified;
    return w;
}

}  // namespace ltc
