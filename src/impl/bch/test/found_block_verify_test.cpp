// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin::block_confirm::resolve_status KAT -- pins the found-block
// confirm/orphan verdict logic wired into the dashboard verifier (#995 BCH arm,
// MiningInterface::set_block_verify_fn in pool_entrypoint.hpp).
//
// The resolver takes a winner_at(height) oracle (the embedded HeaderChain's
// best branch), the tip height, the found block's id and its mint height, and
// returns the core verify_found_block contract: >0 confirmed / <0 orphaned /
// 0 pending. These KATs pin all five branches:
//   1) confirmed once buried >= kDefaultConfirmDepth (returns the conf count)
//   2) in-chain but shallow (< depth) -> pending (0)
//   3) exactly at depth -> confirmed
//   4) a DIFFERENT block won the height -> orphaned (-1)
//   5) height not yet indexed (oracle nullopt) / tip behind -> pending (0)
//
// Harness: plain int main() + assert-style CHECK (CTest treats exit 0 as PASS),
// matching the sibling bch KAT tests. Header-only over coin/block_confirm.hpp +
// <core/uint256.hpp>; NO coin lib link -> per-coin isolation stays clean. The
// resolver is PURE (no chain, no daemon), so no network/daemon is exercised.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <iostream>
#include <map>
#include <optional>

#include <core/uint256.hpp>
#include "../coin/block_confirm.hpp"

namespace {
int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

using bch::coin::block_confirm::resolve_status;
using bch::coin::block_confirm::kDefaultConfirmDepth;

uint256 mk(const char* hex) { uint256 h; h.SetHex(hex); return h; }

// A best-chain oracle: height -> winning block hash. Absent height => nullopt
// (we have not yet reached/indexed it), matching HeaderChain::get_header_by_height.
struct BestChain {
    std::map<uint32_t, uint256> by_height;
    std::optional<uint256> operator()(uint32_t h) const {
        auto it = by_height.find(h);
        if (it == by_height.end()) return std::nullopt;
        return it->second;
    }
};
} // namespace

int main()
{
    const uint256 WON   = mk("00000000000000000000000000000000000000000000000000000000000000aa");
    const uint256 OTHER = mk("00000000000000000000000000000000000000000000000000000000000000bb");
    const uint32_t H = 800000;

    // Sanity: the depth constant is the conventional 6.
    CHECK(kDefaultConfirmDepth == 6);

    // ---- 1) Confirmed: our block won H and is buried >= depth --------------
    {
        BestChain chain;
        for (uint32_t i = 0; i <= 6; ++i) chain.by_height[H + i] = (i == 0) ? WON : mk("00000000000000000000000000000000000000000000000000000000000000c0");
        // tip = H+6 -> confs = 6 - 0 + ... = (H+6) - H + 1 = 7 >= 6 -> confirmed
        int v = resolve_status(chain, /*tip=*/H + 6, WON, /*found=*/H);
        CHECK(v > 0);
        CHECK(v == 7);
    }

    // ---- 2) In-chain but shallow (< depth) -> pending ----------------------
    {
        BestChain chain; chain.by_height[H] = WON;
        // tip = H+2 -> confs = 3 < 6 -> pending
        int v = resolve_status(chain, /*tip=*/H + 2, WON, /*found=*/H);
        CHECK(v == 0);
    }

    // ---- 3) Exactly at depth -> confirmed ----------------------------------
    {
        BestChain chain; chain.by_height[H] = WON;
        // tip = H+5 -> confs = 6 == depth -> confirmed
        int v = resolve_status(chain, /*tip=*/H + 5, WON, /*found=*/H);
        CHECK(v > 0);
        CHECK(v == static_cast<int>(kDefaultConfirmDepth));
    }

    // ---- 4) A DIFFERENT block won H -> orphaned ----------------------------
    {
        BestChain chain; chain.by_height[H] = OTHER;
        int v = resolve_status(chain, /*tip=*/H + 100, WON, /*found=*/H);
        CHECK(v < 0);
        CHECK(v == -1);
    }

    // ---- 5a) Height not yet indexed (oracle nullopt) -> pending ------------
    {
        BestChain chain; // empty -> winner_at(H) == nullopt
        int v = resolve_status(chain, /*tip=*/H - 5, WON, /*found=*/H);
        CHECK(v == 0);
    }

    // ---- 5b) In chain but tip behind found_height (reorg) -> pending -------
    {
        BestChain chain; chain.by_height[H] = WON;
        int v = resolve_status(chain, /*tip=*/H - 1, WON, /*found=*/H);
        CHECK(v == 0);
    }

    // ---- Contract cross-check: the three sign classes are distinct --------
    {
        BestChain confirmed; confirmed.by_height[H] = WON;
        BestChain orphaned;  orphaned.by_height[H]  = OTHER;
        BestChain pending;   // empty
        CHECK(resolve_status(confirmed, H + 10, WON, H) > 0);
        CHECK(resolve_status(orphaned,  H + 10, WON, H) < 0);
        CHECK(resolve_status(pending,   H + 10, WON, H) == 0);
    }

    if (failures) {
        std::cerr << failures << " CHECK(s) failed\n";
        return 1;
    }
    std::cout << "bch_found_block_verify_test: all resolve_status KATs passed\n";
    return 0;
}
