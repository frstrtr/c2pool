// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_template_catchup_kat.cpp
// Catch-up template rule (K28, FR-B1), Fresh = 2:
//   (1) gap 0 / 1 / 2: template on the Monero tip (height M + 1), fresh;
//   (2) gap 3: template at h(t) + 2 on the main-chain block at h(t) + 1,
//       fresh; the template on the Monero tip (h(t) + 3) is not fresh;
//   (3) gap 5: two catch-up carriers, then a template on the Monero tip;
//   (4) Monero below h(t) (gap -1, -5): template on P_t at h(t), fresh;
//   (5) sweep h(t) 1..300 x M 0..320: every template fresh, height = parent
//       height + 1, never below the tip's Monero parent; gap g > Fresh is
//       closed by ceil((g - Fresh) / Fresh) catch-up carriers;
//   (6) Fresh 3: gap 4 -> template at h(t) + 3.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <string>

#include "impl/xmr/pathb/pathb_catchup.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

// Monero tip height for a given gap: gap = M + 1 - h(t).
std::uint64_t monero_for_gap(std::uint64_t h_tip, std::int64_t gap) {
    return static_cast<std::uint64_t>(static_cast<std::int64_t>(h_tip) - 1 + gap);
}

}  // namespace

int main() {
    std::printf("v37_xmr_template_catchup_kat\n");
    const pb::LaneParams p = pb::kRuledLaneParams;
    const std::uint64_t fresh = p.fresh_max;
    check(fresh == 2, "Fresh = 2");
    const std::uint64_t ht = 3777441;  // h(t)

    // (1) gap 0..Fresh
    for (std::int64_t gap = 0; gap <= 2; ++gap) {
        const std::uint64_t m = monero_for_gap(ht, gap);
        const pb::CatchupDecision d = pb::catchup_template(ht, m, p);
        check(d.parent == pb::TemplateParent::MoneroTip && d.parent_height == m && d.template_height == m + 1,
              "gap " + std::to_string(gap) + ": template on the Monero tip at M + 1");
        check(pb::template_fresh(d.template_height, ht, fresh), "gap " + std::to_string(gap) + ": template fresh");
    }

    // (2) gap 3
    {
        const std::uint64_t m = monero_for_gap(ht, 3);
        const pb::CatchupDecision d = pb::catchup_template(ht, m, p);
        check(d.parent == pb::TemplateParent::MainChainAt, "gap 3: catch-up on a main-chain block");
        check(d.parent_height == ht + 1 && d.template_height == ht + 2, "gap 3: parent h(t) + 1, template h(t) + 2");
        check(pb::template_fresh(d.template_height, ht, fresh), "gap 3: catch-up template fresh (d = 2)");
        check(!pb::template_fresh(m + 1, ht, fresh), "gap 3: template on the Monero tip (d = 3) not fresh");
    }

    // (3) gap 5: two catch-up carriers
    {
        std::uint64_t h = ht;
        const std::uint64_t m = monero_for_gap(ht, 5);
        int catchups = 0;
        pb::CatchupDecision d = pb::catchup_template(h, m, p);
        while (d.parent == pb::TemplateParent::MainChainAt && catchups < 10) {
            check(pb::template_fresh(d.template_height, h, fresh), "gap 5: catch-up carrier fresh");
            h = d.template_height;
            ++catchups;
            d = pb::catchup_template(h, m, p);
        }
        check(catchups == 2, "gap 5: two catch-up carriers");
        check(d.parent == pb::TemplateParent::MoneroTip && d.template_height == m + 1,
              "gap 5: then a template on the Monero tip");
        check(pb::template_fresh(d.template_height, h, fresh), "gap 5: final template fresh");
    }

    // (4) Monero below h(t)
    for (std::int64_t gap : {-1, -2, -5}) {
        const std::uint64_t m = monero_for_gap(ht, gap);
        const pb::CatchupDecision d = pb::catchup_template(ht, m, p);
        check(d.parent == pb::TemplateParent::TipParent && d.parent_height == ht - 1 && d.template_height == ht,
              "gap " + std::to_string(gap) + ": template on P_t at h(t)");
        check(pb::template_fresh(d.template_height, ht, fresh), "gap " + std::to_string(gap) + ": template fresh (d = 0)");
    }
    {
        const pb::CatchupDecision d = pb::catchup_template(1, 0, p);
        check(d.parent == pb::TemplateParent::MoneroTip && d.template_height == 1, "h(t) 1, M 0: template at 1");
    }

    // (5) sweep
    {
        bool fresh_all = true, chain_all = true, close_all = true;
        for (std::uint64_t h = 1; h <= 300; ++h) {
            for (std::uint64_t m = 0; m <= 320; ++m) {
                const pb::CatchupDecision d = pb::catchup_template(h, m, fresh);
                if (!pb::template_fresh(d.template_height, h, fresh)) fresh_all = false;
                if (d.template_height != d.parent_height + 1 || d.parent_height + 1 < h) chain_all = false;
                if (m + 1 > h + fresh) {
                    const std::uint64_t g = m + 1 - h;
                    std::uint64_t hh = h;
                    std::uint64_t steps = 0;
                    pb::CatchupDecision e = d;
                    while (e.parent == pb::TemplateParent::MainChainAt && steps <= g) {
                        hh = e.template_height;
                        ++steps;
                        e = pb::catchup_template(hh, m, fresh);
                    }
                    if (steps != pb::ceil_div(g - fresh, fresh) || e.template_height != m + 1) close_all = false;
                }
            }
        }
        check(fresh_all, "sweep: every template fresh");
        check(chain_all, "sweep: template height = parent height + 1, never below the tip's Monero parent");
        check(close_all, "sweep: gap g closed by ceil((g - Fresh) / Fresh) catch-up carriers");
    }

    // (6) Fresh 3
    {
        pb::LaneParams p3 = p;
        p3.fresh_max = 3;
        const pb::CatchupDecision d = pb::catchup_template(ht, monero_for_gap(ht, 4), p3);
        check(d.parent == pb::TemplateParent::MainChainAt && d.parent_height == ht + 2 && d.template_height == ht + 3,
              "Fresh 3, gap 4: template at h(t) + 3 on main-chain h(t) + 2");
        const pb::CatchupDecision e = pb::catchup_template(ht, monero_for_gap(ht, 3), p3);
        check(e.parent == pb::TemplateParent::MoneroTip, "Fresh 3, gap 3: template on the Monero tip");
    }

    return finish("v37_xmr_template_catchup_kat");
}
