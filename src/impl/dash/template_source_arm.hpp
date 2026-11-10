// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// The served-arm classifier behind the c2pool-dash dashboard's live
// template_source (D-DASH.1, follow-up to the #942 node_role basis).
//
// c2pool-dash attaches no core::coin::ICoinNode (attaching one would end
// refresh_work()'s early return and start a failing get_work_view on every
// share tip), so the fact is published through
// MiningInterface::set_embedded_display on EVERY sourced template, never once
// at startup, using the three arm states of the
// "[DASH-STRATUM-GBT] template sourced: arm=" line:
//   EMBEDDED                -> embedded display true
//   dashd-fallback          -> false
//   none(set-gap/no-work)   -> false  (neither arm produced mineable work)
// Before the first sourced template the override stays unset, so the node
// reads template_source null (unknown) rather than claiming an arm.
// ---------------------------------------------------------------------------

#include <cstdint>

namespace dash {

enum class ServedArm : uint8_t { None = 0, Embedded = 1, DashdFallback = 2 };

// A set-gap template (zero bits or null prev-block) is the third state even
// when the embedded arm was the one selected.
constexpr ServedArm classify_served_arm(bool embedded_arm_selected, bool no_work) noexcept
{
    return no_work ? ServedArm::None
                   : (embedded_arm_selected ? ServedArm::Embedded
                                            : ServedArm::DashdFallback);
}

// The one wiring main_dash.cpp and the KATs share. Atomic store only.
template <typename MiningInterfaceT>
void publish_served_arm(MiningInterfaceT& mi, bool embedded_arm_selected, bool no_work)
{
    mi.set_embedded_display(classify_served_arm(embedded_arm_selected, no_work)
                            == ServedArm::Embedded);
}

} // namespace dash
