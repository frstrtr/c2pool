// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// dash::TemplateSourceNode -- display-only core::coin::ICoinNode for the
// c2pool-dash dashboard (D-DASH.1, follow-up to the #942 node_role basis).
//
// /local_stats template_source and /api/node_topology "embedded" read
// m_coin_node->is_embedded() (web_server.cpp rest_local_stats). c2pool-dash
// attaches no ICoinNode: its work comes from DASHWorkSource, so a daemonless
// DASH node reports template_source null (unknown) although it serves
// embedded templates.
//
// This adapter carries ONE live fact: whether the LAST sourced template was
// actually served by the EMBEDDED arm. The DASH stratum work source updates it
// on EVERY sourced template (never once at startup) at the same point that
// writes the "[DASH-STRATUM-GBT] template sourced: arm=" line, using the
// same three arm states:
//   EMBEDDED                -> is_embedded() true
//   dashd-fallback          -> false
//   none(set-gap/no-work)   -> false  (neither arm produced mineable work)
// Before the first sourced template it reads false.
//
// Thread safety: the stratum thread writes and the HTTP thread reads, through
// one std::atomic<uint8_t>. There is no lock and no tracker or peer state.
//
// The remaining ICoinNode members are NEUTRAL by contract, so attaching the
// adapter cannot open a work or submit path inside WebServer:
//   has_rpc()          false. The dashd NodeRPC arm is reported through
//                      MiningInterface::set_coin_rpc_available(), which
//                      template_source already ORs in. Returning true here
//                      would arm WebServer's own getblocktemplate poll and
//                      route submitblock through this adapter.
//   get_work_view()    throws. DASHWorkSource is the only DASH work producer;
//                      WebServer never builds DASH work.
//   submit_block_hex() false. DASH won blocks go out through
//                      dash::coin::broadcast_won_block, never through here.
// ---------------------------------------------------------------------------

#include <atomic>
#include <cstdint>
#include <stdexcept>
#include <string>

#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>

namespace dash {

class TemplateSourceNode final : public core::coin::ICoinNode {
public:
    // The three arm states of the "[DASH-STRATUM-GBT] template sourced" line.
    enum class ServedArm : uint8_t { None = 0, Embedded = 1, DashdFallback = 2 };

    // The arm-line predicate, kept in one place: a set-gap template (zero bits
    // or null prev-block) is the third state even when the embedded arm was
    // the one selected, because neither arm produced mineable work.
    static constexpr ServedArm classify(bool embedded_arm_selected,
                                        bool no_work) noexcept
    {
        return no_work ? ServedArm::None
                       : (embedded_arm_selected ? ServedArm::Embedded
                                                : ServedArm::DashdFallback);
    }

    // Called on every sourced template (stratum thread).
    void note_sourced(ServedArm arm) noexcept
    {
        m_last_arm.store(static_cast<uint8_t>(arm), std::memory_order_release);
    }

    ServedArm last_arm() const noexcept
    {
        return static_cast<ServedArm>(m_last_arm.load(std::memory_order_acquire));
    }

    bool is_embedded() const override { return last_arm() == ServedArm::Embedded; }

    bool has_rpc() const override { return false; }

    core::coin::WorkView get_work_view() override
    {
        throw std::runtime_error(
            "dash::TemplateSourceNode is display-only; DASH work comes from DASHWorkSource");
    }

    bool submit_block_hex(const std::string&, bool) override { return false; }

private:
    std::atomic<uint8_t> m_last_arm{static_cast<uint8_t>(ServedArm::None)};
};

} // namespace dash
