// SPDX-License-Identifier: AGPL-3.0-or-later
//
// LANE-RULES (operator ruling R3, 2026-10-02): the node's own LaneRules
// (xmr_lane_rules.hpp), built ONCE from its configuration. main_v37_xmr.cpp
// calls lane_rules_of() after the settlement config is complete, prints the
// list (the "lane-rules:" startup line), makes it the epoch-1 Deployment of
// the relay HELLO (RULES RATCHET R1: rules_digest rides the epoch table, not
// the chain) and derives the ledger's OwedLedgerRules from it (owed_rules_of).
// KATs build a node's list through the same functions.
#pragma once

#include <cstdint>

#include "impl/xmr/settle/xmr_coinbase.hpp"   // kInputWeight, kTailSubsidy, XMR_COINBASE_MATURITY
#include "relay/xmr_relay_wire.hpp"           // kXmrPoolRulesVersion
#include "xmr_credit_cut.hpp"                 // kPoolFieldVersion (the V37P v2 codec)
#include "xmr_epoch.hpp"                      // RULES RATCHET: the one-entry epoch table
#include <c2pool/v37/w4_settlement.hpp>       // OwedLedgerRules (owed_rules_of)
#include "xmr_enrol_mode.hpp"                 // drops_rule_tag
#include "xmr_fee_model.hpp"                  // fee_model_on, donation_identity
#include "xmr_lane_rules.hpp"
#include "xmr_node_config.hpp"
#include "xmr_recon_ring.hpp"                 // default_max_root_age

namespace c2pool::v37n::xmr::lanerules {

static_assert(::c2pool::v37n::xmr::kXmrMinDConf == ::v37::xmr::settle::XMR_COINBASE_MATURITY,
              "the D_conf floor is Monero's coinbase maturity");

// The relay HELLO network byte (0 mainnet 1 testnet 2 stagenet 3 regtest).
inline std::uint8_t network_byte(MoneroNetwork n) {
    return n == MoneroNetwork::Mainnet ? 0 : n == MoneroNetwork::Testnet ? 1 : n == MoneroNetwork::Stagenet ? 2 : 3;
}

// What the configuration alone does not hold: the daemon's settlement rulings,
// the node's runtime flags outside XmrNodeConfig and the two HELLO digests.
struct LaneRulesInputs {
    bool          book_deferral      = true;           // !--no-book-deferral
    std::uint64_t recon_max_root_age = ~std::uint64_t{0};   // --recon-max-root-age; ~0 = the default (4 x D_conf)
    bool          kfair_salted_ties  = true;           // XmrSettlementConfig rulings the daemon sets
    bool          spend_floor        = true;
    bool          commit_total       = true;
    std::uint32_t output_cap_ceiling = 2700;           // XmrSettlementConfig::output_cap_ceiling
    bytes32       residual_sink_id{};                  // fee OFF: this node's sink identity (fee ON: the donation identity)
    bytes32       lane_params_digest{};                // the HELLO lane_params_digest this node sends
    bytes32       enrol_digest{};                      // the HELLO rule-tagged enrol digest; 0 when DROPS is not live
};

inline LaneRules lane_rules_of(const XmrNodeConfig& c, const LaneRulesInputs& in) {
    namespace fee = ::c2pool::v37n::xmr::fee;
    LaneRules r;
    r.d_conf             = c.d_conf;
    r.settle_h_min       = c.settle_h_min;
    r.output_cap         = c.settle_output_cap != 0 ? c.settle_output_cap : in.output_cap_ceiling;   // resolved
    r.recon_max_root_age = in.recon_max_root_age == ~std::uint64_t{0}
                               ? ::c2pool::v37n::xmr::recon::default_max_root_age(c.d_conf) : in.recon_max_root_age;
    r.book_deferral      = in.book_deferral ? 1 : 0;
    r.arm_floor          = static_cast<std::int64_t>(c.ledger_arm_floor);
    r.rotate_on_payment  = c.ledger_rotate_on_payment ? 1 : 0;
    r.decay_horizon      = c.ledger_decay_horizon;
    r.decay_half_life    = c.ledger_decay_half_life;
    r.anchor_cut         = c.ledger_anchor_cut ? 1 : 0;
    r.merkle_rows        = c.ledger_merkle_rows ? 1 : 0;
    r.drops_rule         = ::c2pool::v37n::xmr::relay::drops_rule_tag(c.ledger_drops_due, c.ledger_raindrop_enrol,
                                                                       c.ledger_drops_window_rw != 0);
    r.drops_window_rw    = c.ledger_drops_window_rw;
    r.kfair_salted_ties  = in.kfair_salted_ties ? 1 : 0;
    r.commit_total       = in.commit_total ? 1 : 0;
    r.input_weight       = ::v37::xmr::settle::kInputWeight;
    r.tail_subsidy       = ::v37::xmr::settle::kTailSubsidy;
    r.coinbase_maturity  = ::v37::xmr::settle::XMR_COINBASE_MATURITY;
    const bool fee_on    = fee::fee_model_on(c.lane_params);
    r.fee_version        = fee_on ? c.lane_params.fee.version : 0;
    r.residual_sink_id   = fee_on ? fee::donation_identity(static_cast<fee::DonationNet>(network_byte(c.network)))
                                  : in.residual_sink_id;
    r.pool_rules_version = ::c2pool::v37n::xmr::relay::kXmrPoolRulesVersion;
    r.owed_demo_amount   = c.owed_demo_amount;
    r.drain_q            = c.drain_q;              // THE DRAIN RULE (settlement-drain.md): 16 / 64 / 1 on the
    r.drain_h_cap        = c.drain_h_cap;          // test networks from its flag day, 0 / 0 / 0 = master
    r.drain_rule_version = c.drain_rule_version;
    r.pool_tag_codec     = ::c2pool::v37n::xmr::credit::kPoolFieldVersion;   // RULES RATCHET: V37P v2
    r.lane_params_digest = in.lane_params_digest;
    r.enrol_digest       = in.enrol_digest;
    r.spend_floor        = in.spend_floor ? 1 : 0;
    return r;
}


// RULES RATCHET: the OwedLedgerRules bits of ONE epoch's LaneRules (spec sec. 3.1:
// m_rules = rules_by_epoch[epoch_cur]; the RATCHET event switches it). The DROPS
// bits come from the rule tag (xmr_enrol_mode.hpp: due 1, raindrop-enrol 2,
// window 4); the drain rule turns lane_height and decay_from_gross on together;
// the window geometry is the lane's own.
inline ::c2pool::v37n::settle::OwedLedgerRules owed_rules_of(const LaneRules& r, const ::v37::LaneParams& lp) {
    ::c2pool::v37n::settle::OwedLedgerRules o;
    o.arm_floor         = static_cast<long long>(r.arm_floor);
    o.rotate_on_payment = r.rotate_on_payment != 0;
    o.decay_horizon     = r.decay_horizon;
    o.decay_half_life   = r.decay_half_life;
    o.anchor_cut        = r.anchor_cut != 0;
    o.merkle_rows       = r.merkle_rows != 0;
    o.drops_due         = (r.drops_rule & ::c2pool::v37n::xmr::relay::kDropsRuleDue) != 0;
    o.raindrop_enrol    = (r.drops_rule & ::c2pool::v37n::xmr::relay::kDropsRuleRaindropEnrol) != 0;
    o.lane_height       = r.drain_rule_version >= 1;
    o.decay_from_gross  = r.drain_rule_version >= 1;
    if (r.drops_window_rw != 0)
        o.drops_window = ::c2pool::v37n::settle::DropsWindowRule{lp.window, lp.half_life, lp.epoch_len(), r.drops_window_rw,
                                                                 ::c2pool::v37n::xmr::kXmrDropsWorkLz};
    return o;
}

// The one-entry epoch table of slice R1: epoch 1 = these rules, ACTIVE from H_act 0.
inline std::vector<::c2pool::v37n::xmr::epoch::Deployment> genesis_deployments(const LaneRules& r) {
    return {::c2pool::v37n::xmr::epoch::genesis_deployment(rules_digest(r))};
}

} // namespace c2pool::v37n::xmr::lanerules
