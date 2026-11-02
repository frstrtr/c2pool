// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Triggers.hpp"

#include "Clock.hpp"

#include "../../family/bitcoin/dash/InjectMaturity.hpp"

#include <algorithm>

namespace c2w::companion::sched {

std::string format_eta_seconds(int64_t seconds)
{
    if (seconds < 0) seconds = 0;
    const int64_t minutes = (seconds + 59) / 60;
    if (minutes < 60) return "~" + std::to_string(minutes) + " m";
    const int64_t m = (seconds / 60) % 60;
    const int64_t h = seconds / 3600;
    if (h < 48) return "~" + std::to_string(h) + " h " + std::to_string(m) + " m";
    return "~" + std::to_string(h / 24) + " d " + std::to_string(h % 24) + " h";
}

std::string format_eta_blocks(int64_t blocks)
{
    return format_eta_seconds(blocks * kSecondsPerBlock);
}

int64_t maturity_fire_tip(const MaturityTrigger& m)
{
    return c2w::dash::maturity::fires_at_tip(m.safe_from_height) + (m.slack_blocks > 0 ? m.slack_blocks : 0);
}

std::string Verdict::why() const
{
    std::string out;
    for (const Unmet& u : unmet) {
        if (!out.empty()) out += "; ";
        out += u.why;
    }
    return out;
}

Verdict evaluate(const Item& it, const ChainSnapshot& chain, int64_t now, const ParentLookup& parents)
{
    Verdict v;
    const Triggers& t = it.triggers;

    if (t.maturity.enabled) {
        const int64_t fire = maturity_fire_tip(t.maturity);
        const std::string rule = "inputs spendable in block >= " + std::to_string(t.maturity.safe_from_height) +
                                 (t.maturity.youngest_input_height > 0
                                      ? ", youngest input h0=" + std::to_string(t.maturity.youngest_input_height)
                                      : std::string()) +
                                 (t.maturity.slack_blocks > 0
                                      ? ", slack " + std::to_string(t.maturity.slack_blocks) + " blocks"
                                      : std::string());
        if (!chain.tip_known) {
            v.unmet.push_back({TriggerKind::Maturity,
                               "maturity: submit at tip >= " + std::to_string(fire) + " (" + rule + "); " +
                                   chain.tip_unknown_why,
                               std::nullopt, std::nullopt});
        } else if (chain.tip < fire) {
            const int64_t left = fire - chain.tip;
            v.unmet.push_back({TriggerKind::Maturity,
                               "maturity: tip " + std::to_string(chain.tip) + " < " + std::to_string(fire) + " (" +
                                   rule + "); " + std::to_string(left) + " blocks " + format_eta_blocks(left),
                               left, std::nullopt});
        }
    }

    if (t.not_before_height) {
        const int64_t h = *t.not_before_height;
        if (!chain.tip_known) {
            v.unmet.push_back({TriggerKind::Height,
                               "height: not before " + std::to_string(h) + "; " + chain.tip_unknown_why,
                               std::nullopt, std::nullopt});
        } else if (chain.tip < h) {
            const int64_t left = h - chain.tip;
            v.unmet.push_back({TriggerKind::Height,
                               "height: tip " + std::to_string(chain.tip) + " < " + std::to_string(h) + "; " +
                                   std::to_string(left) + " blocks " + format_eta_blocks(left),
                               left, std::nullopt});
        }
    }

    if (t.not_before_time) {
        int64_t when = 0;
        std::string perr;
        if (!parse_utc(*t.not_before_time, when, perr)) {
            v.unmet.push_back({TriggerKind::Time, "time: " + perr, std::nullopt, std::nullopt});
        } else if (now < when) {
            v.unmet.push_back({TriggerKind::Time,
                               "time: now " + format_utc(now) + " < " + *t.not_before_time + "; " +
                                   format_eta_seconds(when - now),
                               std::nullopt, when});
        }
    }

    for (const ParentReq& p : t.after_parent) {
        const int64_t req = p.min_confirmations > 0 ? p.min_confirmations : 1;
        const std::string name = "parent " + short_txid(p.txid);
        const ParentStatus ps = parents ? parents(p.txid) : ParentStatus{};
        const std::string state = ps.state_text.empty() ? std::string("not mined") : ps.state_text;
        auto unmet = [&](const std::string& why, std::optional<int64_t> eta = std::nullopt) {
            v.unmet.push_back({TriggerKind::Parent, why, eta, std::nullopt});
        };
        if (!ps.known) {
            unmet(name + " is not tracked; needs to be mined and final");
            continue;
        }
        if (t.allow_unconfirmed_parent) {
            // Operator opt-in: the parent in the node mempool (or mined at any
            // depth) is enough; neither N nor finality applies.
            if (ps.mined || ps.in_mempool) continue;
            unmet(name + " is " + state + " and not in the node mempool (allow_unconfirmed_parent needs it at least "
                                          "in the mempool)");
            continue;
        }
        if (!ps.mined) {
            unmet(name + " is " + state + " (not mined yet" +
                  (ps.in_mempool ? "; it is in the node mempool, but a child never rides an unconfirmed parent "
                                   "without allow_unconfirmed_parent"
                                 : "") +
                  "); needs to be mined and final");
            continue;
        }
        if (ps.height_unknown || !ps.mined_height) {
            unmet(name + " is mined at an unknown height (outside the body window): its finality cannot be "
                         "verified; verify it on a full node, then re-add the child with allow_unconfirmed_parent");
            continue;
        }
        const int64_t h = *ps.mined_height;
        if (!chain.tip_known) {
            unmet(name + " mined at " + std::to_string(h) + "; " + chain.tip_unknown_why);
            continue;
        }
        const bool cl = chain.chainlock_exposed;
        const int64_t need = cl ? req : std::max(req, kFallbackParentConfirmations);
        const int64_t confs = std::max<int64_t>(0, chain.tip - h + 1);
        const std::string fallback =
            "ChainLock not exposed by node; waiting for " + std::to_string(need) +
            (need == 1 ? " confirmation" : " confirmations");
        if (confs < need) {
            const int64_t left = need - confs;
            unmet(name + " mined at " + std::to_string(h) + ", " + std::to_string(confs) + "/" + std::to_string(need) +
                      " confirmations" + (cl ? std::string() : "; " + fallback) + "; " + std::to_string(left) +
                      " blocks " + format_eta_blocks(left),
                  left);
            continue;
        }
        if (!ps.block_still_at_height) {
            unmet(name + " mined at " + std::to_string(h) + ": cannot verify the block at " + std::to_string(h) +
                  " is still its block (" + (ps.block_check_why.empty() ? std::string("not checked") : ps.block_check_why) +
                  ")");
            continue;
        }
        if (!*ps.block_still_at_height) {
            unmet(name + " was mined at " + std::to_string(h) + " but that block is no longer on the node's chain (" +
                  ps.block_check_why + "): reorged out; waiting for the parent to be mined and final again");
            continue;
        }
        if (cl) {
            if (!chain.chainlock_height) {
                unmet(name + " mined at " + std::to_string(h) + ", " + std::to_string(confs) +
                      (confs == 1 ? " confirmation" : " confirmations") + "; not final yet: " +
                      (chain.chainlock_why.empty() ? std::string("no ChainLock reported") : chain.chainlock_why));
                continue;
            }
            if (*chain.chainlock_height < h) {
                const int64_t left = h - *chain.chainlock_height;
                unmet(name + " mined at " + std::to_string(h) + ", " + std::to_string(confs) +
                          (confs == 1 ? " confirmation" : " confirmations") + "; not final yet: bestchainlock height " +
                          std::to_string(*chain.chainlock_height) + " < " + std::to_string(h),
                      left);
                continue;
            }
        }
    }

    v.ready = v.unmet.empty();
    return v;
}

} // namespace c2w::companion::sched
