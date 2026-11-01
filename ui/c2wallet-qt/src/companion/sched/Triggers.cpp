// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Triggers.hpp"

#include "Clock.hpp"

#include "../../family/bitcoin/dash/InjectMaturity.hpp"

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
        const int64_t need = p.min_confirmations > 0 ? p.min_confirmations : 1;
        const std::string name = "parent " + short_txid(p.txid);
        const std::string needs =
            "needs " + std::to_string(need) + (need == 1 ? " confirmation" : " confirmations");
        const ParentStatus ps = parents ? parents(p.txid) : ParentStatus{};
        if (!ps.known) {
            v.unmet.push_back({TriggerKind::Parent, name + " is not tracked; " + needs, std::nullopt, std::nullopt});
            continue;
        }
        if (!ps.mined) {
            v.unmet.push_back({TriggerKind::Parent,
                               name + " is " + (ps.state_text.empty() ? std::string("not mined") : ps.state_text) +
                                   " (not mined yet); " + needs,
                               std::nullopt, std::nullopt});
            continue;
        }
        if (ps.height_unknown || !ps.mined_height) {
            if (need > 1)
                v.unmet.push_back({TriggerKind::Parent,
                                   name + " is mined at an unknown height (outside the body window); cannot count " +
                                       std::to_string(need) + " confirmations",
                                   std::nullopt, std::nullopt});
            continue; // mined => at least one confirmation
        }
        if (!chain.tip_known) {
            v.unmet.push_back({TriggerKind::Parent,
                               name + " mined at " + std::to_string(*ps.mined_height) + "; " + needs + "; " +
                                   chain.tip_unknown_why,
                               std::nullopt, std::nullopt});
            continue;
        }
        const int64_t confs = chain.tip - *ps.mined_height + 1;
        if (confs < need) {
            const int64_t left = need - (confs > 0 ? confs : 0);
            v.unmet.push_back({TriggerKind::Parent,
                               name + " mined at " + std::to_string(*ps.mined_height) + ", " +
                                   std::to_string(confs > 0 ? confs : 0) + "/" + std::to_string(need) +
                                   " confirmations; " + std::to_string(left) + " blocks " + format_eta_blocks(left),
                               left, std::nullopt});
        }
    }

    v.ready = v.unmet.empty();
    return v;
}

} // namespace c2w::companion::sched
