// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// dash::stratum submit-time masternode-payee guard (stale-payee fix, defect 4).
//
// DASH rotates the masternode payee EVERY block, so a coinbase is only valid
// at the exact height its template was fetched for. A won block whose header
// prev matches the CURRENT tip but whose coinbase carries a payee frozen from
// an OLDER template snapshot is deterministically rejected by dashd with
// bad-cb-payee — the block reward is lost. This was hex-confirmed live on
// testnet (.52) at h1517420: the reassembled stratum coinbase was byte-correct
// against the GBT at job-BUILD time, yet rejected at SUBMIT time because the
// payee had rotated in between.
//
// ── CRITICAL INVARIANT (reward safety) ──────────────────────────────────────
// The guard must NEVER refuse a block that dashd would ACCEPT — a false refusal
// forfeits a full block reward (~0.44 DASH per event, empirically observed).
// It must still refuse a block dashd would deterministically reject for
// bad-cb-payee (a genuinely WRONG payee script, or a WRONG height). When in
// doubt, SUBMIT: a truly bad block is rejected by dashd for free, whereas a
// false refusal is a guaranteed, irreversible loss.
//
// ── Why an AMOUNT comparison is WRONG (the false-refusal this fix removes) ───
// The masternode/operator payment amount is subsidy + BLOCK FEES. Fees drift
// every time the template is re-pulled at the same height (the mempool moves),
// so a job's FROZEN coinbase amount routinely differs from the amount in a
// LATER-fetched "current" template — even though both pay the SAME, correct,
// height-deterministic payee script. dashd validates the masternode amount
// against the BLOCK'S OWN fees (self-consistent by GBT construction), NOT
// against some newer template. Comparing the frozen amount to the current
// template's amount therefore false-flags perfectly valid winning blocks as
// "stale payee" and refuses to submit them. Two mainnet blocks (heights
// 2508655, 2508696) were lost this way in a single day: correct payee, correct
// height/parent, multi-minute head start over the eventual network winner,
// rejected purely on fee-driven amount drift.
//
// ── What the guard actually checks ──────────────────────────────────────────
// check_submit_payee() is the last line of defense, called by
// DASHWorkSource::mining_submit() on the won-block path BEFORE dispatching to
// the network. The payee SCRIPT is height-deterministic; the amount is not. So
// the guard verifies payee SCRIPTS by SET MEMBERSHIP and never compares amounts:
//
//   - HeightRace:   the job's prev != the current chain tip. The tip moved
//                   AFTER the job was issued, but "parent moved" ≠ "unwinnable"
//                   and the guard must NOT drop the block (that would forfeit a
//                   winnable reward, violating the invariant above). If the
//                   chain merely extended, our block is a valid competing block
//                   at the same height — dashd ACCEPTS it and we race. If it was
//                   a 1-block reorg, our block is one above the current tip —
//                   submitting makes OUR chain longer and the network reorgs to
//                   us. Only when buried 2+ deep is it unwinnable, and even then
//                   submitting is free (dashd stores a dead orphan, no harm).
//                   dashd is the authority on validity at the block's REAL
//                   height, so we CANNOT run the set-membership payee check here
//                   (m_packed_payments are for the CURRENT tip's height, not our
//                   block's) — we SUBMIT and log a race warning. Dropping would
//                   guarantee the loss; submitting lets the network decide.
//   - PayeeMissing: prev matches (same height) but a GBT-mandated payee SCRIPT
//                   (masternode / operator / superblock / platform burn) is
//                   ABSENT from the coinbase outputs → a genuine bad-cb-payee.
//                   DO NOT submit. (This is the real stale/wrong-payee case;
//                   a mere amount difference is NOT this — see above.)
//   - Unverifiable: the coinbase failed to deserialize. Never block a
//                   submission on a guard-side parse failure — submit, log.
//   - Ok:           every GBT-mandated payee SCRIPT is present in the coinbase
//                   at the current height. Amounts may differ from the current
//                   template (fee drift) — that is fine; dashd validates the
//                   amount against the block's own fees. SUBMIT.
//
// Pure + fenced: no sockets, no RPC, no locks — direct KAT surface
// (test_dash_stratum_work_source.cpp). The payee→script decode reuses the
// verifier-shared SSOT dash::decode_payee_script (share_check.hpp) so the
// guard can never disagree with the builder about script shapes.

#include <impl/dash/coin/rpc_data.hpp>      // DashWorkData, PackedPayment
#include <impl/dash/coin/transaction.hpp>   // MutableTransaction (DASH tx codec)
#include <impl/dash/share_check.hpp>        // decode_payee_script (payee SSOT)

#include <core/coin_params.hpp>
#include <core/pack.hpp>

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace dash::stratum {

enum class PayeeGuardVerdict {
    Ok,           ///< all mandated payee SCRIPTS present at current height — submit
    HeightRace,   ///< job prev != current tip — parent moved — SUBMIT as a height race (dashd decides)
    PayeeMissing, ///< same height, a mandated payee SCRIPT absent — bad-cb-payee — DO NOT submit
    Unverifiable, ///< coinbase would not parse — submit (never guard-block on parse)
};

struct PayeeGuardResult {
    PayeeGuardVerdict verdict{PayeeGuardVerdict::Ok};
    std::string       detail;   ///< human-readable reason for the log line
};

inline PayeeGuardResult check_submit_payee(
    const std::vector<unsigned char>& coinbase_bytes,
    const std::string& job_gbt_prevhash,
    const dash::coin::DashWorkData& current,
    const core::CoinParams& params)
{
    PayeeGuardResult r;

    // Height context: same prev == same height == same expected payee set.
    // A differing prev means the tip moved after the job was issued. That is a
    // RACE, not a guaranteed loss: if the chain merely extended, our block is a
    // valid competing block at the same height (dashd accepts, we race); if it
    // was a 1-block reorg, our block is one above the current tip (submitting
    // makes our chain longer, the network reorgs to us). Only a 2+ deep bury is
    // unwinnable — and even then submitting is free (dashd stores a dead orphan,
    // no harm). Per the reward invariant, when in doubt we SUBMIT and let dashd
    // (the authority at the block's REAL height) decide. We deliberately SKIP
    // the set-membership payee check below: m_packed_payments belong to the
    // CURRENT tip's height, NOT our block's, so comparing against them would be
    // meaningless — dashd validates the payee at the block's own height.
    if (current.m_previous_block.GetHex() != job_gbt_prevhash) {
        r.verdict = PayeeGuardVerdict::HeightRace;
        r.detail  = "job prev=" + job_gbt_prevhash.substr(0, 16)
                  + " current tip=" + current.m_previous_block.GetHex().substr(0, 16)
                  + " (parent moved since job issue — submitting anyway as a"
                    " height race; dashd will accept if valid at the block's real"
                    " height, reject for free if not; dropping would guarantee"
                    " the loss)";
        return r;
    }

    // Deserialize the reassembled coinbase through the DASH tx codec (the
    // same PackStream >> MutableTransaction path rpc.cpp uses for GBT txs).
    dash::coin::MutableTransaction cb;
    try {
        PackStream ps(coinbase_bytes);
        ps >> cb;
    } catch (const std::exception& e) {
        r.verdict = PayeeGuardVerdict::Unverifiable;
        r.detail  = std::string("coinbase deserialize failed: ") + e.what();
        return r;
    }

    // SET-MEMBERSHIP payee-script check (NOT an amount comparison). Every
    // GBT-mandated payee SCRIPT of the current height must appear as SOME
    // coinbase output's scriptPubKey. The payee script is height-deterministic,
    // so the current template's mandated scripts equal the job's mandated
    // scripts whenever the prev matches (verified above). We deliberately do
    // NOT compare out.value against pay.amount: the mandated amount is
    // subsidy + fees and drifts with the mempool between template re-pulls at
    // the same height; dashd checks it against the block's OWN fees, so an
    // amount difference here is NOT a reject and must NOT block the submit.
    for (const auto& pay : current.m_packed_payments) {
        if (pay.amount == 0)
            continue;   // no-op payment — builder emits no output for it
        const auto want_script = dash::decode_payee_script(
            pay.payee, params.address_version, params.address_p2sh_version);
        if (want_script.empty())
            continue;   // undecodable payee — builder drops these too
        bool found = false;
        for (const auto& out : cb.vout) {
            if (out.scriptPubKey.m_data == want_script) {   // script only, ANY amount
                found = true;
                break;
            }
        }
        if (!found) {
            std::ostringstream ss;
            ss << "GBT-mandated payee SCRIPT MISSING from coinbase: payee="
               << pay.payee
               << " (height " << current.m_height
               << " — the coinbase does not pay this mandated payee at all;"
                  " dashd would reject bad-cb-payee)";
            r.verdict = PayeeGuardVerdict::PayeeMissing;
            r.detail  = ss.str();
            return r;
        }
    }

    r.verdict = PayeeGuardVerdict::Ok;
    r.detail  = "all " + std::to_string(current.m_packed_payments.size())
              + " GBT-mandated payee scripts present at current height"
                " (amounts validated by dashd against the block's own fees)";
    return r;
}

}  // namespace dash::stratum
