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
// payee had rotated in between (same staleness class as the h1517187
// bad-chainlock sibling).
//
// check_submit_payee() is the last line of defense, called by
// DASHWorkSource::mining_submit() on the won-block path BEFORE dispatching to
// the network: it compares the job's reassembled coinbase outputs against the
// GBT-mandated payments of the CURRENT template.
//
//   - TipMoved:      the job's prev != current template prev. The block is
//                    internally consistent for ITS OWN height (its payee
//                    matches its own prev), so it is still submitted — it is
//                    an orphan-race candidate, not a doomed bad-cb-payee.
//   - StalePayee:    prev matches (same height) but a GBT-mandated payment
//                    (masternode / superblock / platform burn) is MISSING or
//                    amount-mismatched in the coinbase → dashd WILL reject
//                    bad-cb-payee. The caller must NOT submit (reject-loud —
//                    the steward-ruled posture; never silently submit a
//                    doomed block).
//   - Unverifiable:  the coinbase failed to deserialize. Never block a
//                    submission on a guard-side parse failure — submit, log.
//   - Ok:            every current GBT-mandated payment is present exactly.
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
    Ok,           ///< all current GBT-mandated payments present — submit
    TipMoved,     ///< job prev != current prev — orphan race, still submit
    StalePayee,   ///< same prev, payee missing/mismatched — DO NOT submit
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
    // A differing prev means the tip moved after the job was issued; the
    // block is self-consistent for its own height (orphan-race candidate).
    if (current.m_previous_block.GetHex() != job_gbt_prevhash) {
        r.verdict = PayeeGuardVerdict::TipMoved;
        r.detail  = "job prev=" + job_gbt_prevhash.substr(0, 16)
                  + " current prev=" + current.m_previous_block.GetHex().substr(0, 16)
                  + " (tip moved since job issue — orphan-race submit)";
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

    // Every GBT-mandated payment (masternode / superblock / platform burn) of
    // the CURRENT template must appear as an exact (script, amount) output.
    for (const auto& pay : current.m_packed_payments) {
        if (pay.amount == 0)
            continue;
        const auto want_script = dash::decode_payee_script(
            pay.payee, params.address_version, params.address_p2sh_version);
        if (want_script.empty())
            continue;   // undecodable payee — builder drops these too
        bool found = false;
        for (const auto& out : cb.vout) {
            if (out.value == static_cast<int64_t>(pay.amount)
                && out.scriptPubKey.m_data == want_script) {
                found = true;
                break;
            }
        }
        if (!found) {
            std::ostringstream ss;
            ss << "GBT-mandated payment MISSING from coinbase: payee="
               << pay.payee << " amount=" << pay.amount
               << " (height " << current.m_height
               << " payee set != job's frozen payee set — dashd would reject"
                  " bad-cb-payee)";
            r.verdict = PayeeGuardVerdict::StalePayee;
            r.detail  = ss.str();
            return r;
        }
    }

    r.verdict = PayeeGuardVerdict::Ok;
    r.detail  = "all " + std::to_string(current.m_packed_payments.size())
              + " GBT-mandated payments present at current height";
    return r;
}

}  // namespace dash::stratum
