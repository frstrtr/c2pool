// SPDX-License-Identifier: AGPL-3.0-or-later
// DashInjectModel::sign() — the one model step that calls the signers
// (sign_sweep / sign_collateral / verify_signed_funding_tx), so it lives in
// c2wallet-dash-tx next to them. It includes only std-only headers; the
// vendored dashscript tree stays inside SweepSign.cpp / CollateralTx.cpp.
#include "DashInjectModelImpl.hpp"

#include "DashError.hpp"

#include <utility>

namespace c2w::dash {

void DashInjectModel::sign()
{
    Impl& m = *p_;
    m.require(InjectStage::KeyBound, "sign");
    if (m.stage != InjectStage::KeyBound || !m.key)
        throw DashAbort("sign: no key is bound — load the key first");
    if (!armed())
        throw DashAbort(std::string("not armed: tick \"reviewed\"") +
                        (m.coll ? ", tick the 1-DASH burn box" : "") + " and type " + kSpendWord +
                        ". Nothing was signed.");

    // From here the key is single-use: it is wiped when this scope ends, whether
    // signing succeeds or throws. A refusal leaves the plan (stage Planned), so
    // the operator re-enters the key to try again.
    struct KeyWipe {
        Impl& m;
        ~KeyWipe() { m.wipe_key(); }
    } wipe_on_exit{m};
    m.clear_gate();
    m.stage = InjectStage::Planned;

    std::vector<SignedTx> txs;
    if (m.sweep)
        txs = sign_sweep(*m.sweep, *m.key, /*confirm_spend=*/true);
    else if (m.coll)
        txs.push_back(sign_collateral(*m.coll, *m.key, /*confirm_spend=*/true));
    else
        throw DashAbort("sign: no plan");
    m.wipe_key(); // as soon as the signatures exist

    // Independent re-verification of every tx: re-parse, re-serialize
    // byte-exact, run every scriptSig through the interpreter.
    for (size_t i = 0; i < txs.size(); ++i) {
        try {
            verify_signed_funding_tx(txs[i].hex, m.imp.address, m.testnet);
        } catch (const DashAbort& e) {
            throw DashAbort("re-verify of signed tx " + std::to_string(i + 1) + " FAILED: " + e.what() +
                            " — nothing was emitted");
        }
    }
    m.finish_signed(std::move(txs));
}

} // namespace c2w::dash
