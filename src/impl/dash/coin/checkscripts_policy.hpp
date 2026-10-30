// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// S3a (DESIGN S2 section 6, RUNTIME-INJECT-DESIGN 3.1): the consensus-exact
/// CheckInputScripts gate (dashcore VerifyScript through dash_scriptcheck) is
/// armed whenever an at-tip scriptPubKey source exists — the --embedded-utxo
/// view (accrual or the full set) or the C1 fold — unless the operator opts
/// out with --embedded-fold-checkscripts=false. An explicit
/// --embedded-fold-checkscripts is accepted (it is the default now) and
/// reported as "explicit".
///
/// Armed, the gate runs over every served mempool-tx input (the selector) and
/// over every inject at admission (Mempool::add_inject, inject-script-invalid).
/// Off, the inject lane refuses inject-script-check-unarmed.

namespace dash {
namespace coin {

struct CheckscriptsArm {
    bool        on;
    const char* reason;
};

inline CheckscriptsArm resolve_checkscripts_arm(bool flag_on, bool flag_off, bool view_armed, bool fold_live)
{
    if (flag_off)
        return {false, "operator opt-out (--embedded-fold-checkscripts=false)"};
    if (!view_armed && !fold_live)
        return {false, "no input-script source (no --embedded-utxo view, no fold)"};
    return {true, flag_on ? "explicit" : "default-on (view-backed)"};
}

} // namespace coin
} // namespace dash
