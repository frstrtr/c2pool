// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// c2wallet-qt COMPANION — Family-B (Monero) online leg: CLEARLY-NAMED STUB /
// CROSS-LANE SEAM (design §5.4 Family-B online contract).
//
// The Monero companion counterparty is the v37 XMR node (GitHub series
// xmr(native) #1500-#1612; local ledger tasks #191/#192). The online Monero
// leg — a view-only scan feed, a decoy / output-distribution service, a dynamic
// fee rate, levin NOTIFY_NEW_TRANSACTIONS relay, and accept/reject validation
// feedback, with the monerod-parity check (#1583) as the authoritative leg — is
// NOT implemented in this milestone. The wallet touches the v37 lane only as a
// relay/validate/scan CLIENT, never the sharechain/settlement code.
//
// These are declared as named seams so the boundary is explicit AND greppable.
// None performs I/O; each returns the seam name. The v37 XMR lane wires them.

#include <string>

namespace c2w::companion::monero {

inline constexpr const char* kSeamName = "xmr-companion-v37-cross-lane";

inline const char* scan_feed_seam()                { return kSeamName; } // get_blocks / get_o_indexes
inline const char* decoy_service_seam()            { return kSeamName; } // get_output_distribution / get_outs
inline const char* dynamic_fee_seam()              { return kSeamName; } // dynamic fee rate
inline const char* relay_seam()                    { return kSeamName; } // levin NOTIFY_NEW_TRANSACTIONS
inline const char* validate_feedback_seam()        { return kSeamName; } // accept/reject + reason
inline const char* monerod_parity_authority_seam() { return kSeamName; } // #1583 authoritative leg

} // namespace c2w::companion::monero
