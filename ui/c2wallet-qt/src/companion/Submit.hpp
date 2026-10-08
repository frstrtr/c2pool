// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// c2wallet-qt COMPANION — CONSUME the signed artifact -> SUBMIT (design §5.2
// companion, §5.4 "the validation seam").
//
// The PROVEN, PRIMARY seam is FILE-BASED: write the offline-signed raw hex to
// the file the c2pool loader consumes (--pin-local-tx-hex /
// --embedded-tx-inject-hex, one raw tx hex per line, proven at block 2518186).
// M5-A's SignedContainer already emits that exact byte format; this module
// wires it end-to-end (parse the signed artifact -> write the file the node
// loads). The AND/OR validate-seam op=submit request is also built here; the
// actual node HTTP call is a named seam (ValidateClient), loopback-only and
// armed-flag-gated. NO keys.

#include "TransferContainer.hpp" // c2w::artifact::SignedContainer
#include "ValidateSeam.hpp"      // c2w::artifact::SeamRequest

#include <optional>
#include <string>

namespace c2w::companion {

// Parse the offline-signed artifact (raw-hex-per-line). Thin wrapper over M5-A
// SignedContainer::parse, which mirrors the c2pool loader EXACTLY (intra-line
// whitespace stripped, blank lines skipped, odd hex length => whole-file
// refusal, per-tx oversize refusal).
std::optional<c2w::artifact::SignedContainer>
parse_signed_artifact(const std::string& text, std::string& err);

// PRIMARY PROVEN SEAM. Write the signed hex to `path` — the file the c2pool
// loader (--pin-local-tx-hex / --embedded-tx-inject-hex) consumes. Emits
// EXACTLY SignedContainer::emit() bytes (one raw hex per line, each
// '\n'-terminated). Returns false + err on an I/O failure. This is the file the
// node loads: producing it is the end-to-end submit.
bool write_pin_local_tx_file(const std::string& path,
                             const c2w::artifact::SignedContainer& sc,
                             std::string& err);

// Build the transport-agnostic op=submit request for one carried tx (the
// AND/OR validate-seam path §5.4). Live submit is a money-path (§5.5); this
// only MARSHALS the request — the actual node call is the named ValidateClient
// seam, and the FILE path above is the primary seam.
c2w::artifact::SeamRequest build_submit_request(const std::string& coin,
                                                const std::string& tx_hex);

} // namespace c2w::companion
