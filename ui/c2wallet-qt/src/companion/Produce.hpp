// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// c2wallet-qt COMPANION — PRODUCE the unsigned artifact (design §5.2 companion,
// §5.4 Family-A unsigned). Given public funding data, build the M5-A
// UnsignedContainer (reusing M5-A artifact code) to hand across the air gap.
// NO keys involved.

#include "FundingData.hpp"
#include "TransferContainer.hpp"

#include <optional>
#include <string>

namespace c2w::companion {

// Build the M5-A UnsignedContainer from funding data. Refuses (nullopt + err)
// on empty inputs/outputs. The oversize refusal happens in
// UnsignedContainer::to_hex (100 kB ceiling, §5.4).
std::optional<c2w::artifact::UnsignedContainer>
produce_unsigned(const FundingData& fd, std::string& err);

// Convenience: produce the hex artifact string directly. Empty + err on
// failure (including the to_hex oversize refusal).
std::string produce_unsigned_hex(const FundingData& fd, std::string& err);

} // namespace c2w::companion
