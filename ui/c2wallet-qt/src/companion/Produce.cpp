// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Produce.hpp"

namespace c2w::companion {

std::optional<c2w::artifact::UnsignedContainer>
produce_unsigned(const FundingData& fd, std::string& err) {
    err.clear();
    if (fd.inputs.empty())  { err = "no funding inputs"; return std::nullopt; }
    if (fd.outputs.empty()) { err = "no target outputs"; return std::nullopt; }

    c2w::artifact::UnsignedContainer c;
    c.coin              = fd.coin;
    c.network_version   = fd.network_version;
    c.algebra           = fd.algebra;
    c.preflight_verdict = fd.preflight_verdict;
    c.unsigned_tx       = serialize_unsigned_tx(fd);

    c.inputs.reserve(fd.inputs.size());
    for (const auto& fi : fd.inputs) {
        c2w::artifact::UnsignedInput ui;
        ui.prevout_txid   = fi.prevout_txid;   // already internal byte order
        ui.prevout_index  = fi.prevout_index;
        ui.script_pubkey  = fi.script_pubkey;
        ui.amount         = fi.amount;
        ui.derivation_hint = fi.derivation_hint;
        c.inputs.push_back(std::move(ui));
    }
    return c;
}

std::string produce_unsigned_hex(const FundingData& fd, std::string& err) {
    auto c = produce_unsigned(fd, err);
    if (!c) return {};
    return c->to_hex(err); // enforces the 100 kB oversize ceiling
}

} // namespace c2w::companion
