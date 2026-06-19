#pragma once
// ============================================================================
// embedded_coinbase_value.hpp — SSOT for the embedded-path coinbase value.
//
// p2pool's gentx pays out the block's coinbasevalue = block subsidy + the
// fees of the transactions included in the template. On the external-daemon
// path that figure arrives ready-made in the digibyted getblocktemplate
// "coinbasevalue" field; on the embedded path (no external RPC) c2pool-dgb
// must derive it locally — block_subsidy(height) + sum(tx fees).
//
// This is the SINGLE place the DGB CoinParams::subsidy_func feeds a live
// coinbase-build path. Until this wiring, subsidy_func was populated in
// params.hpp (-> CoinParams::subsidy, oracle-conformed, see
// test/test_dgb_subsidy.cpp) but had ZERO invocation sites — the live path
// only ever read m_coinbase_value off GBT. The embedded TemplateBuilder
// (Stage 4c, src/impl/dgb/stratum/work_source.cpp) consumes this helper so
// the embedded coinbasevalue and the external-daemon GBT coinbasevalue are
// computed from one definition and can never silently diverge.
//
// HARD INVARIANT (project TODO, integrator 2026-06-18): the external-daemon
// GBT fallback MUST PERSIST. resolve_coinbase_value() takes the GBT value
// verbatim whenever it is present — digibyted already summed subsidy+fees
// consensus-correctly, so the embedded derivation is a FALLBACK for the
// no-external-daemon case, never an override of a live GBT figure.
//
// Pure + header-only: takes the subsidy_func callback (core::SubsidyFunc) and
// integer fee totals, so it is directly unit-testable against the oracle
// boundary vectors without standing up a node.
// ============================================================================

#include <core/pow.hpp>   // core::SubsidyFunc = std::function<uint64_t(uint32_t)>

#include <cstdint>
#include <optional>
#include <stdexcept>

namespace dgb::coin
{

// Embedded-path coinbasevalue = subsidy_func(height) + total_fees.
// Mirrors src/impl/ltc/coin/template_builder.hpp:
//     uint64_t coinbasevalue = subsidy + total_fees;
// but sources the subsidy through the coin's CoinParams::subsidy_func SSOT
// (the DGB oracle decay schedule) rather than a hardcoded halving formula.
//
// Throws std::logic_error if subsidy_func is unset — an empty std::function
// here means the CoinParams factory was not wired, which must fail loudly at
// the build site rather than silently pay a zero subsidy.
inline uint64_t embedded_coinbase_value(const core::SubsidyFunc& subsidy_func,
                                        uint32_t height,
                                        uint64_t total_fees)
{
    if (!subsidy_func)
        throw std::logic_error(
            "dgb::coin::embedded_coinbase_value: subsidy_func is unset "
            "(CoinParams factory not wired)");
    return subsidy_func(height) + total_fees;
}

// Resolve the coinbasevalue for a template, preserving the external-daemon
// path. When gbt_coinbasevalue is present (external digibyted GBT), it is
// authoritative and returned verbatim — the embedded derivation is NOT used.
// When absent (embedded TemplateBuilder, no external RPC), derive locally via
// embedded_coinbase_value(subsidy_func, height, total_fees).
inline uint64_t resolve_coinbase_value(const core::SubsidyFunc& subsidy_func,
                                       uint32_t height,
                                       uint64_t total_fees,
                                       std::optional<uint64_t> gbt_coinbasevalue)
{
    if (gbt_coinbasevalue.has_value())
        return *gbt_coinbasevalue;            // external-daemon fallback PERSISTS
    return embedded_coinbase_value(subsidy_func, height, total_fees);
}

} // namespace dgb::coin
