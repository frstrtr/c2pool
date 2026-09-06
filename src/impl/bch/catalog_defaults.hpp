// src/impl/bch/catalog_defaults.hpp
//
// Per-impl L0 (compiled-default) registration for the settings catalog.
// FROM_POOL_CONFIG rows get their compiled value HERE so L0 equals this coin's
// compiled defaults. Overlaid AFTER rc.seed_compiled_defaults(coin) and BEFORE
// the file overlay (see the mains' M0b wiring block).
#ifndef C2POOL_IMPL_BCH_CATALOG_DEFAULTS_HPP
#define C2POOL_IMPL_BCH_CATALOG_DEFAULTS_HPP

#include "core/settings_file.hpp"

namespace c2pool::impl::bch {

inline void register_catalog_defaults(c2pool::settings::ResolvedConfig& rc) {
    // FROM_POOL_CONFIG L0 defaults. Values mirror this coin's compiled
    // defaults; provenance in the trailing comments. The no-file golden gate
    // is byte-identical regardless of these (same code on baseline+candidate);
    // they make the resolved-config dump faithful for the bare-CLI vectors.
    using c2pool::settings::Source;
    rc.set("sharechain.listen", "0.0.0.0:9349", Source::CompiledDefault); // 9349 (bch/config_pool.hpp:64 PoolConfig::P2P_PORT)
    rc.set("web.port", "0", Source::CompiledDefault);                 // 0 (main_bch.cpp:714 http_port default, 0=off)
    rc.set("money.give_author_pct", "0.1", Source::CompiledDefault);  // 0.1% (main_bch.cpp dev_donation default = core::kAuthorFeeDefaultPct)
}

} // namespace c2pool::impl::bch

#endif // C2POOL_IMPL_BCH_CATALOG_DEFAULTS_HPP
