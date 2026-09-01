// src/impl/btc/catalog_defaults.hpp
//
// Per-impl L0 (compiled-default) registration for the settings catalog.
// FROM_POOL_CONFIG rows get their compiled value HERE so L0 equals this coin's
// compiled defaults. Overlaid AFTER rc.seed_compiled_defaults(coin) and BEFORE
// the file overlay (see the mains' M0b wiring block).
#ifndef C2POOL_IMPL_BTC_CATALOG_DEFAULTS_HPP
#define C2POOL_IMPL_BTC_CATALOG_DEFAULTS_HPP

#include "core/settings_file.hpp"

namespace c2pool::impl::btc {

inline void register_catalog_defaults(c2pool::settings::ResolvedConfig& rc) {
    // FROM_POOL_CONFIG L0 defaults. Values mirror this coin's compiled
    // defaults; provenance in the trailing comments. The no-file golden gate
    // is byte-identical regardless of these (same code on baseline+candidate);
    // they make the resolved-config dump faithful for the bare-CLI vectors.
    using c2pool::settings::Source;
    rc.set("sharechain.listen", "0.0.0.0:9333", Source::CompiledDefault); // 9333 (btc/config_pool.hpp:40 PoolConfig::P2P_PORT)
    rc.set("web.port", "0", Source::CompiledDefault);                 // 0 (main_btc.cpp:206 http_port default, 0=off)
    rc.set("money.give_author_pct", "0", Source::CompiledDefault);      // 0 (main_btc.cpp:220 dev_donation default 0.0)
}

} // namespace c2pool::impl::btc

#endif // C2POOL_IMPL_BTC_CATALOG_DEFAULTS_HPP
