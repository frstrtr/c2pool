// src/impl/dash/catalog_defaults.hpp
//
// Per-impl L0 (compiled-default) registration for the settings catalog.
// FROM_POOL_CONFIG rows get their compiled value HERE so L0 equals this coin's
// compiled defaults. Overlaid AFTER rc.seed_compiled_defaults(coin) and BEFORE
// the file overlay (see the mains' M0b wiring block).
#ifndef C2POOL_IMPL_DASH_CATALOG_DEFAULTS_HPP
#define C2POOL_IMPL_DASH_CATALOG_DEFAULTS_HPP

#include "core/settings_file.hpp"

namespace c2pool::impl::dash {

inline void register_catalog_defaults(c2pool::settings::ResolvedConfig& rc) {
    // FROM_POOL_CONFIG L0 defaults. Values mirror this coin's compiled
    // defaults; provenance in the trailing comments. The no-file golden gate
    // is byte-identical regardless of these (same code on baseline+candidate);
    // they make the resolved-config dump faithful for the bare-CLI vectors.
    using c2pool::settings::Source;
    rc.set("sharechain.listen", "0.0.0.0:8999", Source::CompiledDefault); // 8999 (dash/config_pool.hpp:34 SharechainConfig::P2P_PORT)
    rc.set("web.port", "8080", Source::CompiledDefault);                 // 8080 (main_dash.cpp:10572 web_port default)
    rc.set("money.give_author_pct", "0.1", Source::CompiledDefault);      // 0.1 (main_dash.cpp:10565 dev_donation default)
}

} // namespace c2pool::impl::dash

#endif // C2POOL_IMPL_DASH_CATALOG_DEFAULTS_HPP
