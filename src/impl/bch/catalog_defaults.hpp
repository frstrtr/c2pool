// src/impl/bch/catalog_defaults.hpp
//
// Per-impl L0 (compiled-default) registration for the settings catalog.
// FROM_POOL_CONFIG rows get their compiled value HERE, read from this coin's
// config_pool.hpp / config_coin.hpp constexprs -- so L0 is literally today's
// compiled values, never a hand transcription.
//
// M0 SCAFFOLDING: the hook and its call site are established; the concrete
// config_pool.hpp reads are filled in the mains-wiring change (which is the
// step that also compiles this against the coin's headers). Kept literal-free
// of config_pool here so it compiles without pulling coin headers into core.
#ifndef C2POOL_IMPL_BCH_CATALOG_DEFAULTS_HPP
#define C2POOL_IMPL_BCH_CATALOG_DEFAULTS_HPP

#include "core/settings_file.hpp"

namespace c2pool::impl::bch {

// Overlay this coin's FROM_POOL_CONFIG compiled defaults onto `rc` AFTER
// rc.seed_compiled_defaults(coin) and BEFORE the file overlay.
//
// WIRING TODO (mains change): set the FROM_POOL_CONFIG canon defaults from
// config_pool.hpp, e.g. for bch:
//   rc.set("sharechain.listen", host + ":" + std::to_string(SharechainConfig::P2P_PORT), Source::CompiledDefault);
//   rc.set("web.port", std::to_string(DEFAULT_WEB_PORT), Source::CompiledDefault);
//   rc.set("money.give_author_pct", std::to_string(DEFAULT_GIVE_AUTHOR_PCT), Source::CompiledDefault);
inline void register_catalog_defaults(c2pool::settings::ResolvedConfig& rc) {
    (void)rc;  // filled in the wiring change; see WIRING TODO above
}

} // namespace c2pool::impl::bch

#endif // C2POOL_IMPL_BCH_CATALOG_DEFAULTS_HPP
