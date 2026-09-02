// src/impl/bip110/catalog_defaults.hpp
//
// Per-impl L0 (compiled-default) registration for the settings catalog.
// FROM_POOL_CONFIG rows get their compiled value HERE so L0 equals this coin's
// compiled defaults. Overlaid AFTER rc.seed_compiled_defaults(coin) and BEFORE
// the file overlay (see the mains' M0b wiring block). Mirrors
// src/impl/dash/catalog_defaults.hpp.
#ifndef C2POOL_IMPL_BIP110_CATALOG_DEFAULTS_HPP
#define C2POOL_IMPL_BIP110_CATALOG_DEFAULTS_HPP

#include "core/settings_file.hpp"

namespace c2pool::impl::bip110 {

inline void register_catalog_defaults(c2pool::settings::ResolvedConfig& rc) {
    // FROM_POOL_CONFIG L0 defaults. Values mirror this coin's compiled defaults;
    // provenance in the trailing comments. money.node_owner_fee_pct is a LIT "0"
    // catalog row (seeded by seed_compiled_defaults), so only the author/dev
    // donation percent needs its FROM_POOL_CONFIG L0 filled here.
    using c2pool::settings::Source;
    rc.set("money.give_author_pct", "0.1", Source::CompiledDefault); // 0.1% author/dev donation (main_bip110 give_author_pct default; HARD RULE author-fee default=0.1%)
}

} // namespace c2pool::impl::bip110

#endif // C2POOL_IMPL_BIP110_CATALOG_DEFAULTS_HPP
