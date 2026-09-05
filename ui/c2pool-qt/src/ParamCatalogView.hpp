// SPDX-License-Identifier: AGPL-3.0-or-later
// ParamCatalogView — Qt-free, header-only view over the node's canonical
// parameter catalog (src/core/param_catalog.inc), consumed by LaunchCommand so
// the per-coin argv the panel generates is DRIVEN by the same X-macro catalog
// the node's mains are checked against (ci/check_param_catalog.py). No flag
// spelling is retyped in the Qt tree: a flag is emitted for a binary ONLY when
// the catalog carries an alias row for that (binary, canonical) pair, which is
// exactly what stops the panel emitting a flag the target binary rejects
// (e.g. --addnode where DGB/BCH want --sharechain-addnode, or the money flags
// on BCH which has none). See LaunchCommand.hpp.
//
// The catalog's typed enums live in <core/param_catalog.hpp> (Qt-free,
// boost-free). This header re-materialises the .inc with local X-macros into a
// std-only static table so the reward-safe-launch unit test links WITHOUT
// compiling param_catalog.cpp — the .inc is the single source and the Qt build
// stays standalone.

#pragma once

#include <core/param_catalog.hpp>   // c2pool::catalog enums (Bin, CoinBit, Mut, …)

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace c2pool_qt {
namespace catview {

using c2pool::catalog::Bin;
using c2pool::catalog::CoinBit;
using c2pool::catalog::Mut;
using c2pool::catalog::AliasStyle;

struct AliasView {
    Bin         binary;
    std::string spelling;
    AliasStyle  style;
};

struct RowView {
    std::string            canon;
    Mut                    mutability;
    uint32_t               applic_mask;
    std::vector<AliasView> aliases;

    bool is_money() const {
        return mutability == Mut::MONEY_LIVE || mutability == Mut::MONEY_RESTART;
    }
    bool applies_to(CoinBit c) const { return (applic_mask & c) != 0; }
};

inline const std::vector<RowView>& rows()
{
    static const std::vector<RowView> table = [] {
        using namespace c2pool::catalog;   // Sec::*, PType::*, Mut::*, CoinBit, Bin::*, AliasStyle::*
        std::vector<RowView> rows;

#define C2P_PARAM(canon, section, type, mut, applic, dkind, dlit, val, help) \
        rows.push_back(RowView{ canon, Mut::mut,                             \
            static_cast<uint32_t>(applic), {} });
#define C2P_ALIAS(canon, binary, spelling, style) \
        rows.back().aliases.push_back(AliasView{ Bin::binary, spelling, AliasStyle::style });

#include <core/param_catalog.inc>

#undef C2P_PARAM
#undef C2P_ALIAS
        return rows;
    }();
    return table;
}

inline const RowView* find(const std::string& canon)
{
    for (const auto& r : rows())
        if (r.canon == canon) return &r;
    return nullptr;
}

/// The CLI spelling (and style) a given binary uses for a canonical param, or
/// nullopt when that binary has no alias for it — the caller then emits nothing.
inline std::optional<std::pair<std::string, AliasStyle>>
spelling_for(Bin binary, const std::string& canon)
{
    const RowView* r = find(canon);
    if (!r) return std::nullopt;
    for (const auto& a : r->aliases)
        if (a.binary == binary) return std::make_pair(a.spelling, a.style);
    return std::nullopt;
}

/// True when the canonical param applies to the given coin bit (catalog mask).
inline bool applies(const std::string& canon, CoinBit c)
{
    const RowView* r = find(canon);
    return r && r->applies_to(c);
}

/// True when the canonical param is money-class (MONEY_LIVE / MONEY_RESTART).
inline bool is_money(const std::string& canon)
{
    const RowView* r = find(canon);
    return r && r->is_money();
}

} // namespace catview
} // namespace c2pool_qt
