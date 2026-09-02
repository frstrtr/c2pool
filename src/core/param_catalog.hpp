// src/core/param_catalog.hpp
//
// Qt-free, boost-free declarative catalog of every canonical node parameter and
// its per-binary CLI spellings. The data lives in param_catalog.inc (X-macro);
// this header exposes the enums and a queryable in-memory table built from it.
//
// Single source of truth consumed (M0) by the settings-file loader and the
// money-gate; later milestones add the runtime endpoint schema and qt forms.
#ifndef C2POOL_CORE_PARAM_CATALOG_HPP
#define C2POOL_CORE_PARAM_CATALOG_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace c2pool::catalog {

// ---- Coin applicability bitmask (mirrors the coin registry symbols) ---------
// DOGE/NMC are aux lanes carried inside the LTC/BTC binaries; their file keys
// live under [ltc.doge] / [btc.nmc].
enum CoinBit : uint32_t {
    C_LTC  = 1u << 0,
    C_BTC  = 1u << 1,
    C_DOGE = 1u << 2,
    C_DASH = 1u << 3,
    C_DGB  = 1u << 4,
    C_BCH  = 1u << 5,
    C_NMC  = 1u << 6,
    C_BIP110 = 1u << 7,
    C_ALL  = C_LTC | C_BTC | C_DOGE | C_DASH | C_DGB | C_BCH | C_NMC | C_BIP110,
};

enum class Sec {
    Meta, Gate, Global, Network, Sharechain, CoinP2P, DaemonRpc, Stratum,
    WebOps, Money, Embedded, TxIngestion, Replay, Merged, CompileTime,
};

enum class PType {
    BOOL, TRISTATE_BOOL, INT64, UINT16, DBL, STRING, PATH, HOSTPORT,
    ENUM_STR, HEX, LIST_HOSTPORT, PAIR_PATH_HEX, MERGED_SPEC,
};

// Mutability class. The MONEY_* rows are the SINGLE definition of the
// money-gate key set: the gate never keeps its own list.
enum class Mut {
    LIVE, RESTART, MONEY_LIVE, MONEY_RESTART, COMPILE_TIME_READONLY,
};

enum class DefaultKind { LIT, FROM_POOL_CONFIG, NONE };

enum class Validator {
    NONE, PORT_RANGE, PCT_0_100, HEX_EVEN, HEX8_MAGIC, HASH256, ADDR_COIN,
    HOSTPORT_V, PAIR_REQUIRED, ENUM_MEMBER, MIN_101_CONF,
};

enum class Bin { BIN_DASH, BIN_LTC, BIN_BTC, BIN_DGB, BIN_BCH, BIN_BIP110 };

enum class AliasStyle {
    VALUE, FLAG, FLAG_OPT_EQFALSE, FLAG_NO_PREFIX, VALUE_HOSTPORT_COMBINED,
    TWO_ARGS, SHORT,
};

struct Alias {
    Bin         binary;
    std::string spelling;
    AliasStyle  style;
};

struct ParamRow {
    std::string        canon;
    Sec                section;
    PType              type;
    Mut                mutability;
    uint32_t           applic_mask;
    DefaultKind        default_kind;
    std::string        default_literal;
    Validator          validator;
    std::string        help;
    std::vector<Alias> aliases;

    bool is_money() const {
        return mutability == Mut::MONEY_LIVE || mutability == Mut::MONEY_RESTART;
    }
    bool is_compile_readonly() const {
        return mutability == Mut::COMPILE_TIME_READONLY;
    }
    bool applies_to(CoinBit c) const { return (applic_mask & c) != 0; }
};

// The full catalog, materialized once (const). Order matches the .inc.
const std::vector<ParamRow>& all_params();

// Lookups. Return nullptr when absent.
const ParamRow* find_by_canon(const std::string& canon);
// Resolve a CLI spelling for a given binary back to its canonical row.
const ParamRow* find_by_alias(Bin binary, const std::string& spelling);

// Convenience: the money-class key set derived from Mut (never duplicated).
std::vector<const ParamRow*> money_params();

const char* section_name(Sec s);
const char* ptype_name(PType t);
const char* mut_name(Mut m);
const char* bin_name(Bin b);

} // namespace c2pool::catalog

#endif // C2POOL_CORE_PARAM_CATALOG_HPP
