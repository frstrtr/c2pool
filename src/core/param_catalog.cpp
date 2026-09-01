// src/core/param_catalog.cpp
//
// Materializes param_catalog.inc into the queryable table declared in
// param_catalog.hpp. Qt-free, boost-free.
#include "param_catalog.hpp"

#include <unordered_map>

namespace c2pool::catalog {

namespace {

// Map the .inc's bare token identifiers onto the typed enums via the X-macro.
// Section tokens: Meta, Global, Network, ... -> Sec::X
constexpr Sec sec_Meta        = Sec::Meta;
constexpr Sec sec_Gate        = Sec::Gate;
constexpr Sec sec_Global      = Sec::Global;
constexpr Sec sec_Network     = Sec::Network;
constexpr Sec sec_Sharechain  = Sec::Sharechain;
constexpr Sec sec_CoinP2P     = Sec::CoinP2P;
constexpr Sec sec_DaemonRpc   = Sec::DaemonRpc;
constexpr Sec sec_Stratum     = Sec::Stratum;
constexpr Sec sec_WebOps      = Sec::WebOps;
constexpr Sec sec_Money       = Sec::Money;
constexpr Sec sec_Embedded    = Sec::Embedded;
constexpr Sec sec_TxIngestion = Sec::TxIngestion;
constexpr Sec sec_Replay      = Sec::Replay;
constexpr Sec sec_Merged      = Sec::Merged;
constexpr Sec sec_CompileTime = Sec::CompileTime;

std::vector<ParamRow>& mutable_catalog() {
    static std::vector<ParamRow> rows;
    return rows;
}

// Helpers so the X-macro expansion reads naturally.
#define SEC(x)  sec_##x
#define PT(x)   PType::x
#define MT(x)   Mut::x
#define DK(x)   DefaultKind::x
#define VAL(x)  Validator::x
#define BN(x)   Bin::x
#define ST(x)   AliasStyle::x

void build() {
    auto& rows = mutable_catalog();
    if (!rows.empty()) return;

#define C2P_PARAM(canon, section, type, mut, applic, dkind, dlit, val, help) \
    rows.push_back(ParamRow{ canon, SEC(section), PT(type), MT(mut),        \
        static_cast<uint32_t>(applic), DK(dkind), dlit, VAL(val), help, {} });
#define C2P_ALIAS(canon, binary, spelling, style) \
    rows.back().aliases.push_back(Alias{ BN(binary), spelling, ST(style) });

#include "param_catalog.inc"

#undef C2P_PARAM
#undef C2P_ALIAS
}

#undef SEC
#undef PT
#undef MT
#undef DK
#undef VAL
#undef BN
#undef ST

} // namespace

const std::vector<ParamRow>& all_params() {
    build();
    return mutable_catalog();
}

const ParamRow* find_by_canon(const std::string& canon) {
    static const std::unordered_map<std::string, const ParamRow*> idx = [] {
        std::unordered_map<std::string, const ParamRow*> m;
        for (const auto& r : all_params()) m.emplace(r.canon, &r);
        return m;
    }();
    auto it = idx.find(canon);
    return it == idx.end() ? nullptr : it->second;
}

const ParamRow* find_by_alias(Bin binary, const std::string& spelling) {
    for (const auto& r : all_params())
        for (const auto& a : r.aliases)
            if (a.binary == binary && a.spelling == spelling) return &r;
    return nullptr;
}

std::vector<const ParamRow*> money_params() {
    std::vector<const ParamRow*> out;
    for (const auto& r : all_params())
        if (r.is_money()) out.push_back(&r);
    return out;
}

const char* section_name(Sec s) {
    switch (s) {
        case Sec::Meta: return "meta";
        case Sec::Gate: return "gate";
        case Sec::Global: return "global";
        case Sec::Network: return "network";
        case Sec::Sharechain: return "sharechain";
        case Sec::CoinP2P: return "coin_p2p";
        case Sec::DaemonRpc: return "daemon_rpc";
        case Sec::Stratum: return "stratum";
        case Sec::WebOps: return "web";
        case Sec::Money: return "money";
        case Sec::Embedded: return "embedded";
        case Sec::TxIngestion: return "tx_ingestion";
        case Sec::Replay: return "replay";
        case Sec::Merged: return "merged";
        case Sec::CompileTime: return "readonly";
    }
    return "?";
}

const char* ptype_name(PType t) {
    switch (t) {
        case PType::BOOL: return "bool";
        case PType::TRISTATE_BOOL: return "tristate_bool";
        case PType::INT64: return "int64";
        case PType::UINT16: return "uint16";
        case PType::DBL: return "double";
        case PType::STRING: return "string";
        case PType::PATH: return "path";
        case PType::HOSTPORT: return "hostport";
        case PType::ENUM_STR: return "enum";
        case PType::HEX: return "hex";
        case PType::LIST_HOSTPORT: return "list<hostport>";
        case PType::PAIR_PATH_HEX: return "pair<path,hex>";
        case PType::MERGED_SPEC: return "merged_spec";
    }
    return "?";
}

const char* mut_name(Mut m) {
    switch (m) {
        case Mut::LIVE: return "live";
        case Mut::RESTART: return "restart";
        case Mut::MONEY_LIVE: return "money_live";
        case Mut::MONEY_RESTART: return "money_restart";
        case Mut::COMPILE_TIME_READONLY: return "compile_time_readonly";
    }
    return "?";
}

const char* bin_name(Bin b) {
    switch (b) {
        case Bin::BIN_DASH: return "dash";
        case Bin::BIN_LTC: return "ltc";
        case Bin::BIN_BTC: return "btc";
        case Bin::BIN_DGB: return "dgb";
        case Bin::BIN_BCH: return "bch";
    }
    return "?";
}

} // namespace c2pool::catalog
