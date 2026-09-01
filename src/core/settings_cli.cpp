// src/core/settings_cli.cpp
//
// Implementation of the shared CLI <-> settings-file wiring. Qt-free, boost-free.
#include "settings_cli.hpp"

#include <filesystem>
#include <iostream>
#include <string>

#include "filesystem.hpp"

namespace c2pool::settings {

using c2pool::catalog::AliasStyle;
using c2pool::catalog::Bin;
using c2pool::catalog::CoinBit;
using c2pool::catalog::ParamRow;
using c2pool::catalog::PType;

CoinBit coin_of_bin(Bin bin) {
    switch (bin) {
        case Bin::BIN_DASH: return c2pool::catalog::C_DASH;
        case Bin::BIN_LTC:  return c2pool::catalog::C_LTC;
        case Bin::BIN_BTC:  return c2pool::catalog::C_BTC;
        case Bin::BIN_DGB:  return c2pool::catalog::C_DGB;
        case Bin::BIN_BCH:  return c2pool::catalog::C_BCH;
    }
    return c2pool::catalog::C_DASH;
}

namespace {

// How many following tokens an alias style consumes as its value, given the
// row's declared type. SHORT is overloaded across the mains (-h is a flag, but
// -w/-n/-f take a value), so it is resolved by the row's type.
int value_tokens(const ParamRow& row, AliasStyle style) {
    switch (style) {
        case AliasStyle::VALUE:
        case AliasStyle::VALUE_HOSTPORT_COMBINED:
            return 1;
        case AliasStyle::TWO_ARGS:
            return 2;
        case AliasStyle::SHORT:
            return (row.type == PType::BOOL || row.type == PType::TRISTATE_BOOL)
                       ? 0 : 1;
        case AliasStyle::FLAG:
        case AliasStyle::FLAG_OPT_EQFALSE:
        case AliasStyle::FLAG_NO_PREFIX:
        default:
            return 0;
    }
}

// Mirror a recognised CLI hit into rc with Source::Cli. Compile-time-readonly
// rows (meta.settings_path, meta.dump_resolved_config, --version/--help, ...)
// are tracked but never written into rc: they are not resolved config and would
// otherwise make the dump vary by path/invocation.
void set_cli_value(ResolvedConfig& rc, const ParamRow& row, AliasStyle style,
                   const std::string& first_value, bool eqfalse) {
    if (row.is_compile_readonly()) return;

    if (row.type == PType::TRISTATE_BOOL) {
        TriBool t = TriBool::True;
        if (style == AliasStyle::FLAG_NO_PREFIX) t = TriBool::False;
        else if (style == AliasStyle::FLAG_OPT_EQFALSE) t = eqfalse ? TriBool::False : TriBool::True;
        rc.set_tri(row.canon, t, Source::Cli);
        return;
    }
    int n = value_tokens(row, style);
    if (n >= 1) {
        rc.set(row.canon, first_value, Source::Cli);
    } else if (row.type == PType::BOOL) {
        rc.set(row.canon, "true", Source::Cli);
    }
    // Other value-less styles on non-bool rows (e.g. the LTC --debug family that
    // aliases the log_level enum): mark only (done by the caller), leave L0.
}

} // namespace

void scan_cli(int argc, char** argv, Bin bin, CliTracker& tracker,
              ResolvedConfig& rc) {
    for (int i = 1; i < argc; ++i) {
        std::string tok = argv[i];
        if (tok.empty() || tok[0] != '-') continue;  // positional; not the scanner's job

        // FLAG_OPT_EQFALSE forms carry the value inline: --flag=false / --flag=true.
        std::string base = tok;
        std::string optval;
        bool has_eq = false;
        auto eq = tok.find('=');
        if (eq != std::string::npos) {
            base = tok.substr(0, eq);
            optval = tok.substr(eq + 1);
            has_eq = true;
        }

        const ParamRow* row = c2pool::catalog::find_by_alias(bin, base);
        if (!row) continue;  // unknown to the catalog -> real loop rejects it

        // Find the matching alias style for this binary+spelling.
        AliasStyle style = AliasStyle::FLAG;
        for (const auto& a : row->aliases) {
            if (a.binary == bin && a.spelling == base) { style = a.style; break; }
        }

        tracker.mark(row->canon);

        // Capture the value token(s).
        std::string first_value;
        int n = value_tokens(*row, style);
        for (int k = 0; k < n && i + 1 < argc; ++k) {
            ++i;
            if (k == 0) first_value = argv[i];
        }
        bool eqfalse = has_eq && (optval == "false" || optval == "0" || optval == "off");
        set_cli_value(rc, *row, style, first_value, eqfalse);
    }
}

std::string resolve_settings_path(const std::string& explicit_path,
                                  bool& fatal, std::string& err) {
    fatal = false;
    err.clear();
    if (!explicit_path.empty()) {
        std::error_code ec;
        if (!std::filesystem::exists(explicit_path, ec) ||
            std::filesystem::is_directory(explicit_path, ec)) {
            fatal = true;
            err = "settings: --settings path does not exist: " + explicit_path;
            return std::string();
        }
        return explicit_path;
    }
    std::error_code ec;
    std::filesystem::path def = core::filesystem::config_path() / "c2pool.toml";
    if (std::filesystem::exists(def, ec) && !std::filesystem::is_directory(def, ec))
        return def.string();
    return std::string();  // absent -> today's pure compiled + CLI path
}

int wire_settings(const std::string& path, CoinBit coin,
                  const CliTracker& tracker, ResolvedConfig& rc) {
    LoadResult res = SettingsFile::load(path, coin, tracker, rc);
    if (res.status == LoadStatus::RefusedMoney ||
        res.status == LoadStatus::ParseError) {
        for (const auto& m : res.messages) std::cerr << m << "\n";
        return res.exit_code ? res.exit_code : 78;
    }
    // res.status is Ok (file applied, non-CLI keys only) or AbsentOk (no file):
    // in both cases the captured CLI values (already set with Source::Cli by
    // scan_cli) are the winning L2 layer and remain in rc untouched -- the loader
    // never overlays a key the tracker holds. Nothing more to do here.
    (void)res;
    return 0;
}

void dump_resolved(const ResolvedConfig& rc) {
    std::cout << kDumpBegin << "\n";
    std::cout << rc.dump();
    std::cout << kDumpEnd << "\n";
}

} // namespace c2pool::settings
