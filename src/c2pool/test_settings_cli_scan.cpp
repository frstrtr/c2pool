// src/c2pool/test_settings_cli_scan.cpp
//
// Mechanical coverage for the catalog-driven CLI scanner (M0b). The highest-
// consequence risk in the wiring is scan_cli UNDER-MARKING a flag: a missed CLI
// key would let a settings-file value override the command line (precedence
// inversion on a live config). This test iterates EVERY catalog alias of every
// binary, synthesizes an argv per its alias style, and asserts scan_cli marks
// exactly that canonical key -- so full alias coverage == full flag coverage
// (the bidirectional tripwire guarantees alias-set == accepted-flag-set).
//
// It also pins the value-capture and tri-state mapping used by the resolved dump.
// Qt-free, boost-free; links only core/settings_cli + settings_file + param_catalog.
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "core/param_catalog.hpp"
#include "core/settings_cli.hpp"
#include "core/settings_file.hpp"

using namespace c2pool::catalog;
using namespace c2pool::settings;

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) { std::cout << "ok:   " << msg << "\n"; } \
    else { std::cout << "FAIL: " << msg << "\n"; ++g_fail; } } while (0)

// Synthesize a representative argv for one alias and assert its canon is marked.
static void cover_alias(Bin bin, const Alias& a, const std::string& canon,
                        const ParamRow& row) {
    std::string tok = a.spelling;
    std::vector<std::string> toks;
    switch (a.style) {
        case AliasStyle::VALUE:
        case AliasStyle::VALUE_HOSTPORT_COMBINED:
            toks = {tok, "X"}; break;
        case AliasStyle::TWO_ARGS:
            toks = {tok, "A", "B"}; break;
        case AliasStyle::SHORT:
            if (row.type == PType::BOOL || row.type == PType::TRISTATE_BOOL) toks = {tok};
            else toks = {tok, "X"};
            break;
        case AliasStyle::FLAG:
        case AliasStyle::FLAG_NO_PREFIX:
            toks = {tok}; break;
        case AliasStyle::FLAG_OPT_EQFALSE:
            toks = {tok}; break;  // bare form => True
    }
    std::vector<std::string> store; store.push_back("prog");
    for (auto& t : toks) store.push_back(t);
    std::vector<char*> ptrs; for (auto& s : store) ptrs.push_back(const_cast<char*>(s.c_str()));

    CliTracker tr; ResolvedConfig rc; rc.seed_compiled_defaults(coin_of_bin(bin));
    scan_cli(static_cast<int>(ptrs.size()), ptrs.data(), bin, tr, rc);
    CHECK(tr.has(canon), std::string(bin_name(bin)) + " " + tok + " -> marks " + canon);
}

int main() {
    // (1) EXHAUSTIVE alias coverage: every catalog alias of every binary is
    //     recognised by scan_cli and marks its canonical key.
    const Bin bins[] = {Bin::BIN_DASH, Bin::BIN_LTC, Bin::BIN_BTC, Bin::BIN_DGB, Bin::BIN_BCH};
    int alias_count = 0;
    for (Bin b : bins) {
        for (const auto& row : all_params()) {
            for (const auto& a : row.aliases) {
                if (a.binary != b) continue;
                ++alias_count;
                cover_alias(b, a, row.canon, row);
            }
        }
    }
    std::cout << "-- covered " << alias_count << " aliases across 5 binaries\n";

    // (2) VALUE capture: a VALUE flag mirrors its token with Source::Cli.
    {
        std::vector<std::string> s = {"prog", "--web-port", "9099"};
        std::vector<char*> p; for (auto& x : s) p.push_back(const_cast<char*>(x.c_str()));
        CliTracker tr; ResolvedConfig rc; rc.seed_compiled_defaults(C_DASH);
        scan_cli((int)p.size(), p.data(), Bin::BIN_DASH, tr, rc);
        CHECK(rc.get_string("web.port").value_or("") == "9099", "dash --web-port 9099 -> web.port=9099");
        CHECK(rc.source_of("web.port") == Source::Cli, "dash --web-port source=cli");
    }

    // (3) TRI-STATE mapping: FLAG_OPT_EQFALSE bare => True, =false => False.
    {
        std::vector<std::string> s = {"prog", "--embedded-serve-mempool-txs=false"};
        std::vector<char*> p; for (auto& x : s) p.push_back(const_cast<char*>(x.c_str()));
        CliTracker tr; ResolvedConfig rc; rc.seed_compiled_defaults(C_DASH);
        scan_cli((int)p.size(), p.data(), Bin::BIN_DASH, tr, rc);
        CHECK(rc.get_tri("embedded.serve_mempool_txs") == TriBool::False,
              "dash --embedded-serve-mempool-txs=false -> TriBool::False");
    }
    {
        std::vector<std::string> s = {"prog", "--embedded-serve-mempool-txs"};
        std::vector<char*> p; for (auto& x : s) p.push_back(const_cast<char*>(x.c_str()));
        CliTracker tr; ResolvedConfig rc; rc.seed_compiled_defaults(C_DASH);
        scan_cli((int)p.size(), p.data(), Bin::BIN_DASH, tr, rc);
        CHECK(rc.get_tri("embedded.serve_mempool_txs") == TriBool::True,
              "dash --embedded-serve-mempool-txs (bare) -> TriBool::True");
    }

    // (4) FLAG_NO_PREFIX maps to False on its row (the --no-* forms).
    {
        std::vector<std::string> s = {"prog", "--no-embedded-doge"};
        std::vector<char*> p; for (auto& x : s) p.push_back(const_cast<char*>(x.c_str()));
        CliTracker tr; ResolvedConfig rc; rc.seed_compiled_defaults(C_LTC);
        scan_cli((int)p.size(), p.data(), Bin::BIN_LTC, tr, rc);
        CHECK(rc.get_tri("embedded.doge_enabled") == TriBool::False,
              "ltc --no-embedded-doge -> embedded.doge_enabled=False");
    }

    // (5) COMPILE_TIME_READONLY (meta.settings_path) is marked but never mirrored
    //     into rc (so the dump cannot vary by path).
    {
        std::vector<std::string> s = {"prog", "--settings", "/tmp/x.toml", "--web-port", "7"};
        std::vector<char*> p; for (auto& x : s) p.push_back(const_cast<char*>(x.c_str()));
        CliTracker tr; ResolvedConfig rc; rc.seed_compiled_defaults(C_DASH);
        scan_cli((int)p.size(), p.data(), Bin::BIN_DASH, tr, rc);
        CHECK(!rc.has("meta.settings_path"), "dash --settings PATH not mirrored into rc");
        CHECK(rc.get_string("web.port").value_or("") == "7",
              "dash --settings PATH consumes its value token (web-port still parsed)");
    }

    // (6) TWO_ARGS consumes two tokens (--dump-mn-checkpoint H FILE) without
    //     leaking the FILE token as a stray positional/flag.
    {
        std::vector<std::string> s = {"prog", "--dump-mn-checkpoint", "1000", "out.bin", "--run"};
        std::vector<char*> p; for (auto& x : s) p.push_back(const_cast<char*>(x.c_str()));
        CliTracker tr; ResolvedConfig rc; rc.seed_compiled_defaults(C_DASH);
        scan_cli((int)p.size(), p.data(), Bin::BIN_DASH, tr, rc);
        CHECK(tr.has("utility.dump_mn_checkpoint"), "dash --dump-mn-checkpoint marks canon");
        CHECK(tr.has("meta.run"), "dash --run after TWO_ARGS still recognised (H FILE consumed)");
    }

    if (g_fail == 0) std::cout << "\ntest_settings_cli_scan: ALL PASS\n";
    else std::cout << "\ntest_settings_cli_scan: " << g_fail << " FAILURE(S)\n";
    return g_fail == 0 ? 0 : 1;
}
