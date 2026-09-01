// src/c2pool/test_reward_safe_file.cpp
//
// Qt-free KAT proving a settings FILE can never arm money-class keys without a
// matching [gate].money_ack_hash, plus tri-state and precedence semantics.
// Sibling of the qt test_reward_safe_launch (which stays verbatim).
#include "../core/settings_file.hpp"
#include "../core/param_catalog.hpp"

#include <cassert>
#include <cstdio>
#include <fstream>
#include <string>

using namespace c2pool::settings;
using c2pool::catalog::C_DASH;

static std::string tmp_write(const std::string& name, const std::string& body) {
    std::string path = "/tmp/" + name;
    std::ofstream(path) << body;
    return path;
}

static LoadResult load(const std::string& path, const CliTracker& cli, ResolvedConfig& rc) {
    rc.seed_compiled_defaults(C_DASH);
    return SettingsFile::load(path, C_DASH, cli, rc);
}

int main() {
    int failures = 0;
    auto check = [&](bool cond, const char* what) {
        if (!cond) { printf("FAIL: %s\n", what); ++failures; }
        else printf("ok:   %s\n", what);
    };

    // (a) money key (fee) with NO hash -> REFUSED, node must exit
    {
        std::string p = tmp_write("m0_a.toml",
            "[dash]\n[dash.money]\nnode_owner_fee_pct = 5.0\n");
        CliTracker cli; ResolvedConfig rc;
        auto r = load(p, cli, rc);
        check(r.status == LoadStatus::RefusedMoney, "(a) fee without ack -> RefusedMoney");
        check(r.exit_code == 78, "(a) refusal exits EX_CONFIG(78)");
        check(!rc.has("money.node_owner_fee_pct"), "(a) fee value NOT applied");
    }

    // (b) same fee WITH correct hash -> applied, source=file
    {
        std::string body = "[dash]\n[dash.money]\nnode_owner_fee_pct = 5.0\n";
        std::string p = tmp_write("m0_b0.toml", body);
        std::string h = SettingsFile::compute_money_ack_hash(p, C_DASH);
        std::string p2 = tmp_write("m0_b.toml",
            "[gate]\nmoney_ack_hash = \"" + h + "\"\n" + body);
        CliTracker cli; ResolvedConfig rc;
        auto r = load(p2, cli, rc);
        check(r.status == LoadStatus::Ok, "(b) fee WITH ack -> Ok");
        check(rc.file_set("money.node_owner_fee_pct"), "(b) fee applied source=file");
        check(rc.get_double("money.node_owner_fee_pct").value_or(-1) == 5.0, "(b) fee value == 5.0");
    }

    // (c) correct hash then a money value edited -> stale hash -> REFUSED
    {
        std::string body0 = "[dash]\n[dash.money]\nnode_owner_fee_pct = 5.0\n";
        std::string p0 = tmp_write("m0_c0.toml", body0);
        std::string h = SettingsFile::compute_money_ack_hash(p0, C_DASH);
        std::string p = tmp_write("m0_c.toml",
            "[gate]\nmoney_ack_hash = \"" + h + "\"\n"
            "[dash]\n[dash.money]\nnode_owner_fee_pct = 9.0\n");  // edited value, stale hash
        CliTracker cli; ResolvedConfig rc;
        auto r = load(p, cli, rc);
        check(r.status == LoadStatus::RefusedMoney, "(c) edited money value invalidates ack -> Refused");
    }

    // (d) embedded.mainnet = true unacked -> REFUSED (network-identity money class)
    {
        std::string p = tmp_write("m0_d.toml",
            "[dash]\n[dash.embedded]\nmainnet = true\n");
        CliTracker cli; ResolvedConfig rc;
        auto r = load(p, cli, rc);
        check(r.status == LoadStatus::RefusedMoney, "(d) embedded.mainnet unacked -> Refused");
    }

    // (e) network.testnet = true unacked -> REFUSED
    {
        std::string p = tmp_write("m0_e.toml",
            "[dash]\n[dash.network]\ntestnet = true\n");
        CliTracker cli; ResolvedConfig rc;
        auto r = load(p, cli, rc);
        check(r.status == LoadStatus::RefusedMoney, "(e) network.testnet unacked -> Refused");
    }

    // (f) tri-state: absent lever stays Unset (not covered by hash); explicit
    //     tx_serve_own_set=false IS money-class -> REFUSED unacked.
    {
        // absent lever, non-money file -> Ok, lever Unset
        std::string p1 = tmp_write("m0_f1.toml",
            "[dash]\n[dash.embedded]\nserve_mempool_txs = false\n");  // serve_mempool is NOT money
        CliTracker cli1; ResolvedConfig rc1;
        auto r1 = load(p1, cli1, rc1);
        check(r1.status == LoadStatus::Ok, "(f) non-money tristate loads without ack");
        check(rc1.get_tri("embedded.serve_mempool_txs") == TriBool::False, "(f) explicit false -> TriBool::False");
        check(rc1.get_tri("embedded.null_arm") == TriBool::Unset, "(f) untouched lever stays Unset");

        // referee-disarm is money-class -> refused unacked
        std::string p2 = tmp_write("m0_f2.toml",
            "[dash]\n[dash.embedded]\ntx_serve_own_set = false\n");
        CliTracker cli2; ResolvedConfig rc2;
        auto r2 = load(p2, cli2, rc2);
        check(r2.status == LoadStatus::RefusedMoney, "(f) tx_serve_own_set=false unacked -> Refused");
    }

    // (g) non-money file loads with no hash at all
    {
        std::string p = tmp_write("m0_g.toml",
            "[dash]\n[dash.sharechain]\nlisten = \"0.0.0.0:8999\"\n"
            "[dash.stratum]\nmin_diff = 0.0005\n");
        CliTracker cli; ResolvedConfig rc;
        auto r = load(p, cli, rc);
        check(r.status == LoadStatus::Ok, "(g) non-money file loads with no hash");
        check(rc.file_set("sharechain.listen"), "(g) listen applied source=file");
    }

    // (h) precedence: CLI-explicit key is NOT overwritten by the file
    {
        std::string p = tmp_write("m0_h.toml",
            "[dash]\n[dash.sharechain]\nlisten = \"0.0.0.0:9999\"\n");
        CliTracker cli; cli.mark("sharechain.listen");
        ResolvedConfig rc;
        rc.seed_compiled_defaults(C_DASH);
        rc.set("sharechain.listen", "0.0.0.0:1234", Source::Cli);  // CLI set it first
        auto r = SettingsFile::load(p, C_DASH, cli, rc);
        check(r.status == LoadStatus::Ok, "(h) file loads");
        check(rc.get_string("sharechain.listen").value_or("") == "0.0.0.0:1234",
              "(h) CLI value wins over file (cli_explicit generalization)");
        check(rc.source_of("sharechain.listen") == Source::Cli, "(h) source stays cli");
    }

    // (i) unknown own-section key -> ParseError (unknown-flag/typo cannot hide)
    {
        std::string p = tmp_write("m0_i.toml",
            "[dash]\n[dash.sharechain]\nlissten = \"x\"\n");  // typo
        CliTracker cli; ResolvedConfig rc;
        auto r = load(p, cli, rc);
        check(r.status == LoadStatus::ParseError, "(i) unknown own-section key -> ParseError");
    }

    if (failures == 0) { printf("\ntest_reward_safe_file: ALL PASS\n"); return 0; }
    printf("\ntest_reward_safe_file: %d FAILURE(S)\n", failures);
    return 1;
}
