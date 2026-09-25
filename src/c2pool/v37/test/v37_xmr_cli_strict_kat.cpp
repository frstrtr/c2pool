// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_cli_strict_kat -- CLI-STRICT: c2pool-v37-xmr's command line.
//
// The REPRO-BUILD verify (09-25) found that the daemon IGNORED an unknown
// flag: `c2pool-v37-xmr --version` started live stagenet mode against
// 127.0.0.1:38081 and created ~/.c2pool/stagenet/v37_settle_db. A typo in any
// flag therefore started a node on defaults. This KAT runs the BUILT BINARY
// (argv[1]) as a child with a scratch HOME and a scratch cwd and pins:
//
//   B  every bad invocation (unknown flag, typo of a real flag, a positional
//      token, a missing value, a malformed number / enum) exits 2 with ONE
//      output line naming the offending token and pointing at --help, and
//      leaves the scratch HOME empty (nothing created);
//   V  --version and -V exit 0 in < 1 s, print the name, a version, the
//      network default and both pinned snapshot heights, create nothing;
//   H  --help exits 0 and lists --version;
//   C  every flag the daemon accepts (and every flag the repo's rig scripts
//      and docs pass it) still parses: `<flag> [value] --version` exits 0
//      with the version line, which is only reached once the flag was taken.
//
// NETWORK SAFETY. Every invocation that a broken build could turn into a live
// run carries `--network regtest --rpc-host 127.0.0.1 --rpc-port 1 --zmq-port 1`
// first, so the worst case is a refused loopback connect to port 1 -- never a
// real network, never the default ports. The C rows (which include flags that
// dial peers or seed nodes) run only once H has shown this binary knows
// --version. Each child is killed after a bounded wait.
// ---------------------------------------------------------------------------

#include <poll.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "impl/xmr/native/anchor/xmr_anchor_pinned.hpp"

namespace fs = std::filesystem;

namespace {

int g_fail = 0;
int g_pass = 0;

void check(bool ok, const std::string& what) {
    if (ok) { ++g_pass; return; }
    ++g_fail;
    std::printf("FAIL: %s\n", what.c_str());
}

struct Run {
    int         rc = -1;          // exit status, or 128+signal
    bool        timed_out = false;
    std::string out;              // stdout + stderr, interleaved
    double      secs = 0;
    std::size_t files = 0;        // entries created under the scratch HOME/cwd
};

std::string g_bin;
std::string g_tmp_root;

const std::vector<std::string> kSafe = {
    "--network", "regtest", "--rpc-host", "127.0.0.1", "--rpc-port", "1", "--zmq-port", "1"};

std::vector<std::string> safe(std::vector<std::string> tail) {
    std::vector<std::string> v = kSafe;
    v.insert(v.end(), tail.begin(), tail.end());
    return v;
}

std::string join(const std::vector<std::string>& v) {
    std::string s;
    for (const auto& x : v) s += (s.empty() ? "" : " ") + (x.empty() ? std::string("''") : x);
    return s;
}

Run run(const std::vector<std::string>& args, int timeout_ms) {
    Run r;
    std::string tmpl = g_tmp_root + "/v37-cli-strict-kat.XXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    if (::mkdtemp(buf.data()) == nullptr) { r.out = "mkdtemp failed"; return r; }
    const std::string home = buf.data();

    int pfd[2];
    if (::pipe(pfd) != 0) { r.out = "pipe failed"; return r; }
    const auto t0 = std::chrono::steady_clock::now();
    const pid_t pid = ::fork();
    if (pid == 0) {
        ::setpgid(0, 0);
        ::dup2(pfd[1], 1);
        ::dup2(pfd[1], 2);
        ::close(pfd[0]);
        ::close(pfd[1]);
        if (::chdir(home.c_str()) != 0) ::_exit(126);
        ::setenv("HOME", home.c_str(), 1);
        ::unsetenv("XDG_DATA_HOME");
        std::vector<char*> av;
        av.push_back(const_cast<char*>(g_bin.c_str()));
        for (const auto& a : args) av.push_back(const_cast<char*>(a.c_str()));
        av.push_back(nullptr);
        ::execv(g_bin.c_str(), av.data());
        ::_exit(127);
    }
    ::close(pfd[1]);
    int status = 0;
    bool exited = false, eof = false;
    for (;;) {
        const auto el = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t0).count();
        if (el >= timeout_ms) break;
        if (!eof) {
            struct pollfd p{pfd[0], POLLIN, 0};
            if (::poll(&p, 1, 20) > 0) {
                char b[4096];
                const ssize_t n = ::read(pfd[0], b, sizeof b);
                if (n > 0) { if (r.out.size() < (1u << 20)) r.out.append(b, static_cast<std::size_t>(n)); }
                else eof = true;
            }
        } else {
            ::usleep(5000);
        }
        if (!exited && ::waitpid(pid, &status, WNOHANG) == pid) exited = true;
        if (exited && eof) break;
    }
    if (!exited) {
        r.timed_out = true;
        ::kill(-pid, SIGKILL);
        ::kill(pid, SIGKILL);
        ::waitpid(pid, &status, 0);
    }
    ::close(pfd[0]);
    r.secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    r.rc = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(home, ec); !ec && it != fs::recursive_directory_iterator(); it.increment(ec))
        ++r.files;
    fs::remove_all(home, ec);
    return r;
}

std::size_t line_count(const std::string& s) {
    std::size_t n = 0;
    for (char c : s) n += (c == '\n');
    if (!s.empty() && s.back() != '\n') ++n;
    return n;
}

std::string first_line(const std::string& s) { return s.substr(0, s.find('\n')); }

// ---------------------------------------------------------------------------
// B -- bad invocations. `names` is the token the one-line error must name.
// ---------------------------------------------------------------------------
struct Bad { std::vector<std::string> tail; std::string names; const char* what; };

void bad_rows() {
    const std::vector<Bad> rows = {
        {{"--bogus-flag"},                     "--bogus-flag",          "an unknown flag"},
        {{"--verison"},                        "--verison",             "a typo of --version"},
        {{"--netwrok", "regtest"},             "--netwrok",             "a typo of --network"},
        {{"--rpc-prot", "1"},                  "--rpc-prot",            "a typo of --rpc-port"},
        {{"--relay-peers", "127.0.0.1:1"},     "--relay-peers",         "a typo of --relay-peer"},
        {{"-v"},                               "-v",                    "an unknown short flag"},
        {{"stagenet"},                         "stagenet",              "a positional token"},
        {{"--d-conf"},                         "--d-conf",              "a number flag with no value (last)"},
        {{"--data-dir"},                       "--data-dir",            "a path flag with no value (last)"},
        {{"--data-dir", "--randomx"},          "--data-dir",            "a value flag followed by the next flag"},
        {{"--poll-ms", "12abc"},               "--poll-ms",             "a number with trailing junk"},
        {{"--share-diff", "-1"},               "--share-diff",          "a negative unsigned number"},
        {{"--stratum-port", "70000"},          "--stratum-port",        "a port above 65535"},
        {{"--give-author-pct", "abc"},         "--give-author-pct",     "a non-numeric percentage"},
        {{"--network", "mainnett"},            "--network",             "an unknown network"},
        {{"--arm-order", "p2p-frist"},         "--arm-order",           "an unknown arm order"},
        {{"--coinbase", "v73"},                "--coinbase",            "an unknown coinbase mode"},
        {{"--xmr-template-source", "nativ"},   "--xmr-template-source", "an unknown template source"},
        {{"--contested-suspend", "maybe"},     "--contested-suspend",   "an on/off flag given neither"},
        {{"--relay-bind", "rbnd"},             "--relay-bind",          "an unknown relay binding"},
        {{"--native-snapshot-every", "12abc"}, "--native-snapshot-every", "a native-node number with junk"},
        {{"--native-template-fallback", "of"}, "--native-template-fallback", "a native-node on/off typo"},
        {{"--mine", "4x"},                     "--mine",                "a thread count with junk"},
    };
    for (const Bad& b : rows) {
        const auto args = safe(b.tail);
        const Run r = run(args, 5000);
        const std::string tag = std::string("B: ") + b.what + " [" + join(b.tail) + "]";
        check(!r.timed_out, tag + ": did not exit (live mode) within 5 s");
        check(r.rc == 2, tag + ": exit " + std::to_string(r.rc) + ", want 2");
        check(line_count(r.out) == 1, tag + ": " + std::to_string(line_count(r.out)) +
                                          " output lines, want 1: " + first_line(r.out));
        check(r.out.find(b.names) != std::string::npos, tag + ": the error does not name '" + b.names + "'");
        check(r.out.find("--help") != std::string::npos, tag + ": the error does not point at --help");
        check(r.files == 0, tag + ": created " + std::to_string(r.files) + " file(s) under the scratch HOME");
    }
}

// ---------------------------------------------------------------------------
// V -- --version / -V.
// ---------------------------------------------------------------------------
void version_rows() {
    namespace nat = ::c2pool::xmr::native;
    const std::string mh = std::to_string(nat::PINNED_SNAPSHOT_MAINNET.height);
    const std::string sh = std::to_string(nat::PINNED_SNAPSHOT_STAGENET.height);
    const std::vector<std::vector<std::string>> rows = {
        safe({"--version"}), safe({"-V"}),
        {"--version", "--network", "regtest", "--rpc-port", "1", "--zmq-port", "1"},
    };
    for (const auto& args : rows) {
        const Run r = run(args, 5000);
        const std::string tag = "V: [" + join(args) + "]";
        check(!r.timed_out, tag + ": did not exit (live mode) within 5 s");
        check(r.rc == 0, tag + ": exit " + std::to_string(r.rc) + ", want 0");
        check(r.secs < 1.0, tag + ": took " + std::to_string(r.secs) + " s, want < 1 s");
        const std::string l1 = first_line(r.out);
        check(l1.rfind("c2pool-v37-xmr ", 0) == 0 && l1.size() > 15 && l1.find("unknown") == std::string::npos,
              tag + ": first line is not 'c2pool-v37-xmr <version>': " + l1);
        check(r.out.find("network default: stagenet") != std::string::npos, tag + ": no network default");
        check(r.out.find("mainnet height " + mh) != std::string::npos, tag + ": no pinned mainnet height " + mh);
        check(r.out.find("stagenet height " + sh) != std::string::npos, tag + ": no pinned stagenet height " + sh);
        check(r.files == 0, tag + ": created " + std::to_string(r.files) + " file(s)");
    }
}

// ---------------------------------------------------------------------------
// H -- --help lists the new flag (and gates the C rows).
// ---------------------------------------------------------------------------
bool help_rows() {
    const Run r = run(safe({"--help"}), 5000);
    check(!r.timed_out && r.rc == 0, "H: --help did not exit 0 (rc " + std::to_string(r.rc) + ")");
    const bool lists = r.out.find("--version, -V") != std::string::npos;
    check(lists, "H: --help does not list --version, -V");
    check(r.files == 0, "H: --help created files");
    return !r.timed_out && r.rc == 0 && lists;
}

// ---------------------------------------------------------------------------
// C -- every accepted flag still parses. {flag, value...}; an empty value
// list is a switch. Taken from the parse loop, apply_native_node_flag() and
// the invocations in docs/xmr-lane/gap2-rig, scripts/xmr-race-rig,
// docs/xmr-lane/*.md and src/c2pool/v37/xmr/README.md.
// ---------------------------------------------------------------------------
void compat_rows() {
    const std::string H64 = "a03ab8e2191c928bffa5c875c42834f793a356c12cd6d319310619055bcc7005";
    const std::vector<std::vector<std::string>> rows = {
        {"--mock-smoke"}, {"--selftest"},
        {"--network", "stagenet"}, {"--network", "testnet"}, {"--network", "mainnet"}, {"--network", "regtest"},
        {"--rpc-host", "127.0.0.1"}, {"--rpc-port", "1"}, {"--zmq-port", "1"},
        {"--stratum-port", "7321"}, {"--stratum-bind-host", "127.0.0.1"},
        {"--payout-address", ""}, {"--payout-address", "5AddressLikeToken"},
        {"--share-diff", "2000"}, {"--template-reserve", "0"}, {"--poll-ms", "400"}, {"--status-every", "5"},
        {"--no-found-sidecar"}, {"--payee-spend-hex", H64}, {"--payee-view-hex", H64}, {"--payee-subaddress"},
        {"--coinbase", "monerod"}, {"--coinbase", "v37"}, {"--coinbase", "settlement"}, {"--coinbase", "v37-settlement"},
        {"--residual-sink-spend-hex", H64}, {"--residual-sink-view-hex", H64}, {"--residual-sink-subaddress"},
        {"--fee-model", "off"}, {"--fee-model", "v1"}, {"--fee-model", "0"}, {"--fee-model", "1"},
        {"--give-author-pct", "1.5"}, {"--node-owner-fee-pct", "0"}, {"--node-owner-address", "addr"},
        {"--settle-h-min", "0"}, {"--settle-output-cap", "0"}, {"--owed-demo-amount", "0"},
        {"--credit-feed", "feed.txt"}, {"--credit-feed-lag-ms", "0"}, {"--wire-out", "w"}, {"--wire-in", "w"},
        {"--credit-mutate", "-5"}, {"--credit-mutate", "5"},
        {"--no-book-deferral"}, {"--cba-monerod-compare"}, {"--cba-monerod-fallback"}, {"--cba-refetch-bound", "120"},
        {"--relay-feed-monerod-compare"},
        {"--relay-listen", "127.0.0.1:7320"}, {"--pool-genesis", H64}, {"--relay-peer", "127.0.0.1:7322"},
        {"--drops-enrol", H64}, {"--drops-enrol-min-tip", "0"},
        {"--relay-max-peers", "8"}, {"--relay-index-horizon", "64"}, {"--relay-rx-budget", "1,20,16,256"},
        {"--relay-solicited-credits", "256"}, {"--relay-backfill-positions", "2048"}, {"--relay-reoffer-seconds", "60"},
        {"--relay-order", "canonical"}, {"--relay-order", "arrival"}, {"--relay-bin-lag", "1"},
        {"--relay-bin-grace-ms", "4000"}, {"--relay-vault-entries", "0"}, {"--relay-vault-bytes", "0"},
        {"--relay-vault-horizon", "0"}, {"--no-relay-serve"}, {"--relay-test-partition-seconds", "0"},
        {"--test-suspend-lane-seconds", "0"}, {"--relay-bind", "none"}, {"--relay-bind", "rbind"},
        {"--divergence-cap-heights", "0"}, {"--divergence-cap-ticks", "20"}, {"--divergence-cap-terminal", "2"},
        {"--contested-suspend", "on"}, {"--contested-suspend", "off"}, {"--contested-suspend", "true"},
        {"--contested-suspend", "0"},
        {"--minority-converge", "on"}, {"--minority-converge", "off"}, {"--minority-converge", "halt-only"},
        {"--minority-window", "8"}, {"--minority-min-blocks", "3"}, {"--converge-retry-bound", "600"},
        {"--converge-hold-ticks", "0"}, {"--recon-max-root-age", "0"},
        {"--xmr-template-source", "monerod"}, {"--xmr-template-source", "native"},
        {"--native-output-set", "set.bin"}, {"--native-solo"}, {"--native-dos-solicited-credits", "8"},
        {"--no-good-citizen"}, {"--native-inject"}, {"--native-inject-dir", "inj"}, {"--native-inject-hex", "inj.hex"},
        {"--native-inject-ttl-blocks", "720"},
        {"--arm-order", "daemon-first"}, {"--arm-order", "p2p-first"}, {"--arm-order", "p2p"},
        {"--arm-order", "daemonless"},
        {"--no-daemon-rpc"}, {"--lane-chain", "7"}, {"--d-conf", "3"},
        {"--same-height-tiebreak", "prefer-own"}, {"--same-height-tiebreak", "first-seen"},
        {"--own-fork-bound-s", "240"}, {"--same-height-renotify", "3"}, {"--same-height-journal", "off"},
        {"--data-dir", "settle"}, {"--i-understand-mainnet"}, {"--randomx"}, {"--randomx-large-pages"},
        {"--mine"}, {"--mine", "2"}, {"--mine-threads", "2"}, {"--mine-fast"}, {"--mine-msr"},
        {"--mine-no-huge-pages"}, {"--mine-no-affinity"},
        // apply_native_node_flag()
        {"--native-connect", "127.0.0.1:7323"}, {"--native-p2p-bind", "127.0.0.1"}, {"--native-anchor", "a.inc"},
        {"--native-force-synced"}, {"--native-allow-unverified-pow"}, {"--native-seeds"}, {"--seeds"},
        {"--native-parity-monerod"}, {"--native-snapshot-path", "idx.snap"}, {"--native-snapshot-every", "300"},
        {"--native-catchup-window", "256"}, {"--native-backlog-refresh", "3"}, {"--backlog-refresh", "3"},
        {"--anchor-confirm-peers", "4"}, {"--anchor-confirm-timeout-ms", "60000"},
        {"--anchor-confirm-peer-ms", "12000"}, {"--native-ready-timeout", "120"},
        {"--native-template-fallback", "on"}, {"--native-template-fallback", "off"},
    };
    for (const auto& row : rows) {
        auto args = safe(row);
        args.push_back("--version");
        const Run r = run(args, 5000);
        const std::string tag = "C: [" + join(row) + "]";
        check(!r.timed_out && r.rc == 0 && first_line(r.out).rfind("c2pool-v37-xmr ", 0) == 0,
              tag + ": did not parse (rc " + std::to_string(r.rc) + "): " + first_line(r.out));
        check(r.files == 0, tag + ": created files");
    }
    // The GAP-2 rig's node.sh line (docs/xmr-lane/gap2-rig/node.sh, node B),
    // verbatim but for the ports, with an EMPTY payout address as the rig
    // passes it before its wallet exists.
    std::vector<std::string> gap2 = {
        "--network", "regtest", "--rpc-host", "127.0.0.1", "--rpc-port", "1", "--zmq-port", "1",
        "--stratum-bind-host", "127.0.0.1", "--stratum-port", "7321", "--payout-address", "",
        "--payee-spend-hex", H64, "--payee-view-hex", H64,
        "--coinbase", "v37", "--residual-sink-spend-hex", H64, "--residual-sink-view-hex", H64,
        "--share-diff", "2000", "--d-conf", "3", "--poll-ms", "400", "--status-every", "5", "--randomx",
        "--data-dir", "settleB", "--lane-chain", "7",
        "--relay-listen", "127.0.0.1:7320", "--relay-peer", "127.0.0.1:7322", "--version"};
    const Run r = run(gap2, 5000);
    check(!r.timed_out && r.rc == 0, "C: the gap2-rig node.sh line did not parse: " + first_line(r.out));
    // The race rig's node.sh line (scripts/xmr-race-rig/node.sh, node C),
    // verbatim but for the ports.
    const std::string V = "099b5b60c9a497e55985b3843c3fda8da741814c39f0cda7fab35c0c4c1c023d";
    std::vector<std::string> race = {
        "--network", "regtest", "--rpc-host", "127.0.0.1", "--rpc-port", "1", "--zmq-port", "1",
        "--coinbase", "v37", "--xmr-template-source", "native", "--arm-order", "p2p-first", "--native-force-synced",
        "--native-connect", "127.0.0.1:7323", "--native-connect", "127.0.0.1:7324", "--native-connect", "127.0.0.1:7325",
        "--native-p2p-bind", "127.0.0.123", "--native-ready-timeout", "900",
        "--stratum-bind-host", "127.0.0.1", "--stratum-port", "7321", "--payout-address", "5AddressLikeToken",
        "--payee-spend-hex", H64, "--payee-view-hex", V, "--residual-sink-spend-hex", V, "--residual-sink-view-hex", H64,
        "--share-diff", "8", "--d-conf", "10", "--poll-ms", "400", "--status-every", "5", "--randomx",
        "--data-dir", "settleC", "--lane-chain", "7", "--relay-rx-budget", "200,800,600,4000",
        "--relay-listen", "127.0.0.1:7320", "--relay-peer", "127.0.0.1:7322", "--relay-peer", "127.0.0.1:7326",
        "--version"};
    const Run rr = run(race, 5000);
    check(!rr.timed_out && rr.rc == 0, "C: the xmr-race-rig node.sh line did not parse: " + first_line(rr.out));
    check(rr.files == 0, "C: the xmr-race-rig node.sh line created files");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: v37_xmr_cli_strict_kat <path to c2pool-v37-xmr>\n");
        return 2;
    }
    g_bin = argv[1];
    const char* t = std::getenv("TMPDIR");
    g_tmp_root = (t != nullptr && *t != '\0') ? t : "/tmp";
    ::signal(SIGPIPE, SIG_IGN);
    std::printf("v37_xmr_cli_strict_kat: binary %s\n", g_bin.c_str());

    const bool knows_version = help_rows();
    version_rows();
    bad_rows();
    if (knows_version) compat_rows();
    else std::printf("C rows SKIPPED: this binary does not list --version, so a flag row could start it live\n");

    std::printf("v37_xmr_cli_strict_kat: %d passed, %d failed\n", g_pass, g_fail);
    if (g_fail != 0) { std::printf("RESULT: FAIL\n"); return 1; }
    std::printf("RESULT: PASS\n");
    return 0;
}
