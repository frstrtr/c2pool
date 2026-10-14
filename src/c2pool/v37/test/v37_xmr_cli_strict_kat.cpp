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
//      network default and both pinned snapshot heights and no raindrops
//      line, create nothing;
//   H  --help exits 0 and lists --version;
//   T  the flag table: every master flag classified kept or removed, every
//      new flag classified new, every flag --help lists in the table (T1-T3);
//   K  every kept and new flag parses: `<flag> [value] --version` exits 0
//      with the version line, which is only reached once the flag was taken;
//   X  every removed flag (any value) exits 2 with the one line
//      "REFUSED: <flag>: removed at the S4w flag day" and creates nothing;
//   C  the rig scripts' lines are refused naming their first removed flag;
//   F  FORK-FUSE-2's test-only --test-unknown-fork-stall-s is parsed by the
//      strict helpers (C and B rows) and is still REFUSED on mainnet: exit 2
//      naming the flag, before any file is created.
//   S  --node-owner-fee-pct + --give-author-pct above 10000 bp (100 + 0.01,
//      50.01 + 50, 100 + the 0.1 default) is REFUSED at start: exit 2, the
//      refusal line, no file created.
//   R  RELAY-BOOTSTRAP: the built-in relay bootstrap list is exactly the two
//      public mainnet pool nodes and empty on stagenet/testnet/regtest;
//      --no-relay-bootstrap empties it; a default already given as
//      --relay-peer is not dialled twice; the node itself (the --relay-listen
//      port on the listen host or on one of its own addresses) is skipped;
//      --help lists --no-relay-bootstrap and the flag parses (a C row).
//
// NETWORK SAFETY. Every invocation that a broken build could turn into a live
// run carries `--network regtest --rpc-host 127.0.0.1 --rpc-port 1 --zmq-port 1`
// first, so the worst case is a refused loopback connect to port 1 -- never a
// real network, never the default ports. The T/K/X/C rows (which include
// flags that dial peers or seed nodes) run only once H has shown this binary
// knows --version. Each child is killed after a bounded wait.
// ---------------------------------------------------------------------------

#include <poll.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <set>
#include <string>
#include <vector>

#include "impl/xmr/native/anchor/xmr_anchor_pinned.hpp"
#include "c2pool/v37/xmr/relay/xmr_relay_bootstrap.hpp"

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
        {{"--drain-q", "16"},                  "--drain-q",             "the drain rule's Q (a network constant, never a flag)"},
        {{"--drain-h-cap", "64"},              "--drain-h-cap",         "the drain rule's H_cap (a network constant, never a flag)"},
        {{"--drain-rule-version", "1"},        "--drain-rule-version",  "the drain rule's version (the flag day, never a flag)"},
        {{"--verison"},                        "--verison",             "a typo of --version"},
        {{"--netwrok", "regtest"},             "--netwrok",             "a typo of --network"},
        {{"--rpc-prot", "1"},                  "--rpc-prot",            "a typo of --rpc-port"},
        {{"--relay-peers", "127.0.0.1:1"},     "--relay-peers",         "a typo of --relay-peer"},
        {{"-v"},                               "-v",                    "an unknown short flag"},
        {{"stagenet"},                         "stagenet",              "a positional token"},
        {{"--status-every"},                   "--status-every",        "a number flag with no value (last)"},
        {{"--data-dir"},                       "--data-dir",            "a path flag with no value (last)"},
        {{"--data-dir", "--randomx"},          "--data-dir",            "a value flag followed by the next flag"},
        {{"--poll-ms", "12abc"},               "--poll-ms",             "a number with trailing junk"},
        {{"--lane-chain", "-1"},               "--lane-chain",          "a negative unsigned number"},
        {{"--stratum-port", "70000"},          "--stratum-port",        "a port above 65535"},
        {{"--give-author-pct", "abc"},         "--give-author-pct",     "a non-numeric percentage"},
        {{"--network", "mainnett"},            "--network",             "an unknown network"},
        {{"--arm-order", "p2p-frist"},         "--arm-order",           "an unknown arm order"},
        {{"--vote", "yes"},                    "--vote",                "a --vote value other than no"},
        {{"--xmr-template-source", "nativ"},   "--xmr-template-source", "an unknown template source"},
        // RELAY-DISCOVERY
        {{"--relay-discovery", "maybe"},       "--relay-discovery",     "a discovery on/off given neither"},
        {{"--relay-discovery"},                "--relay-discovery",     "the discovery switch with no value (last)"},
        {{"--relay-max-outbound", "8x"},       "--relay-max-outbound",  "an outbound count with junk"},
        {{"--relay-max-outbound", "-1"},       "--relay-max-outbound",  "a negative outbound count"},
        {{"--native-snapshot-every", "12abc"}, "--native-snapshot-every", "a native-node number with junk"},
        {{"--native-template-fallback", "of"}, "--native-template-fallback", "a native-node on/off typo"},
        {{"--mine", "4x"},                     "--mine",                "a thread count with junk"},
        // relay / stratum node policy
        {{"--relay-rx-global", "0"},           "--relay-rx-global",     "a global RandomX refill of 0"},
        {{"--relay-ban-seconds", "1.5"},       "--relay-ban-seconds",   "a fractional relay ban"},
        {{"--stratum-share-rate", "0"},        "--stratum-share-rate",  "a share-rate target of 0"},
        {{"--stratum-share-rate", "x"},        "--stratum-share-rate",  "a non-numeric share-rate target"},
        {{"--stratum-submit-burst", "0"},      "--stratum-submit-burst", "a submit burst of 0"},
        {{"--stratum-vardiff-shares", "0"},    "--stratum-vardiff-shares", "a vardiff share target of 0"},
        {{"--stratum-share-score", "-3,1,-9"}, "--stratum-share-score", "a share score with three fields"},
        {{"--stratum-share-score", "-3,1,x,0"}, "--stratum-share-score", "a share score with junk"},
        {{"--stratum-login-timeout-ms", "-1"}, "--stratum-login-timeout-ms", "a negative login deadline"},
        // the raise-only policy flags below their floors (P-09, P-15, P-50)
        {{"--relay-pending-cap", "18431"},     "--relay-pending-cap",   "a pending cap below its floor (raise only)"},
        {{"--relay-peer-valid-rate", "1.6"},   "--relay-peer-valid-rate", "a valid-object rate below its floor (raise only)"},
        {{"--pathb-claim-alarm-rate", "1"},    "--pathb-claim-alarm-rate", "a claim-alarm rate below its floor (raise only)"},
        {{"--relay-send-queue-bytes", "1x"},   "--relay-send-queue-bytes", "a send-queue bound with junk"},
        // FORK-FUSE-2's test knob, parsed by the strict helpers.
        {{"--test-unknwon-fork-stall-s", "5"}, "--test-unknwon-fork-stall-s", "a typo of --test-unknown-fork-stall-s"},
        {{"--test-unknown-fork-stall-s"},      "--test-unknown-fork-stall-s", "the fuse stall knob with no value (last)"},
        {{"--test-unknown-fork-stall-s", "12abc"}, "--test-unknown-fork-stall-s", "the fuse stall knob with junk"},
        // XMR-WEB: the dashboard flags, parsed by the strict helpers.
        {{"--web-port", "70000"},              "--web-port",            "a web port above 65535"},
        {{"--web-port", "80x"},                "--web-port",            "a web port with junk"},
        {{"--web-port"},                       "--web-port",            "the web port with no value (last)"},
        {{"--web-host"},                       "--web-host",            "the web host with no value (last)"},
        {{"--web-prot", "63600"},              "--web-prot",            "a typo of --web-port"},
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
        check(r.out.find("raindrops") == std::string::npos, tag + ": a raindrops line is printed");
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
// The flag table. kMasterFlags: every flag the master binary (a414b9144)
// accepted (its parse loop, apply_native_node_flag and the short aliases).
// flag_table(): every master flag and every new flag, classified kept /
// removed / new, with the invocations each row runs ({} = none; {{}} = the
// switch).
//   T1  every master flag is in the table, kept or removed;
//   T2  no new flag is a master flag; no flag is listed twice;
//   T3  every flag --help lists is in the table, kept or new; no removed flag
//       is listed by --help;
//   K   a kept or new row: `<flag> [value] --version` exits 0 with the version
//       line and creates nothing;
//   X   a removed row: `<flag> [value]` exits 2 with the one line
//       "REFUSED: <flag>: removed at the S4w flag day" and creates nothing.
// ---------------------------------------------------------------------------
const std::string H64 = "a03ab8e2191c928bffa5c875c42834f793a356c12cd6d319310619055bcc7005";

const std::vector<std::string> kMasterFlags = {
    "--anchor-confirm-peer-ms", "--anchor-confirm-peers", "--anchor-confirm-timeout-ms", "--arm-order",
    "--backlog-refresh", "--cba-monerod-compare", "--cba-monerod-fallback", "--cba-refetch-bound", "--coinbase",
    "--contested-suspend", "--converge-hold-ticks", "--converge-retry-bound", "--credit-feed",
    "--credit-feed-lag-ms", "--credit-mutate", "--d-conf", "--dashboard-dir", "--data-dir",
    "--divergence-cap-heights", "--divergence-cap-terminal", "--divergence-cap-ticks", "--drops-enrol",
    "--drops-enrol-min-tip", "--drops-retain-bins", "--drops-store-persist", "--fee-model", "--give-author-pct",
    "--help", "--i-understand-mainnet", "--lane-chain", "--mine", "--mine-fast", "--mine-msr", "--mine-no-affinity",
    "--mine-no-huge-pages", "--mine-threads", "--minority-converge", "--minority-min-blocks", "--minority-window",
    "--mock-smoke", "--native-allow-unverified-pow", "--native-anchor", "--native-backlog-refresh",
    "--native-catchup-window", "--native-connect", "--native-dos-solicited-credits", "--native-force-synced",
    "--native-inject", "--native-inject-dir", "--native-inject-hex", "--native-inject-ttl-blocks",
    "--native-output-set", "--native-p2p-bind", "--native-parity-monerod", "--native-ready-timeout",
    "--native-seeds", "--native-snapshot-every", "--native-snapshot-path", "--native-solo",
    "--native-template-fallback", "--network", "--no-book-deferral", "--no-daemon-rpc", "--no-found-sidecar",
    "--no-good-citizen", "--no-relay-bootstrap", "--no-relay-serve", "--node-owner-address", "--node-owner-fee-pct",
    "--owed-demo-amount", "--own-fork-bound-s", "--payee-spend-hex", "--payee-subaddress", "--payee-view-hex",
    "--payout-address", "--poll-ms", "--pool-genesis", "--randomx", "--randomx-large-pages", "--recon-max-root-age",
    "--relay-backfill-positions", "--relay-ban-seconds", "--relay-bin-grace-ms", "--relay-bin-lag", "--relay-bind",
    "--relay-deep-order", "--relay-deep-probe-step", "--relay-discovery", "--relay-feed-monerod-compare",
    "--relay-index-horizon", "--relay-keepalive-ms", "--relay-listen", "--relay-max-inbound", "--relay-max-outbound",
    "--relay-max-peers", "--relay-order", "--relay-parked-max", "--relay-peer", "--relay-reoffer-seconds",
    "--relay-rx-budget", "--relay-rx-global", "--relay-shadow-persist", "--relay-shadow-persist-bytes",
    "--relay-silence-timeout-ms", "--relay-solicited-credits", "--relay-test-partition-seconds",
    "--relay-vault-bytes", "--relay-vault-entries", "--relay-vault-horizon", "--relay-verify-threads",
    "--residual-sink-spend-hex", "--residual-sink-subaddress", "--residual-sink-view-hex", "--rpc-host",
    "--rpc-port", "--same-height-journal", "--same-height-renotify", "--same-height-tiebreak", "--seeds",
    "--selftest", "--settle-h-min", "--settle-output-cap", "--share-diff", "--status-every", "--stratum-ban-seconds",
    "--stratum-bind-host", "--stratum-login-timeout-ms", "--stratum-port", "--stratum-share-rate",
    "--stratum-share-score", "--stratum-submit-burst", "--stratum-vardiff-shares", "--template-reserve",
    "--test-crash-after-publish", "--test-suspend-lane-seconds", "--test-unknown-fork-stall-s", "--version",
    "--web-host", "--web-port", "--wire-in", "--wire-out", "--xmr-template-source", "--zmq-port", "-V", "-h",
};

enum class Cls { Kept, Removed, New };
const char* cls_name(Cls c) { return c == Cls::Kept ? "kept" : c == Cls::Removed ? "removed" : "new"; }
struct FlagRow {
    std::string flag;
    Cls cls;
    std::vector<std::vector<std::string>> samples;
};

const std::vector<FlagRow>& flag_table() {
    static const std::vector<FlagRow> t = {
        {"--anchor-confirm-peer-ms", Cls::Kept, {{"12000"}}},
        {"--anchor-confirm-peers", Cls::Kept, {{"4"}}},
        {"--anchor-confirm-timeout-ms", Cls::Kept, {{"60000"}}},
        {"--arm-order", Cls::Kept, {{"daemon-first"}, {"p2p-first"}, {"p2p"}, {"daemonless"}}},
        {"--backlog-refresh", Cls::Kept, {{"3"}}},
        {"--dashboard-dir", Cls::Kept, {{"web"}}},
        {"--data-dir", Cls::Kept, {{"settle"}}},
        {"--give-author-pct", Cls::Kept, {{"1.5"}}},
        {"--help", Cls::Kept, {}},
        {"--i-understand-mainnet", Cls::Kept, {{}}},
        {"--lane-chain", Cls::Kept, {{"7"}}},
        {"--mine", Cls::Kept, {{}, {"2"}}},
        {"--mine-fast", Cls::Kept, {{}}},
        {"--mine-msr", Cls::Kept, {{}}},
        {"--mine-no-affinity", Cls::Kept, {{}}},
        {"--mine-no-huge-pages", Cls::Kept, {{}}},
        {"--mine-threads", Cls::Kept, {{"2"}}},
        {"--native-allow-unverified-pow", Cls::Kept, {{}}},
        {"--native-anchor", Cls::Kept, {{"a.inc"}}},
        {"--native-backlog-refresh", Cls::Kept, {{"3"}}},
        {"--native-catchup-window", Cls::Kept, {{"256"}}},
        {"--native-connect", Cls::Kept, {{"127.0.0.1:7323"}}},
        {"--native-dos-solicited-credits", Cls::Kept, {{"8"}}},
        {"--native-force-synced", Cls::Kept, {{}}},
        {"--native-inject", Cls::Kept, {{}}},
        {"--native-inject-dir", Cls::Kept, {{"inj"}}},
        {"--native-inject-hex", Cls::Kept, {{"inj.hex"}}},
        {"--native-inject-ttl-blocks", Cls::Kept, {{"720"}}},
        {"--native-output-set", Cls::Kept, {{"set.bin"}}},
        {"--native-p2p-bind", Cls::Kept, {{"127.0.0.1"}}},
        {"--native-parity-monerod", Cls::Kept, {{}}},
        {"--native-ready-timeout", Cls::Kept, {{"120"}}},
        {"--native-seeds", Cls::Kept, {{}}},
        {"--native-snapshot-every", Cls::Kept, {{"300"}}},
        {"--native-snapshot-path", Cls::Kept, {{"idx.snap"}}},
        {"--native-solo", Cls::Kept, {{}}},
        {"--native-template-fallback", Cls::Kept, {{"on"}, {"off"}}},
        {"--network", Cls::Kept, {{"stagenet"}, {"testnet"}, {"mainnet"}, {"regtest"}}},
        {"--no-daemon-rpc", Cls::Kept, {{}}},
        {"--no-good-citizen", Cls::Kept, {{}}},
        {"--no-relay-bootstrap", Cls::Kept, {{}}},
        {"--no-relay-serve", Cls::Kept, {{}}},
        {"--node-owner-address", Cls::Kept, {{"addr"}}},
        {"--node-owner-fee-pct", Cls::Kept, {{"0"}}},
        {"--own-fork-bound-s", Cls::Kept, {{"240"}}},
        {"--payout-address", Cls::Kept, {{""}, {"5AddressLikeToken"}}},
        {"--poll-ms", Cls::Kept, {{"400"}}},
        {"--pool-genesis", Cls::Kept, {{H64}, {H64 + ":100"}}},
        {"--randomx", Cls::Kept, {{}}},
        {"--randomx-large-pages", Cls::Kept, {{}}},
        {"--relay-ban-seconds", Cls::Kept, {{"226"}}},
        {"--relay-discovery", Cls::Kept, {{"on"}, {"off"}}},
        {"--relay-keepalive-ms", Cls::Kept, {{"5000"}}},
        {"--relay-listen", Cls::Kept, {{"127.0.0.1:7320"}}},
        {"--relay-max-inbound", Cls::Kept, {{"101"}}},
        {"--relay-max-outbound", Cls::Kept, {{"8"}, {"0"}}},
        {"--relay-max-peers", Cls::Kept, {{"8"}}},
        {"--relay-parked-max", Cls::Kept, {{"64"}}},
        {"--relay-peer", Cls::Kept, {{"127.0.0.1:7322"}}},
        {"--relay-rx-budget", Cls::Kept, {{"1,20,16,256"}}},
        {"--relay-rx-global", Cls::Kept, {{"4"}}},
        {"--relay-silence-timeout-ms", Cls::Kept, {{"25000"}}},
        {"--relay-solicited-credits", Cls::Kept, {{"256"}}},
        {"--relay-test-partition-seconds", Cls::Kept, {{"0"}}},
        {"--relay-verify-threads", Cls::Kept, {{"2"}}},
        {"--rpc-host", Cls::Kept, {{"127.0.0.1"}}},
        {"--rpc-port", Cls::Kept, {{"1"}}},
        {"--same-height-tiebreak", Cls::Kept, {{"prefer-own"}, {"first-seen"}}},
        {"--seeds", Cls::Kept, {{}}},
        {"--status-every", Cls::Kept, {{"5"}}},
        {"--stratum-ban-seconds", Cls::Kept, {{"2"}}},
        {"--stratum-bind-host", Cls::Kept, {{"127.0.0.1"}}},
        {"--stratum-login-timeout-ms", Cls::Kept, {{"5000"}}},
        {"--stratum-port", Cls::Kept, {{"7321"}}},
        {"--stratum-share-rate", Cls::Kept, {{"12.8"}}},
        {"--stratum-share-score", Cls::Kept, {{"-3,1,-9,0"}}},
        {"--stratum-submit-burst", Cls::Kept, {{"24"}}},
        {"--stratum-vardiff-shares", Cls::Kept, {{"3"}}},
        {"--test-unknown-fork-stall-s", Cls::Kept, {{"120"}, {"0"}}},
        {"--version", Cls::Kept, {}},
        {"--web-host", Cls::Kept, {{"127.0.0.1"}}},
        {"--web-port", Cls::Kept, {{"63600"}}},
        {"--xmr-template-source", Cls::Kept, {{"monerod"}, {"native"}}},
        {"--zmq-port", Cls::Kept, {{"1"}}},
        {"-V", Cls::Kept, {}},
        {"-h", Cls::Kept, {}},
        {"--follow-only", Cls::New, {{}}},
        {"--join-min-peers", Cls::New, {{"2"}}},
        {"--journal-depth", Cls::New, {{"1152"}}},
        {"--native-txpool-warm-timeout-ms", Cls::New, {{"30000"}, {"0"}}},
        {"--pathb-abandon-timeout", Cls::New, {{"11"}}},
        {"--pathb-body-keep", Cls::New, {{"4096"}, {"1"}}},
        {"--pathb-bucket-frame", Cls::New, {{"65536"}}},
        {"--pathb-bucket-inflight", Cls::New, {{"1"}}},
        {"--pathb-bucket-rate", Cls::New, {{"1048576"}}},
        {"--pathb-bucket-serve-cap", Cls::New, {{"65536"}}},
        {"--pathb-claim-alarm-rate", Cls::New, {{"8"}, {"1.7"}}},
        {"--pathb-deployments", Cls::New, {{"deployments.bin"}}},
        {"--pathb-header-keep", Cls::New, {{"4096"}, {"1"}}},
        {"--pathb-key-cache-mb", Cls::New, {{"64"}}},
        {"--pathb-launch", Cls::New, {{}}},
        {"--pathb-penalty-fill", Cls::New, {{}}},
        {"--pathb-side-keep", Cls::New, {{"4096"}, {"1"}}},
        {"--relay-peer-valid-rate", Cls::New, {{"1.7"}, {"40"}}},
        {"--relay-pending-cap", Cls::New, {{"18432"}, {"40000"}}},
        {"--relay-send-queue-bytes", Cls::New, {{"16777216"}}},
        {"--pathb-waiting-cap", Cls::New, {{"1152"}}},
        {"--pool-genesis-from", Cls::New, {{"100:" + H64 + ":headline"}}},
        {"--pool-genesis-height", Cls::New, {{"100"}}},
        {"--stratum-min-diff-shift", Cls::New, {{"0"}, {"6"}}},
        {"--vote", Cls::New, {{"no"}}},
        {"--cba-monerod-compare", Cls::Removed, {{}}},
        {"--cba-monerod-fallback", Cls::Removed, {{}}},
        {"--cba-refetch-bound", Cls::Removed, {{"120"}}},
        {"--coinbase", Cls::Removed, {{"monerod"}, {"v37"}, {"settlement"}, {"v37-settlement"}, {"v73"}, {}}},
        {"--contested-suspend", Cls::Removed, {{"on"}, {"off"}, {"true"}, {"0"}}},
        {"--converge-hold-ticks", Cls::Removed, {{"0"}}},
        {"--converge-retry-bound", Cls::Removed, {{"600"}}},
        {"--credit-feed", Cls::Removed, {{"feed.txt"}}},
        {"--credit-feed-lag-ms", Cls::Removed, {{"0"}}},
        {"--credit-mutate", Cls::Removed, {{"-5"}, {"5"}}},
        {"--d-conf", Cls::Removed, {{"3"}}},
        {"--divergence-cap-heights", Cls::Removed, {{"0"}}},
        {"--divergence-cap-terminal", Cls::Removed, {{"2"}}},
        {"--divergence-cap-ticks", Cls::Removed, {{"20"}}},
        {"--drops-enrol", Cls::Removed, {{H64}, {"none"}}},
        {"--drops-enrol-min-tip", Cls::Removed, {{"0"}}},
        {"--drops-retain-bins", Cls::Removed, {{"0"}}},
        {"--drops-store-persist", Cls::Removed, {{"drops"}}},
        {"--fee-model", Cls::Removed, {{"off"}, {"v1"}, {"0"}, {"1"}}},
        {"--minority-converge", Cls::Removed, {{"on"}, {"off"}, {"halt-only"}}},
        {"--minority-min-blocks", Cls::Removed, {{"3"}}},
        {"--minority-window", Cls::Removed, {{"8"}}},
        {"--mock-smoke", Cls::Removed, {{}}},
        {"--no-book-deferral", Cls::Removed, {{}}},
        {"--no-found-sidecar", Cls::Removed, {{}}},
        {"--owed-demo-amount", Cls::Removed, {{"0"}}},
        {"--payee-spend-hex", Cls::Removed, {{H64}}},
        {"--payee-subaddress", Cls::Removed, {{}}},
        {"--payee-view-hex", Cls::Removed, {{H64}}},
        {"--recon-max-root-age", Cls::Removed, {{"0"}}},
        {"--relay-backfill-positions", Cls::Removed, {{"2048"}}},
        {"--relay-bin-grace-ms", Cls::Removed, {{"4000"}}},
        {"--relay-bin-lag", Cls::Removed, {{"1"}}},
        {"--relay-bind", Cls::Removed, {{"none"}, {"rbind"}}},
        {"--relay-deep-order", Cls::Removed, {{"on"}}},
        {"--relay-deep-probe-step", Cls::Removed, {{"64"}}},
        {"--relay-feed-monerod-compare", Cls::Removed, {{}}},
        {"--relay-index-horizon", Cls::Removed, {{"64"}}},
        {"--relay-order", Cls::Removed, {{"canonical"}, {"arrival"}}},
        {"--relay-reoffer-seconds", Cls::Removed, {{"60"}}},
        {"--relay-shadow-persist", Cls::Removed, {{"shadow"}}},
        {"--relay-shadow-persist-bytes", Cls::Removed, {{"0"}}},
        {"--relay-vault-bytes", Cls::Removed, {{"0"}}},
        {"--relay-vault-entries", Cls::Removed, {{"0"}}},
        {"--relay-vault-horizon", Cls::Removed, {{"0"}}},
        {"--residual-sink-spend-hex", Cls::Removed, {{H64}}},
        {"--residual-sink-subaddress", Cls::Removed, {{}}},
        {"--residual-sink-view-hex", Cls::Removed, {{H64}}},
        {"--same-height-journal", Cls::Removed, {{"off"}}},
        {"--same-height-renotify", Cls::Removed, {{"3"}}},
        {"--selftest", Cls::Removed, {{}}},
        {"--settle-h-min", Cls::Removed, {{"0"}}},
        {"--settle-output-cap", Cls::Removed, {{"0"}}},
        {"--share-diff", Cls::Removed, {{"2000"}}},
        {"--template-reserve", Cls::Removed, {{"0"}}},
        {"--test-crash-after-publish", Cls::Removed, {{"1"}}},
        {"--test-suspend-lane-seconds", Cls::Removed, {{"0"}}},
        {"--wire-in", Cls::Removed, {{"w"}}},
        {"--wire-out", Cls::Removed, {{"w"}}},
    };
    return t;
}

const FlagRow* row_of(const std::string& flag) {
    for (const FlagRow& r : flag_table())
        if (r.flag == flag) return &r;
    return nullptr;
}

// Every --flag token of a text.
std::vector<std::string> flag_tokens(const std::string& text) {
    std::vector<std::string> out;
    for (std::size_t i = 0; i + 2 < text.size(); ++i) {
        if (text[i] != '-' || text[i + 1] != '-' || (i > 0 && (std::isalnum(static_cast<unsigned char>(text[i - 1])) || text[i - 1] == '-')))
            continue;
        std::size_t j = i + 2;
        while (j < text.size() && (std::islower(static_cast<unsigned char>(text[j])) || std::isdigit(static_cast<unsigned char>(text[j])) || text[j] == '-'))
            ++j;
        if (j > i + 2) out.push_back(text.substr(i, j - i));
        i = j;
    }
    return out;
}

void table_rows() {
    // T1, T2
    std::set<std::string> seen;
    for (const FlagRow& r : flag_table()) {
        check(seen.insert(r.flag).second, "T2: " + r.flag + " is listed twice");
        if (r.cls == Cls::New)
            check(std::find(kMasterFlags.begin(), kMasterFlags.end(), r.flag) == kMasterFlags.end(),
                  "T2: " + r.flag + " is a master flag classified new");
    }
    for (const std::string& f : kMasterFlags) {
        const FlagRow* r = row_of(f);
        check(r != nullptr, "T1: the master flag " + f + " is missing from the table");
        if (r) check(r->cls != Cls::New, "T1: the master flag " + f + " is classified new");
    }
    // T3
    const Run h = run(safe({"--help"}), 5000);
    const std::vector<std::string> listed = flag_tokens(h.out);
    check(!listed.empty(), "T3: --help lists no flag");
    for (const std::string& f : listed) {
        const FlagRow* r = row_of(f);
        check(r != nullptr, "T3: --help lists " + f + ", which is not in the table");
        if (r) check(r->cls != Cls::Removed, "T3: --help lists the removed flag " + f);
    }
    // K, X
    std::size_t kept = 0, removed = 0, added = 0;
    for (const FlagRow& r : flag_table()) {
        (r.cls == Cls::Kept ? kept : r.cls == Cls::Removed ? removed : added)++;
        for (const auto& tail : r.samples) {
            std::vector<std::string> row = {r.flag};
            row.insert(row.end(), tail.begin(), tail.end());
            auto args = safe(row);
            const std::string tag = (r.cls == Cls::Removed ? "X: [" : "K: [") + join(row) + "]";
            if (r.cls == Cls::Removed) {
                const Run x = run(args, 5000);
                const std::string want = "REFUSED: " + r.flag + ": removed at the S4w flag day";
                check(!x.timed_out && x.rc == 2, tag + ": exit " + std::to_string(x.rc) + ", want 2");
                check(line_count(x.out) == 1 && x.out.find(want) != std::string::npos,
                      tag + ": not refused with '" + want + "': " + first_line(x.out));
                check(x.files == 0, tag + ": created files");
            } else {
                args.push_back("--version");
                const Run k = run(args, 5000);
                check(!k.timed_out && k.rc == 0 && first_line(k.out).rfind("c2pool-v37-xmr ", 0) == 0,
                      tag + ": did not parse (rc " + std::to_string(k.rc) + "): " + first_line(k.out));
                check(k.files == 0, tag + ": created files");
            }
        }
    }
    std::printf("flag table: %zu master flags; %zu kept, %zu removed, %zu new\n", kMasterFlags.size(), kept, removed, added);
    check(kMasterFlags.size() == kept + removed, "T1: the master flags are exactly the kept and removed rows");
}

// ---------------------------------------------------------------------------
// C -- the rig scripts' lines (master flags) are refused, naming their first
// removed flag; nothing is created.
// ---------------------------------------------------------------------------
void rig_rows() {
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
        "--relay-listen", "127.0.0.1:7320", "--relay-peer", "127.0.0.1:7322"};
    const Run r = run(gap2, 5000);
    check(!r.timed_out && r.rc == 2 && line_count(r.out) == 1 &&
              r.out.find("REFUSED: --payee-spend-hex: removed at the S4w flag day") != std::string::npos,
          "C: the gap2-rig node.sh line is not refused naming --payee-spend-hex: " + first_line(r.out));
    check(r.files == 0, "C: the gap2-rig node.sh line created files");
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
        "--relay-listen", "127.0.0.1:7320", "--relay-peer", "127.0.0.1:7322", "--relay-peer", "127.0.0.1:7326"};
    const Run rr = run(race, 5000);
    check(!rr.timed_out && rr.rc == 2 && line_count(rr.out) == 1 &&
              rr.out.find("REFUSED: --coinbase: removed at the S4w flag day") != std::string::npos,
          "C: the xmr-race-rig node.sh line is not refused naming --coinbase: " + first_line(rr.out));
    check(rr.files == 0, "C: the xmr-race-rig node.sh line created files");
}

// ---------------------------------------------------------------------------
// F -- FORK-FUSE-2's test-only stall knob is refused on mainnet. The row
// carries --i-understand-mainnet so the prototype gate passes and the fuse's
// own refusal is what answers; the endpoint is loopback port 1.
// ---------------------------------------------------------------------------
void fuse_rows() {
    const std::vector<std::string> args = {
        "--network", "mainnet", "--i-understand-mainnet", "--rpc-host", "127.0.0.1", "--rpc-port", "1",
        "--zmq-port", "1", "--test-unknown-fork-stall-s", "120"};
    const Run r = run(args, 5000);
    const std::string tag = "F: [" + join(args) + "]";
    check(!r.timed_out, tag + ": did not exit (live mode) within 5 s");
    check(r.rc == 2, tag + ": exit " + std::to_string(r.rc) + ", want 2");
    check(r.out.find("REFUSED: --test-unknown-fork-stall-s") != std::string::npos,
          tag + ": no fuse-knob refusal line: " + first_line(r.out));
    check(r.files == 0, tag + ": created " + std::to_string(r.files) + " file(s)");
}

// ---------------------------------------------------------------------------
// S -- owner fee + give-author above 10000 bp is refused at start.
// ---------------------------------------------------------------------------
void share_sum_rows() {
    const std::vector<std::vector<std::string>> rows = {
        {"--node-owner-fee-pct", "100", "--give-author-pct", "0.01"},
        {"--node-owner-fee-pct", "50.01", "--give-author-pct", "50"},
        {"--node-owner-fee-pct", "100"},
    };
    for (const auto& tail : rows) {
        std::vector<std::string> v = {"--node-owner-address", "addr"};
        v.insert(v.end(), tail.begin(), tail.end());
        const std::vector<std::string> args = safe(v);
        const Run r = run(args, 5000);
        const std::string tag = "S: [" + join(args) + "]";
        check(!r.timed_out, tag + ": did not exit (live mode) within 5 s");
        check(r.rc == 2, tag + ": exit " + std::to_string(r.rc) + ", want 2");
        check(r.out.find("REFUSED: --node-owner-fee-pct + --give-author-pct") != std::string::npos,
              tag + ": no share-sum refusal line: " + first_line(r.out));
        check(r.files == 0, tag + ": created " + std::to_string(r.files) + " file(s)");
    }
}

// ---------------------------------------------------------------------------
// R -- RELAY-BOOTSTRAP: the built-in list and its resolution (pure), + --help.
// ---------------------------------------------------------------------------
void bootstrap_rows() {
    namespace rl = c2pool::v37n::xmr::relay;
    using V = std::vector<std::string>;
    const std::string A = "109.123.238.32:59321", B = "158.220.92.171:59321";
    const auto& m = rl::default_bootstrap_hosts(0);
    check(m == V{A, B}, "R: mainnet default list is not exactly {" + A + ", " + B + "}");
    for (std::uint8_t n : {std::uint8_t{1}, std::uint8_t{2}, std::uint8_t{3}})
        check(rl::default_bootstrap_hosts(n).empty(), "R: network " + std::to_string(n) + " ships defaults");
    check(rl::kBootstrapRelayPort == 59321, "R: bootstrap relay port is not 59321");
    const V none, ips = {"127.0.0.1", "10.0.0.5", "::1"};
    auto p = rl::resolve_bootstrap(0, false, none, "", ips);
    check(p.use == m && p.self.empty() && p.dup.empty(), "R: mainnet, no --relay-peer: does not dial both defaults");
    p = rl::resolve_bootstrap(3, false, none, "0.0.0.0:59321", ips);
    check(p.use.empty() && p.self.empty() && p.dup.empty(), "R: regtest dials a default");
    p = rl::resolve_bootstrap(0, true, {"1.2.3.4:5"}, "0.0.0.0:59321", ips);
    check(p.use.empty() && p.self.empty() && p.dup.empty(), "R: --no-relay-bootstrap does not empty the list");
    p = rl::resolve_bootstrap(0, false, {B}, "", ips);
    check(p.use == V{A} && p.dup == V{B}, "R: a default given as --relay-peer is dialled twice");
    p = rl::resolve_bootstrap(0, false, none, "109.123.238.32:59321", ips);        // self = the listen host
    check(p.use == V{B} && p.self == V{A}, "R: self (listen host) not skipped");
    const V ips_b = {"127.0.0.1", "158.220.92.171"};
    p = rl::resolve_bootstrap(0, false, none, "0.0.0.0:59321", ips_b);             // self = a local address
    check(p.use == V{A} && p.self == V{B}, "R: self (local address, wildcard listen) not skipped");
    p = rl::resolve_bootstrap(0, false, none, "0.0.0.0:60700", ips_b);             // same IP, another port: kept
    check(p.use == m && p.self.empty(), "R: a local address on another relay port was skipped as self");
    p = rl::resolve_bootstrap(0, false, none, "", ips_b);                           // dial-only: never self
    check(p.use == m && p.self.empty(), "R: a dial-only node skipped a default as self");
    const Run h = run(safe({"--help"}), 5000);
    check(h.out.find("--no-relay-bootstrap") != std::string::npos, "R: --help does not list --no-relay-bootstrap");
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
    bootstrap_rows();
    if (knows_version) { table_rows(); rig_rows(); fuse_rows(); share_sum_rows(); }
    else std::printf("T/K/X/C/F/S rows SKIPPED: this binary does not list --version, so a flag row could start it live\n");

    std::printf("v37_xmr_cli_strict_kat: %d passed, %d failed\n", g_pass, g_fail);
    if (g_fail != 0) { std::printf("RESULT: FAIL\n"); return 1; }
    std::printf("RESULT: PASS\n");
    return 0;
}
