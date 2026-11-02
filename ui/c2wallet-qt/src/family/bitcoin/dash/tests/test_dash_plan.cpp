// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KATs for c2wallet-dash-plan, the KEY-FREE DASH plan library (scan & plan
// slice S-A). This binary links ONLY c2wallet-dash-plan (and, privately, the
// hdkeys leaf objects it references); ci/check_key_free.sh runs over it as the
// ctest dash_plan_test_key_free_guard, so a plan that needs key code here fails
// to link or fails the guard.
//
//   P0  compile-time: no plan header declares a key type (see below)
//   P1  the real 170-row XdgF55 getaddressutxos fixture (tip 2563986) at the
//       signer's defaults -> one batch of 128 inputs, the 42 one-duff rows left
//       as dust; size estimates per key encoding pinned
//   P2  the 100000-byte cap boundary: 670 compressed inputs fit one tx, 671
//       split; 552 / 553 for uncompressed keys; max_inputs_per_tx tightens

#include "../DashAddress.hpp"
#include "../DashError.hpp"
#include "../GovCollateral.hpp"
#include "../InjectCaps.hpp"
#include "../InjectManifest.hpp"
#include "../InjectMaturity.hpp"
#include "../SweepPlan.hpp"
#include "../UtxoIntake.hpp"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

// P0: compile-time proof that none of the headers above declares or pulls in a
// key type. Each line below redeclares a name the key layer owns as a
// different kind of entity; if KeyScan.hpp (FoundKey, KeyScanRange,
// find_key_for_address) or the zeroizing secret buffer (SecureBytes) were
// reachable from a plan header, this translation unit would not compile.
namespace c2w::dash {
using FoundKey = void;
using KeyScanRange = void;
[[maybe_unused]] inline constexpr int find_key_for_address = 0;
} // namespace c2w::dash
namespace c2w::secure {
using SecureBytes = void;
} // namespace c2w::secure

using namespace c2w::dash;

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                                                                    \
    do {                                                                                    \
        if (cond) { ++g_pass; }                                                             \
        else { ++g_fail; std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); }   \
    } while (0)

#ifndef C2W_DASH_FIXTURE_DIR
#error "C2W_DASH_FIXTURE_DIR must point at tests/fixtures"
#endif

static const char* kXdgf = "XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u";
static const char* kXdgfScript = "76a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac";
static constexpr int64_t kFixtureTip = 2563986;

static std::string read_file(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// The model's consolidate path (DashInjectModel::Impl::run_plan) on a UTXO list:
// re-screen at the target, then plan_sweep over spendable + immature + dust.
static SweepBatchPlan plan_like_the_signer(const std::vector<Utxo>& utxos, const std::string& address,
                                           int64_t tip, int64_t target, PubkeyEncoding enc,
                                           size_t max_inputs = caps::kMaxInjectInputs,
                                           TargetScreen* screen_out = nullptr)
{
    const TargetScreen ts = rescreen_at_height(utxos, addr_to_h160(address, false), tip, target,
                                               kDefaultMinConf, 1000, true);
    if (screen_out) *screen_out = ts;
    SweepRequest r;
    r.funding_address = address;
    r.utxos = ts.screen.spendable;
    r.utxos.insert(r.utxos.end(), ts.screen.immature.begin(), ts.screen.immature.end());
    r.utxos.insert(r.utxos.end(), ts.screen.dust.begin(), ts.screen.dust.end());
    r.min_confirmations = kDefaultMinConf;
    r.dust_floor = 1000;
    r.max_inputs_per_tx = max_inputs;
    r.key_encoding = enc;
    return plan_sweep(r);
}

static void p1_fixture_one_batch()
{
    std::printf("[P1 the 170-row XdgF55 fixture at tip %lld -> one batch]\n",
                static_cast<long long>(kFixtureTip));
    const std::string json =
        read_file(std::string(C2W_DASH_FIXTURE_DIR) + "/xdgf-getaddressutxos-tip2563986.json");
    CHECK(json.size() > 40000, "fixture readable");
    const UtxoImport imp = parse_getaddressutxos(json, kFixtureTip, false);
    CHECK(imp.utxos.size() == 170, "170 rows");
    CHECK(imp.total == 60963705, "total 0.60963705 DASH");
    CHECK(imp.address == kXdgf, "address derived from the scripts");

    TargetScreen ts;
    const SweepBatchPlan c =
        plan_like_the_signer(imp.utxos, kXdgf, kFixtureTip, kFixtureTip + 2, PubkeyEncoding::Compressed,
                             caps::kMaxInjectInputs, &ts);
    CHECK(ts.screen.spendable.size() == 128 && ts.screen.immature.empty() && ts.screen.dust.size() == 42,
          "screen at tip+2: 128 mature / 0 immature / 42 dust");
    CHECK(c.txs.size() == 1, "one batch");
    CHECK(c.txs.size() == 1 && c.txs[0].inputs.size() == 128, "128 inputs");
    CHECK(c.total_in == 60963663 && c.txs[0].value_out == 60963663,
          "value_out 60963663 = 60963705 - 42 one-duff rows");
    CHECK(c.txs[0].fee == 0 && c.total_fee == 0, "zero fee");
    CHECK(c.skipped_dust == 42 && c.skipped_immature == 0, "42 dust left out");
    CHECK(c.txs[0].est_signed_bytes == 19116, "est 44 + 149*128 = 19116 B (compressed)");
    CHECK(c.txs[0].unsigned_tx.size() == 44 + 41 * 128, "unsigned 44 + 41*128 bytes");
    std::vector<uint8_t> want_spk;
    for (size_t i = 0; i < 50; i += 2) want_spk.push_back(static_cast<uint8_t>(std::stoi(std::string(kXdgfScript + i, 2), nullptr, 16)));
    CHECK(c.txs[0].dest_spk == want_spk, "destination: the funding address itself");

    const SweepBatchPlan u =
        plan_like_the_signer(imp.utxos, kXdgf, kFixtureTip, kFixtureTip + 2, PubkeyEncoding::Uncompressed);
    CHECK(u.txs.size() == 1 && u.txs[0].est_signed_bytes == 23212, "est 44 + 181*128 = 23212 B (uncompressed)");
    const SweepBatchPlan k =
        plan_like_the_signer(imp.utxos, kXdgf, kFixtureTip, kFixtureTip + 2, PubkeyEncoding::Unknown);
    CHECK(k.txs.size() == 1 && k.txs[0].est_signed_bytes == 23212, "unknown encoding plans the 181 B worst case");
    CHECK(c.txs[0].unsigned_tx == u.txs[0].unsigned_tx && c.txs[0].unsigned_tx == k.txs[0].unsigned_tx,
          "the unsigned bytes do not depend on the key encoding");
    // Sorted by (display txid, vout): the planner's default order.
    bool sorted = true;
    for (size_t i = 1; i < c.txs[0].inputs.size(); ++i) {
        const Utxo& a = c.txs[0].inputs[i - 1];
        const Utxo& b = c.txs[0].inputs[i];
        if (a.txid > b.txid || (a.txid == b.txid && a.vout >= b.vout)) sorted = false;
    }
    CHECK(sorted, "inputs sorted by (txid, vout)");
    CHECK(sha256d_display_hex(std::string(c.txs[0].unsigned_tx.begin(), c.txs[0].unsigned_tx.end())).size() == 64,
          "sha256d of the unsigned bytes is computable key-free");
}

static std::vector<Utxo> synthetic_rows(size_t n)
{
    std::vector<Utxo> v;
    v.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        Utxo u;
        u.txid = sha256_hex("c2wallet-dash-plan P2 row " + std::to_string(i));
        u.vout = static_cast<uint32_t>(i % 7);
        u.satoshis = 100000;
        u.height = 2500000 + static_cast<int64_t>(i);
        u.confirmations = kFixtureTip - u.height + 1;
        u.coinbase = true;
        u.script_pubkey_hex = kXdgfScript;
        v.push_back(std::move(u));
    }
    return v;
}

static void p2_byte_cap_boundary()
{
    std::printf("[P2 the 100000 B cap: 670 compressed inputs fit, 671 split]\n");
    const int64_t target = kFixtureTip + 2;
    const SweepBatchPlan a = plan_like_the_signer(synthetic_rows(670), kXdgf, kFixtureTip, target, PubkeyEncoding::Compressed);
    CHECK(a.txs.size() == 1 && a.txs[0].inputs.size() == 670, "670 compressed inputs: one tx");
    CHECK(a.txs.size() == 1 && a.txs[0].est_signed_bytes == 99876, "est 4+3+670*149+1+34+4 = 99876 B");
    const SweepBatchPlan b = plan_like_the_signer(synthetic_rows(671), kXdgf, kFixtureTip, target, PubkeyEncoding::Compressed);
    CHECK(b.txs.size() == 2, "671 compressed inputs: two txs");
    CHECK(b.txs.size() == 2 && b.txs[0].inputs.size() == 670 && b.txs[1].inputs.size() == 1, "split 670 + 1");
    CHECK(b.txs.size() == 2 && b.txs[0].est_signed_bytes <= caps::kMaxInjectTxBytes &&
              b.txs[1].est_signed_bytes == 4 + 1 + 149 + 1 + 34 + 4,
          "every tx within the cap");
    CHECK(b.total_in == 671 * 100000, "every input planned");

    const SweepBatchPlan c = plan_like_the_signer(synthetic_rows(552), kXdgf, kFixtureTip, target, PubkeyEncoding::Uncompressed);
    CHECK(c.txs.size() == 1 && c.txs[0].est_signed_bytes == 99958, "552 uncompressed inputs: one tx, 99958 B");
    const SweepBatchPlan d = plan_like_the_signer(synthetic_rows(553), kXdgf, kFixtureTip, target, PubkeyEncoding::Uncompressed);
    CHECK(d.txs.size() == 2 && d.txs[0].inputs.size() == 552, "553 uncompressed inputs: split 552 + 1");
    const SweepBatchPlan e = plan_like_the_signer(synthetic_rows(553), kXdgf, kFixtureTip, target, PubkeyEncoding::Unknown);
    CHECK(e.txs.size() == 2 && e.txs[0].inputs.size() == 552, "unknown encoding splits like uncompressed");

    const SweepBatchPlan f =
        plan_like_the_signer(synthetic_rows(671), kXdgf, kFixtureTip, target, PubkeyEncoding::Compressed, 600);
    CHECK(f.txs.size() == 2 && f.txs[0].inputs.size() == 600 && f.txs[1].inputs.size() == 71,
          "max_inputs_per_tx 600 (the recommended margin): 600 + 71");
    bool refused = false;
    try {
        SweepRequest r;
        r.funding_address = kXdgf;
        r.utxos = synthetic_rows(3);
        r.max_inputs_per_tx = caps::kMaxInjectInputs + 1;
        (void)plan_sweep(r);
    } catch (const DashAbort&) {
        refused = true;
    }
    CHECK(refused, "max_inputs_per_tx above the node cap is refused");
}

int main()
{
    std::printf("=== c2wallet-dash-plan (key-free) KATs ===\n");
    p1_fixture_one_batch();
    p2_byte_cap_boundary();
    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
