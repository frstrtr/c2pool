// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// v37_xmr_fee_model_kat -- the v36 fee model on the v37 XMR lane
// (src/c2pool/v37/xmr/xmr_fee_model.hpp). Consumer tree only.
//
// Suites
//   A  the donation address: CryptoNote base58 + keccak checksum decode of the
//      compiled-in address == the pinned (B, A) constants; the rig address
//      round-trips to its known keys; corrupted / truncated / integrated
//      inputs are refused; the donation ref torsion-checks.
//   B  give-author = a u16 CARRIED IN THE PoW-COMMITTED RECEIPT (S3): v36
//      encoding, the exact two-push weight split, the gate-OFF single push
//      (master-identical), and the fold of a receipt stream is a function of
//      the STREAM only -- two nodes with different give-author % compute
//      identical pushes (and so identical coinbases, suite D5), while a
//      node-local amount scaler (the NO-SHIP shape) would not.
//   C  node-owner fee = probabilistic payee substitution AT JOB ISSUE: the
//      roll boundaries and choose_payee (the payee the job's rbind commits
//      to; the relay side is pinned in v37_xmr_fee_rbind_kat).
//   D  the donation output on real assembled blocks (the C4-capture monerod
//      arm, deterministic): ONE donation output = max(1, residual) (S1),
//      exact-sum, the shape gate + the donation property ACCEPT; in the
//      exhaust case the 1-piconero dust comes from the LARGEST payee (S2); a
//      coinbase WITHOUT the donation output is REFUSED by the serve property
//      AND by the receive-side booking (decode_lane_coinbase_fee); a separate
//      residual-sink output is refused by the serve property; give-author
//      credit to the donation is booked as an owed deduction; the pure
//      location rule.
//   E  NO finder output anywhere (every output role is Owed or the Fixed
//      donation output).
//   F  the X6 allocator rules in isolation (S1 fold, S2 largest-payee dust,
//      ties, cap slots, the 1-pico edge, and the unchanged non-fold shape).
// ---------------------------------------------------------------------------
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/template/xmr_monerod_miner_data.hpp"
#include "impl/xmr/template/xmr_block_assembly.hpp"

#include "c2pool/v37/xmr/xmr_coinbase_authority.hpp"
#include "c2pool/v37/xmr/xmr_fee_model.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_provider.hpp"
#include "c2pool/v37/xmr/xmr_settlement_coinbase_shape.hpp"

#include "xmr_c4_parity_golden.hpp"

using namespace c2pool::xmr::native;

namespace o2   = c2pool::v37n::xmr::o2;
namespace asm_ = c2pool::xmr::assembly;
namespace auth = c2pool::v37n::xmr::authority;
namespace fee  = c2pool::v37n::xmr::fee;
namespace x6   = ::v37::xmr::settle;
namespace G4   = c2pool::xmr::native::golden_c4;

namespace {

int g_fail = 0;
int g_checks = 0;

#define CHECK(cond, ...)                                       \
    do {                                                       \
        const bool _ok = (cond);                               \
        ++g_checks;                                            \
        if (!_ok) ++g_fail;                                    \
        std::printf("  [%s] ", _ok ? "PASS" : "FAIL");         \
        std::printf(__VA_ARGS__);                              \
        std::printf("\n");                                     \
    } while (0)

bool CHECK_RET_OK(bool ok) {
    ++g_checks; if (!ok) ++g_fail;
    std::printf("  [%s] template builds\n", ok ? "PASS" : "FAIL");
    return ok;
}

std::string hex(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(2 * n);
    for (std::size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}
template <class V> std::string hex(const V& v) { return hex(reinterpret_cast<const std::uint8_t*>(v.data()), v.size()); }

std::array<std::uint8_t, 32> point_of(std::uint8_t k) {
    ::xmr::coin::SecretKey sec{};
    sec.data()[0] = k;
    ::xmr::coin::PublicKey pub{};
    if (!::xmr::coin::secret_key_to_public_key(sec, pub)) return {};
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), pub.data(), 32);
    return out;
}

const std::uint32_t LANE_CHAIN = 0x0000ABCDu;

// ---------------------------------------------------------------------------
// Suite A -- the donation address
// ---------------------------------------------------------------------------
void suite_address() {
    std::printf("== A. donation address: CN base58 + keccak checksum ==\n");
    const fee::DecodedAddress d = fee::decode_xmr_address(fee::kDonationAddress);
    CHECK(d.ok, "the compiled-in donation address decodes: %s", d.ok ? "ok" : d.why.c_str());
    CHECK(d.prefix == fee::kPrefixMainnetStd && !d.subaddress, "mainnet STANDARD address (network byte %llu == 18)",
          static_cast<unsigned long long>(d.prefix));
    CHECK(hex(d.spend) == fee::kDonationSpendHex, "decoded spend key B == pinned kDonationSpendHex (%s…)", hex(d.spend).substr(0, 16).c_str());
    CHECK(hex(d.view) == fee::kDonationViewHex, "decoded view key A == pinned kDonationViewHex (%s…)", hex(d.view).substr(0, 16).c_str());
    CHECK(d.ref() == fee::donation_ref(), "donation_ref() == make_xmr_std(decoded B, A)");
    CHECK(fee::donation_identity() == ::v37::xmr::xmr_identity_key(fee::donation_ref()), "donation_identity() == identity_key(donation_ref)");
    CHECK(::v37::xmr::xmr_ref_valid(fee::donation_ref()), "the donation ref passes the LIVE ed25519 torsion check");

    // The regtest rig's miner address -> its known (spend, view) (cross-check of the decoder).
    const fee::DecodedAddress r = fee::decode_xmr_address(
        "47hHNpPZU8qQRAQ2LZupNPiQoeQvo18tA5DPZvwkWajH1qsUkwHmbugfMyoXv1yQdPQhDTq6x8MFiV6cMmi7uUmX7yhotxk");
    CHECK(r.ok && hex(r.spend) == "a03ab8e2191c928bffa5c875c42834f793a356c12cd6d319310619055bcc7005" &&
          hex(r.view) == "099b5b60c9a497e55985b3843c3fda8da741814c39f0cda7fab35c0c4c1c023d",
          "rig address 47hHN… decodes to the rig's --payee-spend/--payee-view keys");

    std::string bad = fee::kDonationAddress; bad[20] = (bad[20] == 'a') ? 'b' : 'a';
    const fee::DecodedAddress b1 = fee::decode_xmr_address(bad);
    CHECK(!b1.ok, "one flipped character -> refused (%s)", b1.why.c_str());
    const fee::DecodedAddress b2 = fee::decode_xmr_address(std::string(fee::kDonationAddress).substr(0, 90));
    CHECK(!b2.ok, "truncated address -> refused (%s)", b2.why.c_str());
    const fee::DecodedAddress b3 = fee::decode_xmr_address("0OIl");
    CHECK(!b3.ok, "non-base58 characters -> refused (%s)", b3.why.c_str());
    CHECK(!fee::decode_xmr_address("").ok, "empty string -> refused");
}

// ---------------------------------------------------------------------------
// Suite B -- give-author u16 carried in the receipt
// ---------------------------------------------------------------------------
void suite_give_author() {
    std::printf("== B. give-author: a u16 CARRIED IN THE RECEIPT, folded by weight ==\n");
    CHECK(fee::give_author_u16(0.0) == 0, "0%% -> u16 0 (the CCS default: off)");
    CHECK(fee::give_author_u16(1.0) == 655, "1%% -> u16 655 (65535*1/100 = 655.35)");
    CHECK(fee::give_author_u16(0.5) == 328, "0.5%% -> u16 328 (327.675 rounded half-up)");
    CHECK(fee::give_author_u16(100.0) == 65535 && fee::give_author_u16(250.0) == 65535, "100%% (and above) -> 65535");
    CHECK(fee::give_author_u16(-3.0) == 0, "negative -> 0");

    const auto s0 = fee::split_receipt_weight(2000, 0);
    CHECK(s0.miner == 2000 && s0.donation == 0, "d=0: miner keeps the whole weight");
    const auto s1 = fee::split_receipt_weight(2000, 655);
    CHECK(s1.donation == 19 && s1.miner == 1981, "w=2000 d=655: donation floor(2000*655/65535)=19, miner 1981");
    const auto s2 = fee::split_receipt_weight(2000, 65535);
    CHECK(s2.donation == 2000 && s2.miner == 0, "d=65535: all to the donation");
    bool exact = true;
    std::mt19937_64 rng(42);
    for (int i = 0; i < 20000 && exact; ++i) {
        const std::uint64_t w = rng() >> (rng() % 60);
        const std::uint16_t d = static_cast<std::uint16_t>(rng());
        const auto s = fee::split_receipt_weight(w, d);
        exact = (s.miner + s.donation == w) && (s.donation <= w);
    }
    CHECK(exact, "20000 random (w, d): miner + donation == w exactly (no weight created or lost)");
    const auto big = fee::split_receipt_weight(UINT64_MAX, 65534);
    CHECK(big.miner + big.donation == UINT64_MAX, "u64-max weight: 128-bit product, still exact");

    // Pushes of ONE PoW-committed receipt: gate OFF = one push at the legacy
    // weight (master); gate ON = (payee, 65535 - d) then (donation, d) iff d > 0.
    ::v37::ScriptRef miner = ::v37::xmr::make_xmr_std(point_of(1), point_of(2));
    auto off = fee::receipt_lane_pushes(miner, 655, /*fee_on=*/false, 1);
    CHECK(off.size() == 1 && off[0].first == miner && off[0].second == 1,
          "gate OFF: ONE push (payee, 1) whatever the u16 -- byte-identical to master's receipt stream");
    auto p0 = fee::receipt_lane_pushes(miner, 0, true);
    CHECK(p0.size() == 1 && p0[0].first == miner && p0[0].second == fee::kFeeReceiptWeight,
          "gate ON, d=0 -> ONE push (payee, 65535)");
    auto p1 = fee::receipt_lane_pushes(miner, 655, true);
    CHECK(p1.size() == 2 && p1[0].first == miner && p1[0].second == 65535 - 655 && p1[1].first == fee::donation_ref() && p1[1].second == 655,
          "gate ON, d=655 -> (payee, 64880) then (donation, 655): v36 att*(65535-d) / att*d");
    auto p2 = fee::receipt_lane_pushes(miner, 65535, true);
    CHECK(p2.size() == 1 && p2[0].first == fee::donation_ref() && p2[0].second == 65535, "gate ON, d=65535 -> the whole receipt to the donation");
    CHECK(fee::kFeeReceiptWeight == 65535 && fee::kFeeModelVersion == 1, "the pinned per-receipt weight (65535) and gate version (1)");
    ::v37::LaneParams lp;
    CHECK(!lp.fee.enabled && lp.fee.version == 0 && !fee::fee_model_on(lp), "LaneParams default: FeeModelGate OFF (master-identical)");
    lp.fee = ::v37::FeeModelGate::for_version(1);
    CHECK(fee::fee_model_on(lp), "FeeModelGate::for_version(1) -> ON");
    CHECK(!::v37::FeeModelGate::for_version(2).enabled && !::v37::FeeModelGate::for_version(0).enabled, "unknown / 0 versions -> OFF (fail-safe)");

    // The fold is a function of the STREAM. Node A mints with 0.5%, node B with 1.0%;
    // both fold the SAME interleaved stream of (payee, u16) receipts -- the folding
    // node's own policy is not an input.
    const std::uint16_t dA = fee::give_author_u16(0.5), dB = fee::give_author_u16(1.0);
    ::v37::ScriptRef minerA = ::v37::xmr::make_xmr_std(point_of(5), point_of(6));
    ::v37::ScriptRef minerB = ::v37::xmr::make_xmr_std(point_of(7), point_of(6));
    std::vector<std::pair<::v37::ScriptRef, std::uint16_t>> stream;
    for (int i = 0; i < 50; ++i) stream.emplace_back((i % 3) ? minerA : minerB, (i % 3) ? dA : dB);
    auto fold = [&](const std::vector<std::pair<::v37::ScriptRef, std::uint16_t>>& st) {
        std::map<::v37::bytes32, std::uint64_t> w;
        std::vector<std::pair<::v37::ScriptRef, std::uint64_t>> pushes;
        for (const auto& [payee, d] : st)
            for (const auto& p : fee::receipt_lane_pushes(payee, d, true)) { pushes.push_back(p); w[::v37::xmr::xmr_identity_key(p.first)] += p.second; }
        return std::make_pair(pushes, w);
    };
    const auto fa = fold(stream);   // "node A" (give-author 0.5%) folding
    const auto fb = fold(stream);   // "node B" (give-author 1.0%) folding
    CHECK(fa.first == fb.first && fa.second == fb.second, "nodes with DIFFERENT give-author %% fold the shared stream to IDENTICAL pushes (%zu pushes)", fa.first.size());
    std::uint64_t wout = 0; for (const auto& [k, v] : fa.second) wout += v;
    CHECK(wout == 50ull * fee::kFeeReceiptWeight, "total folded weight == 50 receipts x 65535 (%llu)", static_cast<unsigned long long>(wout));
    CHECK(fa.second.count(fee::donation_identity()) && fa.second.at(fee::donation_identity()) == 33ull * dA + 17ull * dB,
          "the donation accrues exactly the receipts' own u16s (33 x %u + 17 x %u = %llu)", (unsigned)dA, (unsigned)dB,
          static_cast<unsigned long long>(fa.second.at(fee::donation_identity())));
    // The NO-SHIP contrast: a node-local coinbase scaler makes the result depend on WHO folds.
    auto scaler = [](std::uint64_t reward, double pct) { return static_cast<std::uint64_t>(double(reward) * pct / 100.0); };
    CHECK(scaler(600000000000ull, 0.5) != scaler(600000000000ull, 1.0),
          "control: a node-local amount scaler (the rejected shape) diverges 0.5%% vs 1.0%% -- the receipt u16 does not");
}

// ---------------------------------------------------------------------------
// Suite C -- node-owner fee at job issue
// ---------------------------------------------------------------------------
void suite_owner_fee() {
    std::printf("== C. node-owner fee: probabilistic payee substitution AT JOB ISSUE ==\n");
    CHECK(fee::pct_to_bp(0) == 0 && fee::pct_to_bp(1.0) == 100 && fee::pct_to_bp(0.25) == 25 && fee::pct_to_bp(100) == 10000, "pct -> basis points");
    CHECK(!fee::owner_fee_hit(0, 0), "fee 0 -> never substitutes (even roll 0)");
    CHECK(fee::owner_fee_hit(0, 1) && !fee::owner_fee_hit(1, 1), "fee 1bp: roll%%10000 == 0 hits, 1 does not");
    CHECK(fee::owner_fee_hit(9999, 10000), "fee 100%%: every roll hits");
    CHECK(fee::owner_fee_hit(4999, 5000) && !fee::owner_fee_hit(5000, 5000), "fee 50%%: boundary 4999 hit / 5000 miss");
    std::mt19937_64 rng(7);
    std::uint64_t hits = 0; const int N = 200000;
    for (int i = 0; i < N; ++i) hits += fee::owner_fee_hit(rng(), 250) ? 1 : 0;
    const double rate = 100.0 * double(hits) / N;
    CHECK(rate > 2.35 && rate < 2.65, "2.5%% fee over %d rolls -> %.3f%% substituted", N, rate);

    ::v37::ScriptRef miner = ::v37::xmr::make_xmr_std(point_of(1), point_of(2));
    ::v37::ScriptRef owner = ::v37::xmr::make_xmr_std(point_of(9), point_of(2));
    bool sub = false;
    CHECK(fee::choose_payee(miner, owner, 5000, 4999, &sub) == owner && sub, "hit -> the JOB's payee is the owner");
    CHECK(fee::choose_payee(miner, owner, 5000, 5000, &sub) == miner && !sub, "miss -> the miner stays the payee");
    CHECK(fee::choose_payee(miner, std::nullopt, 10000, 0, &sub) == miner && !sub, "no owner configured -> never substitutes");
    CHECK(::v37::xmr::xmr_ref_valid(owner), "the owner payee is an ordinary valid XMR ref (peer-admissible work)");
    const auto pushes = fee::receipt_lane_pushes(owner, 655, true);
    CHECK(pushes.size() == 2 && pushes[0].first == owner, "an owner-fee receipt's lane pushes credit the OWNER (plus the donation share from its u16)");
}

// ---------------------------------------------------------------------------
// Suite D -- the donation output on assembled blocks
// ---------------------------------------------------------------------------
class CannedTransport final : public ::c2pool::xmr::node::IMonerodTransport {
public:
    explicit CannedTransport(std::string body) : body_(std::move(body)) {}
    void rpc_post(const std::string&, std::function<void(const ::c2pool::xmr::node::RpcResponse&)> cb) override {
        ::c2pool::xmr::node::RpcResponse r; r.body.assign(body_.begin(), body_.end()); cb(r);
    }
    void zmq_subscribe(const std::string&, std::function<void(const ::c2pool::xmr::node::ZmqFrame&)>) override {}
private:
    std::string body_;
};

enum class Arm { FeeModel, NoMarker, ForeignSink };

struct Built {
    o2::XmrOwedFixture       ledger{static_cast<::v37::ChainId>(LANE_CHAIN)};
    o2::XmrSettlementConfig  scfg;
    CannedTransport          tx{G4::MD_RAW_JSON};
    tmpl::MonerodMinerDataSource src{tx};
    std::unique_ptr<o2::XmrSettlementTemplateProvider> provider;
    o2::SettlementSnapshot   snap;
    asm_::BlockBytes         bytes;
    bool                     ok = false;
    std::string              why;
    // owed: list of (ref, amount); donation_owed > 0 seeds give-author credit to the donation.
    Built(Arm arm, const std::vector<std::pair<::v37::ScriptRef, std::uint64_t>>& owed, std::uint64_t donation_owed = 0) {
        for (const auto& [r, a] : owed) ledger.seed_owed(r, a);
        if (donation_owed) ledger.seed_owed(fee::donation_ref(), donation_owed);
        ledger.learn_ref(fee::donation_ref());
        scfg.h_min = 0; scfg.output_cap = 0;
        if (arm == Arm::ForeignSink) scfg.set_residual_sink_std(point_of(4), point_of(2));
        else { scfg.residual_sink = fee::donation_ref(); scfg.residual_sink_identity = fee::donation_identity(); }
        if (arm == Arm::FeeModel) scfg.fixed = {fee::donation_marker()};
        if (!src.poll(&why)) { why = "daemon arm did not parse the capture: " + why; return; }
        provider = std::make_unique<o2::XmrSettlementTemplateProvider>(src, ledger, scfg, 0);
        if (!provider->refresh()) { why = provider->last_error(); return; }
        snap = provider->current();
        if (!snap.valid || !snap.tpl) { why = "no template"; return; }
        ok = snap.tpl->materialize(0, bytes, &why);
    }
    auth::CoinbaseBooking book() const {
        std::vector<::v37::bytes32> cands{ledger.ledger().owed_digest()};
        return auth::decode_lane_coinbase_fee(bytes.full_blob, LANE_CHAIN, cands, ledger.keys(), ledger.pay_of());
    }
};

std::vector<std::pair<::v37::ScriptRef, std::uint64_t>> three_owed(std::uint64_t scale) {
    return {{::v37::xmr::make_xmr_std(point_of(1), point_of(2)), 3 * scale},
            {::v37::xmr::make_xmr_std(point_of(3), point_of(2)), 2 * scale},
            {::v37::xmr::make_xmr_std(point_of(8), point_of(2)), 1 * scale}};   // distinct keys: derive_output reads B/A only, so std(P1,P2) and sub(P1,P2) derive the SAME one-time key
}

void suite_donation_blocks() {
    std::printf("== D. the ONE mandatory donation output on assembled blocks (C4 capture, monerod arm) ==\n");
    const ::v37::bytes32 D = fee::donation_identity();

    // D1: fee model armed, small owed -> [3 owed][donation = 1 + residual], ONE donation output (S1).
    Built a(Arm::FeeModel, three_owed(1'000'000'000ull));
    CHECK(a.ok, "fee-model template builds + materializes: %s", a.ok ? "ok" : a.why.c_str());
    if (!a.ok) return;
    const auto& outs = a.snap.tpl->outputs();
    const std::uint64_t reward = a.snap.tpl->reward();
    std::uint64_t sum = 0, don = 0; for (const auto& o : outs) { sum += o.amount; if (o.identity == D) don += o.amount; }
    CHECK(outs.size() == 4, "S1: outputs = 3 owed + ONE donation output = 4 (%zu; was 5 = owed + marker + sink)", outs.size());
    CHECK(outs.back().role == x6::CoinbaseOutput::Role::Fixed && outs.back().identity == D && outs.back().amount == reward - 6'000'000'000ull,
          "S1: the last output is the donation, Fixed, = reward - owed = 1 + residual (%llu): the residual FOLDS into it",
          static_cast<unsigned long long>(outs.back().amount));
    bool no_sink = true; for (const auto& o : outs) no_sink &= (o.role != x6::CoinbaseOutput::Role::Sink);
    CHECK(no_sink, "S1: no separate residual-sink output");
    CHECK(sum == reward, "exact-sum: Σ outputs %llu == reward %llu (nothing burned)", static_cast<unsigned long long>(sum), static_cast<unsigned long long>(reward));
    CHECK(don == reward - 6'000'000'000ull, "the donation address receives exactly reward - Σowed (%llu)", static_cast<unsigned long long>(don));
    const o2::KFairCoinbaseShape sh = o2::inspect_kfair_coinbase(*a.snap.tpl, a.ledger.ledger().owed_digest());
    CHECK(sh.ok, "K_fair shape gate ACCEPTs: %s", sh.ok ? "ok" : sh.why.c_str());
    const fee::MarkerLocation dm = fee::inspect_donation_marker(outs, D);
    CHECK(dm.ok && dm.marker == 3, "serve-side donation property ACCEPTs (donation output @3)");
    const auth::CoinbaseBooking bk = a.book();
    CHECK(bk.ok, "receive side: decode_lane_coinbase_fee BOOKS it: %s", bk.ok ? "ok" : bk.why.c_str());
    CHECK(bk.payout.size() == 3 && !bk.payout.count(D), "payout = the 3 owed payees only (the donation output is coverage, D1): %zu payees, donation %s",
          bk.payout.size(), bk.payout.count(D) ? "PRESENT" : "absent");
    CHECK(bk.sink_total == static_cast<long long>(don), "sink_total == the donation output (%lld)", bk.sink_total);
    CHECK(bk.total == reward, "booked total == reward");

    // D2 (S2): the owed pass EXHAUSTS the budget -> the donation output is the 1-piconero
    // minimum, and that piconero comes from the LARGEST payee (V36), not the last partial one.
    {
        const std::uint64_t R = reward;   // same capture, same reward
        const ::v37::ScriptRef p1 = ::v37::xmr::make_xmr_std(point_of(1), point_of(2));
        const ::v37::ScriptRef p2 = ::v37::xmr::make_xmr_std(point_of(3), point_of(2));
        const std::uint64_t big = R / 10 * 8;   // whichever K_fair order: first = 0.8R (LARGEST), second = the 0.2R partial
        Built s(Arm::FeeModel, {{p1, big}, {p2, big}});
        CHECK(s.ok, "exhaust-case template builds: %s", s.ok ? "ok" : s.why.c_str());
        if (s.ok && s.snap.tpl->reward() == R) {
            const auto& so = s.snap.tpl->outputs();
            std::uint64_t ssum = 0; for (const auto& o : so) ssum += o.amount;
            CHECK(so.size() == 3 && so.back().role == x6::CoinbaseOutput::Role::Fixed && so.back().identity == D && so.back().amount == 1,
                  "S2: [largest][partial][donation 1]: the coinbase ends in the 1-piconero donation output (no residual)");
            CHECK(so.size() == 3 && so[0].amount == big - 1 && so[1].amount == R - big,
                  "S2: the LARGEST payee pays the 1-piconero dust (%llu = 0.8R - 1); the last partial payee is untouched (%llu = R - 0.8R)",
                  static_cast<unsigned long long>(so[0].amount), static_cast<unsigned long long>(so.size() > 1 ? so[1].amount : 0));
            CHECK(ssum == R, "S2 exact-sum");
            const fee::MarkerLocation sm = fee::inspect_donation_marker(so, D);
            CHECK(sm.ok && sm.marker == 2, "serve-side property ACCEPTs the 1-piconero shape");
            const auto sbk = s.book();
            CHECK(sbk.ok && sbk.sink_total == 1 && !sbk.payout.count(D), "booked: donation = 1 piconero coverage, no ledger deduction on the donation: %s",
                  sbk.ok ? "ok" : sbk.why.c_str());
            CHECK(sbk.ok && sbk.payout.size() == 2 && sbk.payout.at(so[0].identity) == static_cast<long long>(big - 1),
                  "booked: the largest payee is paid 0.8R - 1 -- the 1 piconero stays OWED to it (lossless carry)");
        } else if (s.ok) {
            CHECK(false, "exhaust-case reward %llu != D1 reward %llu (capture drifted)", static_cast<unsigned long long>(s.snap.tpl->reward()),
                  static_cast<unsigned long long>(R));
        }
    }

    // D3: REFUSE-IF-ABSENT. Same ledger shape (owed exhausts), the donation output NOT configured.
    Built n(Arm::NoMarker, three_owed(1'000'000'000'000'000ull));
    CHECK(n.ok, "no-donation template builds (X6 allows fixed=[]): %s", n.ok ? "ok" : n.why.c_str());
    if (n.ok) {
        const o2::KFairCoinbaseShape nsh = o2::inspect_kfair_coinbase(*n.snap.tpl, n.ledger.ledger().owed_digest());
        CHECK(nsh.ok, "(the K_fair gate alone would ACCEPT it -- the donation property is what closes the gap)");
        const fee::MarkerLocation nm = fee::inspect_donation_marker(n.snap.tpl->outputs(), D);
        CHECK(!nm.ok, "serve side REFUSES a coinbase WITHOUT the donation output: %s", nm.why.c_str());
        const auto nbk = n.book();
        CHECK(!nbk.ok && nbk.is_lane && nbk.why.rfind("donation-refused:", 0) == 0 && nbk.payout.empty(),
              "receive side REFUSES to book it (every node): %s", nbk.why.c_str());
    }
    // D3b: no fixed donation output, residual paid to a donation SINK output (the pre-S1 shape):
    // the serve side refuses the separate sink (S1); on-chain the last output pays the donation
    // >= 1 piconero, so the receive side books it (it IS indistinguishable from 1 + residual).
    Built n2(Arm::NoMarker, three_owed(1'000'000'000ull));
    if (CHECK_RET_OK(n2.ok)) {
        const fee::MarkerLocation nm2 = fee::inspect_donation_marker(n2.snap.tpl->outputs(), D);
        CHECK(!nm2.ok, "serve side REFUSES a separate residual-sink output (must fold, S1): %s", nm2.why.c_str());
        const auto nbk2 = n2.book();
        CHECK(nbk2.ok && !nbk2.payout.count(D),
              "receive side: a last output paying the donation >= 1 piconero books (on-chain == the S1 shape): %s", nbk2.ok ? "ok" : nbk2.why.c_str());
    }
    // D3c: a foreign residual sink (a gate-OFF node's per-node sink) -> not decodable by a fee-model node.
    Built f(Arm::ForeignSink, three_owed(1'000'000'000ull));
    if (CHECK_RET_OK(f.ok)) {
        const auto fbk = f.book();
        CHECK(!fbk.ok, "a coinbase paying a per-node residual sink is REFUSED by a fee-model peer: %s", fbk.why.c_str());
    }

    // D4: give-author credit to the donation is paid as an OWED output BEFORE the donation
    //     output and booked as a ledger deduction (the donation output stays coverage).
    Built g(Arm::FeeModel, three_owed(1'000'000'000ull), 777'000'000ull);
    CHECK(g.ok, "template with donation give-author credit builds: %s", g.ok ? "ok" : g.why.c_str());
    if (g.ok) {
        const auto& go = g.snap.tpl->outputs();
        std::size_t owed_to_D = 0; for (const auto& o : go) if (o.role == x6::CoinbaseOutput::Role::Owed && o.identity == D) ++owed_to_D;
        CHECK(owed_to_D == 1, "the donation's give-author credit is an ordinary K_fair OWED output");
        const auto gbk = g.book();
        CHECK(gbk.ok && gbk.payout.count(D) && gbk.payout.at(D) == 777'000'000ll,
              "booked: payout[donation] == its owed 777000000 (a ledger deduction): %s", gbk.ok ? "ok" : gbk.why.c_str());
        std::uint64_t gsum = 0, gdon = 0; for (const auto& o : go) { gsum += o.amount; if (o.identity == D) gdon += o.amount; }
        CHECK(gbk.ok && gbk.sink_total == static_cast<long long>(gdon - 777'000'000ull), "sink_total == the donation output only");
        CHECK(gsum == g.snap.tpl->reward(), "exact-sum holds with a donation owed output");
    }

    // D5: two ledgers built from the SAME receipts (a node minting at 0.5% and one at 1.0%
    //     fold the same stream) -> byte-identical coinbase.
    {
        const std::uint16_t dA = fee::give_author_u16(0.5), dB = fee::give_author_u16(1.0);
        const ::v37::ScriptRef mA = ::v37::xmr::make_xmr_std(point_of(1), point_of(2));
        const ::v37::ScriptRef mB = ::v37::xmr::make_xmr_std(point_of(3), point_of(2));
        std::vector<std::pair<::v37::ScriptRef, std::uint16_t>> stream;
        for (int i = 0; i < 40; ++i) stream.emplace_back((i & 1) ? mA : mB, (i & 1) ? dA : dB);
        auto ledger_of = [&](const std::vector<std::pair<::v37::ScriptRef, std::uint16_t>>& st) {
            std::map<::v37::ScriptRef, std::uint64_t> w;
            for (const auto& [payee, d] : st) for (const auto& p : fee::receipt_lane_pushes(payee, d, true)) w[p.first] += p.second;
            std::vector<std::pair<::v37::ScriptRef, std::uint64_t>> owed; std::uint64_t dn = 0;
            for (const auto& [ref, ww] : w) { if (ref == fee::donation_ref()) dn = ww * 1'000ull; else owed.emplace_back(ref, ww * 1'000ull); }
            return std::make_pair(owed, dn);
        };
        const auto la = ledger_of(stream), lb = ledger_of(stream);
        Built A(Arm::FeeModel, la.first, la.second), B(Arm::FeeModel, lb.first, lb.second);
        CHECK(A.ok && B.ok && A.bytes.coinbase_prefix() == B.bytes.coinbase_prefix(),
              "two nodes (give-author 0.5%% vs 1.0%%) folding the same receipts -> BYTE-IDENTICAL miner_tx (%zu B)", A.bytes.coinbase_prefix().size());
        CHECK(la.second > 0, "and the donation holds give-author credit from both nodes' receipts (%llu)", static_cast<unsigned long long>(la.second));
    }

    // D6: the pure location rule (S1: the LAST output is the donation output, >= 1).
    const ::v37::bytes32 X = ::v37::xmr::xmr_identity_key(::v37::xmr::make_xmr_std(point_of(1), point_of(2)));
    auto loc = [&](std::vector<::v37::bytes32> ids, std::vector<std::uint64_t> am) { return fee::locate_donation_marker(ids, am, D); };
    auto l1 = loc({X, X, D}, {5, 6, 99});
    CHECK(l1.ok && l1.marker == 2, "[X X D:99] -> donation output @2 (1 + residual 98)");
    auto l2 = loc({X, D, D}, {5, 7, 1});
    CHECK(l2.ok && l2.marker == 2, "[X D:7 D:1] -> donation output @2, D:7 is an OWED output");
    auto l3 = loc({X, D, D}, {5, 1, 1});
    CHECK(l3.ok && l3.marker == 2, "[X D:1 D:1] -> the LAST is the donation output (no S/N ambiguity left, S1)");
    CHECK(!loc({X, X}, {5, 6}).ok, "[X X] -> REFUSED (no donation output)");
    CHECK(!loc({X, D}, {5, 0}).ok, "[X D:0] -> REFUSED (a donation output below the 1-piconero minimum)");
    CHECK(!loc({D, X}, {1, 5}).ok, "[D:1 X] -> REFUSED (the donation output is not at the canonical tail)");
    CHECK(!loc({}, {}).ok, "no outputs -> REFUSED");
    std::map<::v37::bytes32, long long> po; long long st = 7 + 1 + 99;   // the decoder tallied every D vout as sink
    po[X] = 5;
    CHECK(fee::apply_donation_rule({X, D, D, D}, {5, 7, 1, 99}, D, po, st, nullptr) && po[D] == 8 && st == 99,
          "apply_donation_rule re-books the pre-tail D:7 + D:1 as owed (8); the donation output stays coverage (99)");

    // E: no finder output anywhere.
    bool roles_ok = true;
    for (const auto& o : outs) roles_ok &= (o.role == x6::CoinbaseOutput::Role::Owed) ||
                                            (o.role == x6::CoinbaseOutput::Role::Fixed && o.identity == D);
    std::printf("== E. NO finder output ==\n");
    CHECK(roles_ok, "every output is Owed or the ONE donation output -- no finder bonus (V36 dropped it), no separate sink");
}

// ---------------------------------------------------------------------------
// Suite F -- the X6 allocator rules in isolation (S1 fold, S2 largest dust)
// ---------------------------------------------------------------------------
void suite_allocator() {
    std::printf("== F. X6 allocate_exact_sum: S1 fold + S2 largest-payee dust ==\n");
    const ::v37::ScriptRef Dref = fee::donation_ref();
    const ::v37::bytes32 D = fee::donation_identity();
    auto ref_of = [](std::uint8_t k) { return ::v37::xmr::make_xmr_std(point_of(k), point_of(2)); };
    auto entry = [&](std::uint8_t k, std::uint64_t owed, std::uint64_t age) {
        x6::OwedEntry e; e.pay = ref_of(k); e.owed = owed; e.first_eligible = age; e.identity = ::v37::xmr::xmr_identity_key(e.pay); return e; };
    auto base = [&](std::uint64_t budget) {
        x6::CoinbaseInputs in; in.base_reward = budget; in.fees = 0; in.output_cap = 64;
        in.residual_sink = Dref; in.residual_sink_identity = D; in.fixed = {fee::donation_marker()};
        return in; };
    auto sumof = [](const std::vector<x6::CoinbaseOutput>& v) { std::uint64_t s = 0; for (const auto& o : v) s += o.amount; return s; };
    x6::BuildError err = x6::BuildError::None;

    { auto in = base(1000); in.owed = {entry(1, 100, 1), entry(3, 50, 2)};
      const auto r = x6::allocate_exact_sum(in, &err);
      CHECK(x6::residual_folds_into_fixed(in) && r.size() == 3 && r[0].amount == 100 && r[1].amount == 50 &&
            r[2].role == x6::CoinbaseOutput::Role::Fixed && r[2].amount == 850 && sumof(r) == 1000,
            "F1 residual 850 folds: [100][50][D:850] (the minimum 1 is inside the residual)"); }
    { auto in = base(1000); in.owed = {entry(1, 400, 1), entry(3, 700, 2)};
      const auto r = x6::allocate_exact_sum(in, &err);
      CHECK(r.size() == 3 && r[0].amount == 400 && r[1].amount == 599 && r[2].amount == 1 && sumof(r) == 1000,
            "F2 exhaust: owed pass pays [400][600]; the dust comes from the LARGEST (600 -> 599), not the first/last: [400][599][D:1]"); }
    { auto in = base(1000); in.owed = {entry(1, 600, 1), entry(3, 700, 2)};
      const auto r = x6::allocate_exact_sum(in, &err);
      CHECK(r.size() == 3 && r[0].amount == 599 && r[1].amount == 400 && r[2].amount == 1,
            "F2' exhaust, largest first: [600->599][400 partial, untouched][D:1] (the pre-S2 rule would have made it [600][399][1])"); }
    { auto in = base(1000); in.owed = {entry(1, 500, 1), entry(3, 500, 2)};
      const auto r = x6::allocate_exact_sum(in, &err);
      CHECK(r.size() == 3 && r[0].amount == 499 && r[1].amount == 500 && r[2].amount == 1, "F3 tie -> the EARLIEST in K_fair order pays the dust"); }
    { auto in = base(1000); in.output_cap = 1; in.owed = {entry(1, 500, 1)};
      const auto r = x6::allocate_exact_sum(in, &err);
      CHECK(err == x6::BuildError::None && r.size() == 1 && r[0].amount == 1000 && r[0].identity == D,
            "F4 cap 1 = the fixed output alone: allowed (no sink slot when it folds) -> [D:1000], owed carries"); }
    { auto in = base(1); in.owed = {entry(1, 5, 1)};
      const auto r = x6::allocate_exact_sum(in, &err);
      CHECK(r.size() == 1 && r[0].identity == D && r[0].amount == 1, "F5 budget 1: the lone payee is driven to 0 and dropped -> [D:1] (its owed carries)"); }
    { auto in = base(1000); in.owed = {entry(1, 100, 1)};
      in.residual_sink = ref_of(9); in.residual_sink_identity = ::v37::xmr::xmr_identity_key(in.residual_sink);   // sink != the fixed payee
      const auto r = x6::allocate_exact_sum(in, &err);
      CHECK(!x6::residual_folds_into_fixed(in) && r.size() == 3 && r[0].amount == 100 && r[1].amount == 1 &&
            r[1].role == x6::CoinbaseOutput::Role::Fixed && r[2].role == x6::CoinbaseOutput::Role::Sink && r[2].amount == 899,
            "F6 no fold (fixed does not pay the sink): the unchanged pre-S1 shape [100][F:1][S:899]"); }
    { auto in = base(1000); in.fixed.clear(); in.output_cap = 1; in.owed = {entry(1, 100, 1)};
      const auto r = x6::allocate_exact_sum(in, &err);
      CHECK(err == x6::BuildError::None && r.size() == 1 && r[0].role == x6::CoinbaseOutput::Role::Sink && r[0].amount == 1000,
            "F7 fee model OFF (fixed=[]): master's shape -- cap 1 = the sink slot, the sink takes it all"); }
    { auto in = base(1000); in.fixed.push_back(fee::donation_marker()); in.fixed.front().pay = ref_of(9); in.output_cap = 1;
      (void)x6::allocate_exact_sum(in, &err);
      CHECK(err == x6::BuildError::CapTooSmall, "F8 two fixed outputs, cap 1 -> CapTooSmall (the fold frees only the sink slot)"); }
}

} // namespace

int main() {
    std::printf("=== v37_xmr_fee_model_kat (v36 fee model on the XMR lane) ===\n");
    suite_address();
    suite_give_author();
    suite_owner_fee();
    suite_donation_blocks();
    suite_allocator();
    std::printf("=== %d/%d checks passed ===\n", g_checks - g_fail, g_checks);
    return g_fail == 0 ? 0 : 1;
}
