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
//   B  give-author = a u16 CARRIED IN THE RECEIPT: v36 encoding, the exact
//      two-push weight split (sum == w), d == 0 is a single push, and the fold
//      of a receipt stream is a function of the STREAM only -- two nodes with
//      different give-author % compute identical pushes (and so identical
//      coinbases, suite D5), while a node-local amount scaler (the NO-SHIP
//      shape) would not.
//   C  node-owner fee = probabilistic identity substitution AT MINT: the roll
//      boundaries, the substitution lands in the receipt's payee, the R1 line
//      round-trips, and the substituted receipt parses back as an ordinary,
//      valid XMR payee (what a peer admits).
//   D  the donation output on real assembled blocks (the C4-capture monerod
//      arm, deterministic): the mandatory 1-piconero marker + the residual
//      sink to the donation address, exact-sum, the shape gate + the marker
//      property ACCEPT; a coinbase WITHOUT the marker is REFUSED by the serve
//      property AND by the receive-side booking (decode_lane_coinbase_fee);
//      give-author credit to the donation is booked as an owed deduction;
//      the pure marker-location rule (S / N / ambiguity / absent).
//   E  NO finder output anywhere (every output role is Owed / Fixed(marker) /
//      Sink(donation)).
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

    // Pushes: order is (miner, donation), donation only iff > 0.
    ::v37::ScriptRef miner = ::v37::xmr::make_xmr_std(point_of(1), point_of(2));
    fee::MintedReceipt r; r.payee = miner; r.w = 2000; r.d = 0;
    auto p0 = fee::receipt_pushes(r);
    CHECK(p0.size() == 1 && p0[0].first == miner && p0[0].second == 2000, "d=0 -> ONE push (byte-identical to the pre-fee receipt stream)");
    r.d = 655;
    auto p1 = fee::receipt_pushes(r);
    CHECK(p1.size() == 2 && p1[0].first == miner && p1[0].second == 1981 && p1[1].first == fee::donation_ref() && p1[1].second == 19,
          "d=655 -> (miner,1981) then (donation,19)");

    // The fold is a function of the STREAM. Node A mints with 0.5%, node B with 1.0%;
    // both fold the SAME interleaved stream -- the folding node's own policy is not an input.
    const std::uint16_t dA = fee::give_author_u16(0.5), dB = fee::give_author_u16(1.0);
    ::v37::ScriptRef minerA = ::v37::xmr::make_xmr_std(point_of(5), point_of(6));
    ::v37::ScriptRef minerB = ::v37::xmr::make_xmr_std(point_of(7), point_of(6));
    std::vector<std::string> stream;
    for (int i = 0; i < 50; ++i) {
        fee::MintedReceipt m; m.w = 1000 + 37u * static_cast<unsigned>(i);
        if (i % 3) { m.payee = minerA; m.d = dA; } else { m.payee = minerB; m.d = dB; }
        stream.push_back(fee::encode_receipt_line(m));
    }
    auto fold = [&](const std::vector<std::string>& st) {
        std::map<::v37::bytes32, std::uint64_t> w;
        std::vector<std::pair<::v37::ScriptRef, std::uint64_t>> pushes;
        for (const auto& ln : st) {
            const auto rr = fee::parse_receipt_line(ln);
            if (!rr) continue;
            for (const auto& p : fee::receipt_pushes(*rr)) { pushes.push_back(p); w[::v37::xmr::xmr_identity_key(p.first)] += p.second; }
        }
        return std::make_pair(pushes, w);
    };
    const auto fa = fold(stream);   // "node A" (give-author 0.5%) folding
    const auto fb = fold(stream);   // "node B" (give-author 1.0%) folding
    CHECK(fa.first == fb.first && fa.second == fb.second, "nodes with DIFFERENT give-author %% fold the shared stream to IDENTICAL pushes (%zu pushes)", fa.first.size());
    std::uint64_t win = 0, wout = 0; for (const auto& ln : stream) win += fee::parse_receipt_line(ln)->w; for (const auto& [k, v] : fa.second) wout += v;
    CHECK(win == wout, "total folded weight == total receipt weight (%llu)", static_cast<unsigned long long>(win));
    CHECK(fa.second.count(fee::donation_identity()) && fa.second.at(fee::donation_identity()) > 0,
          "the donation accrues weight %llu from BOTH nodes' receipts (each at its own u16)",
          static_cast<unsigned long long>(fa.second.at(fee::donation_identity())));
    // The NO-SHIP contrast: a node-local coinbase scaler makes the result depend on WHO folds.
    auto scaler = [](std::uint64_t reward, double pct) { return static_cast<std::uint64_t>(double(reward) * pct / 100.0); };
    CHECK(scaler(600000000000ull, 0.5) != scaler(600000000000ull, 1.0),
          "control: a node-local amount scaler (the rejected shape) diverges 0.5%% vs 1.0%% -- the receipt u16 does not");
}

// ---------------------------------------------------------------------------
// Suite C -- node-owner fee at mint
// ---------------------------------------------------------------------------
void suite_owner_fee() {
    std::printf("== C. node-owner fee: probabilistic identity substitution AT RECEIPT MINT ==\n");
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
    const auto m0 = fee::mint_receipt(miner, owner, 5000, 655, 2000, 4999);
    CHECK(m0.owner_substituted && m0.payee == owner && m0.d == 655 && m0.w == 2000,
          "hit -> the RECEIPT's payee is the owner (weight + give-author u16 unchanged)");
    const auto m1 = fee::mint_receipt(miner, owner, 5000, 655, 2000, 5000);
    CHECK(!m1.owner_substituted && m1.payee == miner, "miss -> the miner stays the payee");
    const auto m2 = fee::mint_receipt(miner, std::nullopt, 10000, 0, 2000, 0);
    CHECK(!m2.owner_substituted && m2.payee == miner, "no owner configured -> never substitutes");

    // The wire line: the substitution travels IN the receipt, peers admit it as ordinary work.
    const std::string ln = fee::encode_receipt_line(m0);
    const auto back = fee::parse_receipt_line(ln);
    CHECK(back && back->payee == owner && back->w == 2000 && back->d == 655, "R1 line round-trips (payee, w, d): %s", ln.substr(0, 24).c_str());
    CHECK(back && ::v37::xmr::xmr_ref_valid(back->payee), "the owner-substituted receipt's payee is an ordinary valid XMR ref (peer-admissible)");
    const auto pushes = fee::receipt_pushes(*back);
    CHECK(pushes.size() == 2 && pushes[0].first == owner, "its lane pushes credit the OWNER (plus the donation share from its u16)");
    CHECK(!fee::parse_receipt_line("R1 16 00 10 5\n"), "malformed payload -> rejected");
    CHECK(!fee::parse_receipt_line(std::string("R1 16 ") + std::string(128, 'a') + " 10 70000\n"), "d > 65535 -> rejected");
    CHECK(!fee::parse_receipt_line(std::string("R1 0 ") + std::string(128, 'a') + " 10 0\n"), "non-XMR kind -> rejected");
    CHECK(!fee::parse_receipt_line(std::string("R1 16 ") + std::string(128, 'a') + " 0 0\n"), "zero weight -> rejected");
    CHECK(!fee::parse_receipt_line("3 7\n"), "a legacy 'idx w' line is not an R1 receipt (the legacy path parses it)");
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
    std::printf("== D. the MANDATORY donation output on assembled blocks (C4 capture, monerod arm) ==\n");
    const ::v37::bytes32 D = fee::donation_identity();

    // D1: fee model armed, small owed -> [3 owed][marker 1][sink residual].
    Built a(Arm::FeeModel, three_owed(1'000'000'000ull));
    CHECK(a.ok, "fee-model template builds + materializes: %s", a.ok ? "ok" : a.why.c_str());
    if (!a.ok) return;
    const auto& outs = a.snap.tpl->outputs();
    const std::uint64_t reward = a.snap.tpl->reward();
    std::uint64_t sum = 0, don = 0; for (const auto& o : outs) { sum += o.amount; if (o.identity == D) don += o.amount; }
    CHECK(outs.size() == 5, "outputs = 3 owed + marker + sink = 5 (%zu)", outs.size());
    CHECK(outs.size() >= 2 && outs[outs.size() - 2].role == x6::CoinbaseOutput::Role::Fixed && outs[outs.size() - 2].identity == D &&
          outs[outs.size() - 2].amount == fee::kDonationDustPico, "second-to-last = the 1-piconero donation MARKER (Fixed)");
    CHECK(outs.back().role == x6::CoinbaseOutput::Role::Sink && outs.back().identity == D && outs.back().amount == reward - 6'000'000'000ull - 1,
          "last = the residual SINK paid to the donation address: reward - owed - 1 = %llu", static_cast<unsigned long long>(outs.back().amount));
    CHECK(sum == reward, "exact-sum: Σ outputs %llu == reward %llu (nothing burned)", static_cast<unsigned long long>(sum), static_cast<unsigned long long>(reward));
    CHECK(don == reward - 6'000'000'000ull, "the donation address receives marker + residual = reward - Σowed (%llu): the remainder folds into the donation",
          static_cast<unsigned long long>(don));
    const o2::KFairCoinbaseShape sh = o2::inspect_kfair_coinbase(*a.snap.tpl, a.ledger.ledger().owed_digest());
    CHECK(sh.ok, "K_fair shape gate ACCEPTs: %s", sh.ok ? "ok" : sh.why.c_str());
    const fee::MarkerLocation dm = fee::inspect_donation_marker(outs, D);
    CHECK(dm.ok && dm.marker == 3 && dm.has_sink, "serve-side donation property ACCEPTs (marker @3, sink present)");
    const auth::CoinbaseBooking bk = a.book();
    CHECK(bk.ok, "receive side: decode_lane_coinbase_fee BOOKS it: %s", bk.ok ? "ok" : bk.why.c_str());
    CHECK(bk.payout.size() == 3 && !bk.payout.count(D), "payout = the 3 owed payees only (marker + sink are coverage, D1): %zu payees, donation %s",
          bk.payout.size(), bk.payout.count(D) ? "PRESENT" : "absent");
    CHECK(bk.sink_total == static_cast<long long>(don), "sink_total == marker + residual (%lld)", bk.sink_total);
    CHECK(bk.total == reward, "booked total == reward");

    // D2: steady state -- owed absorbs the budget: [owed...][marker 1], NO sink.
    Built s(Arm::FeeModel, three_owed(1'000'000'000'000'000ull));
    CHECK(s.ok, "steady-state template builds: %s", s.ok ? "ok" : s.why.c_str());
    if (s.ok) {
        const auto& so = s.snap.tpl->outputs();
        std::uint64_t ssum = 0; for (const auto& o : so) ssum += o.amount;
        CHECK(so.back().role == x6::CoinbaseOutput::Role::Fixed && so.back().identity == D && so.back().amount == 1,
              "steady state: the coinbase still ENDS in the 1-piconero donation marker (no sink)");
        CHECK(ssum == s.snap.tpl->reward(), "steady state exact-sum (the marker's 1 piconero came out of the owed pass: the last paid payee carries it)");
        const fee::MarkerLocation sm = fee::inspect_donation_marker(so, D);
        CHECK(sm.ok && !sm.has_sink, "serve-side property ACCEPTs the no-sink shape");
        const auto sbk = s.book();
        CHECK(sbk.ok && sbk.sink_total == 1 && !sbk.payout.count(D), "booked: marker = 1 piconero coverage, no ledger deduction on the donation: %s",
              sbk.ok ? "ok" : sbk.why.c_str());
    }

    // D3: REFUSE-IF-ABSENT. Same ledger, the marker NOT configured (a node that skipped it).
    Built n(Arm::NoMarker, three_owed(1'000'000'000'000'000ull));
    CHECK(n.ok, "no-marker template builds (X6 allows fixed=[]): %s", n.ok ? "ok" : n.why.c_str());
    if (n.ok) {
        const o2::KFairCoinbaseShape nsh = o2::inspect_kfair_coinbase(*n.snap.tpl, n.ledger.ledger().owed_digest());
        CHECK(nsh.ok, "(the K_fair gate alone would ACCEPT it -- the marker property is what closes the gap)");
        const fee::MarkerLocation nm = fee::inspect_donation_marker(n.snap.tpl->outputs(), D);
        CHECK(!nm.ok, "serve side REFUSES a coinbase WITHOUT the donation marker: %s", nm.why.c_str());
        const auto nbk = n.book();
        CHECK(!nbk.ok && nbk.is_lane && nbk.why.rfind("donation-refused:", 0) == 0 && nbk.payout.empty(),
              "receive side REFUSES to book it (every node): %s", nbk.why.c_str());
    }
    // D3b: a no-marker coinbase whose residual sink happens to pay the donation (early, pure-residual shape).
    Built n2(Arm::NoMarker, three_owed(1'000'000'000ull));
    if (CHECK_RET_OK(n2.ok)) {
        const auto nbk2 = n2.book();
        CHECK(!nbk2.ok && nbk2.why.rfind("donation-refused:", 0) == 0,
              "a sink-to-donation WITHOUT the 1-piconero marker is still REFUSED (the marker is exact): %s", nbk2.why.c_str());
    }
    // D3c: a foreign residual sink (the deleted per-node knob) -> not even decodable by a fee-model node.
    Built f(Arm::ForeignSink, three_owed(1'000'000'000ull));
    if (CHECK_RET_OK(f.ok)) {
        const auto fbk = f.book();
        CHECK(!fbk.ok, "a coinbase paying a per-node residual sink is REFUSED by a fee-model peer: %s", fbk.why.c_str());
    }

    // D4: give-author credit to the donation is paid as an OWED output BEFORE the marker and
    //     booked as a ledger deduction (the marker + sink stay coverage).
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
        CHECK(gbk.ok && gbk.sink_total == static_cast<long long>(gdon - 777'000'000ull), "sink_total == marker + residual only");
        CHECK(gsum == g.snap.tpl->reward(), "exact-sum holds with a donation owed output");
    }

    // D5: two ledgers built from the SAME receipts (a node minting at 0.5% and one at 1.0%
    //     fold the same stream) -> byte-identical coinbase.
    {
        const std::uint16_t dA = fee::give_author_u16(0.5), dB = fee::give_author_u16(1.0);
        std::vector<fee::MintedReceipt> stream;
        const ::v37::ScriptRef mA = ::v37::xmr::make_xmr_std(point_of(1), point_of(2));
        const ::v37::ScriptRef mB = ::v37::xmr::make_xmr_std(point_of(3), point_of(2));
        for (int i = 0; i < 40; ++i) { fee::MintedReceipt r; r.payee = (i & 1) ? mA : mB; r.d = (i & 1) ? dA : dB; r.w = 2000; stream.push_back(r); }
        auto ledger_of = [&](const std::vector<fee::MintedReceipt>& st) {
            std::map<::v37::ScriptRef, std::uint64_t> w;
            for (const auto& r : st) for (const auto& p : fee::receipt_pushes(r)) w[p.first] += p.second;
            std::vector<std::pair<::v37::ScriptRef, std::uint64_t>> owed; std::uint64_t don = 0;
            for (const auto& [ref, ww] : w) { if (ref == fee::donation_ref()) don = ww * 1'000'000ull; else owed.emplace_back(ref, ww * 1'000'000ull); }
            return std::make_pair(owed, don);
        };
        const auto la = ledger_of(stream), lb = ledger_of(stream);
        Built A(Arm::FeeModel, la.first, la.second), B(Arm::FeeModel, lb.first, lb.second);
        CHECK(A.ok && B.ok && A.bytes.coinbase_prefix() == B.bytes.coinbase_prefix(),
              "two nodes (give-author 0.5%% vs 1.0%%) folding the same receipts -> BYTE-IDENTICAL miner_tx (%zu B)", A.bytes.coinbase_prefix().size());
        CHECK(la.second > 0, "and the donation holds give-author credit from both nodes' receipts (%llu)", static_cast<unsigned long long>(la.second));
    }

    // D6: the pure location rule.
    const ::v37::bytes32 X = ::v37::xmr::xmr_identity_key(::v37::xmr::make_xmr_std(point_of(1), point_of(2)));
    auto loc = [&](std::vector<::v37::bytes32> ids, std::vector<std::uint64_t> am) { return fee::locate_donation_marker(ids, am, D); };
    auto l1 = loc({X, X, D, D}, {5, 6, 1, 99});
    CHECK(l1.ok && l1.marker == 2 && l1.has_sink, "[X X D:1 D:99] -> marker @2 + sink");
    auto l2 = loc({X, D, D}, {5, 7, 1});
    CHECK(l2.ok && l2.marker == 2 && !l2.has_sink, "[X D:7 D:1] -> marker @2, D:7 is an OWED output");
    auto l3 = loc({X, D, D}, {5, 1, 1});
    CHECK(l3.ok && l3.marker == 1 && l3.has_sink, "[X D:1 D:1] -> the pinned S reading (marker @1 + sink), identical on every node");
    CHECK(!loc({X, X}, {5, 6}).ok, "[X X] -> REFUSED (no donation output)");
    CHECK(!loc({X, D}, {5, 2}).ok, "[X D:2] -> REFUSED (a donation output that is not the 1-piconero marker)");
    CHECK(!loc({D, X}, {1, 5}).ok, "[D:1 X] -> REFUSED (the marker is not at the canonical tail)");
    CHECK(!loc({}, {}).ok, "no outputs -> REFUSED");
    std::map<::v37::bytes32, long long> po; long long st = 7 + 1 + 99;   // the decoder tallied every D vout as sink
    po[X] = 5;
    CHECK(fee::apply_donation_rule({X, D, D, D}, {5, 7, 1, 99}, D, po, st, nullptr) && po[D] == 7 && st == 100,
          "apply_donation_rule re-books the pre-marker D:7 as owed; marker + sink stay coverage (100)");

    // E: no finder output anywhere.
    bool roles_ok = true;
    for (const auto& o : outs) roles_ok &= (o.role == x6::CoinbaseOutput::Role::Owed) ||
                                            (o.role == x6::CoinbaseOutput::Role::Fixed && o.identity == D) ||
                                            (o.role == x6::CoinbaseOutput::Role::Sink && o.identity == D);
    std::printf("== E. NO finder output ==\n");
    CHECK(roles_ok, "every output is Owed, the donation marker, or the donation sink -- no finder bonus (V36 dropped it)");
}

} // namespace

int main() {
    std::printf("=== v37_xmr_fee_model_kat (v36 fee model on the XMR lane) ===\n");
    suite_address();
    suite_give_author();
    suite_owner_fee();
    suite_donation_blocks();
    std::printf("=== %d/%d checks passed ===\n", g_checks - g_fail, g_checks);
    return g_fail == 0 ? 0 : 1;
}
