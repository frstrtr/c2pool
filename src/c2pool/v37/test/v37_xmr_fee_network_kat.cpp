// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_fee_network_kat -- DON-NET: one donation identity per Monero network.
//
// The fee model (xmr_fee_model.hpp, FeeModelGate v1) pays ONE mandatory
// donation output. Before DON-NET the identity was a single compiled-in
// MAINNET address, so a stagenet/testnet/regtest node running --fee-model v1
// paid (and folded into its HELLO digest) the mainnet identity. This KAT pins:
//
//   N  per network: donation_address(net) decodes (CN base58 + keccak) to the
//      pinned (B, A) with the network's own address byte (regtest = FAKECHAIN
//      = the mainnet byte 18, distinct keys); ref/identity/marker agree; the
//      ref passes the live ed25519 torsion check; MAINNET is kDonationAddress
//      byte-for-byte and the no-argument forms are mainnet; the four
//      identities are pairwise distinct.
//   D  relay HELLO: lane_params_digest gate OFF is network-independent and
//      keeps master's W4 golden; gate ON on mainnet equals the 3-argument
//      (pre-DON-NET) digest; gate ON differs per network; a node that folds
//      another donation identity on the SAME network byte is refused by
//      hello_mismatch (digest), a different network byte by the network check.
//   P  pushes: a give-author split on network n pays donation_ref(n).
//   C  coinbase: an exact-sum allocation with the regtest donation as the
//      residual sink ends in ONE regtest donation output; the serve-side
//      inspect and the receive-side locate/apply rules accept it for regtest
//      and REFUSE it when checked against the mainnet identity (and vice
//      versa).
//
// Prints the mainnet digests (gate OFF/ON, both bind modes) so a base-vs-fix
// run can diff them. On a pre-DON-NET tree (no C2POOL_V37_XMR_DONATION_PER_NETWORK)
// a shim maps every network to the one mainnet identity: the KAT compiles
// and is RED there (that is the defect this KAT exists for).
// ===========================================================================
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <c2pool/v37/xmr/relay/xmr_relay_wire.hpp>
#include <c2pool/v37/xmr/xmr_fee_model.hpp>
#include "impl/xmr/coin/xmr_derivation.hpp"

namespace fee   = c2pool::v37n::xmr::fee;
namespace relay = c2pool::v37n::xmr::relay;
namespace x6    = ::v37::xmr::settle;

namespace {

int g_fail = 0, g_checks = 0;
#define CHECK(cond, ...)                                       \
    do {                                                       \
        const bool _ok = (cond);                               \
        ++g_checks;                                            \
        if (!_ok) ++g_fail;                                    \
        std::printf("  [%s] ", _ok ? "PASS" : "FAIL");         \
        std::printf(__VA_ARGS__);                              \
        std::printf("\n");                                     \
    } while (0)

std::string hex(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(2 * n);
    for (std::size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}
template <class V> std::string hex(const V& v) { return hex(reinterpret_cast<const std::uint8_t*>(v.data()), v.size()); }

// ---------------------------------------------------------------------------
// The API under test, or (pre-DON-NET tree) a shim that is the old behaviour:
// every network gets the one mainnet identity.
// ---------------------------------------------------------------------------
enum class Net : std::uint8_t { Mainnet = 0, Testnet = 1, Stagenet = 2, Regtest = 3 };
const Net kNets[4] = {Net::Mainnet, Net::Testnet, Net::Stagenet, Net::Regtest};
const char* name(Net n) { static const char* s[4] = {"mainnet", "testnet", "stagenet", "regtest"}; return s[static_cast<int>(n)]; }

#ifdef C2POOL_V37_XMR_DONATION_PER_NETWORK
constexpr bool kPerNetwork = true;
fee::DonationNet dn(Net n) { return static_cast<fee::DonationNet>(n); }
std::string      addr_of(Net n) { return fee::donation_address(dn(n)); }
::v37::ScriptRef ref_of(Net n) { return fee::donation_ref(dn(n)); }
::v37::bytes32   id_of(Net n) { return fee::donation_identity(dn(n)); }
x6::FixedOutput  marker_of(Net n) { return fee::donation_marker(dn(n)); }
relay::bytes32   digest_of(const ::v37::LaneParams& p, relay::BindMode b, Net n) {
    return relay::lane_params_digest(p, 2000, b, static_cast<relay::u8>(n)); }
std::vector<std::pair<::v37::ScriptRef, std::uint64_t>> pushes_of(const ::v37::ScriptRef& payee, std::uint16_t d, Net n) {
    return fee::receipt_lane_pushes(payee, d, true, 1, dn(n)); }
fee::MarkerLocation inspect_of(const std::vector<x6::CoinbaseOutput>& o, Net n) { return fee::inspect_donation_marker(o, dn(n)); }
#else
constexpr bool kPerNetwork = false;
std::string      addr_of(Net) { return fee::kDonationAddress; }
::v37::ScriptRef ref_of(Net) { return fee::donation_ref(); }
::v37::bytes32   id_of(Net) { return fee::donation_identity(); }
x6::FixedOutput  marker_of(Net) { return fee::donation_marker(); }
relay::bytes32   digest_of(const ::v37::LaneParams& p, relay::BindMode b, Net) { return relay::lane_params_digest(p, 2000, b); }
std::vector<std::pair<::v37::ScriptRef, std::uint64_t>> pushes_of(const ::v37::ScriptRef& payee, std::uint16_t d, Net) {
    return fee::receipt_lane_pushes(payee, d, true, 1); }
fee::MarkerLocation inspect_of(const std::vector<x6::CoinbaseOutput>& o, Net) { return fee::inspect_donation_marker(o, fee::donation_identity()); }
#endif

// The pinned per-network identities (public keys only; independent of the header).
struct Pin { const char* addr; const char* spend; const char* view; std::uint64_t prefix; };
const Pin kPins[4] = {
    {"42QtUEQ6E4v2wtkG2h72osTqZgLo7vtjg4SngeG47AnaaQLUUQrGvPXSuvCmHcRVuPa5xxUU5Mfo6jSEqYYUk34Z1PM1oPF",
     "14d413e6ccb14f0ba30999b97c8912a07321d893789b7f149810b7885b2cd7c7",
     "b3157741ab68969aeb7fe9ebd4fa3ec5ce4dcdc7b43249fdb40311cb03779e03", 18},
    {"9yWhJcSRcNFhfrZJAkgh5N4swx92cHLP79hYbP8YJwJKYSCcdKXpgrvYxFHZ5kvfUERtXjvwNTJN4EuW7FypyDZ3114t5rG",
     "a7731abbe9bb2cf3264395231a8645172ffd7f08c6097e3402197f3f1c6ffcbb",
     "ef3c9a659a67c3bf081a352e7cfbfb94cc5e11921a3e8953223fca1ed14e2200", 53},
    {"56eN1fax2baeK1WQtCassh9dpgnWbnzTPTgoPQ7wbWPmBszKeTHwa5ji1wuqZnxERNc284ESw3xoDd76uzEtwjge9gesBUp",
     "7f095705904be1df109bdf44b0027c339fde3ece7d85069f8bdfb19fd8c16c41",
     "0abca326ba53a6f5387785822296c1d15df03e6c51cd44d7dbe270667b5fe34c", 24},
    {"43TryRMP6jdJP9h1CSgskqAFX6dA4h76rXfs7x5wvfGZAVmVBBUxRHjfJ9tfgnBtsJ4D75rdz9gVe8pU4SxA2rJhNrx87oD",
     "3091e80a51918c67eb67b6fefaf77e374dd898240953bbb75d47b82b8615c638",
     "c5d453f0d54332e4f48f12abab2551132f00037f0c51892ebe3b41928ab5bec1", 18},
};

std::array<std::uint8_t, 32> point_of(std::uint8_t k) {
    ::xmr::coin::SecretKey sec{};
    sec.data()[0] = k;
    ::xmr::coin::PublicKey pub{};
    if (!::xmr::coin::secret_key_to_public_key(sec, pub)) return {};
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), pub.data(), 32);
    return out;
}

// ---------------------------------------------------------------------------
void suite_identities() {
    std::printf("== N. one donation identity per network ==\n");
    std::set<std::string> ids;
    for (Net n : kNets) {
        const Pin& p = kPins[static_cast<int>(n)];
        const std::string a = addr_of(n);
        CHECK(a == p.addr, "N1 %s: donation_address == the pinned %s address (%s...)", name(n), name(n), a.substr(0, 12).c_str());
        const fee::DecodedAddress d = fee::decode_xmr_address(a);
        CHECK(d.ok && !d.subaddress, "N2 %s: decodes as a standard address (%s)", name(n), d.ok ? "ok" : d.why.c_str());
        CHECK(d.prefix == p.prefix, "N3 %s: network byte %llu == %llu", name(n), (unsigned long long)d.prefix, (unsigned long long)p.prefix);
        CHECK(hex(d.spend) == p.spend && hex(d.view) == p.view, "N4 %s: decoded (B, A) == pinned (%s..., %s...)", name(n),
              hex(d.spend).substr(0, 12).c_str(), hex(d.view).substr(0, 12).c_str());
        CHECK(d.ref() == ref_of(n), "N5 %s: donation_ref == make_xmr_std(decoded B, A)", name(n));
        CHECK(id_of(n) == ::v37::xmr::xmr_identity_key(ref_of(n)), "N6 %s: donation_identity == identity_key(donation_ref)", name(n));
        const x6::FixedOutput m = marker_of(n);
        CHECK(m.pay == ref_of(n) && m.identity == id_of(n) && m.amount == fee::kDonationDustPico,
              "N7 %s: donation_marker pays this network's donation, minimum %llu", name(n), (unsigned long long)m.amount);
        CHECK(::v37::xmr::xmr_ref_valid(ref_of(n)), "N8 %s: the donation ref passes the LIVE ed25519 torsion check", name(n));
        ids.insert(hex(id_of(n)));
        std::printf("  identity[%s] = %s\n", name(n), hex(id_of(n)).c_str());
    }
    CHECK(ids.size() == 4, "N9 the four network identities are pairwise distinct (%zu distinct)", ids.size());
    CHECK(std::string(fee::kDonationAddress) == kPins[0].addr && fee::donation_ref() == ref_of(Net::Mainnet) &&
          fee::donation_identity() == id_of(Net::Mainnet),
          "N10 mainnet unchanged: kDonationAddress and the no-argument donation_ref/identity are the mainnet identity");
    CHECK(kPerNetwork, "N11 the tree selects the donation identity per network (C2POOL_V37_XMR_DONATION_PER_NETWORK)");
}

void suite_digest() {
    std::printf("== D. relay HELLO lane_params_digest ==\n");
    ::v37::LaneParams off;
    ::v37::LaneParams on;  on.fee.enabled = true; on.fee.version = fee::kFeeModelVersion;
    using BM = relay::BindMode;
    // mainnet digests, printed for a base-vs-fix diff
    for (BM b : {BM::None, BM::Rbind}) {
        std::printf("  digest[mainnet, gate OFF, %s] = %s\n", relay::to_string(b), hex(relay::lane_params_digest(off, 2000, b)).c_str());
        std::printf("  digest[mainnet, gate ON , %s] = %s\n", relay::to_string(b), hex(relay::lane_params_digest(on, 2000, b)).c_str());
    }
    CHECK(hex(relay::lane_params_digest(off, 2000, BM::None)) == "8f49947a8716dc16cf3cbceb01529ba9eb930042693da93f8a43a4186157da3f",
          "D1 gate OFF keeps master's W4 golden");
    std::set<std::string> on_d;
    for (Net n : kNets) {
        for (BM b : {BM::None, BM::Rbind})
            CHECK(digest_of(off, b, n) == relay::lane_params_digest(off, 2000, b),
                  "D2 %s gate OFF, %s: the digest does not depend on the network (no fold)", name(n), relay::to_string(b));
        on_d.insert(hex(digest_of(on, BM::None, n)));
    }
    for (BM b : {BM::None, BM::Rbind})
        CHECK(digest_of(on, b, Net::Mainnet) == relay::lane_params_digest(on, 2000, b),
              "D3 mainnet gate ON, %s: == the mainnet (pre-DON-NET, 3-argument) digest", relay::to_string(b));
    CHECK(on_d.size() == 4, "D4 gate ON: the digest differs per network (%zu distinct of 4)", on_d.size());

    // HELLO: same network byte (regtest), one node folding another donation identity.
    relay::Hello ours, theirs;
    ours.network = theirs.network = static_cast<relay::u8>(Net::Regtest);
    ours.chain_id = theirs.chain_id = 7; ours.share_diff = theirs.share_diff = 2000;
    ours.bind = theirs.bind = BM::None; ours.node_nonce = 1; theirs.node_nonce = 2;
    ours.lane_params_digest = digest_of(on, BM::None, Net::Regtest);
    theirs.lane_params_digest = relay::lane_params_digest(on, 2000, BM::None);   // the mainnet identity on regtest (pre-DON-NET)
    const std::string why = relay::hello_mismatch(ours, theirs);
    CHECK(!why.empty() && why.find("lane_params_digest") != std::string::npos,
          "D5 regtest node vs a node folding the MAINNET donation identity on regtest: HELLO refused (%s)", why.empty() ? "ACCEPTED" : why.c_str());
    theirs.lane_params_digest = ours.lane_params_digest;
    CHECK(relay::hello_mismatch(ours, theirs).empty(), "D6 two regtest nodes with the regtest identity: HELLO compatible");
    theirs.network = static_cast<relay::u8>(Net::Stagenet); theirs.lane_params_digest = digest_of(on, BM::None, Net::Stagenet);
    CHECK(!relay::hello_mismatch(ours, theirs).empty(), "D7 a stagenet node: HELLO refused (%s)", relay::hello_mismatch(ours, theirs).c_str());
}

void suite_pushes() {
    std::printf("== P. give-author pushes pay this network's donation ==\n");
    const ::v37::ScriptRef miner = ::v37::xmr::make_xmr_std(point_of(5), point_of(6));
    for (Net n : kNets) {
        const auto p = pushes_of(miner, 655, n);
        CHECK(p.size() == 2 && p[0].first == miner && p[0].second == 65535 - 655 && p[1].first == ref_of(n) && p[1].second == 655,
              "P1 %s: d=655 -> (miner, 64880), (donation[%s], 655)", name(n), name(n));
        if (n != Net::Mainnet)
            CHECK(p.size() == 2 && !(p[1].first == fee::donation_ref()), "P2 %s: the donation push does NOT pay the mainnet identity", name(n));
    }
}

void suite_coinbase() {
    std::printf("== C. the one donation output, per network ==\n");
    auto ref_k = [](std::uint8_t k) { return ::v37::xmr::make_xmr_std(point_of(k), point_of(2)); };
    auto entry = [&](std::uint8_t k, std::uint64_t owed, std::uint64_t age) {
        x6::OwedEntry e; e.pay = ref_k(k); e.owed = owed; e.first_eligible = age; e.identity = ::v37::xmr::xmr_identity_key(e.pay); return e; };
    for (Net n : {Net::Regtest, Net::Stagenet, Net::Testnet, Net::Mainnet}) {
        x6::CoinbaseInputs in; in.base_reward = 1000; in.fees = 0; in.output_cap = 64;
        in.residual_sink = ref_of(n); in.residual_sink_identity = id_of(n); in.fixed = {marker_of(n)};
        x6::OwedEntry d; d.pay = ref_of(n); d.owed = 30; d.first_eligible = 3; d.identity = id_of(n);
        in.owed = {entry(1, 100, 1), entry(3, 50, 2), d};
        x6::BuildError err = x6::BuildError::None;
        const auto r = x6::allocate_exact_sum(in, &err);
        std::uint64_t sum = 0; std::size_t to_n = 0;
        std::vector<::v37::bytes32> ids; std::vector<std::uint64_t> am;
        for (const auto& o : r) { sum += o.amount; to_n += (o.identity == id_of(n)); ids.push_back(o.identity); am.push_back(o.amount); }
        CHECK(err == x6::BuildError::None && sum == 1000 && to_n == 1 && !r.empty() && r.back().identity == id_of(n) &&
              r.back().owed_part == 30 && r.back().amount == 30 + 1 + 819,
              "C1 %s: exact-sum 1000, ONE donation output, LAST, = owed 30 + 1 + residual 819 (got %llu, %zu outputs)",
              name(n), r.empty() ? 0ull : (unsigned long long)r.back().amount, r.size());
        CHECK(inspect_of(r, n).ok, "C2 %s: serve-side inspect_donation_marker(%s) accepts", name(n), name(n));
        CHECK(fee::locate_donation_marker(ids, am, id_of(n)).ok, "C3 %s: receive-side locate(%s identity) accepts", name(n), name(n));
        std::map<::v37::bytes32, long long> payout; long long sink_total = static_cast<long long>(r.back().amount); std::string why;
        CHECK(fee::apply_donation_rule(ids, am, id_of(n), std::optional<std::uint64_t>(30), payout, sink_total, &why) &&
              payout[id_of(n)] == 30 && sink_total == 820,
              "C4 %s: apply_donation_rule books owed_part 30, leaves 1 + residual = 820 coverage", name(n));
        const Net other = (n == Net::Mainnet) ? Net::Regtest : Net::Mainnet;
        const fee::MarkerLocation xm = inspect_of(r, other);
        CHECK(!xm.ok, "C5 %s coinbase checked as %s: serve-side REFUSED (%s)", name(n), name(other), xm.ok ? "ACCEPTED" : xm.why.c_str());
        const fee::MarkerLocation xl = fee::locate_donation_marker(ids, am, id_of(other));
        CHECK(!xl.ok, "C6 %s coinbase booked as %s: receive-side donation-refused (%s)", name(n), name(other), xl.ok ? "ACCEPTED" : xl.why.c_str());
    }
}

} // namespace

int main() {
    std::printf("v37_xmr_fee_network_kat (DON-NET) per-network=%s\n", kPerNetwork ? "yes" : "NO (pre-DON-NET tree: every network uses the mainnet identity)");
    suite_identities();
    suite_digest();
    suite_pushes();
    suite_coinbase();
    std::printf("\n%d/%d checks passed\n", g_checks - g_fail, g_checks);
    if (g_checks < 60) { std::printf("HOLLOW-GREEN GUARD: only %d checks ran\n", g_checks); return 1; }
    return g_fail ? 1 : 0;
}
