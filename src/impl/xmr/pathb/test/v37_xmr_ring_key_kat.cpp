// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_ring_key_kat (pathb_ring.hpp): the ring key and the ring id.
// SCAFFOLD goldens: every key below is under the TEST tag "v37-ring-c2-test-key";
// none is a production golden. Identities are generated:
// X(c) = sha256d("v37-ring-c2-test-id" || u64 LE c).
//   K1 preimage bytes and keys (chain_id 0x04030201 and 0); refusals
//   K2 first-bit order: byte 0 first, most significant bit first
//   K3 ring_of at depths 0..7, ring_of_payee against the same keys; refusal above 7
//   K4 child = {d + 1, 2j + bit}, parent = {d - 1, j >> 1}; the edges refuse
//   K5 the key does not depend on membership or depth; the ruled rule's fields
//   K6 the TEST tags against the ruled tag
//   K7 ring_of_entry = ring_of_row = ring_of_payee of the MINER, never the owner
//   K8 ring_key digests: none at depth 0, under None or Unset, above depth 7 or
//      for an unset tag / binding; exactly one per call otherwise
//   K9 X = sha256d(01 10 40 || spend || view) = key_ref_identity, the preimage's tail
// ---------------------------------------------------------------------------
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_lane_rules.hpp"  // PathbLaneRules::payment_groups (K17)
#include "impl/xmr/pathb/pathb_ring.hpp"
#include "impl/xmr/pathb/pathb_wire_v3.hpp"  // XmrKeyRef, key_ref_identity
#include "pathb_kat_check.hpp"
#include "pathb_kat_ring.hpp"
#include "sharechain/v37/v37_descriptor_xmr.hpp"

using namespace pathb_kat;
using namespace pathb_kat::ring;

namespace {

constexpr std::uint32_t kChainA = 0x04030201u;  // four distinct bytes
constexpr std::uint32_t kChain0 = 0;            // the default chain_id
constexpr std::uint8_t kBound = pb::kRingDepthBound;

// Oracle (hashlib, independent of pathb_ring.hpp) under the TEST key tag.
const char* kX0 = "327be1757b7fa4370aaeb2cca51cf6ed5f8acc1659f996c68ccba1d05ced01cb";
const char* kPreA = "7633372d72696e672d63322d746573742d6b657901020304"
                    "327be1757b7fa4370aaeb2cca51cf6ed5f8acc1659f996c68ccba1d05ced01cb";
const char* kPre0 = "7633372d72696e672d63322d746573742d6b657900000000"
                    "327be1757b7fa4370aaeb2cca51cf6ed5f8acc1659f996c68ccba1d05ced01cb";
const char* kKeyA0 = "d0660f32740b8e8e1d935d1b340e58049432961d18ef83910cdc73c8b2959f42";
const char* kKey00 = "796b393870cf64d5edbbb5ffdb1a091123ae97d2b1fab628870d1be7c805be71";
const std::array<const char*, 4> kKeyA = {kKeyA0,
                                          "0d6c83cc5f5fce1b81219d26885a2a1e2eaebaf19ec15a457aa91f185644eccf",
                                          "927e9564c388479506a12a314781ddd51e893871efda9f3e0c0c7619d2384ef1",
                                          "cb5c15066a65edc9aa852e63b54e4cb46c43c6260324f0f94382ff1b5ad0e0e6"};
using Rings = std::array<std::size_t, pb::kRingDepthBound + 1>;
const std::array<Rings, 4> kRingsA = {Rings{0, 1, 3, 6, 13, 26, 52, 104}, Rings{0, 0, 0, 0, 0, 1, 3, 6},
                                      Rings{0, 1, 2, 4, 9, 18, 36, 73}, Rings{0, 1, 3, 6, 12, 25, 50, 101}};
const Rings kRings00 = {0, 0, 1, 3, 7, 15, 30, 60};
const Rings kRingsB2 = {0, 1, 2, 5, 11, 22, 44, 89};
const char* kK9Spend = "94e3ba516458fbacadd90312e677dfb300fc5772c82141970112e5f607259d5b";
const char* kK9View = "68d6a1aaeb3ddc8db8aa30ed3a08bbb13f4e3e83336a3a3698007869786653fe";
const char* kK9X = "c00d198004b925f8c50aeac90485674abdab6fe3c8aecc2c8f04e4bbd54cb5ce";
const char* kK9Key = "c0d9f8328223ed8c1e7457801263b6ad13a885d0f1b2acd44ba48e02413ca67c";
const Rings kK9Rings = {0, 1, 3, 6, 12, 24, 48, 96};

pb::Hash32 key_from_hex(const char* h) {
    pb::Hash32 k{};
    auto nib = [](char c) -> std::uint8_t {
        return static_cast<std::uint8_t>(c <= '9' ? c - '0' : c - 'a' + 10);
    };
    for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<std::uint8_t>((nib(h[2 * i]) << 4) | nib(h[2 * i + 1]));
    return k;
}

std::string ring_str(const std::optional<pb::RingId>& r) {
    if (!r) return "refused";
    return "{" + std::to_string(r->depth) + "," + std::to_string(r->index) + "}";
}

void k1() {
    const pb::Hash32 x0 = gen_id(0);
    check(hx(x0) == kX0, "K1 X0 = sha256d(id tag || u64 LE 0): " + hx(x0));
    const auto pa = preimage_of(test_rule(), chain(kChainA), x0);
    check(pa && hx(*pa) == kPreA, "K1 preimage at chain_id 0x04030201 = tag || 01 02 03 04 || X0: " + (pa ? hx(*pa) : "refused"));
    check(pa && pa->size() == kTestKeyTag.size() + sizeof(std::uint32_t) + pb::kHashBytes, "K1 preimage length = |tag| + 4 + 32");
    const auto p0 = preimage_of(test_rule(), chain(kChain0), x0);
    check(p0 && hx(*p0) == kPre0, "K1 preimage at chain_id 0 = tag || 00 00 00 00 || X0: " + (p0 ? hx(*p0) : "refused"));
    const auto ka = key_of(test_rule(), chain(kChainA), x0);
    check(ka && hx(*ka) == kKeyA0, "K1 key at chain_id 0x04030201: " + (ka ? hx(*ka) : "refused"));
    const auto k0 = key_of(test_rule(), chain(kChain0), x0);
    check(k0 && hx(*k0) == kKey00, "K1 key at chain_id 0: " + (k0 ? hx(*k0) : "refused"));
    check(pa && ka && *ka == ::v37::sha256d(*pa), "K1 key = sha256d(preimage)");
    for (std::size_t c = 0; c < kKeyA.size(); ++c) {
        const auto k = key_of(test_rule(), chain(kChainA), gen_id(c));
        check(k && hx(*k) == kKeyA[c], "K1 key of X" + std::to_string(c) + " at chain_id 0x04030201");
    }
    // refusals: an empty tag, an unset binding, any other binding value
    pb::RingKeyRule no_tag = test_rule();
    no_tag.tag.clear();
    check(!preimage_of(no_tag, chain(kChainA), x0) && !key_of(no_tag, chain(kChainA), x0), "K1 refusal: empty tag");
    const pb::RingKeyRule unset = test_rule(pb::Membership::MinerPayee, pb::RingBinding::Unset);
    check(!preimage_of(unset, chain(kChainA), x0) && !key_of(unset, chain(kChainA), x0), "K1 refusal: binding Unset");
    const pb::RingKeyRule other =
            test_rule(pb::Membership::MinerPayee, static_cast<pb::RingBinding>(std::numeric_limits<std::uint8_t>::max()));
    check(!preimage_of(other, chain(kChainA), x0) && !key_of(other, chain(kChainA), x0), "K1 refusal: unknown binding");
}

void k2() {
    pb::Hash32 k{};
    k[0] = 0x80;
    check(is_ring(pb::ring_of(k, 1), 1, 1), "K2 key byte 0 = 0x80: depth 1 -> {1,1}");
    k[0] = 0x7F;
    check(is_ring(pb::ring_of(k, 1), 1, 0), "K2 key byte 0 = 0x7F: depth 1 -> {1,0}");
    pb::Hash32 b2{};
    b2[0] = 0xB2;
    pb::Hash32 b2ff;
    b2ff.fill(0xFF);
    b2ff[0] = 0xB2;
    pb::Hash32 tail{};
    tail.back() = 0xFF;
    for (std::uint8_t d = 0; d <= kBound; ++d) {
        check(is_ring(pb::ring_of(b2, d), d, kRingsB2[d]), "K2 byte 0 = 0xB2 at depth " + std::to_string(d) + ": " +
                                                               ring_str(pb::ring_of(b2, d)));
        check(is_ring(pb::ring_of(b2ff, d), d, kRingsB2[d]), "K2 bytes 1..31 = 0xFF change nothing at depth " + std::to_string(d));
        check(is_ring(pb::ring_of(tail, d), d, 0), "K2 byte 31 = 0xFF, byte 0 = 0: ring 0 at depth " + std::to_string(d));
    }
}

void k3() {
    for (std::size_t c = 0; c < kKeyA.size(); ++c) {
        const pb::Hash32 key = key_from_hex(kKeyA[c]);
        for (std::uint8_t d = 0; d <= kBound; ++d) {
            check(is_ring(pb::ring_of(key, d), d, kRingsA[c][d]),
                  "K3 ring_of(key of X" + std::to_string(c) + ", " + std::to_string(d) + ") = oracle");
            check(is_ring(ring_payee(test_rule(), chain(kChainA), gen_id(c), d), d, kRingsA[c][d]),
                  "K3 ring_of_payee(X" + std::to_string(c) + ", " + std::to_string(d) + ") = oracle");
        }
        check(!pb::ring_of(key, kBound + 1) && !pb::ring_of(key, std::numeric_limits<std::uint8_t>::max()),
              "K3 ring_of refuses depth 8 and 255");
    }
    const pb::Hash32 k00 = key_from_hex(kKey00);
    for (std::uint8_t d = 0; d <= kBound; ++d) {
        check(is_ring(pb::ring_of(k00, d), d, kRings00[d]), "K3 ring_of(key at chain_id 0, " + std::to_string(d) + ")");
        check(is_ring(ring_payee(test_rule(), chain(kChain0), gen_id(0), d), d, kRings00[d]),
              "K3 ring_of_payee(X0) at chain_id 0, depth " + std::to_string(d));
    }
}

void k4() {
    check(is_ring(pb::child(pb::RingId{3, 5}, false), 4, 10) && is_ring(pb::child(pb::RingId{3, 5}, true), 4, 11),
          "K4 child({3,5}) = {4,10} / {4,11}");
    check(is_ring(pb::parent(pb::RingId{4, 11}), 3, 5) && is_ring(pb::parent(pb::RingId{4, 10}), 3, 5),
          "K4 parent({4,10}) = parent({4,11}) = {3,5}");
    std::size_t cases = 0;
    for (std::uint8_t d = 0; d <= kBound; ++d) {
        for (std::size_t j = 0; j < (std::size_t{1} << d); ++j) {
            const pb::RingId r{d, static_cast<std::uint8_t>(j)};
            for (const bool one : {false, true}) {
                const auto c = pb::child(r, one);
                if (d == kBound) {
                    check(!c, "K4 child at depth 7 refused");
                } else {
                    check(is_ring(c, d + 1, 2 * j + (one ? 1 : 0)), "K4 child({" + std::to_string(d) + "," +
                                                                           std::to_string(j) + "}) = {d + 1, 2j + bit}");
                    check(c && pb::parent(*c) && *pb::parent(*c) == r, "K4 parent(child(r)) = r");
                }
                ++cases;
            }
            if (d == 0) check(!pb::parent(r), "K4 parent of {0,0} refused");
        }
    }
    check(!pb::parent(pb::RingId{1, 2}) && !pb::child(pb::RingId{1, 2}, false), "K4 invalid {1,2} refused");
    check(!pb::parent(pb::RingId{0, 1}) && !pb::child(pb::RingId{0, 1}, true), "K4 invalid {0,1} refused");
    check(!pb::parent(pb::RingId{kBound + 1, 0}) && !pb::child(pb::RingId{kBound + 1, 0}, false),
          "K4 invalid {8,0} refused");
    // ring_of at depth d + 1 is the child of ring_of at d along bit d of the key
    const std::array<bool, pb::kRingDepthBound> b2_bits = {true, false, true, true, false, false, true};
    pb::Hash32 b2{};
    b2[0] = 0xB2;
    for (std::uint8_t d = 0; d < kBound; ++d) {
        const auto r = pb::ring_of(b2, d);
        const auto n = pb::ring_of(b2, d + 1);
        check(r && n && pb::child(*r, b2_bits[d]) && *pb::child(*r, b2_bits[d]) == *n,
              "K4 ring_of(k, d + 1) = child(ring_of(k, d), bit d), d = " + std::to_string(d));
        check(n && pb::parent(*n) && *pb::parent(*n) == *r, "K4 parent(ring_of(k, d + 1)) = ring_of(k, d)");
    }
    std::printf("  K4: %zu child cases\n", cases);
}

void k5() {
    const pb::Hash32 x0 = gen_id(0);
    const auto km = key_of(test_rule(pb::Membership::MinerPayee), chain(kChainA), x0);
    const auto kn = key_of(test_rule(pb::Membership::None), chain(kChainA), x0);
    const auto ku = key_of(test_rule(pb::Membership::Unset), chain(kChainA), x0);
    check(km && kn && ku && *km == *kn && *km == *ku && hx(*km) == kKeyA0,
          "K5 the key of X0 is the same under every membership value");
    const pb::Hash32 key = key_from_hex(kKeyA0);
    for (std::uint8_t d = 0; d < kBound; ++d) {
        const auto r = pb::ring_of(key, d);
        const auto n = pb::ring_of(key, d + 1);
        check(r && n && pb::parent(*n) && *pb::parent(*n) == *r, "K5 one key: the ring at d + 1 lies in the ring at d");
    }
    // the ruled rule: its fields only; no key is computed under it here
    const std::vector<std::uint8_t> ruled_tag{0x56, 0x33, 0x37, 0x52, 0x42};  // "V37RB"
    check(bytes_of(pb::kRingTagRuled) == ruled_tag, "K5 kRingTagRuled = 56 33 37 52 42, no NUL, no length");
    const pb::RingKeyRule ruled = pb::ruled_ring_key_rule();
    check(ruled.tag == ruled_tag && ruled.binding == pb::RingBinding::ChainIdLe32 &&
                  ruled.membership == pb::Membership::MinerPayee,
          "K5 ruled_ring_key_rule() = {V37RB, ChainIdLe32, MinerPayee}");
    const pb::RingKeyRule unset{};
    check(unset.tag.empty() && unset.binding == pb::RingBinding::Unset && unset.membership == pb::Membership::Unset,
          "K5 RingKeyRule{} is all unset");
    static_assert(pb::kRingDepthBound ==
                          std::numeric_limits<decltype(pb::PathbLaneRules{}.payment_groups)>::digits - 1,
                  "the depth bound is K17's width minus one");
    check(pb::kRingDepthBound == 7, "K5 kRingDepthBound = 7");
}

void k6() {
    const std::vector<std::uint8_t> ruled = bytes_of(pb::kRingTagRuled);
    for (const std::string_view t : {kTestKeyTag, kTestIdTag}) {
        const std::vector<std::uint8_t> b = bytes_of(t);
        check(!b.empty() && !ruled.empty() && b[0] != ruled[0],
              "K6 test tag '" + std::string(t) + "' differs from the ruled tag in byte 0");
        const std::size_t n = b.size() < ruled.size() ? b.size() : ruled.size();
        check(!std::equal(b.begin(), b.begin() + static_cast<std::ptrdiff_t>(n), ruled.begin()),
              "K6 neither tag is a prefix of the other");
    }
    check(!is_ruled_tag(test_rule().tag), "K6 test_rule() carries the TEST tag");
    const std::uint64_t before = pb::ring_key_digests();
    const pb::RingKeyRule ruled_rule = pb::ruled_ring_key_rule();
    check(!admissible(ruled_rule) && !key_of(ruled_rule, chain(kChainA), gen_id(0)) &&
                  !preimage_of(ruled_rule, chain(kChainA), gen_id(0)) &&
                  !ring_payee(ruled_rule, chain(kChainA), gen_id(0), 1),
          "K6 the KATs' entry refuses the ruled tag");
    check(pb::ring_key_digests() == before, "K6 nothing was computed under the ruled tag");
}

void k7() {
    // ordered pairs (miner, owner) of X0..X3, miner != owner
    std::size_t rows = 0;
    bool owner_differs_at_1 = false;
    for (std::size_t m = 0; m < kKeyA.size(); ++m) {
        for (std::size_t o = 0; o < kKeyA.size(); ++o) {
            if (m == o) continue;
            pb::BucketRow row;
            row.miner = gen_id(m);
            row.owner = gen_id(o);
            pb::WinEntry e;
            e.miner = row.miner;
            e.owner = row.owner;
            owner_differs_at_1 = owner_differs_at_1 || kRingsA[m][1] != kRingsA[o][1];
            for (std::uint8_t d = 0; d <= kBound; ++d) {
                const auto re = ring_entry(test_rule(), chain(kChainA), e, d);
                const auto rr = ring_row(test_rule(), chain(kChainA), row, d);
                const auto rp = ring_payee(test_rule(), chain(kChainA), row.miner, d);
                const std::string at = "X" + std::to_string(m) + "/X" + std::to_string(o) + " d " + std::to_string(d);
                check(is_ring(rr, d, kRingsA[m][d]), "K7 ring_of_row = the miner's ring, " + at + ": " + ring_str(rr));
                check(is_ring(re, d, kRingsA[m][d]), "K7 ring_of_entry = the miner's ring, " + at + ": " + ring_str(re));
                check(re && rr && rp && *re == *rr && *rr == *rp, "K7 entry = row = payee, " + at);
            }
            ++rows;
        }
    }
    check(owner_differs_at_1, "K7 some row's owner sits in another ring than its miner at depth 1");
    std::printf("  K7: %zu rows x %d depths\n", rows, kBound + 1);
}

void k8() {
    const pb::Hash32 x = gen_id(0);
    pb::BucketRow row;
    row.miner = x;
    row.owner = gen_id(1);
    pb::WinEntry e;
    e.miner = row.miner;
    e.owner = row.owner;
    std::size_t cases = 0;
    auto none_computed = [&](const pb::RingKeyRule& r, std::uint8_t d, bool expect_pool, const std::string& what) {
        const std::uint64_t before = pb::ring_key_digests();
        const auto a = ring_entry(r, chain(kChainA), e, d);
        const auto b = ring_row(r, chain(kChainA), row, d);
        const auto c = ring_payee(r, chain(kChainA), x, d);
        check(pb::ring_key_digests() == before, "K8 no key computed: " + what);
        if (expect_pool)
            check(is_ring(a, 0, 0) && is_ring(b, 0, 0) && is_ring(c, 0, 0), "K8 {0,0}: " + what);
        else
            check(!a && !b && !c, "K8 refused: " + what);
        ++cases;
    };
    for (const pb::Membership m : {pb::Membership::Unset, pb::Membership::None, pb::Membership::MinerPayee})
        none_computed(test_rule(m), 0, true, "depth 0, membership " + std::to_string(static_cast<int>(m)));
    none_computed(pb::RingKeyRule{}, 0, true, "depth 0, RingKeyRule{}");
    for (std::uint8_t d = 1; d <= kBound; ++d) {
        none_computed(test_rule(pb::Membership::None), d, false, "None at depth " + std::to_string(d));
        none_computed(test_rule(pb::Membership::Unset), d, false, "Unset at depth " + std::to_string(d));
        pb::RingKeyRule no_tag = test_rule();
        no_tag.tag.clear();
        none_computed(no_tag, d, false, "empty tag at depth " + std::to_string(d));
        none_computed(test_rule(pb::Membership::MinerPayee, pb::RingBinding::Unset), d, false,
                      "binding Unset at depth " + std::to_string(d));
    }
    none_computed(test_rule(), kBound + 1, false, "depth 8");
    none_computed(test_rule(), std::numeric_limits<std::uint8_t>::max(), false, "depth 255");
    // control: one digest per call under MinerPayee at depths 1..7
    for (std::uint8_t d = 1; d <= kBound; ++d) {
        std::uint64_t before = pb::ring_key_digests();
        const auto a = ring_entry(test_rule(), chain(kChainA), e, d);
        check(a && pb::ring_key_digests() == before + 1, "K8 control: ring_of_entry computes one key at depth " + std::to_string(d));
        before = pb::ring_key_digests();
        const auto b = ring_row(test_rule(), chain(kChainA), row, d);
        check(b && pb::ring_key_digests() == before + 1, "K8 control: ring_of_row computes one key at depth " + std::to_string(d));
        before = pb::ring_key_digests();
        const auto c = ring_payee(test_rule(), chain(kChainA), x, d);
        check(c && pb::ring_key_digests() == before + 1, "K8 control: ring_of_payee computes one key at depth " + std::to_string(d));
        ++cases;
    }
    const std::uint64_t before = pb::ring_key_digests();
    check(key_of(test_rule(), chain(kChainA), x) && pb::ring_key_digests() == before + 1, "K8 control: ring_key counts itself");
    std::printf("  K8: %zu cases\n", cases);
}

void k9() {
    pb::XmrKeyRef ref;
    ref.spend = gen_part("spend", 0);
    ref.view = gen_part("view", 0);
    check(hx(ref.spend) == kK9Spend && hx(ref.view) == kK9View, "K9 generated spend / view");
    std::vector<std::uint8_t> pre{::v37::PayoutDescriptor::VERSION, static_cast<std::uint8_t>(::v37::xmr::XMR_STD),
                                  static_cast<std::uint8_t>(pb::kKeyRefPayloadBytes)};
    pre.insert(pre.end(), ref.spend.begin(), ref.spend.end());
    pre.insert(pre.end(), ref.view.begin(), ref.view.end());
    const pb::Hash32 x = ::v37::sha256d(pre);
    check(hx(x) == kK9X, "K9 X = sha256d(01 10 40 || spend || view): " + hx(x));
    check(pb::key_ref_identity(ref) == x, "K9 key_ref_identity(spend, view) = X");
    const auto p = preimage_of(test_rule(), chain(kChainA), x);
    check(p && p->size() >= pb::kHashBytes &&
                  std::equal(x.begin(), x.end(), p->end() - static_cast<std::ptrdiff_t>(pb::kHashBytes)),
          "K9 X is the preimage's last 32 bytes");
    const auto k = key_of(test_rule(), chain(kChainA), x);
    check(k && hx(*k) == kK9Key, "K9 key of X");
    for (std::uint8_t d = 0; d <= kBound; ++d)
        check(is_ring(ring_payee(test_rule(), chain(kChainA), x, d), d, kK9Rings[d]),
              "K9 ring_of_payee(X) at depth " + std::to_string(d));
}

}  // namespace

int main() {
    k1();
    k2();
    k3();
    k4();
    k5();
    k6();
    k7();
    k8();
    k9();
    return finish("v37_xmr_ring_key_kat");
}
