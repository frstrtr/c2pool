// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_epoch_field_kat -- LANE-EPOCH (E1): the V37E lineage field on the
// wire and in real assembled blocks.
//
//   A CODEC      encode/parse round trip in the full 0x02 tail order
//                [nonce|pad|V37D|V37E|V37P|V37C]; absent without the field or
//                without a V37P field; fver != 1 -> MALFORMED (strict); the
//                V37D / V37N readers skip a well-formed V37E and land on the
//                pre-epoch offset when it is absent (gate OFF = master offsets).
//   B EMPTY ROOT sha256d('V37Q') == OwedLedger::owed_digest() of a ledger
//                without rows (the E1 opener root is the real empty ledger's).
//   C BLOCKS     a gate-ON continue block = the gate-OFF block with exactly the
//                45-byte field spliced before V37P; its ChainFact reads Own,
//                the field, the ledger's root and the cut; an OPENER block
//                commits the EMPTY root over a non-empty ledger; a plan that
//                forbids building refuses the template.
//   D HELLO      lane_params_digest: gate OFF == the pre-epoch digest (no
//                EPC1 bytes), gate ON differs by version / N / origin (a mixed
//                fleet refuses at HELLO, never a silent divergence).
// ---------------------------------------------------------------------------
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/template/xmr_monerod_miner_data.hpp"
#include "impl/xmr/template/xmr_block_assembly.hpp"

#include "c2pool/v37/xmr/xmr_coinbase_authority.hpp"
#include "c2pool/v37/xmr/xmr_credit_cut.hpp"
#include "c2pool/v37/xmr/xmr_fee_model.hpp"
#include "c2pool/v37/xmr/xmr_lane_epoch_chain.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_provider.hpp"
#include "c2pool/v37/xmr/xmr_paynow.hpp"
#include "c2pool/v37/xmr/xmr_pool_tag.hpp"
#include "c2pool/v37/xmr/relay/xmr_relay_wire.hpp"

#include "xmr_c4_parity_golden.hpp"

using namespace c2pool::xmr::native;

namespace o2      = c2pool::v37n::xmr::o2;
namespace asm_    = c2pool::xmr::assembly;
namespace credit  = c2pool::v37n::xmr::credit;
namespace ep      = c2pool::v37n::xmr::epoch;
namespace fee     = c2pool::v37n::xmr::fee;
namespace paynow  = c2pool::v37n::xmr::paynow;
namespace lineage = c2pool::v37n::xmr::lineage;
namespace relay   = c2pool::v37n::xmr::relay;
namespace x6      = ::v37::xmr::settle;
namespace G4      = c2pool::xmr::native::golden_c4;

// THE tie the impl tree names: its parse bound == the consumer-tree format.
static_assert(asm_::EPOCH_FIELD_BYTES == credit::kEpochFieldBytes,
              "impl-tree EPOCH_FIELD_BYTES must mirror credit::kEpochFieldBytes");
static_assert(credit::kEpochFieldBytes == 45, "V37E field: 4 magic + 1 fver + 4 seq + 4 version + 32 parent");

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

std::string hex(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(2 * n);
    for (std::size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}
template <class V> std::string hex(const V& v) { return hex(reinterpret_cast<const std::uint8_t*>(v.data()), v.size()); }

::v37::bytes32 b32(std::uint8_t seed) { ::v37::bytes32 b{}; for (int i = 0; i < 32; ++i) b[i] = static_cast<std::uint8_t>(seed + i); return b; }

credit::CreditCut fixture_cut() {
    credit::CreditCut c;
    c.next_pos = 0x0000000000BC614Eull;
    for (std::size_t i = 0; i < 32; ++i) c.spine_digest[i] = static_cast<std::uint8_t>(0xA0 + i);
    return c;
}

const credit::EpochField kField{7, ep::kEpochRuleVersion, b32(0x51)};

std::vector<std::uint8_t> payload_of(bool v37d, const credit::EpochField* e, const ::v37::bytes32* tag, bool cut) {
    std::vector<std::uint8_t> p(14, 0x00);
    p[0] = 0xDE; p[1] = 0xAD; p[2] = 0xBE; p[3] = 0xEF;
    if (v37d) { const auto t = fee::encode_donation_owed_tail(424242); p.insert(p.end(), t.begin(), t.end()); }
    if (e)    { const auto t = credit::encode_epoch_field(*e);        p.insert(p.end(), t.begin(), t.end()); }
    if (tag)  { const auto t = credit::encode_pool_tag_field(*tag);   p.insert(p.end(), t.begin(), t.end()); }
    if (cut)  { const auto t = credit::encode_tail(fixture_cut());   p.insert(p.end(), t.begin(), t.end()); }
    return p;
}

std::vector<unsigned char> tx_extra_of(const std::vector<std::uint8_t>& payload) {
    std::vector<unsigned char> x;
    x.push_back(0x01); for (int i = 0; i < 32; ++i) x.push_back(static_cast<unsigned char>(0x10 + i));
    x.push_back(0x02);
    for (std::size_t n = payload.size(); ; n >>= 7) {   // the nonce length is a varint (the payload exceeds 127 B)
        if (n < 0x80) { x.push_back(static_cast<unsigned char>(n)); break; }
        x.push_back(static_cast<unsigned char>((n & 0x7f) | 0x80));
    }
    x.insert(x.end(), payload.begin(), payload.end());
    x.push_back(0x03); x.push_back(0x21); x.push_back(0x00);
    for (int i = 0; i < 32; ++i) x.push_back(static_cast<unsigned char>(0xC0 + i));
    return x;
}

void suite_codec() {
    std::printf("== A. V37E codec in the 0x02 tail order [nonce|pad|V37D|V37E|V37P|V37C] ==\n");
    const auto tag = b32(0x33);
    const auto enc = credit::encode_epoch_field(kField);
    CHECK(enc.size() == 45 && std::memcmp(enc.data(), "V37E", 4) == 0 && enc[4] == 1 && enc[5] == 7 && enc[9] == 1,
          "encode: 45 B, magic V37E, fver 1, seq u32le, version u32le, parent: %s", hex(enc).substr(0, 30).c_str());
    const auto full = payload_of(true, &kField, &tag, true);
    credit::EpochField got{};
    CHECK(credit::parse_epoch_payload(full, &got) == credit::EpochParse::Present && got == kField,
          "round trip: seq %u version %u parent %s", got.seq, got.version, hex(got.parent).substr(0, 16).c_str());
    CHECK(credit::parse_epoch(tx_extra_of(full), &got) == credit::EpochParse::Present && got == kField,
          "round trip through tx_extra (0x01 R | 0x02 payload | 0x03 root)");
    CHECK(credit::parse_epoch_payload(payload_of(true, nullptr, &tag, true)) == credit::EpochParse::Absent,
          "no V37E field -> Absent (gate OFF: every pre-epoch lane block reads as epoch 0)");
    CHECK(credit::parse_epoch_payload(payload_of(false, &kField, nullptr, true)) == credit::EpochParse::Absent,
          "V37E without a V37P field -> Absent (an epoch is meaningful only behind OUR pool tag)");
    auto mal = full;
    mal[14 + 12 + 4] = 2;   // the fver byte of V37E (after the 14-byte lead and the 12-byte V37D)
    CHECK(credit::parse_epoch_payload(mal) == credit::EpochParse::Malformed, "V37E fver 2 -> MALFORMED (strict)");
    // the readers of the fields BEFORE the lineage fields: same values with and without V37E
    const auto off = payload_of(true, nullptr, &tag, true);
    CHECK(credit::end_before_lineage_fields(full) == credit::end_before_lineage_fields(off) &&
          credit::end_before_lineage_fields(full) == 14 + 12,
          "end_before_lineage_fields: %zu with V37E == %zu without (the V37D field ends there)",
          credit::end_before_lineage_fields(full), credit::end_before_lineage_fields(off));
    CHECK(fee::parse_donation_owed_payload(full) == std::optional<std::uint64_t>(424242) &&
          fee::parse_donation_owed_payload(off) == std::optional<std::uint64_t>(424242),
          "V37D owed_in reads 424242 with and without V37E");
    auto withn = paynow::encode_tail(99);
    std::vector<std::uint8_t> pn(full.begin(), full.begin() + 14);
    pn.insert(pn.end(), withn.begin(), withn.end());
    pn.insert(pn.end(), full.begin() + 14, full.end());
    CHECK(paynow::parse_payload(pn) == std::optional<std::uint64_t>(99), "V37N base reads 99 in front of V37D|V37E|V37P|V37C");
    CHECK(credit::parse_tail(full).has_value() && credit::parse_pool_tag_payload(full) == credit::PoolTagParse::Present,
          "V37C and V37P still parse (V37E sits before them)");
    auto malx = mal;
    CHECK(credit::end_before_lineage_fields(malx) == credit::end_before_lineage_fields(full) + 45 &&
          !fee::parse_donation_owed_payload(malx).has_value(),
          "a MALFORMED V37E is not skipped: the V37D reader fails closed");
}

void suite_empty_root() {
    std::printf("== B. the E1 opener root is the real empty ledger's ==\n");
    const c2pool::v37n::settle::OwedLedger empty(static_cast<::v37::ChainId>(7));
    CHECK(empty.owed_digest() == ep::empty_owed_digest(), "OwedLedger{}.owed_digest() == sha256d('V37Q') = %s",
          hex(ep::empty_owed_digest()).c_str());
    CHECK(ep::empty_root(7) == ep::mm_root_of(7, empty.owed_digest()) && !(ep::empty_root(7) == ep::empty_root(8)),
          "empty_root(chain) = the 0x03 mm root of that digest (chain-bound): %s", hex(ep::empty_root(7)).substr(0, 16).c_str());
}

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

class CannedTransport final : public ::c2pool::xmr::node::IMonerodTransport {
public:
    explicit CannedTransport(std::string body) : body_(std::move(body)) {}
    void rpc_post(const std::string&, std::function<void(const ::c2pool::xmr::node::RpcResponse&)> cb) override {
        ::c2pool::xmr::node::RpcResponse r;
        r.body.assign(body_.begin(), body_.end());
        cb(r);
    }
    void zmq_subscribe(const std::string&, std::function<void(const ::c2pool::xmr::node::ZmqFrame&)>) override {}
private:
    std::string body_;
};

// mode: 0 = gate OFF (no epoch_source), 1 = continue kField, 2 = opener kField, 3 = plan forbids building
struct Built {
    o2::XmrOwedFixture                                 ledger{static_cast<::v37::ChainId>(LANE_CHAIN)};
    o2::XmrSettlementConfig                            scfg;
    CannedTransport                                    tx{G4::MD_RAW_JSON};
    tmpl::MonerodMinerDataSource                       src{tx};
    std::unique_ptr<o2::XmrSettlementTemplateProvider> provider;
    o2::SettlementSnapshot                             snap;
    asm_::BlockBytes                                   bytes;
    bool                                               ok = false;
    std::string                                        why;
    std::uint64_t                                      asked_h = 0;
    Built(const ::v37::bytes32& tag, int mode) {
        const auto P1 = point_of(1), P2 = point_of(2), P3 = point_of(3), P4 = point_of(4);
        ledger.seed_owed(::v37::xmr::make_xmr_std(P1, P2), 3'000'000'000ull);
        ledger.seed_owed(::v37::xmr::make_xmr_std(P3, P2), 2'000'000'000ull);
        scfg.h_min = 0; scfg.output_cap = 0;
        scfg.set_residual_sink_std(P4, P2);
        scfg.credit_cut_source = [](std::uint64_t& P, ::v37::bytes32& dg) {
            const credit::CreditCut c = fixture_cut(); P = c.next_pos; dg = c.spine_digest; return true; };
        scfg.pool_tag = tag;
        if (mode != 0)
            scfg.epoch_source = [this, mode](std::uint64_t h, credit::EpochField& f, bool& opener, std::string& w) -> int {
                asked_h = h;
                if (mode == 3) { w = "wait: epoch 7 is alive but this node does not hold its history"; return -1; }
                f = kField; opener = (mode == 2); return 1;
            };
        if (!src.poll(&why)) { why = "daemon arm did not parse the capture: " + why; return; }
        provider = std::make_unique<o2::XmrSettlementTemplateProvider>(src, ledger, scfg, 0);
        if (!provider->refresh()) { why = provider->last_error(); return; }
        snap = provider->current();
        if (!snap.valid || !snap.tpl) { why = "no template"; return; }
        ok = snap.tpl->materialize(0, bytes, &why);
    }
};

std::optional<ep::ChainFact> fact_of(const Built& b, const ::v37::bytes32& tag) {
    return ep::fact_of_blob(1234, b32(0x99), b.bytes.full_blob, tag);
}

void suite_blocks() {
    std::printf("== C. real assembled blocks: gate OFF vs continue vs opener vs plan-forbids ==\n");
    const ::v37::LaneParams lp{};
    const auto TAG = lineage::pool_tag_for(LANE_CHAIN, lp, b32(0xA0));
    Built off(TAG, 0), cont(TAG, 1), open(TAG, 2), wait(TAG, 3);
    CHECK(off.ok && cont.ok && open.ok, "three templates build + materialize (%s / %s / %s)", off.ok ? "ok" : off.why.c_str(),
          cont.ok ? "ok" : cont.why.c_str(), open.ok ? "ok" : open.why.c_str());
    if (!(off.ok && cont.ok && open.ok)) return;
    CHECK(!wait.ok && wait.why.find("lane-epoch:") != std::string::npos,
          "a plan that forbids building refuses the template: %s", wait.why.c_str());
    const std::uint8_t* op = off.bytes.full_blob.data() + off.bytes.extra_nonce_offset;
    const std::uint8_t* cp = cont.bytes.full_blob.data() + cont.bytes.extra_nonce_offset;
    const std::size_t tail = 37 + 44;   // V37P + V37C
    const std::size_t lead = off.bytes.extra_nonce_size - tail;
    const auto fld = credit::encode_epoch_field(kField);
    CHECK(cont.bytes.extra_nonce_size == off.bytes.extra_nonce_size + 45 &&
          std::memcmp(cp, op, lead) == 0 && std::memcmp(cp + lead, fld.data(), 45) == 0 && std::memcmp(cp + lead + 45, op + lead, tail) == 0,
          "continue payload = the gate-OFF payload with the 45-byte V37E spliced before V37P (%zu -> %zu B)",
          off.bytes.extra_nonce_size, cont.bytes.extra_nonce_size);
    CHECK(cont.bytes.merkle_root == off.bytes.merkle_root, "continue: the MM commitment root is unchanged (same ledger)");
    const auto fo = fact_of(off, TAG), fc = fact_of(cont, TAG), fp = fact_of(open, TAG);
    CHECK(fo && fc && fp, "ChainFacts read from the three blobs");
    if (!(fo && fc && fp)) return;
    const auto root_ledger = ep::mm_root_of(LANE_CHAIN, cont.ledger.ledger().owed_digest());
    CHECK(fo->own && fo->ep == credit::EpochParse::Absent && ep::effective_field(*fo).seq == 0,
          "gate-OFF block: Own, no field -> read as epoch 0");
    CHECK(fc->own && fc->ep == credit::EpochParse::Present && fc->f == kField && fc->has_root && fc->root == root_ledger && fc->has_cut,
          "continue block: Own, field (seq %u), root = the ledger's (%s), cut present", fc->f.seq, hex(fc->root).substr(0, 16).c_str());
    CHECK(fp->own && fp->f == kField && fp->root == ep::empty_root(LANE_CHAIN) && !(fp->root == root_ledger) && fp->has_cut,
          "OPENER block over a 2-row ledger commits the EMPTY root %s (E1: every node books the new epoch from empty)",
          hex(fp->root).substr(0, 16).c_str());
    CHECK(cont.asked_h == open.asked_h && cont.asked_h > 0, "the plan is asked for the template height (%llu)",
          static_cast<unsigned long long>(cont.asked_h));
    const auto foreign = ep::fact_of_blob(1234, b32(0x99), cont.bytes.full_blob, b32(0x01));
    CHECK(foreign && !foreign->own, "another pool's tag: the same block is not Own (the rule never reads it)");
}

void suite_hello() {
    std::printf("== D. relay HELLO lane_params_digest ==\n");
    ::v37::LaneParams off{}, on1{}, on2{}, on3{};
    on1.epoch = ::v37::EpochGate::for_version(1, 40, 1);
    on2.epoch = ::v37::EpochGate::for_version(1, 41, 1);
    on3.epoch = ::v37::EpochGate::for_version(1, 40, 900);
    const auto dof = relay::lane_params_digest(off, 2000, relay::BindMode::None, 3);
    const auto d1 = relay::lane_params_digest(on1, 2000, relay::BindMode::None, 3);
    const auto d2 = relay::lane_params_digest(on2, 2000, relay::BindMode::None, 3);
    const auto d3 = relay::lane_params_digest(on3, 2000, relay::BindMode::None, 3);
    CHECK(!::v37::EpochGate::for_version(2, 40, 1).enabled && !::v37::EpochGate::for_version(1, 0, 1).enabled &&
          !::v37::EpochGate::for_version(1, 40, 0).enabled, "unknown version / N 0 / origin 0 -> gate OFF (fail-safe)");
    std::printf("  gate OFF digest %s\n", hex(dof).c_str());
    CHECK(!(dof == d1) && !(d1 == d2) && !(d1 == d3), "gate ON differs from OFF, and by N and by origin (mixed fleets refuse at HELLO)");
    CHECK(lineage::pool_tag_for(LANE_CHAIN, on1, b32(0xA0)) == lineage::pool_tag_for(LANE_CHAIN, off, b32(0xA0)),
          "pool_tag is unchanged by the flip: ONE structure, the epoch lives inside it");
}

} // namespace

int main() {
    std::printf("v37_xmr_epoch_field_kat: LANE-EPOCH V37E field\n");
    suite_codec();
    suite_empty_root();
    suite_blocks();
    suite_hello();
    std::printf("v37_xmr_epoch_field_kat: %d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
