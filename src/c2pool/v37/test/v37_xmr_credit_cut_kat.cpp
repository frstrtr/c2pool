// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// v37_xmr_credit_cut_kat -- R1: the ON-CHAIN CREDIT CUT tail (armed coinbase shape)
//
// The consumer-tree KAT the impl tree points at from xmr_block_assembly.hpp
// (CREDIT_CUT_TAIL_BYTES "static_assert lives in v37_xmr_credit_cut_kat").
// It pins the R1 coinbase-shape golden bump (operator-approved 2026-09-21):
//
//   0x02  varint(len)  [ nonce(4) | pad(0..10) | "V37C" | u64le P | b32 spine ]
//
// Suites
//   A  byte format: encode/parse round trip, negative controls, the
//      static_assert that ties the impl-tree parse bound to the format.
//   B  the ARMED template vs the UNARMED template built from the SAME fixture
//      (the monerod arm over the captured C4 get_miner_data, no tx backlog, so
//      every byte is deterministic):
//        * miner_tx grows by EXACTLY +44, the 0x02 length varint stays ONE byte
//          (the weight-invariance trick is untouched);
//        * deterministic r / R, the 0x03 MM root, every vout (key, amount,
//          view tag) are BYTE-IDENTICAL armed vs unarmed -- the tail moves
//          neither owed_digest nor the lane commitment;
//        * the tail parses back to the committed (P, spine) and the coinbase-
//          authority decoder reads it (has_credit_cut) -- and does NOT on the
//          unarmed block;
//        * the per-extra_nonce patch touches only the first 4 payload bytes,
//          never the tail;
//        * inspect_kfair_coinbase ACCEPTs both shapes (the gate rebuilds with the
//          payload AS ASSEMBLED).
//   C  the GOLDEN: the armed and unarmed miner_tx prefixes, frozen as hex.
//      The unarmed golden is the pre-R1 shape (byte-identical without a
//      credit_cut_source, as the R1 commit promises); the armed golden is the
//      unarmed one with the 44-byte tail spliced into the 0x02 payload and the
//      length byte bumped by 44 -- proven structurally AND against the frozen
//      hex. Regenerate with V37_XMR_CREDIT_CUT_KAT_PRINT=1 when the shape is
//      deliberately moved (operator-hand: it is a consensus-adjacent golden).
//
// SCOPE FENCE: consumer tree + src/impl/xmr. No v37 consensus digest is
// touched; the OwedLedger fold and owed_digest() are read, never changed.
// ---------------------------------------------------------------------------
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/template/xmr_monerod_miner_data.hpp"
#include "impl/xmr/template/xmr_block_assembly.hpp"

#include "c2pool/v37/xmr/xmr_coinbase_authority.hpp"
#include "c2pool/v37/xmr/xmr_credit_cut.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_provider.hpp"
#include "c2pool/v37/xmr/xmr_settlement_coinbase_shape.hpp"

#include "xmr_c4_parity_golden.hpp"

using namespace c2pool::xmr::native;

namespace o2     = c2pool::v37n::xmr::o2;
namespace asm_   = c2pool::xmr::assembly;
namespace credit = c2pool::v37n::xmr::credit;
namespace auth   = c2pool::v37n::xmr::authority;
namespace G4     = c2pool::xmr::native::golden_c4;

// THE tie the impl tree names: its parse bound == the consumer-tree format.
static_assert(asm_::CREDIT_CUT_TAIL_BYTES == credit::kTailBytes,
              "impl-tree CREDIT_CUT_TAIL_BYTES must mirror credit::kTailBytes (44)");
static_assert(credit::kTailBytes == 44, "R1: 4 magic + 8 u64 P + 32 spine");

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

#define CHECK_RET(cond, ...) ([&] {                            \
        const bool _ok = (cond);                               \
        ++g_checks;                                            \
        if (!_ok) ++g_fail;                                    \
        std::printf("  [%s] ", _ok ? "PASS" : "FAIL");         \
        std::printf(__VA_ARGS__);                              \
        std::printf("\n");                                     \
        return _ok;                                            \
    }())

std::string hex(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(2 * n);
    for (std::size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}
template <class V> std::string hex(const V& v) { return hex(reinterpret_cast<const std::uint8_t*>(v.data()), v.size()); }

// ---------------------------------------------------------------------------
// The lane fixture (as v37_xmr_m2_native_settlement_kat): four DISTINCT payees
// the LIVE point check accepts (P_k = k*G, prime-order by construction), three
// owed + the residual sink.
// ---------------------------------------------------------------------------
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

struct LaneFixture {
    o2::XmrOwedFixture      ledger{static_cast<::v37::ChainId>(LANE_CHAIN)};
    o2::XmrSettlementConfig scfg;
    std::size_t             n_owed = 0;
    LaneFixture() {
        const auto P1 = point_of(1), P2 = point_of(2), P3 = point_of(3), P4 = point_of(4);
        ledger.seed_owed(::v37::xmr::make_xmr_std(P1, P2), 3'000'000'000ull);
        ledger.seed_owed(::v37::xmr::make_xmr_std(P3, P2), 2'000'000'000ull);
        ledger.seed_owed(::v37::xmr::make_xmr_sub(P1, P2), 1'000'000'000ull);
        n_owed = 3;
        scfg.h_min      = 0;
        scfg.output_cap = 0;
        scfg.set_residual_sink_std(P4, P2);
    }
};

// A fake IMonerodTransport answering the captured C4 get_miner_data (no tx
// backlog in that capture => a fully deterministic template).
class CannedTransport final : public ::c2pool::xmr::node::IMonerodTransport {
public:
    explicit CannedTransport(std::string body) : body_(std::move(body)) {}
    void rpc_post(const std::string&,
                  std::function<void(const ::c2pool::xmr::node::RpcResponse&)> cb) override {
        ::c2pool::xmr::node::RpcResponse r;
        r.body.assign(body_.begin(), body_.end());
        cb(r);
    }
    void zmq_subscribe(const std::string&,
                       std::function<void(const ::c2pool::xmr::node::ZmqFrame&)>) override {}
private:
    std::string body_;
};

// The committed cut under test: a distinctive P and spine.
credit::CreditCut fixture_cut() {
    credit::CreditCut c;
    c.next_pos = 0x0000000000BC614Eull;   // 12345678
    for (std::size_t i = 0; i < 32; ++i) c.spine_digest[i] = static_cast<std::uint8_t>(0xA0 + i);
    return c;
}

struct Built {
    LaneFixture                                   lane;
    CannedTransport                               tx{G4::MD_RAW_JSON};
    tmpl::MonerodMinerDataSource                  src{tx};
    std::unique_ptr<o2::XmrSettlementTemplateProvider> provider;   // built AFTER arming (the provider COPIES scfg)
    o2::SettlementSnapshot                        snap;
    asm_::BlockBytes                              bytes;      // extra_nonce 0
    bool                                          ok = false;
    std::string                                   why;
    explicit Built(bool armed) {
        if (armed) {
            lane.scfg.credit_cut_source = [](std::uint64_t& P, ::v37::bytes32& dg) {
                const credit::CreditCut c = fixture_cut(); P = c.next_pos; dg = c.spine_digest; return true; };
        }
        if (!src.poll(&why)) { why = "daemon arm did not parse the capture: " + why; return; }   // one get_miner_data
        provider = std::make_unique<o2::XmrSettlementTemplateProvider>(src, lane.ledger, lane.scfg, 0);
        if (!provider->refresh()) { why = provider->last_error(); return; }
        snap = provider->current();
        if (!snap.valid || !snap.tpl) { why = "no template"; return; }
        ok = snap.tpl->materialize(0, bytes, &why);
    }
};

// ---------------------------------------------------------------------------
// Suite A -- the byte format.
// ---------------------------------------------------------------------------
void suite_format() {
    std::printf("== A. byte format: V37C | u64le P | b32 spine (44 B) ==\n");
    const credit::CreditCut c = fixture_cut();
    const auto t = credit::encode_tail(c);
    CHECK(t.size() == 44, "encode_tail is exactly 44 bytes (%zu)", t.size());
    CHECK(std::memcmp(t.data(), "V37C", 4) == 0, "magic V37C leads the tail");
    CHECK(t[4] == 0x4E && t[5] == 0x61 && t[6] == 0xBC && t[7] == 0x00 && t[11] == 0x00, "P is u64 LITTLE-endian");
    CHECK(std::memcmp(t.data() + 12, c.spine_digest.data(), 32) == 0, "spine follows P verbatim");
    const auto back = credit::parse_tail(t);
    CHECK(back && *back == c, "parse_tail(encode_tail(c)) == c");

    // The tail rides AFTER the nonce + padding: a 14-byte padded payload + tail.
    std::vector<std::uint8_t> payload(14, 0x00);
    payload[0] = 0xDE; payload[1] = 0xAD; payload[2] = 0xBE; payload[3] = 0xEF;
    payload.insert(payload.end(), t.begin(), t.end());
    const auto back2 = credit::parse_tail(payload);
    CHECK(back2 && *back2 == c, "the tail is read from the END of a padded payload (14 + 44)");
    CHECK(payload.size() == 58 && payload.size() < 0x80, "EXTRA_NONCE_MAX_SIZE 14 + 44 = 58 < 0x80: one-byte varint");

    // Negative controls.
    std::vector<std::uint8_t> bad = payload; bad[bad.size() - 44] = 'X';
    CHECK(!credit::parse_tail(bad), "wrong magic -> no cut");
    std::vector<std::uint8_t> shrt(t.begin(), t.end() - 1);
    CHECK(!credit::parse_tail(shrt), "43 bytes -> no cut");
    CHECK(!credit::parse_tail(std::vector<std::uint8_t>(14, 0)), "bare 14-byte nonce payload -> no cut (unarmed shape)");

    // Through a synthetic tx_extra: 01 <32 pubkey> | 02 <varint len> <payload> | 03 21 00 <root>.
    std::vector<unsigned char> extra;
    extra.push_back(0x01); for (int i = 0; i < 32; ++i) extra.push_back(static_cast<unsigned char>(0x10 + i));
    extra.push_back(0x02); extra.push_back(static_cast<unsigned char>(payload.size()));
    extra.insert(extra.end(), payload.begin(), payload.end());
    extra.push_back(0x03); extra.push_back(0x21); extra.push_back(0x00); for (int i = 0; i < 32; ++i) extra.push_back(static_cast<unsigned char>(0x40 + i));
    const auto f = credit::extra_nonce_field(extra);
    CHECK(f && *f == payload, "extra_nonce_field finds the whole 0x02 payload behind the 0x01 pubkey");
    const auto back3 = credit::parse_from_tx_extra(extra);
    CHECK(back3 && *back3 == c, "parse_from_tx_extra reads the cut; the 0x03 tag after it is untouched");
    std::vector<unsigned char> extra_no02;
    extra_no02.push_back(0x01); for (int i = 0; i < 32; ++i) extra_no02.push_back(0);
    extra_no02.push_back(0x03); extra_no02.push_back(0x21); extra_no02.push_back(0x00); for (int i = 0; i < 32; ++i) extra_no02.push_back(0);
    CHECK(!credit::parse_from_tx_extra(extra_no02), "no 0x02 field -> no cut");
}

// ---------------------------------------------------------------------------
// Suite B -- armed vs unarmed template from the same fixture.
// ---------------------------------------------------------------------------
struct Parsed {
    ParsedBlock pb{};
    bool        parses = false;
    ::v37::xmr::settle::ReceivedCoinbase got;
    std::uint64_t height = 0;
    std::size_t   used = 0;
    bool        cb_parses = false;
};
Parsed parse(const asm_::BlockBytes& b) {
    Parsed p;
    const auto st = parse_block(b.full_blob.data(), b.full_blob.size(), p.pb);
    p.parses = (st == BlockParseStatus::Ok || st == BlockParseStatus::TxCountMismatch);
    if (!p.parses) return p;
    p.cb_parses = asm_::parse_coinbase_prefix(b.full_blob.data() + p.pb.miner_tx_offset, p.pb.miner_tx_size,
                                              p.got, &p.height, &p.used);
    return p;
}

void suite_armed_vs_unarmed(std::string& unarmed_hex, std::string& armed_hex) {
    std::printf("== B. ARMED vs UNARMED template (same fixture, monerod arm over the C4 capture) ==\n");
    Built u(false), a(true);
    if (!CHECK_RET(u.ok, "unarmed template builds + materializes: %s", u.ok ? "ok" : u.why.c_str())) return;
    if (!CHECK_RET(a.ok, "armed template builds + materializes: %s", a.ok ? "ok" : a.why.c_str())) return;
    CHECK(u.snap.height == G4::MD_HEIGHT && a.snap.height == G4::MD_HEIGHT, "both at the capture's height %llu",
          static_cast<unsigned long long>(G4::MD_HEIGHT));
    CHECK(u.snap.n_tx == 0 && a.snap.n_tx == 0, "no tx backlog in the capture: fees 0, deterministic bytes");

    // --- sizes: +44 exactly, one-byte varint --------------------------------
    CHECK(a.bytes.extra_nonce_size == u.bytes.extra_nonce_size + 44,
          "0x02 payload: unarmed %zu B -> armed %zu B (+44)", u.bytes.extra_nonce_size, a.bytes.extra_nonce_size);
    CHECK(a.bytes.miner_tx_size == u.bytes.miner_tx_size + 44,
          "miner_tx: unarmed %zu B -> armed %zu B (+44, the weight invariant)", u.bytes.miner_tx_size, a.bytes.miner_tx_size);
    const std::uint8_t len_u = u.bytes.full_blob[u.bytes.extra_nonce_offset - 1];
    const std::uint8_t len_a = a.bytes.full_blob[a.bytes.extra_nonce_offset - 1];
    CHECK(len_u == u.bytes.extra_nonce_size && len_a == a.bytes.extra_nonce_size && len_a < 0x80 && len_a == len_u + 44,
          "0x02 length varint: %u -> %u, still ONE byte", len_u, len_a);
    CHECK(a.bytes.full_blob.size() == u.bytes.full_blob.size() + 44, "full blob +44 and nothing else");
    CHECK(a.bytes.extra_nonce_offset == u.bytes.extra_nonce_offset, "the payload starts at the same offset (only the length byte moved)");

    // --- the tail is where R1 says, and parses back ---------------------------
    const credit::CreditCut want = fixture_cut();
    const auto tail = credit::encode_tail(want);
    const std::uint8_t* tp = a.bytes.full_blob.data() + a.bytes.extra_nonce_offset + a.bytes.extra_nonce_size - 44;
    CHECK(std::memcmp(tp, tail.data(), 44) == 0, "the last 44 payload bytes are V37C|P|spine");
    CHECK(std::memcmp(a.bytes.full_blob.data() + a.bytes.extra_nonce_offset,
                      u.bytes.full_blob.data() + u.bytes.extra_nonce_offset, u.bytes.extra_nonce_size) == 0,
          "the nonce + padding bytes before the tail are byte-identical to the unarmed payload");

    // --- everything the tail must NOT move -------------------------------------
    Parsed pu = parse(u.bytes), pa = parse(a.bytes);
    CHECK(pu.parses && pa.parses && pu.cb_parses && pa.cb_parses, "both blocks + coinbase prefixes parse");
    CHECK(pu.height == G4::MD_HEIGHT && pa.height == G4::MD_HEIGHT, "txin_gen height unchanged");
    CHECK(pa.got.R == pu.got.R, "tx pubkey R byte-identical (deterministic r untouched)");
    CHECK(pa.got.amounts == pu.got.amounts && pa.got.keys == pu.got.keys && pa.got.view_tags.size() == pu.got.view_tags.size(),
          "every vout (amount, one-time key) byte-identical (%zu outputs)", pa.got.amounts.size());
    bool vt = pa.got.view_tags.size() == pu.got.view_tags.size();
    for (std::size_t i = 0; vt && i < pa.got.view_tags.size(); ++i) vt = (pa.got.view_tags[i].tag == pu.got.view_tags[i].tag);
    CHECK(vt, "every view tag byte-identical");
    CHECK(pa.got.tx_extra.size() == pu.got.tx_extra.size() + 44, "tx_extra +44");
    CHECK(pa.got.tx_extra.size() >= 35 && pu.got.tx_extra.size() >= 35 &&
          std::memcmp(pa.got.tx_extra.data() + pa.got.tx_extra.size() - 35, pu.got.tx_extra.data() + pu.got.tx_extra.size() - 35, 35) == 0,
          "the 0x03 21 00 root (35-byte tail of tx_extra) byte-identical: lane commitment / owed_digest untouched");
    CHECK(a.bytes.merkle_root == u.bytes.merkle_root, "MM commitment root identical");
    CHECK(std::memcmp(a.bytes.full_blob.data(), u.bytes.full_blob.data(), a.bytes.miner_tx_offset) == 0,
          "block header byte-identical (%zu B)", a.bytes.miner_tx_offset);
    CHECK(u.lane.ledger.ledger().owed_digest() == a.lane.ledger.ledger().owed_digest(), "owed_digest identical on both fixtures");

    // --- the cut reads back through both decoders -------------------------------
    const auto cut_a = credit::parse_from_tx_extra(pa.got.tx_extra);
    const auto cut_u = credit::parse_from_tx_extra(pu.got.tx_extra);
    CHECK(cut_a && *cut_a == want, "parse_from_tx_extra(armed) == the committed (P, spine)");
    CHECK(!cut_u, "parse_from_tx_extra(unarmed) -> no cut");
    {
        std::vector<::v37::bytes32> cands{a.lane.ledger.ledger().owed_digest()};
        const auto keys = a.lane.ledger.keys();
        const auto bk_a = auth::decode_lane_coinbase(a.bytes.full_blob, LANE_CHAIN, cands, keys,
                                                     a.lane.scfg.residual_sink, a.lane.scfg.residual_sink_identity, a.lane.ledger.pay_of());
        const auto bk_u = auth::decode_lane_coinbase(u.bytes.full_blob, LANE_CHAIN, cands, keys,
                                                     u.lane.scfg.residual_sink, u.lane.scfg.residual_sink_identity, u.lane.ledger.pay_of());
        CHECK(bk_a.ok && bk_a.is_lane, "coinbase authority decodes the ARMED block: %s", bk_a.ok ? "ok" : bk_a.why.c_str());
        CHECK(bk_u.ok && bk_u.is_lane, "coinbase authority decodes the UNARMED block: %s", bk_u.ok ? "ok" : bk_u.why.c_str());
        CHECK(bk_a.has_credit_cut && bk_a.credit_cut == want, "authority reads has_credit_cut + the committed cut off the armed block");
        CHECK(!bk_u.has_credit_cut, "authority reads NO credit cut off the unarmed block");
        CHECK(bk_a.payout == bk_u.payout && bk_a.total == bk_u.total && bk_a.lane_commitment == bk_u.lane_commitment,
              "payout map / total / lane_commitment identical armed vs unarmed (%zu payees, %llu piconero)",
              bk_a.payout.size(), static_cast<unsigned long long>(bk_a.total));
        // R-C rework-2 (F-MONEY M2): an output mapping to NO known payee keeps the
        // block fail-closed for booking, but the decoder now reports the mapped
        // part + the unmapped sum instead of clearing the payout map (so a refusing
        // node can debit what it can attribute). Keep ONLY the last paid key in the
        // payee registry (the fixture aliases STD/SUB refs over the same keys, so
        // dropping one key is not enough): every other owed output is unmapped.
        if (bk_a.payout.size() >= 2) {
            const ::v37::bytes32 kept = bk_a.payout.rbegin()->first;
            const ::v37::bytes32 dropped = bk_a.payout.begin()->first;
            std::vector<::v37::bytes32> keys_minus{kept};
            const auto bk_p = auth::decode_lane_coinbase(a.bytes.full_blob, LANE_CHAIN, cands, keys_minus,
                                                         a.lane.scfg.residual_sink, a.lane.scfg.residual_sink_identity, a.lane.ledger.pay_of());
            std::map<::v37::bytes32, long long> expect; expect[kept] = bk_a.payout.at(kept);
            long long dropped_amt = 0; for (const auto& [k, v] : bk_a.payout) if (!(k == kept)) dropped_amt += v;
            (void)dropped;
            CHECK(!bk_p.ok && bk_p.payout_partial && bk_p.unmapped_outputs >= 1 &&
                  bk_p.unmapped_total == static_cast<std::uint64_t>(dropped_amt) && bk_p.payout == expect &&
                  bk_p.sink_total == bk_a.sink_total,
                  "unmapped payee: fail-closed (ok=0) but PARTIAL payout kept (%zu of %zu keys) + unmapped_total=%llu == the unregistered keys' %lld",
                  bk_p.payout.size(), bk_a.payout.size(), static_cast<unsigned long long>(bk_p.unmapped_total), dropped_amt);
        }
    }

    // --- the K_fair shape gate ACCEPTs both -------------------------------------
    const o2::KFairCoinbaseShape su = o2::inspect_kfair_coinbase(*u.snap.tpl, u.lane.ledger.ledger().owed_digest());
    const o2::KFairCoinbaseShape sa = o2::inspect_kfair_coinbase(*a.snap.tpl, a.lane.ledger.ledger().owed_digest());
    CHECK(su.ok, "shape gate ACCEPTs the unarmed template: %s", su.ok ? "ok" : su.why.c_str());
    CHECK(sa.ok, "shape gate ACCEPTs the armed template: %s", sa.ok ? "ok" : sa.why.c_str());
    CHECK(sa.canonical && su.canonical, "canonical_coinbase_matches on both (the rebuild uses the payload AS ASSEMBLED)");
    CHECK(sa.n_owed == u.lane.n_owed && su.n_owed == u.lane.n_owed, "%zu owed outputs on both", sa.n_owed);

    // --- the per-extra_nonce patch never touches the tail ---------------------
    asm_::BlockBytes a1; std::string w1;
    if (CHECK_RET(a.snap.tpl->materialize(1, a1, &w1), "armed template materializes for extra_nonce 1: %s", w1.c_str())) {
        CHECK(a1.extra_nonce_size == a.bytes.extra_nonce_size && a1.full_blob.size() == a.bytes.full_blob.size(),
              "extra_nonce 1: same sizes");
        CHECK(std::memcmp(a1.full_blob.data() + a1.extra_nonce_offset, a.bytes.full_blob.data() + a.bytes.extra_nonce_offset, 4) != 0,
              "extra_nonce 1: the first 4 payload bytes changed");
        CHECK(std::memcmp(a1.full_blob.data() + a1.extra_nonce_offset + 4, a.bytes.full_blob.data() + a.bytes.extra_nonce_offset + 4,
                          a.bytes.extra_nonce_size - 4) == 0,
              "extra_nonce 1: padding + tail untouched (the tail is never patched)");
        const auto cut1 = credit::parse_from_tx_extra(parse(a1).got.tx_extra);
        CHECK(cut1 && *cut1 == want, "extra_nonce 1: the cut still reads back");
    }

    unarmed_hex = hex(u.bytes.coinbase_prefix());
    armed_hex   = hex(a.bytes.coinbase_prefix());
}

// ---------------------------------------------------------------------------
// Suite C -- the frozen goldens (regenerate: V37_XMR_CREDIT_CUT_KAT_PRINT=1).
// ---------------------------------------------------------------------------
// The pre-R1 (unarmed) coinbase prefix for this fixture -- byte-identical
// without a credit_cut_source (the R1 promise) -- and the R1 ARMED shape.
constexpr const char* GOLDEN_UNARMED_PREFIX_HEX = "02dcca860101ffa0ca86010480bcc1960b038b3a956499d0e159fcd89371adc8035e60945b8a9aeccc6cd0f7041dab9cae792780a8d6b90703ed0db69829682ca9be8da6084d1fa73f8e7ba8afb8db9c1d9fbd93bd13e1bcd7268094ebdc03036ff5d18649e31f8761df7cee0ad9bc9571ece9f1639dbf5ee02640547c8d61eee280e8a2e9a41103269c97dc5a9b2e98831977dc1a875239173d49702e0116a253c27a7f61a61eb1d44a01b04a687c0d03d07c7491314f056ad2bef6ad797a0d14b6b465db210cd2f7f3e90204000000000321008642184bd345ab87e9faf921ec3b0496737d390d9110bbc2f41477ac9105018d";
constexpr const char* GOLDEN_ARMED_PREFIX_HEX   = "02dcca860101ffa0ca86010480bcc1960b038b3a956499d0e159fcd89371adc8035e60945b8a9aeccc6cd0f7041dab9cae792780a8d6b90703ed0db69829682ca9be8da6084d1fa73f8e7ba8afb8db9c1d9fbd93bd13e1bcd7268094ebdc03036ff5d18649e31f8761df7cee0ad9bc9571ece9f1639dbf5ee02640547c8d61eee280e8a2e9a41103269c97dc5a9b2e98831977dc1a875239173d49702e0116a253c27a7f61a61eb1d47601b04a687c0d03d07c7491314f056ad2bef6ad797a0d14b6b465db210cd2f7f3e9023000000000563337434e61bc0000000000a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0321008642184bd345ab87e9faf921ec3b0496737d390d9110bbc2f41477ac9105018d";

void suite_golden(const std::string& unarmed_hex, const std::string& armed_hex) {
    std::printf("== C. coinbase-shape GOLDEN (armed R1 tail) ==\n");
    if (std::getenv("V37_XMR_CREDIT_CUT_KAT_PRINT")) {
        std::printf("GOLDEN_UNARMED_PREFIX_HEX=%s\nGOLDEN_ARMED_PREFIX_HEX=%s\n", unarmed_hex.c_str(), armed_hex.c_str());
        std::fflush(stdout);
    }
    if (unarmed_hex.empty() || armed_hex.empty()) { CHECK(false, "suite B produced no bytes"); return; }
    CHECK(unarmed_hex == GOLDEN_UNARMED_PREFIX_HEX, "UNARMED miner_tx prefix == frozen pre-R1 golden (%zu B)", unarmed_hex.size() / 2);
    CHECK(armed_hex == GOLDEN_ARMED_PREFIX_HEX, "ARMED miner_tx prefix == frozen R1 golden (%zu B)", armed_hex.size() / 2);
    // Structural derivation: armed == unarmed with the 44-byte tail spliced in
    // right after the padded nonce and the 0x02 length byte bumped by 44.
    std::vector<std::uint8_t> ub, ab;
    auto unhex = [](const std::string& h, std::vector<std::uint8_t>& out) {
        out.clear();
        if (h.find_first_not_of("0123456789abcdef") != std::string::npos || (h.size() % 2)) return;   // an unpinned golden: derivation fails loudly below
        for (std::size_t i = 0; i + 1 < h.size(); i += 2) out.push_back(static_cast<std::uint8_t>(std::stoul(h.substr(i, 2), nullptr, 16))); };
    unhex(std::string(GOLDEN_UNARMED_PREFIX_HEX), ub); unhex(std::string(GOLDEN_ARMED_PREFIX_HEX), ab);
    // locate the 0x02 field in the unarmed prefix: the tx_extra is the last part; find "02 <len>" after the 01 pubkey
    bool derived = false;
    if (!ub.empty() && ab.size() == ub.size() + 44) {
        // The first differing byte is the tx_extra length varint (+44, one byte as
        // long as tx_extra < 128 B -- true for this fixture); the second is the
        // 0x02 field's length byte (+44). Splice after the padded nonce.
        std::size_t i = 0; while (i < ub.size() && ub[i] == ab[i]) ++i;
        if (i < ub.size() && ab[i] == static_cast<std::uint8_t>(ub[i] + 44)) {
            std::vector<std::uint8_t> ub2 = ub; ub2[i] = ab[i];           // tx_extra length bumped
            ++i; while (i < ub2.size() && ub2[i] == ab[i]) ++i;           // next difference: the 0x02 length byte
            ub = ub2;
        }
        if (i < ub.size() && ab[i] == static_cast<std::uint8_t>(ub[i] + 44) && ub[i - 1] == 0x02) {
            const std::size_t len = ub[i];
            const std::size_t payload_end = i + 1 + len;
            std::vector<std::uint8_t> synth(ub.begin(), ub.begin() + static_cast<std::ptrdiff_t>(payload_end));
            synth[i] = static_cast<std::uint8_t>(len + 44);
            const auto tail = credit::encode_tail(fixture_cut());
            synth.insert(synth.end(), tail.begin(), tail.end());
            synth.insert(synth.end(), ub.begin() + static_cast<std::ptrdiff_t>(payload_end), ub.end());
            derived = (synth == ab);
        }
    }
    CHECK(derived, "ARMED golden == UNARMED golden + (0x02 len += 44) + 44-byte tail spliced after the padded nonce");
}

} // namespace

int main() {
    std::printf("=== v37_xmr_credit_cut_kat (R1: on-chain credit cut, armed coinbase shape) ===\n");
    suite_format();
    std::string uh, ah;
    suite_armed_vs_unarmed(uh, ah);
    suite_golden(uh, ah);
    std::printf("=== %d/%d checks passed ===\n", g_checks - g_fail, g_checks);
    return g_fail == 0 ? 0 : 1;
}
