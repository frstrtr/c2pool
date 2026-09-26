// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// v37_xmr_pool_lineage_kat -- POOL-LINEAGE: the block-level pool id
// (operator ruling 2026-09-25).
//
//   pool_tag = sha256d( 'V37PT' || lane_tag || pool_genesis_id )
//
// committed in the V37C coinbase tail of every lane block as the versioned
// field "V37P" | u8 1 | b32 pool_tag (37 B) just before the credit cut, and
// pool_genesis_id carried in the relay HELLO next to the lane_tag.
//
// Suites
//   A  derivation: the formula recomputed from raw sha256d, the S1 lane_tag
//      input, the per-network default genesis, --pool-genesis parsing.
//   B  the V37P field codec: 37 B, END-anchored before V37C, V37C / V37D
//      still parse through it, STRICT version check (malformed reject).
//   C  classify: own tag -> lane block, other tag -> ordinary, missing /
//      pre-lineage tail -> ordinary, malformed -> strict reject (ordinary);
//      also through a two-byte 0x02 length varint.
//   D  REAL assembled blocks (monerod arm over the C4 capture, the credit cut
//      armed): the coinbase delta vs an untagged (master-shape) block is
//      exactly the 37-byte V37P field; the coinbase-authority decoder books
//      OUR block and returns "not-lane:" (never a lane cut / never a root
//      question) for another pool's block and for a pre-lineage block --
//      while WITHOUT the pool tag (the pre-lineage decoder) another pool's
//      same-config block DOES match our root and would be booked as a lane
//      cut (the D-1 stall root, reproduced).
//   E  the widest 0x02 payload [nonce|rbind 32|pad|V37D|V37P|V37C] = 139 B
//      (a TWO-byte length varint) assembles, materializes and parses.
//   F  the relay HELLO: +32 B genesis, round trip, a different genesis =
//      TAG_MISMATCH field=pool_genesis, same genesis = compatible.
// ---------------------------------------------------------------------------
#include <algorithm>
#include <array>
#include <cctype>
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
#include "c2pool/v37/xmr/xmr_fee_model.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_provider.hpp"
#include "c2pool/v37/xmr/xmr_pool_tag.hpp"
#include "c2pool/v37/xmr/xmr_settlement_coinbase_shape.hpp"
#include "c2pool/v37/xmr/relay/xmr_relay_wire.hpp"

#include "xmr_c4_parity_golden.hpp"

using namespace c2pool::xmr::native;

namespace o2      = c2pool::v37n::xmr::o2;
namespace asm_    = c2pool::xmr::assembly;
namespace credit  = c2pool::v37n::xmr::credit;
namespace auth    = c2pool::v37n::xmr::authority;
namespace fee     = c2pool::v37n::xmr::fee;
namespace lineage = c2pool::v37n::xmr::lineage;
namespace relay   = c2pool::v37n::xmr::relay;
namespace x6      = ::v37::xmr::settle;
namespace G4      = c2pool::xmr::native::golden_c4;

// THE tie the impl tree names: its parse bound == the consumer-tree format.
static_assert(asm_::POOL_TAG_FIELD_BYTES == credit::kPoolTagFieldBytes,
              "impl-tree POOL_TAG_FIELD_BYTES must mirror credit::kPoolTagFieldBytes (37)");
static_assert(credit::kPoolTagFieldBytes == 37, "V37P field: 4 magic + 1 version + 32 pool_tag");
static_assert(relay::kHelloBytesPoolGenesis == 174 && relay::kHelloPoolGenesisBytes == 32,
              "HELLO + pool_genesis_id = 142 + 32");

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

// ---------------------------------------------------------------------------
// Frozen: the default REGTEST pool of the bare XMR LaneParams{} on chain 0
// (regenerate with V37_XMR_POOL_LINEAGE_KAT_PRINT=1 only on a deliberate move).
// ---------------------------------------------------------------------------
constexpr const char* GOLDEN_REGTEST_DEFAULT_GENESIS = "95f448de1c380509b4fd7250ee9d2675fc52fec311e8baf66eb8bcf63bbf7d7f";
constexpr const char* GOLDEN_REGTEST_DEFAULT_POOL_TAG = "3aed952f5525426d99c4ba07c2f8b5283bec072bf62903985d4c04df366fd033";

void suite_derivation() {
    std::printf("== A. pool_tag = sha256d('V37PT' || lane_tag || pool_genesis_id) ==\n");
    const ::v37::LaneParams p{};
    const auto lt = lineage::lane_tag_of(0, p);
    const auto lt_ref = ::c2pool::v37n::rb::lane_tag(::c2pool::v37n::rb::LaneTagContext::of(0, p, ::v37::SHIPPED_CONSENSUS_VERSION, 0), 0, 0, 0);
    CHECK(lt == lt_ref, "lane_tag input == the S1 single-roundabout tag (map_epoch 0, rb 0, stripe 0)");
    CHECK(lt == relay::pool_id_of(0, p).lane_tag, "lane_tag input == the relay HELLO lane_tag (pool_id_of)");
    const auto g = b32(0x11);
    std::vector<std::uint8_t> pre = {'V', '3', '7', 'P', 'T'};
    pre.insert(pre.end(), lt.begin(), lt.end());
    pre.insert(pre.end(), g.begin(), g.end());
    CHECK(pre.size() == 69, "preimage is 5 + 32 + 32 = 69 bytes");
    CHECK(lineage::pool_tag(lt, g) == ::v37::sha256d(pre), "pool_tag == sha256d of the raw preimage");
    CHECK(lineage::pool_tag_for(0, p, g) == lineage::pool_tag(lt, g), "pool_tag_for(chain, LaneParams, genesis) == pool_tag(lane_tag_of, genesis)");
    CHECK(lineage::pool_tag(lt, b32(0x12)) != lineage::pool_tag(lt, g), "another genesis -> another pool_tag");
    CHECK(lineage::pool_tag_for(7, p, g) != lineage::pool_tag_for(0, p, g), "another chain_id (another lane_tag) -> another pool_tag");
    const auto dg0 = lineage::default_pool_genesis(0), dg2 = lineage::default_pool_genesis(2), dg3 = lineage::default_pool_genesis(3);
    std::vector<std::uint8_t> gp = {'V', '3', '7', 'P', 'G', 3};
    CHECK(dg3 == ::v37::sha256d(gp), "default genesis(regtest) == sha256d('V37PG' || u8 3)");
    CHECK(dg0 != dg2 && dg2 != dg3 && dg0 != dg3, "one default pool PER network (mainnet/stagenet/regtest ids differ)");
    const auto tag3 = lineage::pool_tag_for(0, p, dg3);
    if (std::getenv("V37_XMR_POOL_LINEAGE_KAT_PRINT"))
        std::printf("GOLDEN_REGTEST_DEFAULT_GENESIS=%s\nGOLDEN_REGTEST_DEFAULT_POOL_TAG=%s\n", hex(dg3).c_str(), hex(tag3).c_str());
    CHECK(hex(dg3) == GOLDEN_REGTEST_DEFAULT_GENESIS, "frozen default regtest genesis %s", hex(dg3).substr(0, 16).c_str());
    CHECK(hex(tag3) == GOLDEN_REGTEST_DEFAULT_POOL_TAG, "frozen default regtest pool_tag %s", hex(tag3).substr(0, 16).c_str());

    ::v37::bytes32 out{};
    CHECK(lineage::parse_genesis_hex(hex(g), out) && out == g, "--pool-genesis parses 64 hex digits");
    std::string up = hex(g); for (auto& c : up) c = static_cast<char>(std::toupper(c));
    CHECK(lineage::parse_genesis_hex(up, out) && out == g, "--pool-genesis accepts upper case");
    CHECK(!lineage::parse_genesis_hex(hex(g).substr(0, 63), out), "63 digits -> refused");
    CHECK(!lineage::parse_genesis_hex(hex(g) + "0", out), "65 digits -> refused");
    std::string bad = hex(g); bad[10] = 'g';
    CHECK(!lineage::parse_genesis_hex(bad, out), "a non-hex digit -> refused");
}

// ---------------------------------------------------------------------------
// Suite B -- the V37P field codec.
// ---------------------------------------------------------------------------
credit::CreditCut fixture_cut() {
    credit::CreditCut c;
    c.next_pos = 0x0000000000BC614Eull;
    for (std::size_t i = 0; i < 32; ++i) c.spine_digest[i] = static_cast<std::uint8_t>(0xA0 + i);
    return c;
}

std::vector<std::uint8_t> payload_of(bool v37d, const ::v37::bytes32* tag, bool cut, std::size_t lead = 14) {
    std::vector<std::uint8_t> p(lead, 0x00);
    if (lead >= 4) { p[0] = 0xDE; p[1] = 0xAD; p[2] = 0xBE; p[3] = 0xEF; }
    if (v37d) { const auto t = fee::encode_donation_owed_tail(424242); p.insert(p.end(), t.begin(), t.end()); }
    if (tag)  { const auto t = credit::encode_pool_tag_field(*tag);   p.insert(p.end(), t.begin(), t.end()); }
    if (cut)  { const auto t = credit::encode_tail(fixture_cut());   p.insert(p.end(), t.begin(), t.end()); }
    return p;
}

void suite_codec() {
    std::printf("== B. the V37P field: \"V37P\" | u8 1 | b32 pool_tag (37 B), before V37C ==\n");
    const auto T = b32(0x50);
    const auto f = credit::encode_pool_tag_field(T);
    CHECK(f.size() == 37 && std::memcmp(f.data(), "V37P", 4) == 0 && f[4] == 1 && std::memcmp(f.data() + 5, T.data(), 32) == 0,
          "encode: 37 bytes, magic V37P, version 1, the tag verbatim");
    ::v37::bytes32 got{};
    for (int v37d = 0; v37d < 2; ++v37d)
        for (int cut = 0; cut < 2; ++cut) {
            const auto p = payload_of(v37d, &T, cut);
            got = {};
            const auto st = credit::parse_pool_tag_payload(p, &got);
            CHECK(st == credit::PoolTagParse::Present && got == T, "[nonce|pad%s|V37P%s] -> Present, tag read back",
                  v37d ? "|V37D" : "", cut ? "|V37C" : "");
            const auto cc = credit::parse_tail(p);
            CHECK(cut ? (cc && *cc == fixture_cut()) : !cc, "  the credit cut %s (parse_tail unchanged, V37C stays LAST)", cut ? "still parses" : "is absent");
            const auto dn = fee::parse_donation_owed_payload(p);
            CHECK(v37d ? (dn && *dn == 424242) : !dn, "  the V37D owed_in %s through the V37P field", v37d ? "still parses" : "is absent");
        }
    CHECK(credit::parse_pool_tag_payload(payload_of(false, nullptr, true)) == credit::PoolTagParse::Absent,
          "[nonce|pad|V37C] (the pre-lineage tail) -> Absent");
    CHECK(credit::parse_pool_tag_payload(payload_of(true, nullptr, true)) == credit::PoolTagParse::Absent,
          "[nonce|pad|V37D|V37C] (pre-lineage, fee model) -> Absent");
    CHECK(credit::parse_pool_tag_payload(std::vector<std::uint8_t>(14, 0)) == credit::PoolTagParse::Absent, "bare 14-byte nonce payload -> Absent");
    CHECK(credit::parse_pool_tag_payload({}) == credit::PoolTagParse::Absent, "empty payload -> Absent");
    auto p = payload_of(false, &T, true);
    p[p.size() - 44 - 37 + 4] = 2;   // version byte
    CHECK(credit::parse_pool_tag_payload(p) == credit::PoolTagParse::Malformed, "V37P magic with version 2 -> Malformed (strict)");
    p[p.size() - 44 - 37 + 4] = 0;
    CHECK(credit::parse_pool_tag_payload(p) == credit::PoolTagParse::Malformed, "V37P magic with version 0 -> Malformed (strict)");
    auto pd = payload_of(true, &T, true); pd[pd.size() - 44 - 37 + 4] = 9;
    CHECK(!fee::parse_donation_owed_payload(pd), "a malformed V37P field makes the V37D read fail CLOSED (never mis-located)");
    auto pm = payload_of(false, &T, true); pm[pm.size() - 44 - 37] = 'X';
    CHECK(credit::parse_pool_tag_payload(pm) == credit::PoolTagParse::Absent, "wrong magic at the field position -> Absent (no field)");
}

// ---------------------------------------------------------------------------
// Suite C -- classify over a synthetic tx_extra.
// ---------------------------------------------------------------------------
std::vector<unsigned char> tx_extra_of(const std::vector<std::uint8_t>& payload) {
    std::vector<unsigned char> e;
    e.push_back(0x01); for (int i = 0; i < 32; ++i) e.push_back(static_cast<unsigned char>(0x10 + i));
    e.push_back(0x02);
    std::size_t n = payload.size();
    while (n >= 0x80) { e.push_back(static_cast<unsigned char>((n & 0x7f) | 0x80)); n >>= 7; }
    e.push_back(static_cast<unsigned char>(n));
    e.insert(e.end(), payload.begin(), payload.end());
    e.push_back(0x03); e.push_back(0x21); e.push_back(0x00); for (int i = 0; i < 32; ++i) e.push_back(static_cast<unsigned char>(0x40 + i));
    return e;
}

void suite_classify() {
    std::printf("== C. classify: own -> lane, other -> ordinary, missing/old -> ordinary, malformed -> strict reject ==\n");
    const auto OUR = b32(0x50), OTHER = b32(0x60);
    ::v37::bytes32 seen{};
    CHECK(lineage::classify_lineage(tx_extra_of(payload_of(false, &OUR, true)), OUR) == lineage::BlockLineage::Own, "our tag -> Own (a lane block of this pool)");
    CHECK(lineage::classify_lineage(tx_extra_of(payload_of(false, &OTHER, true)), OUR, &seen) == lineage::BlockLineage::Foreign && seen == OTHER,
          "another pool's tag -> Foreign (ordinary), the foreign tag reported");
    CHECK(lineage::classify_lineage(tx_extra_of(payload_of(false, nullptr, true)), OUR) == lineage::BlockLineage::Untagged, "pre-lineage V37C tail -> Untagged (ordinary)");
    CHECK(lineage::classify_lineage(tx_extra_of(payload_of(false, nullptr, false)), OUR) == lineage::BlockLineage::Untagged, "no tail at all -> Untagged (ordinary)");
    std::vector<unsigned char> no02;
    no02.push_back(0x01); for (int i = 0; i < 32; ++i) no02.push_back(0);
    CHECK(lineage::classify_lineage(no02, OUR) == lineage::BlockLineage::Untagged, "no 0x02 field -> Untagged (ordinary)");
    auto pm = payload_of(false, &OUR, true); pm[pm.size() - 44 - 37 + 4] = 7;
    CHECK(lineage::classify_lineage(tx_extra_of(pm), OUR) == lineage::BlockLineage::Malformed, "OUR tag under an unknown version -> Malformed (strict: never Own)");
    // the widest shape: nonce 4 | rbind 32 | pad 10 | V37D | V37P | V37C = 139 B -> a two-byte varint
    auto wide = payload_of(true, &OUR, true, 46);
    const auto e = tx_extra_of(wide);
    CHECK(wide.size() == 139 && e[34] == static_cast<unsigned char>((139 & 0x7f) | 0x80) && e[35] == 0x01,
          "widest payload %zu B: the 0x02 length is a TWO-byte varint (%02x %02x)", wide.size(), e[34], e[35]);
    CHECK(lineage::classify_lineage(e, OUR) == lineage::BlockLineage::Own, "  classify reads through the two-byte varint -> Own");
    const auto cc = credit::parse_from_tx_extra(e);
    CHECK(cc && *cc == fixture_cut(), "  the credit cut still parses through it");
}

// ---------------------------------------------------------------------------
// Suite D -- real assembled blocks (the credit-cut KAT fixture).
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
    LaneFixture() {
        const auto P1 = point_of(1), P2 = point_of(2), P3 = point_of(3), P4 = point_of(4);
        ledger.seed_owed(::v37::xmr::make_xmr_std(P1, P2), 3'000'000'000ull);
        ledger.seed_owed(::v37::xmr::make_xmr_std(P3, P2), 2'000'000'000ull);
        ledger.seed_owed(::v37::xmr::make_xmr_sub(P1, P2), 1'000'000'000ull);
        scfg.h_min      = 0;
        scfg.output_cap = 0;
        scfg.set_residual_sink_std(P4, P2);
    }
};

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

struct Built {
    LaneFixture                                        lane;
    CannedTransport                                    tx{G4::MD_RAW_JSON};
    tmpl::MonerodMinerDataSource                       src{tx};
    std::unique_ptr<o2::XmrSettlementTemplateProvider> provider;
    o2::SettlementSnapshot                             snap;
    asm_::BlockBytes                                   bytes;
    bool                                               ok = false;
    std::string                                        why;
    explicit Built(std::optional<::v37::bytes32> tag) {
        lane.scfg.credit_cut_source = [](std::uint64_t& P, ::v37::bytes32& dg) {
            const credit::CreditCut c = fixture_cut(); P = c.next_pos; dg = c.spine_digest; return true; };
        lane.scfg.pool_tag = tag;
        if (!src.poll(&why)) { why = "daemon arm did not parse the capture: " + why; return; }
        provider = std::make_unique<o2::XmrSettlementTemplateProvider>(src, lane.ledger, lane.scfg, 0);
        if (!provider->refresh()) { why = provider->last_error(); return; }
        snap = provider->current();
        if (!snap.valid || !snap.tpl) { why = "no template"; return; }
        ok = snap.tpl->materialize(0, bytes, &why);
    }
};

struct Parsed_ { x6::ReceivedCoinbase got; bool ok = false; };
Parsed_ parse_(const asm_::BlockBytes& b) {
    Parsed_ p; std::uint64_t h = 0; std::size_t used = 0;
    p.ok = asm_::parse_coinbase_prefix(b.full_blob.data() + b.miner_tx_offset, b.miner_tx_size, p.got, &h, &used);
    return p;
}

void suite_blocks() {
    std::printf("== D. real assembled blocks: pool A (ours) vs pool B vs a pre-lineage block, same ledger + config ==\n");
    const ::v37::LaneParams lp{};
    const auto TAG_A = lineage::pool_tag_for(LANE_CHAIN, lp, b32(0xA0));
    const auto TAG_B = lineage::pool_tag_for(LANE_CHAIN, lp, b32(0xB0));
    Built a(TAG_A), b(TAG_B), u(std::nullopt);
    CHECK(a.ok && b.ok && u.ok, "three templates build + materialize (%s / %s / %s)", a.ok ? "ok" : a.why.c_str(),
          b.ok ? "ok" : b.why.c_str(), u.ok ? "ok" : u.why.c_str());
    if (!(a.ok && b.ok && u.ok)) return;

    // --- the coinbase delta vs the untagged (master-shape) block: exactly the V37P field
    // (+1 byte only if the tx_extra length varint crosses 128 B: a varint, not a new field)
    auto vlen = [](std::size_t n) { std::size_t k = 1; while (n >= 0x80) { n >>= 7; ++k; } return k; };
    Parsed_ pa = parse_(a.bytes), pu = parse_(u.bytes);
    CHECK(pa.ok && pu.ok, "both coinbase prefixes parse");
    if (!(pa.ok && pu.ok)) return;
    const std::size_t grow = vlen(pa.got.tx_extra.size()) - vlen(pu.got.tx_extra.size());
    CHECK(pa.got.tx_extra.size() == pu.got.tx_extra.size() + 37, "tx_extra %zu -> %zu B (+37: the V37P field)",
          pu.got.tx_extra.size(), pa.got.tx_extra.size());
    CHECK(a.bytes.miner_tx_size == u.bytes.miner_tx_size + 37 + grow && a.bytes.full_blob.size() == u.bytes.full_blob.size() + 37 + grow,
          "miner_tx %zu -> %zu B (+37 field +%zu tx_extra length-varint byte%s)", u.bytes.miner_tx_size, a.bytes.miner_tx_size,
          grow, grow ? " (the length crossed 128 B)" : "s");
    CHECK(a.bytes.extra_nonce_size == u.bytes.extra_nonce_size + 37 && a.bytes.extra_nonce_size < 0x80,
          "0x02 payload %zu -> %zu B (+37; one-byte varint without rbind/V37D)", u.bytes.extra_nonce_size, a.bytes.extra_nonce_size);
    const std::uint8_t* ap = a.bytes.full_blob.data() + a.bytes.extra_nonce_offset;
    const std::uint8_t* up = u.bytes.full_blob.data() + u.bytes.extra_nonce_offset;
    const std::size_t lead = u.bytes.extra_nonce_size - 44;
    const auto fld = credit::encode_pool_tag_field(TAG_A);
    CHECK(std::memcmp(ap, up, lead) == 0 && std::memcmp(ap + lead, fld.data(), 37) == 0 && std::memcmp(ap + lead + 37, up + lead, 44) == 0,
          "payload = the untagged payload with the 37-byte V37P field spliced before the 44-byte V37C tail");
    // everything else byte-identical: rebuild the tagged coinbase prefix from the untagged one
    bool spliced = false;
    {
        const std::vector<std::uint8_t> ua = u.bytes.coinbase_prefix(), aa = a.bytes.coinbase_prefix();
        const auto& ue = pu.got.tx_extra;
        const std::size_t head = ua.size() - ue.size() - vlen(ue.size());   // tx_extra is the prefix's LAST field
        // the untagged extra: 01 R(32) | 02 len payload | 03 ...
        std::vector<std::uint8_t> ne(ue.begin(), ue.end());
        if (ne.size() > 35 && ne[33] == 0x02 && ne[34] == u.bytes.extra_nonce_size) {
            ne[34] = static_cast<std::uint8_t>(ne[34] + 37);
            ne.insert(ne.begin() + static_cast<std::ptrdiff_t>(35 + lead), fld.begin(), fld.end());
            std::vector<std::uint8_t> synth(ua.begin(), ua.begin() + static_cast<std::ptrdiff_t>(head));
            std::size_t n = ne.size();
            while (n >= 0x80) { synth.push_back(static_cast<std::uint8_t>((n & 0x7f) | 0x80)); n >>= 7; }
            synth.push_back(static_cast<std::uint8_t>(n));
            synth.insert(synth.end(), ne.begin(), ne.end());
            spliced = (synth == aa);
        }
    }
    CHECK(spliced, "tagged miner_tx prefix == untagged prefix with (0x02 len += 37, V37P field spliced, tx_extra length re-encoded): "
                   "NOTHING else moves (r/R, every vout, the 0x03 root, the V37C cut)");
    CHECK(a.bytes.merkle_root == u.bytes.merkle_root && a.bytes.merkle_root == b.bytes.merkle_root,
          "the MM commitment root is identical on all three (same ledger, same owed_digest)");

    // --- the coinbase-authority decoder, gated by OUR tag (pool A) -------------
    std::vector<::v37::bytes32> cands{a.lane.ledger.ledger().owed_digest()};
    const auto keys = a.lane.ledger.keys();
    auto decode = [&](const Built& x, const ::v37::bytes32* tag) {
        return auth::decode_lane_coinbase(x.bytes.full_blob, LANE_CHAIN, cands, keys, a.lane.scfg.residual_sink,
                                          a.lane.scfg.residual_sink_identity, a.lane.ledger.pay_of(), tag);
    };
    const auto own = decode(a, &TAG_A), foreign = decode(b, &TAG_A), old = decode(u, &TAG_A);
    CHECK(own.ok && own.is_lane && own.lineage_gated && own.lineage == lineage::BlockLineage::Own && own.has_credit_cut,
          "OUR block: Own -> booked as a lane block (%s)", own.ok ? "ok" : own.why.c_str());
    CHECK(!foreign.ok && !foreign.is_lane && foreign.lineage == lineage::BlockLineage::Foreign && foreign.lineage_seen_tag == TAG_B &&
          foreign.why.rfind("not-lane:", 0) == 0 && foreign.payout.empty() && !foreign.has_credit_cut,
          "pool B's block: Foreign -> \"not-lane:\" (ordinary: no lane cut, no root match, no hold): %s", foreign.why.c_str());
    CHECK(!old.ok && !old.is_lane && old.lineage == lineage::BlockLineage::Untagged && old.why.rfind("not-lane:", 0) == 0,
          "a pre-lineage block (untagged V37C tail): Untagged -> \"not-lane:\": %s", old.why.c_str());
    // the reverse view: pool B's nodes see A's block as ordinary and their own as a lane block
    const auto b_own = decode(b, &TAG_B), b_sees_a = decode(a, &TAG_B);
    CHECK(b_own.ok && b_own.is_lane && !b_sees_a.is_lane && b_sees_a.lineage == lineage::BlockLineage::Foreign,
          "symmetric: pool B books its own block and sees pool A's as Foreign");
    // --- the D-1 root, reproduced: WITHOUT the gate (pre-lineage decoder) the other
    // pool's same-config block matches OUR root and would be booked as a lane cut.
    const auto ungated = decode(b, nullptr);
    CHECK(ungated.is_lane && ungated.has_credit_cut && !ungated.lineage_gated,
          "ungated (pre-lineage decoder): pool B's block MATCHES pool A's root and is taken as a lane cut -- the stall the gate removes");
    // --- malformed: a tag field with an unknown version is never Own
    std::vector<std::uint8_t> mal = a.bytes.full_blob;
    mal[a.bytes.extra_nonce_offset + lead + 4] = 2;
    const auto mk = auth::decode_lane_coinbase(mal, LANE_CHAIN, cands, keys, a.lane.scfg.residual_sink,
                                               a.lane.scfg.residual_sink_identity, a.lane.ledger.pay_of(), &TAG_A);
    CHECK(!mk.is_lane && mk.lineage == lineage::BlockLineage::Malformed && mk.why.rfind("not-lane:", 0) == 0,
          "our block with the V37P version byte flipped to 2: Malformed -> strict reject, \"not-lane:\"");
    // the K_fair shape gate ACCEPTs the tagged template (the rebuild uses the payload AS ASSEMBLED)
    const o2::KFairCoinbaseShape sa = o2::inspect_kfair_coinbase(*a.snap.tpl, a.lane.ledger.ledger().owed_digest());
    CHECK(sa.ok && sa.canonical, "shape gate ACCEPTs the tagged template: %s", sa.ok ? "ok" : sa.why.c_str());
    // the per-extra_nonce patch never touches the field
    asm_::BlockBytes a1; std::string w1;
    const bool m1 = a.snap.tpl->materialize(1, a1, &w1);
    CHECK(m1 && std::memcmp(a1.full_blob.data() + a1.extra_nonce_offset + 4, ap + 4, a.bytes.extra_nonce_size - 4) == 0,
          "extra_nonce 1: padding + V37P + V37C untouched");
}

// ---------------------------------------------------------------------------
// Suite E -- the widest payload assembles (two-byte 0x02 length varint).
// ---------------------------------------------------------------------------
void suite_widest() {
    std::printf("== E. widest 0x02 payload [nonce|rbind 32|pad|V37D 12|V37P 37|V37C 44] assembles + parses ==\n");
    namespace akat = ::c2pool::xmr::assembly::kat;
    asm_::AssemblyInputs a;
    a.miner = akat::miner(3000000, 300000, 18000000000000000000ull);
    a.settle = akat::lane_ctx();
    a.settle.residual_sink = fee::donation_ref();
    a.settle.residual_sink_identity = fee::donation_identity();
    a.settle.fixed = {fee::donation_marker()};
    a.mempool = akat::txs(5, 2000, 30000000);
    for (unsigned char i = 0; i < 4; ++i) {
        x6::OwedEntry e; e.pay = akat::std_ref(); e.owed = 1000000000ull * (i + 1); e.first_eligible = 100 + i;
        e.identity = akat::id_of(static_cast<unsigned char>(0x40 + i));
        a.settle.owed.push_back(e);
    }
    x6::OwedEntry d; d.pay = fee::donation_ref(); d.owed = 424242; d.first_eligible = 101; d.identity = fee::donation_identity();
    a.settle.owed.push_back(d);
    const auto TAG = b32(0x77);
    a.extra_nonce_tail = fee::encode_donation_owed_tail(x6::fold_identity_owed(a.settle));
    { const auto f = credit::encode_pool_tag_field(TAG); a.extra_nonce_tail.insert(a.extra_nonce_tail.end(), f.begin(), f.end()); }
    { const auto ct = credit::encode_tail(fixture_cut()); a.extra_nonce_tail.insert(a.extra_nonce_tail.end(), ct.begin(), ct.end()); }
    a.extra_nonce_bind_size = 32;
    a.extra_nonce_bind = [](std::uint32_t en, std::uint8_t* out) { for (int i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(en * 7 + i); return true; };
    std::string why;
    auto t = asm_::XmrBlockAssembler::build(a, &why);
    CHECK(t != nullptr, "the widest payload builds (bound 14 + 32 + 12 + 37 + 44 = 139): %s", t ? "ok" : why.c_str());
    if (!t) return;
    asm_::BlockBytes b;
    const bool m = t->materialize(5, b, &why);
    CHECK(m && b.extra_nonce_size >= 0x80, "materializes; 0x02 payload %zu B >= 128 (a two-byte length varint): %s", b.extra_nonce_size, why.c_str());
    if (!m) return;
    CHECK(b.full_blob[b.extra_nonce_offset - 1] == 0x01 && (b.full_blob[b.extra_nonce_offset - 2] & 0x80) &&
          b.full_blob[b.extra_nonce_offset - 3] == 0x02,
          "the block carries 02 | varint(%zu) two bytes | payload", b.extra_nonce_size);
    x6::ReceivedCoinbase rc; std::uint64_t h = 0; std::size_t used = 0;
    const bool pp = asm_::parse_coinbase_prefix(b.full_blob.data() + b.miner_tx_offset, b.miner_tx_size, rc, &h, &used);
    ParsedBlock pb{};
    const auto st = parse_block(b.full_blob.data(), b.full_blob.size(), pb);
    CHECK(pp && (st == BlockParseStatus::Ok || st == BlockParseStatus::TxCountMismatch), "the block and its coinbase prefix parse");
    const auto dn = pp ? fee::parse_donation_owed(rc.tx_extra) : std::nullopt;
    const auto cp = pp ? credit::parse_from_tx_extra(rc.tx_extra) : std::nullopt;
    CHECK(pp && dn && *dn == 424242 && cp && *cp == fixture_cut() && lineage::classify_lineage(rc.tx_extra, TAG) == lineage::BlockLineage::Own,
          "V37D owed_in, the V37P tag (Own) and the V37C cut all read back");
}

// ---------------------------------------------------------------------------
// Suite F -- the relay HELLO carries pool_genesis_id.
// ---------------------------------------------------------------------------
void suite_hello() {
    std::printf("== F. relay HELLO: lane_tag + pool_genesis_id (+32 B), TAG_MISMATCH field=pool_genesis ==\n");
    const ::v37::LaneParams lp{};
    relay::Hello h;
    h.network = 3; h.chain_id = 0; h.share_diff = 1; h.node_nonce = 42;
    h.pool = relay::pool_id_of(0, lp);
    const auto e142 = relay::encode_hello(h);
    h.pool->genesis = b32(0xA0);
    const auto e174 = relay::encode_hello(h);
    CHECK(e142.size() == 142 && e174.size() == 174 && e174.size() - e142.size() == 32, "HELLO 142 -> 174 B (+32: the genesis)");
    CHECK(std::equal(e142.begin(), e142.end(), e174.begin()), "the 142-byte POOL-ID HELLO is a strict prefix");
    relay::Hello back; std::string why;
    CHECK(relay::decode_hello(e174, back, &why) && back == h && back.pool->genesis == b32(0xA0), "174-byte HELLO round-trips (genesis kept)");
    relay::Hello back142;
    CHECK(relay::decode_hello(e142, back142, &why) && back142.pool && !back142.pool->genesis, "142-byte HELLO still decodes (no genesis)");
    std::vector<std::uint8_t> e175 = e174; e175.push_back(0);
    CHECK(!relay::decode_hello(e175, back, &why), "175 bytes -> refused (%s)", why.c_str());
    relay::Hello other = h; other.pool->genesis = b32(0xB0); other.node_nonce = 43;
    const std::string mis = relay::hello_mismatch(h, other);
    CHECK(relay::is_tag_mismatch(mis) && mis.find("field=pool_genesis") != std::string::npos, "different genesis: %s", mis.substr(0, 60).c_str());
    const std::string mis_rev = relay::hello_mismatch(other, h);
    CHECK(relay::is_tag_mismatch(mis_rev) && mis_rev.find("field=pool_genesis") != std::string::npos, "refused in BOTH directions");
    relay::Hello same = h; same.node_nonce = 44;
    CHECK(relay::hello_mismatch(h, same).empty(), "same lane_tag + same genesis: compatible");
    relay::Hello pre = h; pre.pool->genesis.reset(); pre.node_nonce = 45;
    const std::string mis_pre = relay::hello_mismatch(h, pre);
    CHECK(relay::is_tag_mismatch(mis_pre) && mis_pre.find("field=pool_genesis") != std::string::npos, "a pre-lineage peer (no genesis): TAG_MISMATCH field=pool_genesis");
    relay::Hello geo = h; geo.pool = relay::pool_id_of(0, [] { ::v37::LaneParams q{}; q.window += 1; return q; }()); geo.pool->genesis = b32(0xA0);
    const std::string mis_geo = relay::hello_mismatch(h, geo);
    CHECK(relay::is_tag_mismatch(mis_geo) && mis_geo.find("field=geometry") != std::string::npos, "same genesis, other geometry: still field=geometry");
}

} // namespace

int main() {
    std::printf("=== v37_xmr_pool_lineage_kat (POOL-LINEAGE: block-level pool id) ===\n");
    suite_derivation();
    suite_codec();
    suite_classify();
    suite_blocks();
    suite_widest();
    suite_hello();
    std::printf("=== %d/%d checks passed ===\n", g_checks - g_fail, g_checks);
    return g_fail == 0 ? 0 : 1;
}
