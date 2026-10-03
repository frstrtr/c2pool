// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// v37_xmr_pool_lineage_kat -- the POOL IDENTITY of the XMR lane
// (RULES RATCHET R1, operator rulings 2026-10-03; THE LAST flag day).
//
//   pool_genesis = sha256d( "V37GEN" || block_hash(H) || u8 len || headline )     (derived, "nothing up my sleeve")
//   pool_id      = sha256d( "V37PID" || u8 network || u32 chain_id || b32 pool_genesis )
//   V37P v2 (45 B) = "V37P" | 02 | b32 pool_id | u32 epoch_cur | u32 epoch_max   FIRST in the 0x02 payload, [4..49)
//
// Nothing on chain names a RULE any more: a lane block names its POOL and its
// EPOCH; the rules of every epoch ride the relay HELLO (the Deployment list)
// and the RATCHET event. The former pool_tag (V37PT2, V37P v1 in the V37C tail)
// is retired.
//
// Suites
//   A  derivation: the two sha256d recomputed from raw bytes (goldens), the
//      headline grammar (printable ASCII 1..120, no edge space), the
//      --pool-genesis-from grammar, the chain check (hash at H, >= 60 deep),
//      the raw form (regtest / test nets with a warning, REFUSED on mainnet).
//   B  the V37P v2 codec: 45 B at the fixed offset [4..49), Present / Absent /
//      Malformed (strict version), the tail readers (V37C / V37D / V37N)
//      untouched by the head.
//   C  classify: own -> lane block, other -> ordinary, no field -> ordinary,
//      another version -> strict reject; through a two-byte 0x02 varint.
//   D  REAL assembled blocks (monerod arm over the C4 capture, the credit cut
//      armed): the coinbase delta vs an unfielded block is exactly the 45-byte
//      head spliced after the nonce; the coinbase-authority decoder books OUR
//      block, answers "not-lane:" for another pool's and for a block without
//      the field, parses (pool_id, epoch_cur, epoch_max); the per-job patch
//      never touches the head; the shape gate accepts.
//   E  the widest 0x02 payload [nonce 4 | V37P 45 | rbind 32 | pad 10 | V37R 12
//      | V37F 69 | V37N 12 | V37D 12 | V37C 44] = 240 B (<= 255) assembles,
//      materializes and every field reads back.
//   F  the relay HELLO: the genesis (+32 B), a different genesis =
//      TAG_MISMATCH field=pool_genesis; pool_id is a function of three HELLO
//      fields (network, chain_id, genesis) and is not carried.
//   G  rules under the ratchet: other lane rules -> ANOTHER rules_digest ->
//      refused at HELLO by name (the SAME pool_id: nothing on chain changes);
//      a block of my pool built under other rules is Own and its recompute is
//      Mismatch (debit-only: the deviant node is the refused one); a block
//      naming another epoch_cur / an epoch_max below it is "misbuilt" /
//      malformed at the recompute; equal rules -> Canonical.
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
#include "c2pool/v37/xmr/xmr_paynow.hpp"
#include "c2pool/v37/xmr/xmr_lane_rules.hpp"
#include "c2pool/v37/xmr/xmr_lane_rules_build.hpp"
#include "c2pool/v37/xmr/xmr_coinbase_recompute.hpp"
#include "c2pool/v37/xmr/xmr_settlement_coinbase_shape.hpp"
#include "c2pool/v37/xmr/relay/xmr_relay_wire.hpp"

#include "xmr_c4_parity_golden.hpp"

using namespace c2pool::xmr::native;

namespace o2      = c2pool::v37n::xmr::o2;
namespace asm_    = c2pool::xmr::assembly;
namespace credit  = c2pool::v37n::xmr::credit;
namespace auth    = c2pool::v37n::xmr::authority;
namespace fee     = c2pool::v37n::xmr::fee;
namespace pn      = c2pool::v37n::xmr::paynow;
namespace lineage = c2pool::v37n::xmr::lineage;
namespace lr      = c2pool::v37n::xmr::lanerules;
namespace relay   = c2pool::v37n::xmr::relay;
namespace x6      = ::v37::xmr::settle;
namespace G4      = c2pool::xmr::native::golden_c4;

// THE tie the impl tree names: its parse bound == the consumer-tree format.
static_assert(asm_::POOL_FIELD_BYTES == credit::kPoolFieldBytes,
              "impl-tree POOL_FIELD_BYTES must mirror credit::kPoolFieldBytes (45)");
static_assert(credit::kPoolFieldBytes == 45, "V37P v2: 4 magic + 1 version + 32 pool_id + 4 epoch_cur + 4 epoch_max");
static_assert(credit::kPoolFieldOffset == 4 && credit::kRbindOffset == 49, "V37P at [4..49), rbind at [49..81)");
static_assert(asm_::WIDEST_EXTRA_NONCE_PAYLOAD_BYTES == 240, "the widest 0x02 payload is 240 B");
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
// Frozen goldens (regenerate with V37_XMR_POOL_LINEAGE_KAT_PRINT=1 only on a
// deliberate move). The derivation inputs: block hash = bytes 0x10..0x2f, the
// headline "attempt 11: the last flag day" (29 B), stagenet (2), chain 0xABCD.
// ---------------------------------------------------------------------------
constexpr const char* GOLDEN_REGTEST_DEFAULT_GENESIS = "95f448de1c380509b4fd7250ee9d2675fc52fec311e8baf66eb8bcf63bbf7d7f";
constexpr const char* GOLDEN_HEADLINE               = "attempt 11: the last flag day";
constexpr const char* GOLDEN_DERIVED_GENESIS        = "6c7d98c6218459f422993479b05296eb53716c6970ab036f92ffc259e347854e";
constexpr const char* GOLDEN_POOL_ID_STAGENET_ABCD  = "61e75d6890eb0111b4ed796bae08dec0fcee62dfae767e8335336f04b06a72ed";

const std::uint32_t LANE_CHAIN = 0x0000ABCDu;

void suite_derivation() {
    std::printf("== A. pool_genesis = sha256d('V37GEN' || hash(H) || u8 len || headline); pool_id = sha256d('V37PID' || net || chain || genesis) ==\n");
    const ::v37::bytes32 bh = b32(0x10);
    const std::string hl = GOLDEN_HEADLINE;
    std::vector<std::uint8_t> pre = {'V', '3', '7', 'G', 'E', 'N'};
    pre.insert(pre.end(), bh.begin(), bh.end());
    pre.push_back(static_cast<std::uint8_t>(hl.size()));
    pre.insert(pre.end(), hl.begin(), hl.end());
    const auto g = lineage::pool_genesis_derived(bh, hl);
    CHECK(pre.size() == 6 + 32 + 1 + 29 && g == ::v37::sha256d(pre), "pool_genesis == sha256d of the raw 68-byte preimage (6 + 32 + 1 + 29)");
    std::vector<std::uint8_t> pid = {'V', '3', '7', 'P', 'I', 'D', 2, 0xCD, 0xAB, 0x00, 0x00};
    pid.insert(pid.end(), g.begin(), g.end());
    const auto id = lineage::pool_id(2, LANE_CHAIN, g);
    CHECK(pid.size() == 6 + 1 + 4 + 32 && id == ::v37::sha256d(pid), "pool_id == sha256d('V37PID' || u8 2 || u32 LE 0xABCD || genesis) (43-byte preimage)");
    if (std::getenv("V37_XMR_POOL_LINEAGE_KAT_PRINT"))
        std::printf("GOLDEN_DERIVED_GENESIS=%s\nGOLDEN_POOL_ID_STAGENET_ABCD=%s\n", hex(g).c_str(), hex(id).c_str());
    CHECK(hex(g) == GOLDEN_DERIVED_GENESIS, "frozen derived genesis %s...", hex(g).substr(0, 16).c_str());
    CHECK(hex(id) == GOLDEN_POOL_ID_STAGENET_ABCD, "frozen pool_id (stagenet, chain 0xABCD) %s...", hex(id).substr(0, 16).c_str());
    CHECK(lineage::pool_genesis_derived(b32(0x11), hl) != g, "another block hash -> another genesis");
    CHECK(lineage::pool_genesis_derived(bh, "attempt 11: the last flag day.") != g, "another headline byte -> another genesis (no normalisation)");
    CHECK(lineage::pool_genesis_derived(bh, "Attempt 11: the last flag day") != g, "case is not folded");
    CHECK(lineage::pool_id(0, LANE_CHAIN, g) != id && lineage::pool_id(2, 7, g) != id && lineage::pool_id(2, LANE_CHAIN, b32(0x12)) != id,
          "pool_id moves with the network, the chain_id and the genesis (fixed for life otherwise)");

    // the headline grammar (operator default 2026-10-03: printable ASCII 0x20-0x7E, 1..120 B, no edge space)
    CHECK(lineage::headline_refusal(hl).empty(), "headline grammar: the golden headline is well-formed");
    CHECK(!lineage::headline_refusal("").empty(), "  empty -> refused");
    CHECK(lineage::headline_refusal(std::string(120, 'a')).empty() && !lineage::headline_refusal(std::string(121, 'a')).empty(),
          "  120 bytes ok, 121 refused (u8 length prefix, <= 120)");
    CHECK(!lineage::headline_refusal(" a").empty() && !lineage::headline_refusal("a ").empty(), "  a leading / trailing space -> refused");
    CHECK(!lineage::headline_refusal("a\tb").empty() && !lineage::headline_refusal(std::string("a\x7f") + "b").empty(),
          "  a control byte (0x09, 0x7f) -> refused");
    CHECK(!lineage::headline_refusal(std::string("caf\xc3\xa9")).empty(), "  a non-ASCII byte (UTF-8 e-acute) -> refused (ASCII-only default)");
    CHECK(lineage::headline_refusal("a:b \"quoted\" ~").empty(), "  ':' '\"' '~' and inner spaces are fine");

    // --pool-genesis-from <H>:<hash64>:"<headline>"
    lineage::GenesisSpec spec;
    const std::string arg = "3412000:" + hex(bh) + ":\"" + hl + "\"";
    CHECK(lineage::parse_genesis_from(arg, spec).empty() && spec.height == 3412000 && spec.block_hash == bh && spec.headline == hl,
          "--pool-genesis-from parses H, the hash and the quoted headline (the quotes are stripped)");
    CHECK(lineage::parse_genesis_from("1:" + hex(bh) + ":" + hl, spec).empty() && spec.headline == hl, "  an unquoted headline parses too");
    CHECK(lineage::parse_genesis_from("1:" + hex(bh) + ":a:b", spec).empty() && spec.headline == "a:b", "  the headline may contain ':'");
    CHECK(!lineage::parse_genesis_from("x:" + hex(bh) + ":a", spec).empty(), "  a non-decimal height -> refused");
    CHECK(!lineage::parse_genesis_from("1:" + hex(bh).substr(0, 63) + ":a", spec).empty(), "  63 hex digits -> refused");
    CHECK(!lineage::parse_genesis_from("1:" + hex(bh), spec).empty(), "  no headline part -> refused");
    CHECK(!lineage::parse_genesis_from("1:" + hex(bh) + ":", spec).empty(), "  an empty headline -> refused");
    const auto idd = lineage::identity_derived(2, LANE_CHAIN, spec);
    CHECK(idd.form == lineage::GenesisForm::Derived && idd.pool_genesis == lineage::pool_genesis_derived(bh, "a:b") &&
              idd.pool_id == lineage::pool_id(2, LANE_CHAIN, idd.pool_genesis),
          "identity_derived: form Derived, genesis + pool_id from the spec");
    const std::string line = lineage::identity_line(idd);
    CHECK(line.rfind("genesis: H=1 hash=", 0) == 0 && line.find("headline=\"a:b\" (hex 613a62)") != std::string::npos &&
              line.find("pool_genesis=" + hex(idd.pool_genesis)) != std::string::npos && line.find("pool_id=" + hex(idd.pool_id)) != std::string::npos,
          "the start line prints H, hash, the headline as text AND hex, pool_genesis, pool_id");

    // the chain check (spec 1.1 (c)): hash(H) on this chain and tip - H >= D_conf
    lineage::GenesisSpec g2; g2.height = 1000; g2.block_hash = bh; g2.headline = hl;
    CHECK(lineage::genesis_chain_refusal(g2, bh, 1060).empty(), "chain check: hash at H matches, 60 deep -> ok");
    CHECK(lineage::genesis_chain_refusal(g2, bh, 1059) == "genesis: H is 59 deep, needs >= 60", "  59 deep -> \"genesis: H is 59 deep, needs >= 60\"");
    CHECK(lineage::genesis_chain_refusal(g2, b32(0x11), 1060).rfind("genesis: block " + hex(bh) + " is not height 1000 on this chain", 0) == 0,
          "  another hash at H -> \"genesis: block <hash> is not height H on this chain\"");
    CHECK(!lineage::genesis_chain_refusal(g2, std::nullopt, 1060).empty(), "  a chain view that does not hold H -> refused (cannot be checked)");
    CHECK(lineage::genesis_chain_refusal(g2, bh, 1003, 3).empty() && !lineage::genesis_chain_refusal(g2, bh, 1002, 3).empty(),
          "  regtest D_conf 3: the depth floor follows D_conf");

    // the raw form
    CHECK(lineage::raw_genesis_refusal(0) == "mainnet: the pool genesis must be derived, use --pool-genesis-from", "raw genesis on mainnet: REFUSED by name");
    CHECK(lineage::raw_genesis_refusal(1).empty() && lineage::raw_genesis_refusal(2).empty() && lineage::raw_genesis_refusal(3).empty(),
          "raw genesis on testnet / stagenet / regtest: accepted (the test nets with the WARNING \"%s\")", lineage::raw_genesis_warning());
    const auto dg0 = lineage::default_pool_genesis(0), dg2 = lineage::default_pool_genesis(2), dg3 = lineage::default_pool_genesis(3);
    std::vector<std::uint8_t> gp = {'V', '3', '7', 'P', 'G', 3};
    CHECK(dg3 == ::v37::sha256d(gp), "default (raw) genesis(regtest) == sha256d('V37PG' || u8 3)");
    CHECK(dg0 != dg2 && dg2 != dg3 && dg0 != dg3, "one default raw genesis PER network");
    CHECK(hex(dg3) == GOLDEN_REGTEST_DEFAULT_GENESIS, "frozen default regtest genesis %s (unchanged)", hex(dg3).substr(0, 16).c_str());
    const auto idr = lineage::identity_raw(3, LANE_CHAIN, dg3);
    CHECK(idr.form == lineage::GenesisForm::Raw && idr.pool_id == lineage::pool_id(3, LANE_CHAIN, dg3) &&
              lineage::identity_line(idr).find("RAW (not derived)") != std::string::npos,
          "identity_raw: form Raw, the start line says so");

    ::v37::bytes32 out{};
    CHECK(lineage::parse_genesis_hex(hex(g), out) && out == g, "--pool-genesis parses 64 hex digits");
    std::string up = hex(g); for (auto& c : up) c = static_cast<char>(std::toupper(c));
    CHECK(lineage::parse_genesis_hex(up, out) && out == g, "--pool-genesis accepts upper case");
    CHECK(!lineage::parse_genesis_hex(hex(g).substr(0, 63), out) && !lineage::parse_genesis_hex(hex(g) + "0", out), "63 / 65 digits -> refused");
}

// ---------------------------------------------------------------------------
// Suite B -- the V37P v2 field codec.
// ---------------------------------------------------------------------------
credit::CreditCut fixture_cut() {
    credit::CreditCut c;
    c.next_pos = 0x0000000000BC614Eull;
    for (std::size_t i = 0; i < 32; ++i) c.spine_digest[i] = static_cast<std::uint8_t>(0xA0 + i);
    return c;
}

// [nonce 4 | V37P 45? | rbind 32? | pad | V37N? | V37D? | V37C?]
std::vector<std::uint8_t> payload_of(const credit::PoolField* f, bool rbind, std::size_t pad, bool v37n, bool v37d, bool cut) {
    std::vector<std::uint8_t> p = {0xDE, 0xAD, 0xBE, 0xEF};
    if (f) { const auto t = credit::encode_pool_field(*f); p.insert(p.end(), t.begin(), t.end()); }
    if (rbind) { const auto r = b32(0x70); p.insert(p.end(), r.begin(), r.end()); }
    p.resize(p.size() + pad, 0x00);
    if (v37n) { const auto t = pn::encode_tail(0x0102030405060708ull); p.insert(p.end(), t.begin(), t.end()); }
    if (v37d) { const auto t = fee::encode_donation_owed_tail(424242); p.insert(p.end(), t.begin(), t.end()); }
    if (cut)  { const auto t = credit::encode_tail(fixture_cut());   p.insert(p.end(), t.begin(), t.end()); }
    return p;
}

void suite_codec() {
    std::printf("== B. V37P v2: \"V37P\" | 02 | b32 pool_id | u32 epoch_cur | u32 epoch_max (45 B) at 0x02[4..49) ==\n");
    const credit::PoolField F{b32(0x50), 1, 1};
    const auto f = credit::encode_pool_field(F);
    CHECK(f.size() == 45 && std::memcmp(f.data(), "V37P", 4) == 0 && f[4] == 2 && std::memcmp(f.data() + 5, F.pool_id.data(), 32) == 0 &&
              f[37] == 1 && f[38] == 0 && f[39] == 0 && f[40] == 0 && f[41] == 1 && f[42] == 0 && f[43] == 0 && f[44] == 0,
          "encode: 45 bytes, magic V37P, version 2, pool_id verbatim, epoch_cur / epoch_max u32 LE");
    const credit::PoolField F2{b32(0x50), 7, 9};
    const auto f2 = credit::encode_pool_field(F2);
    CHECK(f2[37] == 7 && f2[41] == 9, "encode: epoch_cur 7 / epoch_max 9 land at [37..41) / [41..45)");
    credit::PoolField got;
    for (int rb = 0; rb < 2; ++rb)
        for (int n = 0; n < 2; ++n)
            for (int d = 0; d < 2; ++d)
                for (int c = 0; c < 2; ++c) {
                    const auto p = payload_of(&F2, rb, 10, n, d, c);
                    got = {};
                    CHECK(credit::parse_pool_field_payload(p, &got) == credit::PoolFieldParse::Present && got == F2,
                          "[nonce|V37P%s|pad%s%s%s] -> Present at [4..49), the field read back", rb ? "|rbind" : "", n ? "|V37N" : "",
                          d ? "|V37D" : "", c ? "|V37C" : "");
                    const auto cc = credit::parse_tail(p);
                    const auto dn = fee::parse_donation_owed_payload(p);
                    const auto nn = pn::parse_payload(p);
                    CHECK((c ? (cc && *cc == fixture_cut()) : !cc) && (d ? (dn && *dn == 424242) : !dn) &&
                              (n ? (nn && *nn == 0x0102030405060708ull) : !nn),
                          "  the END-anchored readers (V37C / V37D / V37N) are untouched by the head");
                }
    CHECK(credit::parse_pool_field_payload(payload_of(nullptr, false, 10, false, false, true)) == credit::PoolFieldParse::Absent,
          "[nonce|pad|V37C] (no field) -> Absent");
    CHECK(credit::parse_pool_field_payload(std::vector<std::uint8_t>(14, 0)) == credit::PoolFieldParse::Absent, "bare 14-byte nonce payload -> Absent");
    CHECK(credit::parse_pool_field_payload({}) == credit::PoolFieldParse::Absent, "empty payload -> Absent");
    CHECK(credit::parse_pool_field_payload({0xDE, 0xAD, 0xBE, 0xEF, 'V', '3', '7'}) == credit::PoolFieldParse::Absent, "a 7-byte payload -> Absent (no room for the magic)");
    auto p = payload_of(&F, false, 10, false, false, true);
    p[4 + 4] = 1;
    CHECK(credit::parse_pool_field_payload(p) == credit::PoolFieldParse::Malformed, "V37P magic with version 1 (the retired field) -> Malformed (strict)");
    p[4 + 4] = 3;
    CHECK(credit::parse_pool_field_payload(p) == credit::PoolFieldParse::Malformed, "V37P magic with version 3 -> Malformed (strict: no epoch may change the layout)");
    std::vector<std::uint8_t> shrt(f.begin(), f.begin() + 30); shrt.insert(shrt.begin(), {0xDE, 0xAD, 0xBE, 0xEF});
    CHECK(credit::parse_pool_field_payload(shrt) == credit::PoolFieldParse::Malformed, "the magic with a truncated field -> Malformed");
    auto pm = payload_of(&F, false, 10, false, false, true); pm[4] = 'X';
    CHECK(credit::parse_pool_field_payload(pm) == credit::PoolFieldParse::Absent, "wrong magic at [4..8) -> Absent (no field)");
    // a V37P v1 field in the TAIL (the retired layout) is not the head field
    std::vector<std::uint8_t> old = {0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'V', '3', '7', 'P', 1};
    old.resize(old.size() + 32, 0x55);
    { const auto c = credit::encode_tail(fixture_cut()); old.insert(old.end(), c.begin(), c.end()); }
    CHECK(credit::parse_pool_field_payload(old) == credit::PoolFieldParse::Absent && credit::parse_tail(old).has_value(),
          "a pre-ratchet payload (V37P v1 in the tail) -> Absent: an untagged, ordinary block for a ratchet node");
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
    std::printf("== C. classify: own -> lane, other -> ordinary, no field -> ordinary, another version -> strict reject ==\n");
    const auto OUR = b32(0x50), OTHER = b32(0x60);
    const credit::PoolField ours{OUR, 1, 1}, theirs{OTHER, 3, 4};
    credit::PoolField seen;
    CHECK(lineage::classify_lineage(tx_extra_of(payload_of(&ours, false, 10, false, false, true)), OUR, &seen) == lineage::BlockLineage::Own && seen == ours,
          "our pool_id -> Own (a lane block of this pool), the field reported");
    CHECK(lineage::classify_lineage(tx_extra_of(payload_of(&theirs, false, 10, false, false, true)), OUR, &seen) == lineage::BlockLineage::Foreign &&
              seen.pool_id == OTHER && seen.epoch_cur == 3 && seen.epoch_max == 4,
          "another pool's id -> Foreign (ordinary), the foreign field reported (pool_id, epoch 3 of 4)");
    CHECK(lineage::classify_lineage(tx_extra_of(payload_of(nullptr, false, 10, false, false, true)), OUR) == lineage::BlockLineage::Untagged,
          "a V37C tail without the head -> Untagged (ordinary)");
    CHECK(lineage::classify_lineage(tx_extra_of(payload_of(nullptr, false, 10, false, false, false)), OUR) == lineage::BlockLineage::Untagged,
          "no field at all -> Untagged (ordinary)");
    std::vector<unsigned char> no02;
    no02.push_back(0x01); for (int i = 0; i < 32; ++i) no02.push_back(0);
    CHECK(lineage::classify_lineage(no02, OUR) == lineage::BlockLineage::Untagged, "no 0x02 field -> Untagged (ordinary)");
    auto pm = payload_of(&ours, false, 10, false, false, true); pm[4 + 4] = 1;
    CHECK(lineage::classify_lineage(tx_extra_of(pm), OUR) == lineage::BlockLineage::Malformed, "OUR id under version 1 -> Malformed (strict: never Own)");
    // the widest shape: nonce 4 | V37P 45 | rbind 32 | pad 10 | V37N | V37D | V37C = 159 B -> a two-byte varint
    auto wide = payload_of(&ours, true, 10, true, true, true);
    const auto e = tx_extra_of(wide);
    CHECK(wide.size() == 159 && e[34] == static_cast<unsigned char>((159 & 0x7f) | 0x80) && e[35] == 0x01,
          "wide payload %zu B: the 0x02 length is a TWO-byte varint (%02x %02x)", wide.size(), e[34], e[35]);
    CHECK(lineage::classify_lineage(e, OUR) == lineage::BlockLineage::Own, "  classify reads through the two-byte varint -> Own");
    const auto cc = credit::parse_from_tx_extra(e);
    CHECK(cc && *cc == fixture_cut() && std::memcmp(wide.data() + credit::kRbindOffset, b32(0x70).data(), 32) == 0,
          "  the credit cut still parses through it; rbind sits at [49..81)");
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
    explicit Built(std::optional<credit::PoolField> field, std::uint64_t h_min = 0, bool commit_total = false, bool bind = false) {
        lane.scfg.credit_cut_source = [](std::uint64_t& P, ::v37::bytes32& dg) {
            const credit::CreditCut c = fixture_cut(); P = c.next_pos; dg = c.spine_digest; return true; };
        lane.scfg.pool_field = field;
        lane.scfg.h_min = h_min;   // suite G: a node whose lane rules carry another owed floor
        lane.scfg.commit_total = commit_total;   // ... or another commit_total ruling
        if (!src.poll(&why)) { why = "daemon arm did not parse the capture: " + why; return; }
        provider = std::make_unique<o2::XmrSettlementTemplateProvider>(src, lane.ledger, lane.scfg, 0);
        if (bind) provider->set_extra_nonce_bind(32, [](std::uint32_t en, std::uint8_t* out) { for (int i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(en * 7 + i); return true; });
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
    std::printf("== D. real assembled blocks: pool A (ours) vs pool B vs a block without the field, same ledger + config ==\n");
    const auto ID_A = lineage::pool_id(3, LANE_CHAIN, b32(0xA0));
    const auto ID_B = lineage::pool_id(3, LANE_CHAIN, b32(0xB0));
    const credit::PoolField FA{ID_A, 1, 1}, FB{ID_B, 1, 1};
    Built a(FA), b(FB), u(std::nullopt);
    CHECK(a.ok && b.ok && u.ok, "three templates build + materialize (%s / %s / %s)", a.ok ? "ok" : a.why.c_str(),
          b.ok ? "ok" : b.why.c_str(), u.ok ? "ok" : u.why.c_str());
    if (!(a.ok && b.ok && u.ok)) return;

    // --- the coinbase delta vs the unfielded block: exactly the 45-byte head after the nonce
    auto vlen = [](std::size_t n) { std::size_t k = 1; while (n >= 0x80) { n >>= 7; ++k; } return k; };
    Parsed_ pa = parse_(a.bytes), pu = parse_(u.bytes);
    CHECK(pa.ok && pu.ok, "both coinbase prefixes parse");
    if (!(pa.ok && pu.ok)) return;
    const std::size_t grow = vlen(pa.got.tx_extra.size()) - vlen(pu.got.tx_extra.size());
    CHECK(pa.got.tx_extra.size() == pu.got.tx_extra.size() + 45, "tx_extra %zu -> %zu B (+45: the V37P v2 head)",
          pu.got.tx_extra.size(), pa.got.tx_extra.size());
    CHECK(a.bytes.miner_tx_size == u.bytes.miner_tx_size + 45 + grow && a.bytes.full_blob.size() == u.bytes.full_blob.size() + 45 + grow,
          "miner_tx %zu -> %zu B (+45 head +%zu tx_extra length-varint byte%s)", u.bytes.miner_tx_size, a.bytes.miner_tx_size,
          grow, grow ? " (the length crossed 128 B)" : "s");
    CHECK(a.bytes.extra_nonce_size == u.bytes.extra_nonce_size + 45 && a.bytes.extra_nonce_size < 0x80,
          "0x02 payload %zu -> %zu B (+45; one-byte varint without rbind)", u.bytes.extra_nonce_size, a.bytes.extra_nonce_size);
    const std::uint8_t* ap = a.bytes.full_blob.data() + a.bytes.extra_nonce_offset;
    const std::uint8_t* up = u.bytes.full_blob.data() + u.bytes.extra_nonce_offset;
    const auto fld = credit::encode_pool_field(FA);
    CHECK(std::memcmp(ap, up, 4) == 0 && std::memcmp(ap + 4, fld.data(), 45) == 0 &&
              std::memcmp(ap + 49, up + 4, u.bytes.extra_nonce_size - 4) == 0,
          "payload = [nonce 4 | the 45-byte V37P v2 head | the unfielded payload's pad + tail]: the head is spliced right after the nonce");
    bool spliced = false;
    {
        const std::vector<std::uint8_t> ua = u.bytes.coinbase_prefix(), aa = a.bytes.coinbase_prefix();
        const auto& ue = pu.got.tx_extra;
        const std::size_t head = ua.size() - ue.size() - vlen(ue.size());   // tx_extra is the prefix's LAST field
        std::vector<std::uint8_t> ne(ue.begin(), ue.end());
        if (ne.size() > 35 && ne[33] == 0x02 && ne[34] == u.bytes.extra_nonce_size) {
            ne[34] = static_cast<std::uint8_t>(ne[34] + 45);
            ne.insert(ne.begin() + 35 + 4, fld.begin(), fld.end());
            std::vector<std::uint8_t> synth(ua.begin(), ua.begin() + static_cast<std::ptrdiff_t>(head));
            std::size_t n = ne.size();
            while (n >= 0x80) { synth.push_back(static_cast<std::uint8_t>((n & 0x7f) | 0x80)); n >>= 7; }
            synth.push_back(static_cast<std::uint8_t>(n));
            synth.insert(synth.end(), ne.begin(), ne.end());
            spliced = (synth == aa);
        }
    }
    CHECK(spliced, "fielded miner_tx prefix == unfielded prefix with (0x02 len += 45, the head spliced after the nonce, tx_extra length re-encoded): "
                   "NOTHING else moves (r/R, every vout, the 0x03 root, the V37C cut)");
    CHECK(a.bytes.merkle_root == u.bytes.merkle_root && a.bytes.merkle_root == b.bytes.merkle_root,
          "the MM commitment root is identical on all three (same ledger, same owed_digest)");

    // --- the coinbase-authority decoder, gated by OUR pool_id (pool A) -------------
    std::vector<::v37::bytes32> cands{a.lane.ledger.ledger().owed_digest()};
    const auto keys = a.lane.ledger.keys();
    auto decode = [&](const Built& x, const ::v37::bytes32* id) {
        return auth::decode_lane_coinbase(x.bytes.full_blob, LANE_CHAIN, cands, keys, a.lane.scfg.residual_sink,
                                          a.lane.scfg.residual_sink_identity, a.lane.ledger.pay_of(), id);
    };
    const auto own = decode(a, &ID_A), foreign = decode(b, &ID_A), old = decode(u, &ID_A);
    CHECK(own.ok && own.is_lane && own.lineage_gated && own.lineage == lineage::BlockLineage::Own && own.has_credit_cut &&
              own.pool_field == FA,
          "OUR block: Own -> booked as a lane block; the field parsed (pool_id, epoch 1 of 1) (%s)", own.ok ? "ok" : own.why.c_str());
    CHECK(!foreign.ok && !foreign.is_lane && foreign.lineage == lineage::BlockLineage::Foreign && foreign.lineage_seen_tag == ID_B &&
              foreign.pool_field == FB && foreign.why.rfind("not-lane:", 0) == 0 && foreign.payout.empty() && !foreign.has_credit_cut,
          "pool B's block: Foreign -> \"not-lane:\" (ordinary: no lane cut, no root match, no hold): %s", foreign.why.c_str());
    CHECK(!old.ok && !old.is_lane && old.lineage == lineage::BlockLineage::Untagged && old.why.rfind("not-lane:", 0) == 0,
          "a block without the field (a pre-ratchet / foreign-software block): Untagged -> \"not-lane:\": %s", old.why.c_str());
    const auto b_own = decode(b, &ID_B), b_sees_a = decode(a, &ID_B);
    CHECK(b_own.ok && b_own.is_lane && !b_sees_a.is_lane && b_sees_a.lineage == lineage::BlockLineage::Foreign,
          "symmetric: pool B books its own block and sees pool A's as Foreign");
    const auto ungated = decode(b, nullptr);
    CHECK(ungated.is_lane && ungated.has_credit_cut && !ungated.lineage_gated,
          "ungated (no pool_id passed): pool B's block MATCHES pool A's root and is taken as a lane cut -- the stall the gate removes");
    std::vector<std::uint8_t> mal = a.bytes.full_blob;
    mal[a.bytes.extra_nonce_offset + 4 + 4] = 1;
    const auto mk = auth::decode_lane_coinbase(mal, LANE_CHAIN, cands, keys, a.lane.scfg.residual_sink,
                                               a.lane.scfg.residual_sink_identity, a.lane.ledger.pay_of(), &ID_A);
    CHECK(!mk.is_lane && mk.lineage == lineage::BlockLineage::Malformed && mk.why.rfind("not-lane:", 0) == 0,
          "our block with the V37P version byte flipped to 1: Malformed -> strict reject, \"not-lane:\"");
    const o2::KFairCoinbaseShape sa = o2::inspect_kfair_coinbase(*a.snap.tpl, a.lane.ledger.ledger().owed_digest());
    CHECK(sa.ok && sa.canonical, "shape gate ACCEPTs the fielded template: %s", sa.ok ? "ok" : sa.why.c_str());
    asm_::BlockBytes a1; std::string w1;
    const bool m1 = a.snap.tpl->materialize(1, a1, &w1);
    CHECK(m1 && std::memcmp(a1.full_blob.data() + a1.extra_nonce_offset + 4, ap + 4, a.bytes.extra_nonce_size - 4) == 0 &&
              a1.full_blob[a1.extra_nonce_offset] == 1 && a1.full_blob[a1.extra_nonce_offset + 1] == 0,
          "extra_nonce 1: the nonce changes, the head + padding + V37C are untouched");
    // --- a BOUND template: rbind at [49..81), after the head
    Built ab(FA, 0, false, /*bind=*/true);
    CHECK(ab.ok, "a bound fielded template builds (%s)", ab.ok ? "ok" : ab.why.c_str());
    if (ab.ok) {
        const std::uint8_t* bp = ab.bytes.full_blob.data() + ab.bytes.extra_nonce_offset;
        bool rb_ok = ab.bytes.extra_nonce_size == a.bytes.extra_nonce_size + 32 && std::memcmp(bp + 4, fld.data(), 45) == 0;
        for (int i = 0; rb_ok && i < 32; ++i) rb_ok = bp[credit::kRbindOffset + i] == static_cast<std::uint8_t>(0 * 7 + i);
        CHECK(rb_ok, "bound: +32 B, the head still at [4..49), rbind_v1 at [49..81) (kRbindOffset)");
        const auto bk = decode(ab, &ID_A);
        CHECK(bk.ok && bk.is_lane && bk.lineage == lineage::BlockLineage::Own, "bound: Own, booked");
    }
}

// ---------------------------------------------------------------------------
// Suite E -- the widest payload assembles (two-byte 0x02 length varint).
// ---------------------------------------------------------------------------
void suite_widest() {
    std::printf("== E. widest 0x02 payload [nonce 4|V37P 45|rbind 32|pad 10|V37R 12|V37F 69|V37N 12|V37D 12|V37C 44] = 240 B assembles + parses ==\n");
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
    const credit::PoolField F{b32(0x77), 1, 1};
    a.extra_nonce_head = credit::encode_pool_field(F);
    const ::v37::ScriptRef finder = akat::std_ref();
    a.extra_nonce_tail = pn::encode_finder_field(finder);
    for (const auto& part : {pn::encode_tail(10000000001ull), fee::encode_donation_owed_tail(x6::fold_identity_owed(a.settle)), credit::encode_tail(fixture_cut())})
        a.extra_nonce_tail.insert(a.extra_nonce_tail.end(), part.begin(), part.end());
    a.reward_total_field = true;
    a.extra_nonce_bind_size = 32;
    a.extra_nonce_bind = [](std::uint32_t en, std::uint8_t* out) { for (int i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(en * 7 + i); return true; };
    std::string why;
    auto t = asm_::XmrBlockAssembler::build(a, &why);
    CHECK(t != nullptr, "the widest payload builds (bound 14 + 45 + 32 + 12 + 69 + 12 + 12 + 44 = 240 <= 255): %s", t ? "ok" : why.c_str());
    if (!t) return;
    asm_::BlockBytes b;
    const bool m = t->materialize(5, b, &why);
    CHECK(m && b.extra_nonce_size >= 0x80 && b.extra_nonce_size <= 240, "materializes; 0x02 payload %zu B (a two-byte length varint, <= 240): %s", b.extra_nonce_size, why.c_str());
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
    credit::PoolField seen;
    const auto nf = pp ? credit::extra_nonce_field(rc.tx_extra) : std::nullopt;
    bool rb_ok = nf && nf->size() >= 81;
    for (int i = 0; rb_ok && i < 32; ++i) rb_ok = (*nf)[credit::kRbindOffset + i] == static_cast<std::uint8_t>(5 * 7 + i);
    CHECK(pp && dn && cp && *cp == fixture_cut() && lineage::classify_lineage(rc.tx_extra, F.pool_id, &seen) == lineage::BlockLineage::Own && seen == F &&
              pn::parse(rc.tx_extra) == std::optional<std::uint64_t>(10000000001ull) && pn::parse_finder(rc.tx_extra) == std::optional<::v37::ScriptRef>(finder) &&
              pn::parse_reward_total(rc.tx_extra) == std::optional<std::uint64_t>(t->reward()) && rb_ok,
          "V37P (Own, epoch 1/1) at the head, rbind at [49..81), V37R, V37F, V37N, V37D and the V37C cut all read back");
}

// ---------------------------------------------------------------------------
// Suite F -- the relay HELLO carries the pool genesis; pool_id is a function of it.
// ---------------------------------------------------------------------------
void suite_hello() {
    std::printf("== F. relay HELLO: lane_tag + pool_genesis (+32 B), TAG_MISMATCH field=pool_genesis; pool_id = f(network, chain_id, genesis) ==\n");
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
    relay::Hello other = h; other.pool->genesis = b32(0xB0); other.node_nonce = 43;
    const std::string mis = relay::hello_mismatch(h, other);
    CHECK(relay::is_tag_mismatch(mis) && mis.find("field=pool_genesis") != std::string::npos, "different genesis: %s", mis.substr(0, 60).c_str());
    CHECK(relay::is_tag_mismatch(relay::hello_mismatch(other, h)), "refused in BOTH directions");
    relay::Hello same = h; same.node_nonce = 44;
    CHECK(relay::hello_mismatch(h, same).empty(), "same lane_tag + same genesis: compatible");
    // pool_id is not carried: it is a function of three fields already in the frame
    const auto id = lineage::pool_id(back.network, back.chain_id, *back.pool->genesis);
    CHECK(id == lineage::pool_id(3, 0, b32(0xA0)) && lineage::pool_id(other.network, other.chain_id, *other.pool->genesis) != id,
          "pool_id recomputed from the decoded HELLO (network, chain_id, genesis); the other genesis gives another pool_id");
    // a rules frame carries the epoch trailer: 174 + 1 + 2 + 278 + 66 = 521 B
    relay::Hello r = h;
    lr::LaneRules rules; rules.lane_params_digest = h.lane_params_digest;
    r.rules = rules;
    const auto e521 = relay::encode_hello(r);
    relay::Hello rb;
    CHECK(e521.size() == 521 && relay::decode_hello(e521, rb, &why) && rb.epochs.size() == 1 && rb.epoch_cur == 1 &&
              rb.epochs[0].rules_digest == lr::rules_digest(rules),
          "a rules HELLO = 521 B: the epoch trailer carries epoch_cur 1 and the one Deployment (%s)", why.c_str());
}

// ---------------------------------------------------------------------------
// Suite G -- the lane rules under the ratchet: HELLO refuses, the chain names no rule.
// ---------------------------------------------------------------------------
lr::LaneRules node_rules(std::uint64_t d_conf, std::uint32_t drain_q = 0, std::uint64_t h_min = 0, bool commit_total = false) {
    c2pool::v37n::xmr::XmrNodeConfig c;
    c.network = c2pool::v37n::xmr::MoneroNetwork::Regtest;
    c.d_conf = d_conf; c.drain_q = drain_q; c.settle_h_min = h_min;
    lr::LaneRulesInputs in;
    in.kfair_salted_ties = false; in.spend_floor = false; in.commit_total = commit_total;
    in.lane_params_digest = relay::lane_params_digest(::v37::LaneParams{}, 1, relay::BindMode::None, 3);
    return lr::lane_rules_of(c, in);
}

void suite_rules() {
    std::printf("== G. under the ratchet: other lane rules = another epoch-1 digest = refused at HELLO; the SAME pool_id on chain ==\n");
    const auto G = b32(0xA0);
    const auto ID = lineage::pool_id(3, LANE_CHAIN, G);
    const lr::LaneRules r60 = node_rules(60), r61 = node_rules(61), r60b = node_rules(60);
    const lr::LaneRules q16 = node_rules(60, 16), hm = node_rules(60, 0, 2'500'000'000ull);
    CHECK(r60 == r60b && lr::rules_digest(r60) == lr::rules_digest(r60b), "equal configs -> equal lane rules -> the SAME rules_digest (the epoch-1 Deployment)");
    CHECK(lr::rules_digest(r60) != lr::rules_digest(r61) && lr::rules_digest(r60) != lr::rules_digest(q16) && lr::rules_digest(r60) != lr::rules_digest(hm),
          "d_conf 60/61, drain_q 0/16, settle_h_min -> different rules_digest");
    CHECK(r60.pool_tag_codec == 2, "lane-rules field 26 pool_tag_codec = 2 (the V37P v2 codec)");
    // HELLO: the same pool (genesis), other rules -> refused BY NAME; the pool_id is unchanged
    auto hello_of = [&](const lr::LaneRules& rr, std::uint64_t nonce) {
        relay::Hello h; h.network = 3; h.chain_id = LANE_CHAIN; h.share_diff = 1; h.node_nonce = nonce;
        h.pool = relay::pool_id_of(LANE_CHAIN, ::v37::LaneParams{}); h.pool->genesis = G;
        h.lane_params_digest = rr.lane_params_digest; h.rules = rr;
        return h;
    };
    const std::string m = relay::hello_mismatch(hello_of(r60, 1), hello_of(r61, 2));
    CHECK(m.rfind("LANE_RULES_MISMATCH field=d_conf ours=60 theirs=61", 0) == 0, "HELLO: d_conf 60 vs 61 (same genesis): %s", m.substr(0, 60).c_str());
    CHECK(relay::hello_mismatch(hello_of(r60, 1), hello_of(r60b, 3)).empty(), "HELLO: equal rules interoperate");
    CHECK(lineage::pool_id(3, LANE_CHAIN, G) == ID, "the pool_id does not depend on the rules: nothing on chain names a rule");

    // --- the chain: a block built under rules X by a node of MY pool is Own; the recompute decides
    const credit::PoolField F{ID, 1, 1};
    Built x(F), y(F);
    CHECK(x.ok && y.ok, "two templates build + materialize (%s / %s)", x.ok ? "ok" : x.why.c_str(), y.ok ? "ok" : y.why.c_str());
    if (!(x.ok && y.ok)) return;
    CHECK(x.bytes.full_blob == y.bytes.full_blob, "two nodes with different lane rules (d_conf) build BYTE-IDENTICAL coinbases: the rule lives in HELLO, not on chain");
    std::vector<::v37::bytes32> cands{y.lane.ledger.ledger().owed_digest()};
    const auto keys = y.lane.ledger.keys();
    auto decode = [&](const asm_::BlockBytes& b, const ::v37::bytes32& id) {
        return auth::decode_lane_coinbase(b.full_blob, LANE_CHAIN, cands, keys, y.lane.scfg.residual_sink,
                                          y.lane.scfg.residual_sink_identity, y.lane.ledger.pay_of(), &id);
    };
    namespace rc = c2pool::v37n::xmr::recompute;
    auto lane_inputs = [&](bool commit_total, const credit::PoolField& f, std::uint32_t epoch_cur = 1) {
        rc::LaneInputs li;
        li.chain_id = LANE_CHAIN; li.h_min = 0; li.owed_cap = 2700; li.wire_cap = 2700; li.commit_total = commit_total;
        li.residual_sink = y.lane.scfg.residual_sink; li.residual_sink_identity = y.lane.scfg.residual_sink_identity;
        li.pool_field = f; li.epoch_cur = epoch_cur;
        return li;
    };
    // K3 under the ratchet: Y runs commit_total ON, X built without it (same pool_id): Own on Y, recompute Mismatch (debit-only)
    const auto bk = decode(x.bytes, ID);
    CHECK(bk.ok && bk.is_lane && bk.lineage == lineage::BlockLineage::Own, "X's block (same pool_id, other rules) is Own on Y");
    const auto before = y.lane.ledger.ledger().owed_digest();
    const auto v_y = rc::verify_lane_coinbase(x.bytes.full_blob, bk, y.lane.ledger.ledger(), y.lane.ledger.pay_of(), lane_inputs(true, F), rc::CutInputs{});
    const auto v_x = rc::verify_lane_coinbase(x.bytes.full_blob, bk, y.lane.ledger.ledger(), y.lane.ledger.pay_of(), lane_inputs(false, F), rc::CutInputs{});
    std::printf("    Y's recompute of X's block (commit_total ON vs OFF): %s (%s)\n", rc::to_string(v_y.verdict), v_y.why.c_str());
    CHECK(v_y.verdict == rc::Verdict::Mismatch, "Y's recompute = Mismatch (debit-only): the deviant node was refused at HELLO by name; its block is its own loss");
    CHECK(v_x.verdict == rc::Verdict::Canonical, "under X's own rules the same block is Canonical");
    CHECK(y.lane.ledger.ledger().owed_digest() == before, "the recompute moved no ledger state");
    // the EPOCH checks of the recompute (spec 1.4, R1 with the one-epoch table)
    const credit::PoolField F2{ID, 2, 2};
    Built x2(F2);
    CHECK(x2.ok, "a template naming epoch_cur 2 builds (%s)", x2.ok ? "ok" : x2.why.c_str());
    if (x2.ok) {
        const auto bk2 = decode(x2.bytes, ID);
        CHECK(bk2.ok && bk2.is_lane && bk2.pool_field == F2, "a block of my pool naming epoch_cur 2 is Own (the pool question), the field parsed");
        const auto v2 = rc::verify_lane_coinbase(x2.bytes.full_blob, bk2, y.lane.ledger.ledger(), y.lane.ledger.pay_of(), lane_inputs(false, F), rc::CutInputs{});
        CHECK(v2.verdict == rc::Verdict::Mismatch && v2.why.find("misbuilt: V37P epoch_cur 2 != epoch_of(h) 1") != std::string::npos,
              "on an epoch-1 ledger it is MISBUILT -> Mismatch (debit-only): %s", v2.why.substr(0, 80).c_str());
        const auto v2b = rc::verify_lane_coinbase(x2.bytes.full_blob, bk2, y.lane.ledger.ledger(), y.lane.ledger.pay_of(), lane_inputs(false, F2, 2), rc::CutInputs{});
        CHECK(v2b.verdict == rc::Verdict::Canonical, "the same block under an epoch-2 ledger (R3's epoch_of(h) = 2) is Canonical");
    }
    const credit::PoolField F3{ID, 2, 1};   // epoch_max below epoch_cur
    Built x3(F3);
    if (x3.ok) {
        const auto bk3 = decode(x3.bytes, ID);
        const auto v3 = rc::verify_lane_coinbase(x3.bytes.full_blob, bk3, y.lane.ledger.ledger(), y.lane.ledger.pay_of(), lane_inputs(false, F, 2), rc::CutInputs{});
        CHECK(v3.verdict == rc::Verdict::Mismatch && v3.why.find("epoch_max 1 < epoch_cur 2") != std::string::npos,
              "epoch_max below epoch_cur -> Mismatch (%s)", v3.why.substr(0, 60).c_str());
    }
    const auto bk_self = decode(y.bytes, ID);
    const auto v_self = rc::verify_lane_coinbase(y.bytes.full_blob, bk_self, y.lane.ledger.ledger(), y.lane.ledger.pay_of(), lane_inputs(false, F), rc::CutInputs{});
    CHECK(bk_self.is_lane && v_self.verdict == rc::Verdict::Canonical, "on an equal-rules node our own block is Own and books Canonical");
    Built yc(F, 0, true);
    const auto bk_yc = decode(yc.bytes, ID);
    const auto v_yc = rc::verify_lane_coinbase(yc.bytes.full_blob, bk_yc, y.lane.ledger.ledger(), y.lane.ledger.pay_of(), lane_inputs(true, F), rc::CutInputs{});
    CHECK(yc.ok && bk_yc.is_lane && v_yc.verdict == rc::Verdict::Canonical, "Y's own (commit_total) block: Own, Canonical on Y");
}

} // namespace

int main() {
    std::printf("=== v37_xmr_pool_lineage_kat (RULES RATCHET R1: pool identity from a headline genesis, V37P v2) ===\n");
    suite_derivation();
    suite_codec();
    suite_classify();
    suite_blocks();
    suite_widest();
    suite_hello();
    suite_rules();
    std::printf("=== %d/%d checks passed ===\n", g_checks - g_fail, g_checks);
    return g_fail == 0 ? 0 : 1;
}
