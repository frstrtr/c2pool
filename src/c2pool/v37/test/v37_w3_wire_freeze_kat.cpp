// V37 Track A2 / W3-B5 — carrier-wire BYTE FREEZE golden KAT.
//
// Pins the CarrierWire byte layout (w3_relay.hpp, wire version 0x01) as
// canonical and stable. The send-side (a node emitting its own stratum wins as
// carriers, main_v37_btc_dash.cpp) relies on the wire being identical across
// nodes and builds; this KAT is the tripwire that makes any change to a field,
// its width, order, or endianness a VISIBLE test failure rather than a silent
// cross-node incompatibility.
//
// It encodes a FIXED carrier (a deterministic WorkEvent + one receipt, chosen
// to exercise every field of the frozen layout — see the byte-map in the
// w3_relay.hpp header) and asserts the bytes equal the pinned golden. It also
// round-trips decode(encode(c)) == c and re-asserts the transport framing
// constants. No PoW grind: encode/decode do not verify PoW, so every field is a
// fixed literal, keeping the golden 100% reproducible.
//
// REGEN: run with the env var V37_W3_FREEZE_REGEN set to print the hex to pin.
//
// stdlib-only, no threads (unlike the multi-node socket test).

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include <c2pool/v37/w3_relay.hpp>
#include <c2pool/v37/carrier_net.hpp>   // kMaxCarrierFrame (framing freeze)
#include <c2pool/v37/w3_wire_freeze.hpp>   // frozen constants, size model, fixtures A/B/C, selfcheck()

using namespace c2pool::v37n;

// The transport ceiling is frozen in w3_wire_freeze.hpp (which deliberately does
// not include carrier_net.hpp); pin the two together here so they cannot drift.
static_assert(kMaxCarrierFrame == wire_freeze::kTransportMaxFrame,
              "W3-B5: carrier_net.hpp kMaxCarrierFrame drifted from the frozen transport ceiling");

static int g_failures = 0;
static int g_checks = 0;
#define CHECK(cond)                                                          \
    do {                                                                     \
        ++g_checks;                                                          \
        if (!(cond)) { ++g_failures;                                         \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); }    \
    } while (0)

static std::string to_hex(const std::vector<std::uint8_t>& b) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (std::uint8_t x : b) { s.push_back(kHex[x >> 4]); s.push_back(kHex[x & 0x0f]); }
    return s;
}

// A fixed 32-byte pattern (byte i = base + i), so the golden is legible.
static bytes32 pat(std::uint8_t base) {
    bytes32 h{};
    for (int i = 0; i < 32; ++i) h[i] = static_cast<std::uint8_t>(base + i);
    return h;
}

static ::v37::PayoutDescriptor p2pkh_desc(std::uint8_t fill) {
    ::v37::ScriptRef r;
    r.kind = ::v37::ScriptKind::P2PKH;
    r.payload.assign(20, fill);
    ::v37::PayoutDescriptor d;
    d.pay = r;
    return d;   // identity_key() is a pure function of `pay`
}

// The FROZEN fixture. Every field is a literal; identity is bound to the
// descriptor (W3-MUST), so decode() returns OK on the round trip.
static Carrier frozen_carrier() {
    ::v37::PayoutDescriptor desc = p2pkh_desc(0x11);

    WorkEvent carrier;
    carrier.chain_id       = 1;
    carrier.identity       = desc.identity_key();
    carrier.prev_block_hash = pat(0x40);
    carrier.prev_own_share  = bytes32{};              // genesis
    carrier.lz_bits        = 8;
    carrier.nonce          = 0x0123456789abcdefULL;
    carrier.descriptor     = desc;
    carrier.tag            = "c";

    WorkEvent r0;
    r0.chain_id        = 1;
    r0.identity        = desc.identity_key();
    r0.prev_block_hash = pat(0x60);
    r0.prev_own_share  = carrier.prev_block_hash;      // any 32-byte value
    r0.lz_bits         = 8;
    r0.nonce           = 0xfeedface0badc0deULL;
    r0.descriptor      = desc;
    r0.tag             = "r0";

    Carrier c;
    c.carrier  = carrier;
    c.receipts = {r0};
    return c;
}

// The golden hex of encode(frozen_carrier()) under wire version 0x01.
// Regenerate with V37_W3_FREEZE_REGEN=1 if (and only if) an INTENTIONAL,
// version-bumped wire change lands.
static const char* kGoldenHex =
    "0101000000fd2e83fe009e7e6c791745176f53719653bc35f5705564e912d4af2413cce77d404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000000000000000000000000000000000000000000000000000000000000008000000efcdab89674523010014111111111111111111111111111111111111111100000000000100630101000000fd2e83fe009e7e6c791745176f53719653bc35f5705564e912d4af2413cce77d606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f08000000dec0ad0bcefaedfe00141111111111111111111111111111111111111111000000000002007230";

static bool events_equal(const WorkEvent& a, const WorkEvent& b) {
    return a.chain_id == b.chain_id && a.identity == b.identity &&
           a.prev_block_hash == b.prev_block_hash &&
           a.prev_own_share == b.prev_own_share && a.lz_bits == b.lz_bits &&
           a.nonce == b.nonce && a.tag == b.tag &&
           a.descriptor.identity_key() == b.descriptor.identity_key();
}

int main() {
    const Carrier c = frozen_carrier();
    const std::vector<std::uint8_t> bytes = CarrierWire::encode(c);
    const std::string hex = to_hex(bytes);

    if (std::getenv("V37_W3_FREEZE_REGEN")) {
        std::printf("REGEN golden (%zu bytes):\n%s\n", bytes.size(), hex.c_str());
        return 0;
    }

    // (1) Byte freeze: the wire bytes are EXACTLY the pinned golden.
    CHECK(hex == kGoldenHex);
    if (hex != kGoldenHex)
        std::printf("  got   : %s\n  golden: %s\n", hex.c_str(), kGoldenHex);

    // (2) Version tag is the first byte and equals the frozen 0x01.
    CHECK(!bytes.empty() && bytes[0] == W3_WIRE_VERSION && W3_WIRE_VERSION == 0x01);

    // (3) Round trip: decode(encode(c)) reconstructs the carrier + receipt and
    //     returns OK (identity binding holds), losing nothing.
    DecodeResult dr = CarrierWire::decode(bytes);
    CHECK(dr.status == WireStatus::OK);
    CHECK(dr.dropped.empty());
    CHECK(events_equal(dr.carrier.carrier, c.carrier));
    CHECK(dr.carrier.receipts.size() == 1);
    if (dr.carrier.receipts.size() == 1)
        CHECK(events_equal(dr.carrier.receipts[0], c.receipts[0]));

    // (4) Re-encoding the decoded carrier is byte-identical (no drift on relay).
    CHECK(CarrierWire::encode(dr.carrier) == bytes);

    // (5) Transport framing ceiling is frozen (carrier_net.hpp length prefix).
    CHECK(kMaxCarrierFrame == (1u << 20));

    // (6) The full W3-B5 byte-KAT body (w3_wire_freeze.hpp::selfcheck): fixtures
    //     A (this file's golden, byte-identical), B (every descriptor branch +
    //     R_MAX receipts + tag at cap) and C (attribution slot + 0 receipts);
    //     independent size/offset model, decode(golden)==fixture, truncation
    //     sweep, trailing byte, version policy, R_MAX+1, W3-MUST binding, and
    //     the F-1/F-2 policy pins. Same body the daemon runs at boot.
    {
        const wire_freeze::SelfCheck sc = wire_freeze::selfcheck();
        if (!sc.ok()) std::printf("%s", sc.log.c_str());
        CHECK(sc.ok());
        std::printf("wire-freeze selfcheck [%s]: %u checks, %u failures\n",
                    wire_freeze::layout_id(), sc.checks, sc.failures);
        // The golden this file pins IS fixture A's golden — one source of truth.
        CHECK(std::string(kGoldenHex) == wire_freeze::kGoldenHexA);
    }

    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
