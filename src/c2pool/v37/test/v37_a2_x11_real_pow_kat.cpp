// V37 Track A2 / S-1 — REAL-X11 END-TO-END KAT (the SSOT-linked proof).
//
// WHY THIS TARGET EXISTS. Its sibling v37_a2_x11_wire_kat keeps the BYTES honest
// but is stdlib-only: it reaches "X11" through an injected sha256d STUB, so CI
// compiled ZERO X11 primitives for S-1 and the genuine end-to-end proof lived in
// an out-of-tree harness nobody's CI ran. This target closes that gap. It links
// the real DASH X11 SSOT — the vendored 12-file sph reference C behind
// dash::crypto::hash_x11 (target dash_x11, src/impl/dash/crypto), the same SSOT
// the shipped node hashes with — and keeps the WORK honest.
//
// ONE TRANSLATION UNIT, BOTH CONCERNS. This file includes the wire layer
// (w3_relay_x11.hpp), the bind/credit layer (x11_share_envelope.hpp) and the
// consensus verifier (impl/dash/x11_share_verify.hpp) TOGETHER. That is only
// possible because the duplicate c2pool::v37n::X11Carrier / duplicate 0x02 codec
// was reconciled: there is now exactly ONE carrier, ONE codec, ONE golden, ONE
// PoW implementation and ONE OP_RETURN extractor. Before the reconcile the two
// headers each defined X11Carrier with byte-incompatible 0x02 layouts under the
// SAME version byte, so no TU could hold both and encode+verify could never be
// proven together.
//
// THE FIXTURE IS A REAL ACCEPTED DASH SHARE. Every constant below was captured
// off a live stratum mining.submit from a real minerd -a x11 against a DASH
// regtest node (block 243) and is pinned here fully resolved: no network, no
// daemon, and NO endianness-convention search (the out-of-tree capture tool
// stays out of tree as the FIXTURE GENERATOR; CI consumes the resolved fixture).
// kNodePowHashDisplay is the node's OWN logged pow_hash. RX-1 reduces the
// paper's §2/§15 claim — "a receipt is proof of the real coin PoW, trustlessly
// re-verifiable" — to one comparison a stranger can rerun.
//
// Plain int main() + a selfcheck counter, matching every other v37 test target
// (no GTest). Nonzero exit on any failed check.

#include <c2pool/v37/w3_relay_x11.hpp>        // L1 WIRE  (stdlib-only)
#include <c2pool/v37/x11_share_envelope.hpp>  // L3 BIND  (includes L2)
#include <c2pool/v37/w3_wire_freeze.hpp>      // the FROZEN v0x01 fixtures + golden
#include <impl/dash/x11_share_verify.hpp>     // L2 VERIFY (the SSOT)
#include <impl/dash/crypto/hash_x11.hpp>      // dash::crypto::hash_x11 + the sph stages

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace c2pool::v37n;

// ── check harness ──────────────────────────────────────────────────────────
static unsigned g_checks = 0, g_fail = 0;
static bool CHK(bool cond, const char* what) {
    ++g_checks;
    if (!cond) { ++g_fail; std::printf("  FAIL %s\n", what); }
    return cond;
}
static void SECTION(const char* s) { std::printf("-- %s\n", s); }

// ── hex helpers ────────────────────────────────────────────────────────────
static std::string to_hex(const std::uint8_t* p, std::size_t n) {
    static const char* k = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) { s.push_back(k[p[i] >> 4]); s.push_back(k[p[i] & 15]); }
    return s;
}
static std::string to_hex(const std::vector<std::uint8_t>& b) { return to_hex(b.data(), b.size()); }
static int nib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static std::vector<std::uint8_t> from_hex(const std::string& h) {
    std::vector<std::uint8_t> o;
    if (h.size() % 2) return o;
    o.reserve(h.size() / 2);
    for (std::size_t i = 0; i < h.size(); i += 2) {
        int hi = nib(h[i]), lo = nib(h[i + 1]);
        if (hi < 0 || lo < 0) return {};
        o.push_back(std::uint8_t((hi << 4) | lo));
    }
    return o;
}
static bytes32 b32_from_hex(const char* h) {
    auto v = from_hex(h);
    bytes32 b{};
    if (v.size() == 32) std::memcpy(b.data(), v.data(), 32);
    return b;
}

// ═══════════════════════════════════════════════════════════════════════════
// THE PINNED REAL SHARE (DASH regtest block 243, real minerd -a x11 submit).
// ═══════════════════════════════════════════════════════════════════════════
static constexpr std::uint32_t kHeaderVersion = 0x30000000u;
static constexpr std::uint32_t kNtime         = 0x6a9fe19bu;
static constexpr std::uint32_t kNbits         = 0x207fffffu;   // regtest powLimit
static constexpr std::uint32_t kNonce         = 0x60e919c0u;
// header.hashPrevBlock in INTERNAL (uint256::data(), little-endian) order.
static constexpr const char* kPrevBlockInternalHex =
    "9bc2a3730e7b2e185364ee77c64e4063b52812f068880ef32fe8e23fe6050000";
// The full reassembled coinbase (coinb1 || extranonce1 || extranonce2 || coinb2),
// 194 bytes. A well-formed 3-output tx whose 3rd output script is
// 0x2a || 6a 28 || ref_hash(32) || nonce64(8) — so it survives the SSOT's proper
// vin/vout walk, not merely a byte search.
static constexpr const char* kCoinbaseHex =
    "010000000100000000000000000000000000000000000000000000000000000000000000"
    "00ffffffff1802f3002f5032506f6f6c2d74444153482f6332706f6f6c2fffffffff0324"
    "c75bcf0a0000001976a9142373070b954075e10f01e425363e62f41d22674988ac010000"
    "00000000001976a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac0000000000"
    "0000002a6a28000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000";
// The node's OWN logged pow_hash for this share (display / big-endian GetHex).
static constexpr const char* kNodePowHashDisplay =
    "0000033c306d27775e5be78efd7314424a201198c1ac120a8a8cb2284ec36e40";
// The reconstructed merkle root (empty branch => == coinbase txid), display order.
static constexpr const char* kMerkleRootDisplay =
    "b4bb386be54640189838b0ed2f6bcbdb3b3d6bd96e11805dd809686a4cfdef5c";
// The 80-byte header those fields rebuild (pinned so a serialize_header80 drift
// is caught as a layout change, not silently as a wrong hash).
static constexpr const char* kHeader80Hex =
    "000000309bc2a3730e7b2e185364ee77c64e4063b52812f068880ef32fe8e23fe6050000"
    "5ceffd4c6a6809d85d80116ed96b3d3bdbcb6b2fedb03898184046e56b38bbb49be19f6a"
    "ffff7f20c019e960";

// RX-2 per-primitive tripwire: the ELEVEN 512-bit sph stage outputs for that
// header, in pipeline order. A silently-broken single sph .c is named, not merely
// caught as "the composition changed".
static constexpr const char* kStageNames[11] = {
    "BLAKE", "BMW", "GROESTL", "SKEIN", "JH", "KECCAK",
    "LUFFA", "CUBEHASH", "SHAVITE", "SIMD", "ECHO"};
static constexpr const char* kStageHex[11] = {
    "de6ef52bf27200b65c4728dc78d5fa1822189701ad7cc98105d353af09d359290ad618e0cb2ebae3d4327b0e6febc4b7354be633c5359f1adfc1ea016f9a7bc5",
    "a51bb7b3dd83a922fc9f0638b0a6956ea8c4f1195be49f70330dfb7b1ad7dac3a80f0f6181c0198ec2879af256dbe0d4a1c43f4403ee50dc06a933180c993f0f",
    "70bf2bdfb027d85491dab01aff40dfdf66e5aedf2ff9088909d7574e9684bd9c0c46cd6b4f5e6014028e32ae3f3627d0cec29d1ea03d2d9b37a98fbdaef75760",
    "2f341e1db077503b201c11d05066bc525f001cee37172583cd36660f46b4b57be75a0eaf12f771475df9887e097ea24a36b2b70ef4976843d6995c4cfdb43453",
    "33c8ee1ad21fec6c2926c1b9cb83aa7fae581e5f48bbdce849d8e98883366607e7afc8d1d30acbce4b70587bd98b54d9e2dae912ed89e6985060c6730459968f",
    "68c484ee2ddbc8372db6adc01f32f6374aed00663ce8a507db05914f792348b88fcb919c1303ed2c2da8ddfc01aec53538c8ec5cfee97e6d03532ab048496edf",
    "ce140d81acbd47512e131d4f69ff94243e3e1d85abde4c070ed8b9f4af926625d458ce8037d939a294cb4df552da0b3d34b306d0c8378f81cf05fef284e52c98",
    "dbef255ad32e5de3a17a6b2b4c559df0ebf322176c1a61df59f854014b99abfea2deff4cb45c4bd8c4f5afd6901c6ffd734a3ceb836e9c543d9d501f6180cafa",
    "f1d739a025bf0932092ce10baf2b6273713ad6cca8379ca23af2c821fbb1f496b34e97d514f4790c1ea8474dfa23e58bbaf29d904969f77f75da99b259013f1c",
    "fbad4e32f024f45f46cb5284d30d7b34c26a2113e83a2d35a657082677c55451aa23f3cde93db10fd08c66ee0971a67779b6f0f471255838c8b0f8695a4e21f2",
    "406ec34e28b28c8a0a12acc19811204a421473fd8ee75b5e77276d303c030000b93bea98488bb277a1d59dc84302facfdfaafbd6ac43c115ac19c47fa8abfeff",
};

// RX-11: the carrier-wire 0x02 frame for exactly this share (1 carrier, 0
// receipts, P2PKH descriptor 20x0x11, tag "s1"), under the CANONICAL L1 layout.
// 368 bytes. NOTE (declared in the PR): the PR body's original 360-byte hex was
// generated under the deleted second layout; this is the same capture re-encoded
// under the surviving one — it gains the 8-byte last_txout_nonce and orders
// prev_block before prev_own. Subject to X11-OQ1 / X11-OQ2 (see the header).
static constexpr const char* kRealCaptureGoldenHex =
    "0201000000fd2e83fe009e7e6c791745176f53719653bc35f5705564e912d4af2413cce7"
    "7d9bc2a3730e7b2e185364ee77c64e4063b52812f068880ef32fe8e23fe6050000000000"
    "0000000000000000000000000000000000000000000000000000000000000000309be19f"
    "6affff7f20c019e960ffff7f20ffff7f200000000000000000c200000001000000010000"
    "000000000000000000000000000000000000000000000000000000000000ffffffff1802"
    "f3002f5032506f6f6c2d74444153482f6332706f6f6c2fffffffff0324c75bcf0a000000"
    "1976a9142373070b954075e10f01e425363e62f41d22674988ac01000000000000001976"
    "a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac00000000000000002a6a2800"
    "000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000001411111111111111111111111111111111111111110000"
    "0000000200733100";

// ── build the pinned event ─────────────────────────────────────────────────
static ::v37::PayoutDescriptor pinned_descriptor() {
    ::v37::PayoutDescriptor d;
    d.pay.kind = ::v37::ScriptKind::P2PKH;
    d.pay.payload.assign(20, 0x11);
    return d;
}
static X11WorkEvent pinned_event() {
    X11WorkEvent e;
    const auto d = pinned_descriptor();
    e.chain_id         = 1;
    e.descriptor       = d;
    e.identity         = d.identity_key();          // W3-MUST bound
    e.prev_block_hash  = b32_from_hex(kPrevBlockInternalHex);
    e.prev_own_share   = bytes32{};
    e.header_version   = kHeaderVersion;
    e.ntime            = kNtime;
    e.nbits            = kNbits;
    e.nonce            = kNonce;
    e.share_bits       = kNbits;                    // credited at the block target here
    e.max_bits         = kNbits;
    e.last_txout_nonce = 0;
    e.coinbase         = from_hex(kCoinbaseHex);
    e.coinbase_payload = {};
    e.merkle_branch    = {};
    e.tag              = "s1";
    return e;
}

// Grind a REAL X11 nonce for `ev` until its PoW meets `bits`. Deterministic (the
// same nonce every run) and cheap at kGrindBits (~2^-8, so ~256 expected tries).
static constexpr std::uint32_t kGrindBits = 0x2000ffffu;
static bool grind_real_nonce(X11WorkEvent& ev, std::uint32_t bits = kGrindBits) {
    ev.share_bits = bits;
    const uint256 target = dash::coin::target_from_nbits(bits);
    if (target.IsNull()) return false;
    for (std::uint32_t n = 0; n < (1u << 22); ++n) {
        ev.nonce = n;
        if (x11_pow_hash_u(ev) <= target) return true;
    }
    return false;
}

// Smallest compact whose SetCompact() target is >= pow yet ~1 ULP above it, so a
// mutated hash almost never meets it. GetCompact rounds toward zero, so bump the
// mantissa by one to land just above pow.
static std::uint32_t compact_just_above(const uint256& pow) {
    std::uint32_t c = pow.GetCompact();
    uint256 t; t.SetCompact(c);
    if (!(t < pow)) return c;
    std::uint32_t exp = c >> 24, mant = (c & 0x007fffffu) + 1;
    if (mant & 0x00800000u) { mant >>= 8; exp += 1; }
    return (exp << 24) | (mant & 0x007fffffu);
}

// ═══════════════════════════════════════════════════════════════════════════
int main() {
    const X11WorkEvent e = pinned_event();
    const std::vector<std::uint8_t> cb = e.coinbase;
    CHK(cb.size() == 194, "fixture: coinbase is the captured 194 bytes");

    // ── RX-1  REAL-X11 IDENTITY (the headline) ─────────────────────────────
    SECTION("RX-1  real X11 == the node's own logged pow_hash");
    const uint256 txid  = x11_coinbase_txid_u(e);
    const uint256 mroot = x11_merkle_root_u(e);
    unsigned char hdr[80];
    x11_fill_header80(e, hdr);
    const uint256 pow = dash::crypto::hash_x11(hdr, 80);
    std::printf("   merkle_root = %s\n", mroot.GetHex().c_str());
    std::printf("   X11 pow     = %s\n", pow.GetHex().c_str());
    std::printf("   node pow    = %s\n", kNodePowHashDisplay);
    CHK(to_hex(hdr, 80) == std::string(kHeader80Hex), "RX-1 serialize_header80 byte layout pinned");
    CHK(pow.GetHex() == std::string(kNodePowHashDisplay),
        "RX-1 recomputed X11 == the node's logged pow_hash (same accepted share)");
    CHK(x11_pow_hash_u(e) == pow, "RX-1 x11_pow_hash_u(e) agrees with a direct SSOT call");

    // ── RX-2  STUB TRIPWIRE + per-primitive pins ───────────────────────────
    SECTION("RX-2  genuine 11-primitive pipeline, not a sha256d stand-in");
    {
        std::vector<std::uint8_t> hv(hdr, hdr + 80);
        const bytes32 stub_sha = ::v37::sha256d(hv);          // the wire-KAT's stub
        const uint256 stub_bp  = dash::coin::bp_sha256d(std::span<const unsigned char>(hdr, 80));
        CHK(internal_from_u256(pow) != stub_sha, "RX-2 X11 != ::v37::sha256d(header) (stub tripwire)");
        CHK(pow != stub_bp, "RX-2 X11 != dash::coin::bp_sha256d(header)");

        dash::crypto::uint512_t h[11];
        sph_blake512_context c0;    sph_blake512_init(&c0);    sph_blake512(&c0, hdr, 80);       sph_blake512_close(&c0, h[0].data);
        sph_bmw512_context c1;      sph_bmw512_init(&c1);      sph_bmw512(&c1, h[0].data, 64);   sph_bmw512_close(&c1, h[1].data);
        sph_groestl512_context c2;  sph_groestl512_init(&c2);  sph_groestl512(&c2, h[1].data,64);sph_groestl512_close(&c2, h[2].data);
        sph_skein512_context c3;    sph_skein512_init(&c3);    sph_skein512(&c3, h[2].data, 64); sph_skein512_close(&c3, h[3].data);
        sph_jh512_context c4;       sph_jh512_init(&c4);       sph_jh512(&c4, h[3].data, 64);    sph_jh512_close(&c4, h[4].data);
        sph_keccak512_context c5;   sph_keccak512_init(&c5);   sph_keccak512(&c5, h[4].data, 64);sph_keccak512_close(&c5, h[5].data);
        sph_luffa512_context c6;    sph_luffa512_init(&c6);    sph_luffa512(&c6, h[5].data, 64); sph_luffa512_close(&c6, h[6].data);
        sph_cubehash512_context c7; sph_cubehash512_init(&c7); sph_cubehash512(&c7,h[6].data,64);sph_cubehash512_close(&c7, h[7].data);
        sph_shavite512_context c8;  sph_shavite512_init(&c8);  sph_shavite512(&c8,h[7].data,64); sph_shavite512_close(&c8, h[8].data);
        sph_simd512_context c9;     sph_simd512_init(&c9);     sph_simd512(&c9, h[8].data, 64);  sph_simd512_close(&c9, h[9].data);
        sph_echo512_context c10;    sph_echo512_init(&c10);    sph_echo512(&c10, h[9].data, 64); sph_echo512_close(&c10, h[10].data);
        for (int i = 0; i < 11; ++i) {
            const bool ok = to_hex(h[i].data, 64) == std::string(kStageHex[i]);
            if (!ok) std::printf("   stage %s drifted: %s\n", kStageNames[i], to_hex(h[i].data, 64).c_str());
            CHK(ok, kStageNames[i]);
        }
        CHK(h[10].trim256() == pow, "RX-2 ECHO stage lower 256 bits == hash_x11 output");
    }

    // ── RX-3  MERKLE RECONSTRUCTION ────────────────────────────────────────
    SECTION("RX-3  merkle root is RECONSTRUCTED, never carried");
    CHK(mroot.GetHex() == std::string(kMerkleRootDisplay), "RX-3 fold_merkle_branch == pinned merkle root");
    CHK(mroot == txid, "RX-3 empty branch => merkle_root == coinbase_txid");
    CHK(std::memcmp(hdr + 36, mroot.data(), 32) == 0, "RX-3 that root is exactly what the header committed");

    // ── RX-4  PEER ADMITS ──────────────────────────────────────────────────
    SECTION("RX-4  dash::verify_x11_share admits the real share");
    const uint256 kClaimedRef;   // the capture commits an all-zero ref_hash
    dash::X11VerifyResult vr = dash::verify_x11_share(to_dash_envelope(e, kClaimedRef));
    std::printf("   status=%s meets_share=%d won_block=%d\n",
                dash::x11_verify_status_name(vr.status), vr.meets_share_target, vr.won_block);
    CHK(vr.status == dash::X11VerifyStatus::OK, "RX-4 status == OK");
    CHK(vr.meets_share_target, "RX-4 meets_share_target");
    CHK(vr.won_block, "RX-4 won_block (share_bits == nbits here)");
    CHK(vr.committed_ref_hash == kClaimedRef, "RX-4 committed_ref_hash == the claimed 00*32");
    CHK(vr.committed_nonce64 == 0, "RX-4 committed nonce64 == 0");
    CHK(vr.coinbase_txid == vr.merkle_root, "RX-4 coinbase_txid == merkle_root (empty branch)");
    CHK(vr.pow_hash == pow, "RX-4 the verifier's pow_hash IS the SSOT X11");
    CHK(internal_from_u256(vr.pow_hash) == x11_share_id(e), "RX-4 share id == verifier pow_hash");

    // ── RX-5..RX-10  FAIL-CLOSED ON FORGERY ────────────────────────────────
    SECTION("RX-5..RX-10  six forgeries, each rejected fail-closed");
    {   // RX-5 insufficient PoW at a target the honest share still meets
        const std::uint32_t tight = compact_just_above(pow);
        dash::X11VerifyResult good = dash::verify_x11_share(to_dash_envelope(
            [&]{ X11WorkEvent t = e; t.share_bits = tight; return t; }(), kClaimedRef));
        CHK(good.status == dash::X11VerifyStatus::OK, "RX-5 the honest share is still OK at the tight target (not vacuous)");
        bool rejected = false;
        for (std::uint32_t k = 1; k <= 64 && !rejected; ++k) {
            X11WorkEvent bad = e; bad.nonce = e.nonce ^ k; bad.share_bits = tight;
            rejected = dash::verify_x11_share(to_dash_envelope(bad, kClaimedRef)).status
                       == dash::X11VerifyStatus::REJECT_POW;
        }
        CHK(rejected, "RX-5 mutated nonce -> REJECT_POW");
    }
    {   // RX-6 claimed ref_hash != what the coinbase commits
        uint256 forged = kClaimedRef;
        forged.data()[0] ^= 0x01;
        CHK(dash::verify_x11_share(to_dash_envelope(e, forged)).status
                == dash::X11VerifyStatus::REJECT_PAYOUT_COMMITMENT,
            "RX-6 forged payout claim -> REJECT_PAYOUT_COMMITMENT");
    }
    {   // RX-7 OP_RETURN marker destroyed. Replace OP_RETURN with OP_TRUE so the
        // script LENGTH and the tx structure are untouched and only the commitment
        // is gone; meets_share_target is asserted so the verdict is the COMMITMENT
        // arm, not a PoW short-circuit (the mutation does change the merkle root).
        X11WorkEvent bad = e;
        for (std::size_t i = 0; i + 1 < bad.coinbase.size(); ++i)
            if (bad.coinbase[i] == 0x6a && bad.coinbase[i + 1] == 0x28) { bad.coinbase[i] = 0x51; break; }
        // The mutation changes the merkle root, hence the PoW, so re-grind a REAL
        // nonce: the forged share must carry genuine work or the commitment arm is
        // never reached and the check would be vacuous.
        CHK(grind_real_nonce(bad), "RX-7 re-ground a real nonce for the commitment-less coinbase");
        const dash::X11VerifyResult r7 = dash::verify_x11_share(to_dash_envelope(bad, kClaimedRef));
        CHK(r7.meets_share_target, "RX-7 the mutated share carries real work (not vacuous)");
        CHK(r7.status == dash::X11VerifyStatus::REJECT_NO_COMMITMENT,
            "RX-7 no OP_RETURN commitment -> REJECT_NO_COMMITMENT");
    }
    {   // RX-8 truncated coinbase
        X11WorkEvent bad = e; bad.coinbase.resize(6);
        CHK(dash::verify_x11_share(to_dash_envelope(bad, kClaimedRef)).status
                == dash::X11VerifyStatus::REJECT_STRUCTURE,
            "RX-8 truncated coinbase -> REJECT_STRUCTURE");
    }
    {   // RX-9 null share-target compact
        X11WorkEvent bad = e; bad.share_bits = 0x00000000u;
        CHK(dash::verify_x11_share(to_dash_envelope(bad, kClaimedRef)).status
                == dash::X11VerifyStatus::REJECT_SHARE_TARGET,
            "RX-9 share_bits == 0 -> REJECT_SHARE_TARGET");
    }
    {   // RX-10 tamper-evidence: you cannot move the payout without redoing the work
        X11WorkEvent bad = e; bad.coinbase[80] ^= 0x01;
        CHK(x11_merkle_root_u(bad) != mroot, "RX-10 a flipped coinbase byte changes the merkle root");
        CHK(x11_pow_hash_u(bad) != pow, "RX-10 ... and therefore the X11 share id (tamper-evident)");
    }

    // ── RX-11  ONE-TU CLOSURE (encode -> decode_any -> verify) ─────────────
    SECTION("RX-11  one TU: X11CarrierWire::encode -> decode_any -> verify");
    {
        X11Carrier c; c.carrier = e;
        const std::vector<std::uint8_t> frame = X11CarrierWire::encode(c);
        const std::string hex = to_hex(frame);
        if (!CHK(hex == std::string(kRealCaptureGoldenHex), "RX-11 encode == the pinned 0x02 real-capture golden"))
            std::printf("   got   : %s\n   golden: %s\n", hex.c_str(), kRealCaptureGoldenHex);
        CHK(frame.size() == wire_x11::frame_size(c), "RX-11 size == the independent frame_size model");
        CHK(frame.size() == 368, "RX-11 the real-capture frame is 368 bytes");
        AnyDecode any = decode_any(frame);
        CHK(any.ok() && any.kind == AnyWireKind::V2_X11, "RX-11 decode_any routes the frame to V2_X11");
        if (any.ok() && any.kind == AnyWireKind::V2_X11) {
            const X11WorkEvent& d = any.v2.carrier;
            CHK(X11CarrierWire::encode(any.v2) == frame, "RX-11 re-encode is byte-identical");
            CHK(x11_pow_hash_u(d).GetHex() == std::string(kNodePowHashDisplay),
                "RX-11 the DECODED event still recomputes the node's pow_hash");
            CHK(dash::verify_x11_share(to_dash_envelope(d, kClaimedRef)).status == dash::X11VerifyStatus::OK,
                "RX-11 decoded -> to_dash_envelope -> dash::verify_x11_share == OK");
        }
        // the golden decodes on its own, independent of encode()
        AnyDecode ag = decode_any(from_hex(std::string(kRealCaptureGoldenHex)));
        CHK(ag.ok() && ag.kind == AnyWireKind::V2_X11, "RX-11 decode(golden hex) routes to V2_X11");
    }

    // ── RX-12  THE HOOK INSTALLER IS THE SSOT ──────────────────────────────
    SECTION("RX-12  install_dash_x11_hook() installs the genuine permutation");
    {
        set_x11_hash(nullptr);
        CHK(x11_hash_hook() == nullptr, "RX-12 hook is fail-closed before installation");
        install_dash_x11_hook();
        CHK(x11_hash_hook() != nullptr, "RX-12 hook is installed");
        const bytes32 via_hook = x11_hash_hook()(hdr);
        CHK(via_hook == internal_from_u256(dash::crypto::hash_x11(hdr, 80)),
            "RX-12 hook(header) == dash::crypto::hash_x11 byte-for-byte");
        CHK(via_hook == x11_share_id(e), "RX-12 ... and that IS the consensus share id");
    }

    // ── RX-13  v0x01 STILL DECODABLE (freeze intact, both directions) ──────
    SECTION("RX-13  the frozen v0x01 wire is untouched and still version-gated");
    {
        const Carrier v1 = wire_freeze::fixture_a();
        const std::vector<std::uint8_t> v1frame = CarrierWire::encode(v1);
        CHK(to_hex(v1frame) == std::string(wire_freeze::kGoldenHexA),
            "RX-13 the FROZEN v0x01 golden is byte-unchanged by this PR");
        AnyDecode a1 = decode_any(v1frame);
        CHK(a1.ok() && a1.kind == AnyWireKind::V1_SYNTHETIC, "RX-13 decode_any routes 0x01 to the frozen decoder");
        CHK(CarrierWire::encode(a1.v1) == v1frame, "RX-13 the synthetic carrier round-trips lossless");
        X11Carrier c2; c2.carrier = e;
        CHK(CarrierWire::decode(X11CarrierWire::encode(c2)).status == WireStatus::REJECT_BAD_VERSION,
            "RX-13 the frozen 0x01 decoder REFUSES a 0x02 frame");
        CHK(decode_any({0x03, 0x00}).status == WireStatus::REJECT_BAD_VERSION,
            "RX-13 decode_any refuses 0x03 (outside the dual-accept set)");
    }

    // ── RX-14  FRESHLY MINED, NOT ONLY A REPLAY ────────────────────────────
    SECTION("RX-14  a share this KAT itself ground with real X11");
    {
        // A well-formed legacy coinbase whose LAST output is the OP_RETURN payout
        // commitment (0x6a 0x28 || ref_hash || nonce64).
        uint256 ref;
        for (int i = 0; i < 32; ++i) ref.data()[i] = static_cast<unsigned char>(0x40 + i);
        std::vector<std::uint8_t> mine;
        auto p32 = [&](std::uint32_t v) { for (int i = 0; i < 4; ++i) mine.push_back(std::uint8_t(v >> (8 * i))); };
        auto p64 = [&](std::uint64_t v) { for (int i = 0; i < 8; ++i) mine.push_back(std::uint8_t(v >> (8 * i))); };
        p32(1);
        mine.push_back(0x01);
        for (int i = 0; i < 32; ++i) mine.push_back(0x00);
        p32(0xffffffffu);
        const std::uint8_t ss[] = {0x03, 0xe2, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef};
        mine.push_back(std::uint8_t(sizeof ss));
        mine.insert(mine.end(), ss, ss + sizeof ss);
        p32(0xffffffffu);
        mine.push_back(0x02);
        p64(5000000000ULL);
        const std::uint8_t spk[] = {0x76, 0xa9, 0x14, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                    0x11, 0x11, 0x11, 0x88, 0xac};
        mine.push_back(std::uint8_t(sizeof spk));
        mine.insert(mine.end(), spk, spk + sizeof spk);
        p64(0);
        mine.push_back(0x2a); mine.push_back(0x6a); mine.push_back(0x28);
        mine.insert(mine.end(), ref.data(), ref.data() + 32);
        p64(0x0011223344556677ULL);
        p32(0);

        X11WorkEvent m = e;
        m.coinbase = mine;
        // A HARDER mainchain block target than the grind target, so the ground
        // share clears the SHARE target without also being a solved block —
        // which is what makes the won_block classification below non-vacuous.
        m.nbits = 0x1e00ffffu;
        m.merkle_branch = {b32_from_hex("505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f")};
        m.tag = "rx14";
        m.last_txout_nonce = 0x0011223344556677ULL;
        // Grind a REAL nonce with dash::crypto::hash_x11 to 0x2000ffff (~2^-8, so
        // ~256 expected tries — a genuine ground nonce, cheap enough for the
        // ASan+UBSan leg). Deterministic: the same nonce every run.
        CHK(grind_real_nonce(m), "RX-14 ground a real X11 nonce");
        std::printf("   ground nonce=%u pow=%s\n", m.nonce, x11_pow_hash_u(m).GetHex().c_str());

        // RX-3 / RX-4 analogues on the freshly-mined share.
        CHK(x11_merkle_root_u(m) != x11_coinbase_txid_u(m), "RX-14 a 1-node branch actually folds");
        dash::X11VerifyResult mr = dash::verify_x11_share(to_dash_envelope(m, ref));
        CHK(mr.status == dash::X11VerifyStatus::OK, "RX-14 the freshly-mined share verifies OK");
        CHK(mr.committed_ref_hash == ref, "RX-14 its OP_RETURN commitment is extracted by the vin/vout walk");
        CHK(mr.committed_nonce64 == 0x0011223344556677ULL, "RX-14 ... together with its nonce64");
        CHK(mr.merkle_root == x11_merkle_root_u(m), "RX-14 the verifier rebuilt the same root");
        CHK(!mr.won_block, "RX-14 it clears the SHARE target but not the (harder) block target");
        // the six forgeries again, on a share the KAT produced itself
        {
            const std::uint32_t tight = compact_just_above(mr.pow_hash);
            X11WorkEvent t = m; t.share_bits = tight;
            CHK(dash::verify_x11_share(to_dash_envelope(t, ref)).status == dash::X11VerifyStatus::OK,
                "RX-14/5 honest share OK at the tight target");
            bool rejected = false;
            for (std::uint32_t k = 1; k <= 64 && !rejected; ++k) {
                X11WorkEvent bad = t; bad.nonce = m.nonce ^ k;
                rejected = dash::verify_x11_share(to_dash_envelope(bad, ref)).status
                           == dash::X11VerifyStatus::REJECT_POW;
            }
            CHK(rejected, "RX-14/5 mutated nonce -> REJECT_POW");
            uint256 forged = ref; forged.data()[0] ^= 0x01;
            CHK(dash::verify_x11_share(to_dash_envelope(m, forged)).status
                    == dash::X11VerifyStatus::REJECT_PAYOUT_COMMITMENT, "RX-14/6 forged claim rejected");
            // Destroying the OP_RETURN marker also changes the coinbase txid, hence
            // the merkle root, hence the X11 hash — and verify_x11_share gates PoW
            // BEFORE the commitment. So replace OP_RETURN with OP_TRUE (script
            // LENGTH unchanged, tx still well-formed, commitment gone) and RE-GRIND
            // a real nonce, so the share carries genuine work and the verdict is
            // genuinely the COMMITMENT arm rather than a short-circuit REJECT_POW.
            X11WorkEvent b7 = m;
            for (std::size_t i = 0; i + 1 < b7.coinbase.size(); ++i)
                if (b7.coinbase[i] == 0x6a && b7.coinbase[i + 1] == 0x28) { b7.coinbase[i] = 0x51; break; }
            CHK(grind_real_nonce(b7), "RX-14/7 re-ground a real nonce for the commitment-less coinbase");
            const dash::X11VerifyResult r7 = dash::verify_x11_share(to_dash_envelope(b7, ref));
            CHK(r7.meets_share_target, "RX-14/7 the commitment-less share DOES carry real work (not vacuous)");
            CHK(r7.status == dash::X11VerifyStatus::REJECT_NO_COMMITMENT,
                "RX-14/7 real work but no OP_RETURN commitment -> REJECT_NO_COMMITMENT");
            X11WorkEvent b8 = m; b8.coinbase.resize(6);
            CHK(dash::verify_x11_share(to_dash_envelope(b8, ref)).status
                    == dash::X11VerifyStatus::REJECT_STRUCTURE, "RX-14/8 truncated coinbase rejected");
            X11WorkEvent b9 = m; b9.share_bits = 0;
            CHK(dash::verify_x11_share(to_dash_envelope(b9, ref)).status
                    == dash::X11VerifyStatus::REJECT_SHARE_TARGET, "RX-14/9 null share target rejected");
            X11WorkEvent b10 = m; b10.coinbase[40] ^= 0x01;
            CHK(x11_merkle_root_u(b10) != x11_merkle_root_u(m) &&
                x11_pow_hash_u(b10) != x11_pow_hash_u(m), "RX-14/10 tamper-evident");
        }

        // The W2 credit path over the freshly-mined share (structure only; the
        // S-1 consensus activation is the operator's tap and is NOT wired here).
        struct Idx : IMainchainIndex { std::optional<u64> height_of(const bytes32&) const override { return 243; } };
        struct Trk : IShareTracker {
            bool has_prev_own(const bytes32&, const bytes32&) const override { return true; }
            void record_share(const bytes32&, const bytes32&) override {}
        };
        struct Tgt : IConsensusTargets {
            std::uint32_t nb, sb;
            Tgt(std::uint32_t a, std::uint32_t b) : nb(a), sb(b) {}
            std::optional<std::uint32_t> block_bits_at(u64) const override { return nb; }
            std::optional<std::uint32_t> share_bits_at(u64) const override { return sb; }
        };
        Idx idx; Trk trk; Tgt tgt(m.nbits, m.share_bits);
        X11ReceiptAdmitter adm(1, idx, trk, tgt);
        X11ReceiptAdmitter::Result ar = adm.admit(m, {});
        CHK(ar.carrier_status == CarrierStatus::OK, "RX-14 X11ReceiptAdmitter admits the carrier");
        CHK(ar.pushes.size() == 1 && ar.pushes[0].w_raw == x11_work(m),
            "RX-14 one target-based credit push, w_raw == x11_work(share target)");
    }

    std::printf("v37_a2_x11_real_pow_kat: checks=%u failures=%u\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
