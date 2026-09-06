/*
 * v37_xmr_canon_p1_kat.cpp — P-1 canon-activation KAT for the XMR (Family B)
 * PayoutDescriptor kinds (0x10 XMR_STD / 0x11 XMR_SUB).
 *
 * This file is part of c2pool (frstrtr/c2pool).
 * Copyright (c) 2026 The c2pool developers.
 * AGPL-3.0-or-later. See <https://www.gnu.org/licenses/>.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS PROVES
 *
 *   P-1 wires the ratified PayoutDescriptor canon (v37_descriptor.hpp) to
 *   RECOGNIZE the two reserved XMR kind bytes: PayoutDescriptor::valid() now
 *   dispatches an XMR-carrying descriptor to the isolated XMR validator
 *   (v37_descriptor_xmr.hpp: is_xmr_kind + xmr_ref_valid) instead of rejecting
 *   it as an unknown kind. This KAT is stdlib-only (no Monero crypto backend):
 *   it installs a TEST point-check stub + the canon validator hook, exactly the
 *   way the ref10 backend TU installs the real ones.
 *
 *   ★ PRIME SAFETY INVARIANT — non-XMR byte-identity. The change is ADD-ONLY:
 *     for any descriptor that carries NO XMR kind, validity AND every consensus
 *     digest (identity_key / canonical_bytes) are BYTE-IDENTICAL to master. This
 *     KAT proves it two ways:
 *       (i)  a fixed non-XMR corpus is fingerprinted (sha256d over each row's
 *            valid(false)/valid(true)/identity_key/canonical_bytes) and asserted
 *            equal to MASTER_NONXMR_FINGERPRINT — a golden computed by compiling
 *            THIS SAME FILE with -DV37_P1_NONXMR_ONLY against a pristine master
 *            checkout of the canon header (see the CI/PR proof);
 *       (ii) the fingerprint is recomputed AFTER installing the XMR validator
 *            and asserted unchanged — the hook never perturbs the non-XMR path.
 *
 *   Compiled with -DV37_P1_NONXMR_ONLY the file reduces to a corpus-fingerprint
 *   dumper that touches ONLY canon symbols (ScriptRef / PayoutDescriptor /
 *   canonicalize_script / sha256d), so it compiles against the master canon
 *   header unchanged and prints the very fingerprint embedded below. That is how
 *   the golden is derived, and re-deriving it against master vs this branch is
 *   the byte-identity diff.
 * ---------------------------------------------------------------------------
 */

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "v37_descriptor.hpp"   // the ratified canon (both build modes)

using namespace v37;

// --- fixed non-XMR corpus (canon symbols ONLY; compiles vs master too) ------
static std::vector<PayoutDescriptor> nonxmr_corpus() {
    std::vector<PayoutDescriptor> v;
    auto mkref = [](ScriptKind k, std::uint8_t fill, std::size_t n) {
        ScriptRef r; r.kind = k; r.payload.assign(n, fill); return r;
    };
    // Template kinds at their canonical widths (valid) across several fills.
    for (std::uint8_t f : {std::uint8_t(0x00), std::uint8_t(0x7f),
                           std::uint8_t(0xab), std::uint8_t(0xff)}) {
        { PayoutDescriptor d; d.pay = mkref(ScriptKind::P2PKH,  f, 20); v.push_back(d); }
        { PayoutDescriptor d; d.pay = mkref(ScriptKind::P2SH,   f, 20); v.push_back(d); }
        { PayoutDescriptor d; d.pay = mkref(ScriptKind::P2WPKH, f, 20); v.push_back(d); }
        { PayoutDescriptor d; d.pay = mkref(ScriptKind::P2WSH,  f, 32); v.push_back(d); }
        { PayoutDescriptor d; d.pay = mkref(ScriptKind::P2TR,   f, 32); v.push_back(d); }
    }
    // RAW with a binding raw_script (an exotic OP_RETURN script): valid.
    const std::vector<std::uint8_t> exotic = {0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef};
    { PayoutDescriptor d; d.pay = canonicalize_script(exotic); d.raw_script = exotic; v.push_back(d); }
    // RAW with a NON-binding raw_script: invalid.
    { PayoutDescriptor d; d.pay = canonicalize_script(exotic); d.raw_script = {0x00}; v.push_back(d); }
    // RAW with an empty raw_script: invalid.
    { PayoutDescriptor d; d.pay = canonicalize_script(exotic); v.push_back(d); }
    // Template kind with the WRONG payload width: invalid.
    { PayoutDescriptor d; d.pay = mkref(ScriptKind::P2PKH, 0x22, 32); v.push_back(d); }
    // Template kind that carries a raw_script (meaningless): invalid.
    { PayoutDescriptor d; d.pay = mkref(ScriptKind::P2TR, 0x33, 32); d.raw_script = {0x01, 0x02}; v.push_back(d); }
    // An UNKNOWN non-XMR kind byte (0x09): invalid, and NOT an XMR kind.
    { PayoutDescriptor d; ScriptRef r; r.kind = static_cast<ScriptKind>(0x09);
      r.payload.assign(20, 0x44); d.pay = r; v.push_back(d); }
    // attribution present (invalid under allow=false, valid under allow=true).
    { PayoutDescriptor d; d.pay = mkref(ScriptKind::P2PKH, 0x55, 20);
      d.attribution = mkref(ScriptKind::P2SH, 0x66, 20); v.push_back(d); }
    // aux sorted + unique: valid.
    { PayoutDescriptor d; d.pay = mkref(ScriptKind::P2WPKH, 0x77, 20);
      AuxEntry a1; a1.chain_id = 1; a1.ref = mkref(ScriptKind::P2PKH, 0x01, 20);
      AuxEntry a2; a2.chain_id = 5; a2.ref = mkref(ScriptKind::P2TR,  0x02, 32);
      d.aux = {a1, a2}; v.push_back(d); }
    // aux duplicate chain_id (unsorted rule): invalid.
    { PayoutDescriptor d; d.pay = mkref(ScriptKind::P2WPKH, 0x77, 20);
      AuxEntry a1; a1.chain_id = 5; a1.ref = mkref(ScriptKind::P2PKH, 0x01, 20);
      AuxEntry a2; a2.chain_id = 5; a2.ref = mkref(ScriptKind::P2TR,  0x02, 32);
      d.aux = {a1, a2}; v.push_back(d); }
    return v;
}

// Deterministic fingerprint over the corpus's validity + digest outputs. Uses
// only canon operations, so master and this branch MUST agree byte-for-byte.
static bytes32 corpus_fingerprint() {
    std::vector<std::uint8_t> acc;
    for (const auto& d : nonxmr_corpus()) {
        acc.push_back(d.valid(false) ? 1 : 0);
        acc.push_back(d.valid(true)  ? 1 : 0);
        auto ik = d.identity_key();
        acc.insert(acc.end(), ik.begin(), ik.end());
        auto cb = d.canonical_bytes();
        std::uint32_t n = static_cast<std::uint32_t>(cb.size());
        for (int i = 0; i < 4; ++i) acc.push_back(static_cast<std::uint8_t>(n >> (8 * i)));
        acc.insert(acc.end(), cb.begin(), cb.end());
    }
    return sha256d(acc);
}

static std::string hex(const bytes32& b) {
    static const char* H = "0123456789abcdef";
    std::string s; s.reserve(64);
    for (auto x : b) { s.push_back(H[x >> 4]); s.push_back(H[x & 0xf]); }
    return s;
}

#ifdef V37_P1_NONXMR_ONLY
// Master-vs-branch byte-identity harness: print the non-XMR corpus fingerprint
// and exit. Compiles against the master canon header unchanged (no XMR / hook
// symbols referenced here).
int main() {
    std::printf("%s\n", hex(corpus_fingerprint()).c_str());
    return 0;
}
#else

#include "v37_descriptor_xmr.hpp"   // the isolated XMR extension (branch-only)

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// GOLDEN: the non-XMR corpus fingerprint computed by compiling THIS file with
// -DV37_P1_NONXMR_ONLY against a PRISTINE master checkout of v37_descriptor.hpp.
// If the P-1 canon edit ever perturbs a non-XMR validity or digest, the branch
// fingerprint diverges from this and the KAT REDs. (Regeneration: see header.)
static const char* MASTER_NONXMR_FINGERPRINT =
    "540f7afac2302be26d84670aa7b7beabaa628884ceba1fe97ecfbb8897893dce";

// TEST-ONLY point predicate: rejects exactly the known small-order/identity
// vector, accepts everything else. Stands in for the crypto backend so the
// dispatch plumbing runs in a header-only build (mirrors v37_descriptor_xmr_test).
static bool test_point_stub(const std::uint8_t* pt) {
    return std::memcmp(pt, xmr::kat::TORSION_FAIL_IDENTITY.data(), 32) != 0;
}

int main() {
    // (0) reserved kind bytes are EXACTLY 0x10 / 0x11 and payload width 64 —
    //     P-1 must not move them.
    static_assert(static_cast<std::uint8_t>(xmr::XMR_STD) == 0x10, "XMR_STD kind byte moved");
    static_assert(static_cast<std::uint8_t>(xmr::XMR_SUB) == 0x11, "XMR_SUB kind byte moved");
    static_assert(xmr::XMR_PAYLOAD_LEN == 64, "XMR payload width moved");
    CHECK(is_xmr_dispatch_kind(xmr::XMR_STD));
    CHECK(is_xmr_dispatch_kind(xmr::XMR_SUB));
    CHECK(!is_xmr_dispatch_kind(ScriptKind::P2PKH));
    CHECK(!is_xmr_dispatch_kind(ScriptKind::RAW));
    CHECK(!is_xmr_dispatch_kind(static_cast<ScriptKind>(0x0f)));
    CHECK(!is_xmr_dispatch_kind(static_cast<ScriptKind>(0x12)));

    // (1) XMR identity_key goldens hold (SHA-256 only; sanity that the extension
    //     header is intact and the digest path serializes 64-byte payloads).
    CHECK(xmr::kat::check_identity_kats());

    // (2) ★ non-XMR byte-identity vs master, BEFORE any validator is installed.
    const bytes32 fp_before = corpus_fingerprint();
    CHECK(hex(fp_before) == std::string(MASTER_NONXMR_FINGERPRINT));

    // Build a well-formed XMR_STD descriptor from the real KAT points.
    ScriptRef xpay = xmr::make_xmr_std(xmr::kat::STD_KAT.p0, xmr::kat::STD_KAT.p1);
    PayoutDescriptor dstd; dstd.pay = xpay;

    // (3) FAIL-CLOSED: with NO validator installed the canon's own valid()
    //     rejects the XMR descriptor exactly as the pre-P-1 unknown-kind path.
    CHECK(xmr_descriptor_validator() == nullptr);
    CHECK(!dstd.valid(false));
    CHECK(!dstd.valid(true));

    // (4) Install the point-check stub + the canon dispatch validator (the same
    //     hook the ref10 backend TU installs in production).
    xmr::set_point_check_backend(&test_point_stub);
    set_xmr_descriptor_validator(&xmr::xmr_descriptor_valid);
    CHECK(xmr_descriptor_validator() != nullptr);

    // (5) ★ ACTIVATION: the canon's PayoutDescriptor::valid() now ACCEPTS a
    //     well-formed XMR descriptor (0x10) — previously rejected as unknown.
    CHECK(dstd.valid(false));
    {   // XMR_SUB (0x11) likewise.
        ScriptRef sub = xmr::make_xmr_sub(xmr::kat::SUB_KAT.p0, xmr::kat::SUB_KAT.p1);
        PayoutDescriptor d; d.pay = sub;
        CHECK(d.valid(false));
        CHECK(d.identity_key() == xmr::kat::SUB_KAT.expected_identity_key);
    }
    CHECK(dstd.identity_key() == xmr::kat::STD_KAT.expected_identity_key);

    // (6) MALFORMED XMR rejected by the canon dispatch:
    {   // wrong payload width (63 bytes)
        PayoutDescriptor d; d.pay = xpay; d.pay.payload.pop_back();
        CHECK(!d.valid(false));
    }
    {   // a torsion/identity point in the spend half => stub rejects => invalid
        PayoutDescriptor d; d.pay = xpay;
        std::memcpy(d.pay.payload.data(), xmr::kat::TORSION_FAIL_IDENTITY.data(), 32);
        CHECK(!d.valid(false));
    }
    {   // XMR pay must carry no raw_script
        PayoutDescriptor d; d.pay = xpay; d.raw_script = {0x00};
        CHECK(!d.valid(false));
    }

    // (7) XMR kind as an aux settlement target on a Bitcoin-identity miner: the
    //     canon dispatch validates it (canon alone would reject the aux kind).
    {
        ScriptRef btc; btc.kind = ScriptKind::P2WPKH; btc.payload.assign(20, 0x11);
        PayoutDescriptor d; d.pay = btc;
        AuxEntry ax; ax.chain_id = 0xC0FFEE;
        ax.ref = xmr::make_xmr_std(xmr::kat::STD_KAT.p0, xmr::kat::STD_KAT.p1);
        d.aux.push_back(ax);
        CHECK(d.valid(false));
        // ...and the same shape with a torsion-bad aux point is rejected.
        PayoutDescriptor bad = d;
        std::memcpy(bad.aux[0].ref.payload.data(), xmr::kat::TORSION_FAIL_IDENTITY.data(), 32);
        CHECK(!bad.valid(false));
    }

    // (8) ★ the XMR validator hook did NOT perturb the non-XMR path: recompute
    //     the corpus fingerprint AFTER install — still byte-identical to master.
    const bytes32 fp_after = corpus_fingerprint();
    CHECK(hex(fp_after) == std::string(MASTER_NONXMR_FINGERPRINT));
    CHECK(fp_before == fp_after);

    if (g_fail == 0)
        std::printf("ALL P-1 XMR CANON-ACTIVATION KATS GREEN "
                    "(non-XMR fingerprint %s == master)\n", hex(fp_after).c_str());
    else
        std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
#endif
