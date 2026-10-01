/*
 * v37_descriptor_xmr_test.cpp — unit test for the XMR PayoutDescriptor kinds.
 *
 * This file is part of c2pool (frstrtr/c2pool).
 * Copyright (c) 2026 The c2pool developers.
 * AGPL-3.0-or-later. See <https://www.gnu.org/licenses/>.
 *
 * Exercises the SHA-256 identity_key KATs (no crypto backend needed) and the
 * structural / fail-closed / backend-gated validity paths. The torsion vectors
 * are checked against a TEST stub here; the real backend
 * (xmr_point_check_ref10.cpp) is validated in the lane build that links Monero
 * crypto.
 */

#include <cstdio>
#include <cstring>

#include "v37_descriptor_xmr.hpp"

using namespace v37;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// A TEST-ONLY point predicate: rejects only the all-known small-order/identity
// vector, accepts anything else. It is NOT a real torsion check — it stands in
// for the crypto backend so the validity plumbing can be exercised in a
// header-only build.
static bool test_point_stub(const std::uint8_t* pt) {
    return std::memcmp(pt, xmr::kat::TORSION_FAIL_IDENTITY.data(), 32) != 0;
}

int main() {
    // (1) identity_key goldens — must hold with NO backend installed.
    CHECK(xmr::kat::check_identity_kats());

    // Spot-check the canon serialization width: XMR_STD preimage is
    // VERSION(1) + kind(1) + len(1) + payload(64) = 67 bytes.
    {
        auto B = xmr::kat::STD_KAT.p0;
        auto A = xmr::kat::STD_KAT.p1;
        ScriptRef pay = xmr::make_xmr_std(B, A);
        CHECK(pay.kind == xmr::XMR_STD);
        CHECK(pay.payload.size() == xmr::XMR_PAYLOAD_LEN);
        PayoutDescriptor d; d.pay = pay;
        CHECK(d.identity_preimage().size() == 67);
        CHECK(d.identity_key() == xmr::kat::STD_KAT.expected_identity_key);
    }

    // (2) table rows.
    CHECK(xmr::xmr_size(xmr::XMR_STD) == 42);
    CHECK(xmr::xmr_size(xmr::XMR_SUB) == 42);
    CHECK(xmr::xmr_dust(xmr::XMR_STD) == 0);

    // (3) FCMP++/CARROT fence.
    CHECK(xmr::xmr_precarrot_ok(16));
    CHECK(!xmr::xmr_precarrot_ok(17));

    // (4) fail-closed: with no backend installed, a structurally well-formed
    //     XMR ref is NOT valid (torsion check cannot pass).
    {
        ScriptRef pay = xmr::make_xmr_std(xmr::kat::STD_KAT.p0, xmr::kat::STD_KAT.p1);
        CHECK(xmr::xmr_ref_well_formed(pay));      // structural: ok
        CHECK(!xmr::xmr_ref_valid(pay));           // no backend => invalid
    }

    // (5) install a test stub, then the validity + torsion plumbing works.
    xmr::set_point_check_backend(&test_point_stub);
    {
        ScriptRef pay = xmr::make_xmr_std(xmr::kat::STD_KAT.p0, xmr::kat::STD_KAT.p1);
        CHECK(xmr::xmr_ref_valid(pay));
        PayoutDescriptor d; d.pay = pay;
        CHECK(xmr::xmr_descriptor_valid(d));
        // wrong payload width rejected
        ScriptRef bad = pay; bad.payload.pop_back();
        CHECK(!xmr::xmr_ref_well_formed(bad));
        // XMR pay must carry no raw_script
        PayoutDescriptor draw = d; draw.raw_script = {0x00};
        CHECK(!xmr::xmr_descriptor_valid(draw));
        // torsion spec vectors against the stub
        CHECK(xmr::kat::check_torsion_kats());
    }

    // (6) XMR kind as an aux settlement target on a Bitcoin-identity miner.
    {
        ScriptRef btc; btc.kind = ScriptKind::P2WPKH; btc.payload.assign(20, 0x11);
        PayoutDescriptor d; d.pay = btc;
        AuxEntry ax; ax.chain_id = 0xC0FFEE;
        ax.ref = xmr::make_xmr_std(xmr::kat::STD_KAT.p0, xmr::kat::STD_KAT.p1);
        d.aux.push_back(ax);
        CHECK(xmr::xmr_descriptor_valid(d));       // BTC pay + XMR aux settles
    }

    if (g_fail == 0) std::printf("ALL XMR DESCRIPTOR KATS/CHECKS GREEN\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    // (A2) composite give_author lane identity (kind 0x1F)
    {
        set_xmr_descriptor_validator(&xmr::xmr_descriptor_valid);
        xmr::set_point_check_backend(&test_point_stub);
        const ScriptRef payee = xmr::make_xmr_std(xmr::kat::STD_KAT.p0, xmr::kat::STD_KAT.p1);
        const ScriptRef donat = xmr::make_xmr_std(xmr::kat::STD_KAT.p1, xmr::kat::STD_KAT.p0);
        const ScriptRef ga = xmr::make_xmr_give_author(655, payee, donat);
        CHECK(ga.kind == xmr::XMR_LANE_GA && ga.payload.size() == xmr::XMR_GA_PAYLOAD_LEN);
        xmr::XmrGiveAuthor g;
        CHECK(xmr::decode_xmr_give_author(ga, g) && g.d == 655 && g.payee == payee && g.donation == donat);
        CHECK(xmr::xmr_ga_well_formed(ga) && xmr::xmr_ga_valid(ga));
        PayoutDescriptor d; d.pay = ga;
        CHECK(d.valid());                                           // dispatches to the XMR validator
        CHECK(d.identity_preimage().size() == 1 + 1 + 1 + 132);     // u8 length field holds 132
        // refusals: d out of range, payee == donation, torsion-failing half, bad length
        CHECK(!xmr::xmr_ga_valid(xmr::make_xmr_give_author(0, payee, donat)));
        CHECK(!xmr::xmr_ga_valid(xmr::make_xmr_give_author(65535, payee, donat)));
        CHECK(xmr::xmr_ga_valid(xmr::make_xmr_give_author(1, payee, donat)) && xmr::xmr_ga_valid(xmr::make_xmr_give_author(65534, payee, donat)));
        CHECK(!xmr::xmr_ga_valid(xmr::make_xmr_give_author(655, payee, payee)));
        ScriptRef bad = xmr::make_xmr_std(xmr::kat::TORSION_FAIL_IDENTITY, xmr::kat::STD_KAT.p1);
        CHECK(!xmr::xmr_ga_valid(xmr::make_xmr_give_author(655, bad, donat)));
        ScriptRef shortp = ga; shortp.payload.pop_back();
        CHECK(!xmr::decode_xmr_give_author(shortp, g));
        // never an attribution or aux target; refused BEFORE delegating (no recursion)
        PayoutDescriptor at; at.pay = payee; at.attribution = ga;
        CHECK(!at.valid(true));
        PayoutDescriptor ax; ax.pay = payee; ax.aux.push_back(AuxEntry{1, ga});
        CHECK(!ax.valid());
        PayoutDescriptor gx; gx.pay = ga; gx.aux.push_back(AuxEntry{1, payee});
        CHECK(!gx.valid());
        // the split: donation = floor(W*d/65535), payee = W - donation, exact at 2^255
        auto s1 = xmr::xmr_ga_split(U256::from_u128(65535), 655);
        CHECK(s1.donation.v[0] == 655 && s1.payee.v[0] == 64880);
        auto s2 = xmr::xmr_ga_split(U256::from_u128(1), 65534);
        CHECK(s2.donation.is_zero() && s2.payee.v[0] == 1);           // floor: the payee keeps the remainder
        U256 big; big.v[3] = 0x8000000000000000ull;                    // 2^255
        auto s3 = xmr::xmr_ga_split(big, 65534);
        CHECK(s3.payee + s3.donation == big && s3.donation < big);
        xmr::set_point_check_backend(nullptr);
    }
    std::printf("%s\n", g_fail ? "FAIL" : "OK");
    return g_fail ? 1 : 0;
}
