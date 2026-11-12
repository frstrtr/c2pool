/* SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Plain-C self-test of c2pool_dashbls.dll, run by scripts/build_dashbls_win64.sh
 * right after the DLL is linked and before it is installed into the prefix.
 * It goes through the C ABI only (no C++ on this side), so it also proves the
 * exports are usable from a foreign toolchain.
 *
 * Vector: the real testnet llmq_50_60 final commitment at block 1519931, the
 * same one test/test_dash_bls_verify.cpp anchors on. MSG is its
 * BuildCommitmentHash (SHA256d of the commitment preimage), signed by the
 * quorum key.
 */
#include "c2pool_dashbls_abi.h"

#include <stdio.h>
#include <string.h>

static const char* PK_HEX =
    "a51db3577089e74a6aa0b3ed0e8b8697e56f43b330be3c34e88fe7d4d1e3889e"
    "781fea3c5aa385edcbca6540ddd49fa1";
static const char* SIG_HEX =
    "93a37bd57ef329e8953deb448a0348124cafa52df0e5b7ca1076fc57e9a801ae"
    "fd445c259b1a65e43472959a3b16e3f901aa42b7e830706b5525841e3c7b388b"
    "94be4a72da1776f52b1f90e73d8dff21831fc90332634c88311b7f7ac6aa166b";
static const char* MSG_HEX =
    "fda5e2b76b8d83aa328b694b0f827b0d589babb656d81fb8b92f3b193ed86594";

static void unhex(const char* s, uint8_t* out, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) {
        unsigned v = 0;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static int fails = 0;

static void expect(int cond, const char* what)
{
    printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
    if (!cond) ++fails;
}

int main(void)
{
    uint8_t pk[C2DBLS_G1_SIZE], sig[C2DBLS_G2_SIZE], msg[32], ser[C2DBLS_G1_SIZE];
    c2dbls_g1* g1 = NULL;
    c2dbls_g2* g2 = NULL;
    c2dbls_g2* g2bad = NULL;
    c2dbls_sk* sk = NULL;
    c2dbls_g1* own_pk = NULL;
    c2dbls_g2* own_sig = NULL;
    int r = -1;
    uint8_t seed[32];

    printf("c2pool_dashbls self-test: %s\n", c2dbls_build_info());
    unhex(PK_HEX, pk, sizeof pk);
    unhex(SIG_HEX, sig, sizeof sig);
    unhex(MSG_HEX, msg, sizeof msg);

    expect(c2dbls_g1_from_bytes(pk, sizeof pk, 0, &g1) == C2DBLS_OK, "quorum public key decodes (basic)");
    expect(c2dbls_g2_from_bytes(sig, sizeof sig, 0, &g2) == C2DBLS_OK, "quorum signature decodes (basic)");
    if (!g1 || !g2) return 1;

    expect(c2dbls_basic_verify(g1, msg, sizeof msg, g2, &r) == C2DBLS_OK && r == 1,
           "real quorum signature verifies over the commitment hash");
    msg[7] ^= 1;
    expect(c2dbls_basic_verify(g1, msg, sizeof msg, g2, &r) == C2DBLS_OK && r == 0,
           "one flipped message bit is rejected");
    msg[7] ^= 1;
    sig[95] ^= 1;
    expect(c2dbls_g2_from_bytes(sig, sizeof sig, 0, &g2bad) == C2DBLS_EXCEPTION && g2bad == NULL,
           "a corrupted signature is refused at decode");
    expect(strlen(c2dbls_last_error()) > 0, "the refusal carries the dashbls message");
    sig[95] ^= 1;
    expect(c2dbls_g1_serialize(g1, 0, ser) == C2DBLS_OK && memcmp(ser, pk, sizeof pk) == 0,
           "public key re-serializes to its wire bytes");

    memset(seed, 0x11, sizeof seed);
    expect(c2dbls_basic_keygen(seed, sizeof seed, &sk) == C2DBLS_OK, "keygen");
    expect(sk && c2dbls_sk_get_g1(sk, &own_pk) == C2DBLS_OK, "public key from secret key");
    expect(sk && c2dbls_basic_sign(sk, msg, sizeof msg, &own_sig) == C2DBLS_OK, "sign");
    expect(own_pk && own_sig && c2dbls_basic_verify(own_pk, msg, sizeof msg, own_sig, &r) == C2DBLS_OK && r == 1,
           "own signature verifies");
    expect(own_sig && c2dbls_basic_verify(g1, msg, sizeof msg, own_sig, &r) == C2DBLS_OK && r == 0,
           "own signature does not verify under the quorum key");

    c2dbls_g2_free(own_sig);
    c2dbls_g1_free(own_pk);
    c2dbls_sk_free(sk);
    c2dbls_g2_free(g2);
    c2dbls_g1_free(g1);

    printf("c2pool_dashbls self-test: %s\n", fails ? "FAILED" : "PASS");
    return fails ? 1 : 0;
}
