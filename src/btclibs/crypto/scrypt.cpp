/*
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2012-2013 pooler
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 *
 * Adapted from Litecoin Core to use CSHA256 instead of OpenSSL.
 */

#include <crypto/scrypt.h>
#include <crypto/sha256.h>

#include <cstdlib>
#include <cstdint>
#include <cstring>

// ============================================================================
// HMAC-SHA256 using CSHA256
// ============================================================================

struct HMAC_SHA256_CTX {
    CSHA256 ictx;
    CSHA256 octx;
};

static void
HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx, const void *_K, size_t Klen)
{
    unsigned char pad[64];
    unsigned char khash[32];
    const unsigned char *K = (const unsigned char *)_K;
    size_t i;

    if (Klen > 64) {
        CSHA256().Write(K, Klen).Finalize(khash);
        K = khash;
        Klen = 32;
    }

    ctx->ictx.Reset();
    memset(pad, 0x36, 64);
    for (i = 0; i < Klen; i++)
        pad[i] ^= K[i];
    ctx->ictx.Write(pad, 64);

    ctx->octx.Reset();
    memset(pad, 0x5c, 64);
    for (i = 0; i < Klen; i++)
        pad[i] ^= K[i];
    ctx->octx.Write(pad, 64);

    memset(khash, 0, 32);
}

static void
HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx, const void *in, size_t len)
{
    ctx->ictx.Write((const unsigned char *)in, len);
}

static void
HMAC_SHA256_Final(unsigned char digest[32], HMAC_SHA256_CTX *ctx)
{
    unsigned char ihash[32];
    ctx->ictx.Finalize(ihash);
    ctx->octx.Write(ihash, 32);
    ctx->octx.Finalize(digest);
    memset(ihash, 0, 32);
}

// ============================================================================
// PBKDF2-SHA256
// ============================================================================

void
PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen, const uint8_t *salt,
    size_t saltlen, uint64_t c, uint8_t *buf, size_t dkLen)
{
    HMAC_SHA256_CTX PShctx, hctx;
    size_t i;
    uint8_t ivec[4];
    uint8_t U[32] = {};
    uint8_t T[32] = {};
    uint64_t j;
    int k;
    size_t clen;

    HMAC_SHA256_Init(&PShctx, passwd, passwdlen);
    HMAC_SHA256_Update(&PShctx, salt, saltlen);

    for (i = 0; i * 32 < dkLen; i++) {
        be32enc(ivec, (uint32_t)(i + 1));

        memcpy(&hctx, &PShctx, sizeof(HMAC_SHA256_CTX));
        HMAC_SHA256_Update(&hctx, ivec, 4);
        HMAC_SHA256_Final(U, &hctx);

        memcpy(T, U, 32);

        for (j = 2; j <= c; j++) {
            HMAC_SHA256_Init(&hctx, passwd, passwdlen);
            HMAC_SHA256_Update(&hctx, U, 32);
            HMAC_SHA256_Final(U, &hctx);

            for (k = 0; k < 32; k++)
                T[k] ^= U[k];
        }

        clen = dkLen - i * 32;
        if (clen > 32)
            clen = 32;
        memcpy(&buf[i * 32], T, clen);
    }

    memset(&PShctx, 0, sizeof(HMAC_SHA256_CTX));
}

// ============================================================================
// Salsa20/8 core
// ============================================================================

#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

static inline void xor_salsa8(uint32_t B[16], const uint32_t Bx[16])
{
    uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
    int i;

    x00 = (B[ 0] ^= Bx[ 0]);
    x01 = (B[ 1] ^= Bx[ 1]);
    x02 = (B[ 2] ^= Bx[ 2]);
    x03 = (B[ 3] ^= Bx[ 3]);
    x04 = (B[ 4] ^= Bx[ 4]);
    x05 = (B[ 5] ^= Bx[ 5]);
    x06 = (B[ 6] ^= Bx[ 6]);
    x07 = (B[ 7] ^= Bx[ 7]);
    x08 = (B[ 8] ^= Bx[ 8]);
    x09 = (B[ 9] ^= Bx[ 9]);
    x10 = (B[10] ^= Bx[10]);
    x11 = (B[11] ^= Bx[11]);
    x12 = (B[12] ^= Bx[12]);
    x13 = (B[13] ^= Bx[13]);
    x14 = (B[14] ^= Bx[14]);
    x15 = (B[15] ^= Bx[15]);
    for (i = 0; i < 8; i += 2) {
        /* Operate on columns. */
        x04 ^= ROTL(x00 + x12,  7);  x09 ^= ROTL(x05 + x01,  7);
        x14 ^= ROTL(x10 + x06,  7);  x03 ^= ROTL(x15 + x11,  7);

        x08 ^= ROTL(x04 + x00,  9);  x13 ^= ROTL(x09 + x05,  9);
        x02 ^= ROTL(x14 + x10,  9);  x07 ^= ROTL(x03 + x15,  9);

        x12 ^= ROTL(x08 + x04, 13);  x01 ^= ROTL(x13 + x09, 13);
        x06 ^= ROTL(x02 + x14, 13);  x11 ^= ROTL(x07 + x03, 13);

        x00 ^= ROTL(x12 + x08, 18);  x05 ^= ROTL(x01 + x13, 18);
        x10 ^= ROTL(x06 + x02, 18);  x15 ^= ROTL(x11 + x07, 18);

        /* Operate on rows. */
        x01 ^= ROTL(x00 + x03,  7);  x06 ^= ROTL(x05 + x04,  7);
        x11 ^= ROTL(x10 + x09,  7);  x12 ^= ROTL(x15 + x14,  7);

        x02 ^= ROTL(x01 + x00,  9);  x07 ^= ROTL(x06 + x05,  9);
        x08 ^= ROTL(x11 + x10,  9);  x13 ^= ROTL(x12 + x15,  9);

        x03 ^= ROTL(x02 + x01, 13);  x04 ^= ROTL(x07 + x06, 13);
        x09 ^= ROTL(x08 + x11, 13);  x14 ^= ROTL(x13 + x12, 13);

        x00 ^= ROTL(x03 + x02, 18);  x05 ^= ROTL(x04 + x07, 18);
        x10 ^= ROTL(x09 + x08, 18);  x15 ^= ROTL(x14 + x13, 18);
    }
    B[ 0] += x00;
    B[ 1] += x01;
    B[ 2] += x02;
    B[ 3] += x03;
    B[ 4] += x04;
    B[ 5] += x05;
    B[ 6] += x06;
    B[ 7] += x07;
    B[ 8] += x08;
    B[ 9] += x09;
    B[10] += x10;
    B[11] += x11;
    B[12] += x12;
    B[13] += x13;
    B[14] += x14;
    B[15] += x15;
}

// ============================================================================
// scrypt ROMix (N=1024, r=1, p=1)
// ============================================================================

void
scrypt_1024_1_1_256_sp(const char *input, char *output, char *scratchpad)
{
    uint8_t B[128];
    uint32_t X[32];
    uint32_t *V;
    uint32_t i, j, k;

    V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~(uintptr_t)(63));

    PBKDF2_SHA256((const uint8_t *)input, 80, (const uint8_t *)input, 80, 1, B, 128);

    for (k = 0; k < 32; k++)
        X[k] = le32dec(&B[4 * k]);

    for (i = 0; i < 1024; i++) {
        memcpy(&V[i * 32], X, 128);
        xor_salsa8(&X[0], &X[16]);
        xor_salsa8(&X[16], &X[0]);
    }
    for (i = 0; i < 1024; i++) {
        j = 32 * (X[16] & 1023);
        for (k = 0; k < 32; k++)
            X[k] ^= V[j + k];
        xor_salsa8(&X[0], &X[16]);
        xor_salsa8(&X[16], &X[0]);
    }

    for (k = 0; k < 32; k++)
        le32enc(&B[4 * k], X[k]);

    PBKDF2_SHA256((const uint8_t *)input, 80, B, 128, 1, (uint8_t *)output, 32);
}

void scrypt_1024_1_1_256(const char *input, char *output)
{
    char scratchpad[SCRYPT_SCRATCHPAD_SIZE];
    scrypt_1024_1_1_256_sp(input, output, scratchpad);
}
