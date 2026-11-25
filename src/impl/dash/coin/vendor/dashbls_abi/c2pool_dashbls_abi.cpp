// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The DLL side of c2pool_dashbls_abi.h. Compiled ONLY by mingw-w64 GCC, in the
// same toolchain and against the same static libdashbls.a / libgmp.a that
// scripts/build_dashbls.sh produces from dash's own src/dashbls subtree, and
// linked into c2pool_dashbls.dll by scripts/build_dashbls_win64.sh. It is never
// part of the MSVC build.
//
// Each export performs exactly one dashbls call on real dashbls objects. The
// only logic here is the boundary itself: catch every C++ exception and turn it
// into C2DBLS_EXCEPTION plus a thread-local message, copy fixed-size encodings
// into caller buffers, and own the heap objects behind the opaque handles.

#ifndef C2DBLS_BUILDING_DLL
#define C2DBLS_BUILDING_DLL 1
#endif
#include "c2pool_dashbls_abi.h"

#include <dashbls/bls.hpp>
#include <dashbls/elements.hpp>
#include <dashbls/privatekey.hpp>
#include <dashbls/schemes.hpp>

#include <cstring>
#include <exception>
#include <string>
#include <vector>

#ifndef C2DBLS_DASH_REF
#error "C2DBLS_DASH_REF must name the dash tag the linked dashbls was built from"
#endif

struct c2dbls_g1 { bls::G1Element v; };
struct c2dbls_g2 { bls::G2Element v; };
struct c2dbls_sk { bls::PrivateKey v; };

namespace {

thread_local std::string g_last_error;

template <typename F>
int guarded(F&& f) noexcept
{
    try {
        return f();
    } catch (const std::exception& e) {
        g_last_error = e.what();
    } catch (...) {
        g_last_error = "unknown exception from dashbls";
    }
    return C2DBLS_EXCEPTION;
}

template <size_t N>
int copy_encoding(const std::vector<uint8_t>& v, uint8_t* out)
{
    if (v.size() != N) {
        g_last_error = "dashbls serialized an element to an unexpected size";
        return C2DBLS_EXCEPTION;
    }
    std::memcpy(out, v.data(), N);
    return C2DBLS_OK;
}

bls::Bytes bytes(const uint8_t* data, size_t len)
{
    return bls::Bytes(data, len);
}

#define C2DBLS_STR2(x) #x
#define C2DBLS_STR(x) C2DBLS_STR2(x)

std::string make_build_info()
{
    std::string s = "dashbls ";
    s += C2DBLS_DASH_REF;
#if defined(ARITH) && defined(GMP) && ARITH == GMP
    s += " ARITH=GMP gmp " C2DBLS_STR(__GNU_MP_VERSION) "." C2DBLS_STR(__GNU_MP_VERSION_MINOR)
         "." C2DBLS_STR(__GNU_MP_VERSION_PATCHLEVEL);
#else
    s += " ARITH=EASY";
#endif
#if defined(__VERSION__)
    s += " gcc ";
    s += __VERSION__;
#endif
    return s;
}

} // namespace

extern "C" {

const char* c2dbls_last_error(void)
{
    return g_last_error.c_str();
}

const char* c2dbls_build_info(void)
{
    static const std::string info = make_build_info();
    return info.c_str();
}

// ── G1Element ────────────────────────────────────────────────────────────────

int c2dbls_g1_new(c2dbls_g1** out)
{
    if (!out) return C2DBLS_BAD_ARG;
    return guarded([&] { *out = new c2dbls_g1{bls::G1Element()}; return C2DBLS_OK; });
}

int c2dbls_g1_copy(const c2dbls_g1* in, c2dbls_g1** out)
{
    if (!in || !out) return C2DBLS_BAD_ARG;
    return guarded([&] { *out = new c2dbls_g1{in->v}; return C2DBLS_OK; });
}

void c2dbls_g1_free(c2dbls_g1* p)
{
    delete p;
}

int c2dbls_g1_from_bytes(const uint8_t* data, size_t len, int legacy, c2dbls_g1** out)
{
    if (!out || (!data && len)) return C2DBLS_BAD_ARG;
    return guarded([&] {
        *out = new c2dbls_g1{bls::G1Element::FromBytes(bytes(data, len), legacy != 0)};
        return C2DBLS_OK;
    });
}

int c2dbls_g1_is_valid(const c2dbls_g1* p, int* out)
{
    if (!p || !out) return C2DBLS_BAD_ARG;
    return guarded([&] { *out = p->v.IsValid() ? 1 : 0; return C2DBLS_OK; });
}

int c2dbls_g1_serialize(const c2dbls_g1* p, int legacy, uint8_t out[C2DBLS_G1_SIZE])
{
    if (!p || !out) return C2DBLS_BAD_ARG;
    return guarded([&] { return copy_encoding<C2DBLS_G1_SIZE>(p->v.Serialize(legacy != 0), out); });
}

int c2dbls_g1_equal(const c2dbls_g1* a, const c2dbls_g1* b, int* out)
{
    if (!a || !b || !out) return C2DBLS_BAD_ARG;
    return guarded([&] { *out = (a->v == b->v) ? 1 : 0; return C2DBLS_OK; });
}

// ── G2Element ────────────────────────────────────────────────────────────────

int c2dbls_g2_new(c2dbls_g2** out)
{
    if (!out) return C2DBLS_BAD_ARG;
    return guarded([&] { *out = new c2dbls_g2{bls::G2Element()}; return C2DBLS_OK; });
}

int c2dbls_g2_copy(const c2dbls_g2* in, c2dbls_g2** out)
{
    if (!in || !out) return C2DBLS_BAD_ARG;
    return guarded([&] { *out = new c2dbls_g2{in->v}; return C2DBLS_OK; });
}

void c2dbls_g2_free(c2dbls_g2* p)
{
    delete p;
}

int c2dbls_g2_from_bytes(const uint8_t* data, size_t len, int legacy, c2dbls_g2** out)
{
    if (!out || (!data && len)) return C2DBLS_BAD_ARG;
    return guarded([&] {
        *out = new c2dbls_g2{bls::G2Element::FromBytes(bytes(data, len), legacy != 0)};
        return C2DBLS_OK;
    });
}

int c2dbls_g2_is_valid(const c2dbls_g2* p, int* out)
{
    if (!p || !out) return C2DBLS_BAD_ARG;
    return guarded([&] { *out = p->v.IsValid() ? 1 : 0; return C2DBLS_OK; });
}

int c2dbls_g2_serialize(const c2dbls_g2* p, int legacy, uint8_t out[C2DBLS_G2_SIZE])
{
    if (!p || !out) return C2DBLS_BAD_ARG;
    return guarded([&] { return copy_encoding<C2DBLS_G2_SIZE>(p->v.Serialize(legacy != 0), out); });
}

int c2dbls_g2_equal(const c2dbls_g2* a, const c2dbls_g2* b, int* out)
{
    if (!a || !b || !out) return C2DBLS_BAD_ARG;
    return guarded([&] { *out = (a->v == b->v) ? 1 : 0; return C2DBLS_OK; });
}

// ── PrivateKey ───────────────────────────────────────────────────────────────

int c2dbls_sk_copy(const c2dbls_sk* in, c2dbls_sk** out)
{
    if (!in || !out) return C2DBLS_BAD_ARG;
    return guarded([&] { *out = new c2dbls_sk{in->v}; return C2DBLS_OK; });
}

void c2dbls_sk_free(c2dbls_sk* p)
{
    delete p;
}

int c2dbls_sk_get_g1(const c2dbls_sk* p, c2dbls_g1** out)
{
    if (!p || !out) return C2DBLS_BAD_ARG;
    return guarded([&] { *out = new c2dbls_g1{p->v.GetG1Element()}; return C2DBLS_OK; });
}

// ── BasicSchemeMPL ───────────────────────────────────────────────────────────

int c2dbls_basic_keygen(const uint8_t* seed, size_t len, c2dbls_sk** out)
{
    if (!out || (!seed && len)) return C2DBLS_BAD_ARG;
    return guarded([&] {
        *out = new c2dbls_sk{bls::BasicSchemeMPL().KeyGen(bytes(seed, len))};
        return C2DBLS_OK;
    });
}

int c2dbls_basic_sign(const c2dbls_sk* sk, const uint8_t* msg, size_t len, c2dbls_g2** out)
{
    if (!sk || !out || (!msg && len)) return C2DBLS_BAD_ARG;
    return guarded([&] {
        *out = new c2dbls_g2{bls::BasicSchemeMPL().Sign(sk->v, bytes(msg, len))};
        return C2DBLS_OK;
    });
}

int c2dbls_basic_verify(const c2dbls_g1* pk, const uint8_t* msg, size_t len,
                        const c2dbls_g2* sig, int* out)
{
    if (!pk || !sig || !out || (!msg && len)) return C2DBLS_BAD_ARG;
    return guarded([&] {
        *out = bls::BasicSchemeMPL().Verify(pk->v, bytes(msg, len), sig->v) ? 1 : 0;
        return C2DBLS_OK;
    });
}

int c2dbls_basic_aggregate_secure(const c2dbls_g1* const* pks, size_t n_pks,
                                  const c2dbls_g2* const* sigs, size_t n_sigs,
                                  const uint8_t* msg, size_t len, c2dbls_g2** out)
{
    if (!out || (!pks && n_pks) || (!sigs && n_sigs) || (!msg && len)) return C2DBLS_BAD_ARG;
    for (size_t i = 0; i < n_pks; ++i) if (!pks[i]) return C2DBLS_BAD_ARG;
    for (size_t i = 0; i < n_sigs; ++i) if (!sigs[i]) return C2DBLS_BAD_ARG;
    return guarded([&] {
        std::vector<bls::G1Element> vpk;
        vpk.reserve(n_pks);
        for (size_t i = 0; i < n_pks; ++i) vpk.push_back(pks[i]->v);
        std::vector<bls::G2Element> vsig;
        vsig.reserve(n_sigs);
        for (size_t i = 0; i < n_sigs; ++i) vsig.push_back(sigs[i]->v);
        *out = new c2dbls_g2{bls::BasicSchemeMPL().AggregateSecure(vpk, vsig, bytes(msg, len))};
        return C2DBLS_OK;
    });
}

int c2dbls_basic_verify_secure(const c2dbls_g1* const* pks, size_t n_pks,
                               const c2dbls_g2* sig, const uint8_t* msg, size_t len, int* out)
{
    if (!sig || !out || (!pks && n_pks) || (!msg && len)) return C2DBLS_BAD_ARG;
    for (size_t i = 0; i < n_pks; ++i) if (!pks[i]) return C2DBLS_BAD_ARG;
    return guarded([&] {
        std::vector<bls::G1Element> vpk;
        vpk.reserve(n_pks);
        for (size_t i = 0; i < n_pks; ++i) vpk.push_back(pks[i]->v);
        *out = bls::BasicSchemeMPL().VerifySecure(vpk, sig->v, bytes(msg, len)) ? 1 : 0;
        return C2DBLS_OK;
    });
}

} // extern "C"
