// SPDX-License-Identifier: AGPL-3.0-or-later
//
// C ABI over dashbls for the Windows (MSVC) build of c2pool-dash.
//
// WHY THIS EXISTS. dashd builds its BLS library (src/dashbls: bls-signatures +
// relic + mimalloc) with autotools and GCC, and its Windows release does the
// same with mingw-w64 against a static GMP (ARITH=GMP, MULTI=PTHREAD). c2pool
// builds for Windows with MSVC. The dashbls C++ API cannot cross that compiler
// boundary (different C++ ABI, different standard library), and building the
// subtree with MSVC would not be dashd's configuration: relic's 64-bit word
// type needs __int128, there are no pthreads for MULTI=PTHREAD, and there is no
// autotools-generated relic_conf.h for MSVC.
//
// So on Windows the library is built exactly as dashd's Windows release builds
// it (scripts/build_dashbls.sh under MSYS2 MINGW64, same pinned dash tag), and
// linked together with c2pool_dashbls_abi.cpp into ONE self-contained DLL,
// c2pool_dashbls.dll. This header is the only thing that crosses the
// boundary: plain C types, opaque handles that the DLL allocates and frees,
// and an int status. No C++ object, exception or CRT resource ever crosses.
//
// Every function is a 1:1 forwarder to ONE dashbls call on real dashbls
// objects that live inside the DLL; the handles are those objects. The
// MSVC-side facade (facade/dashbls/*.hpp) wraps the handles back into the
// dashbls class names, so bls_verify.{hpp,cpp} and the BLS KATs compile
// unchanged on every platform.
//
// Status: C2DBLS_OK on success. C2DBLS_EXCEPTION when dashbls threw: the
// facade rethrows it as std::runtime_error carrying c2dbls_last_error(), so a
// caller's try/catch sees the same control flow as with the native library.
// C2DBLS_BAD_ARG on a null handle or output pointer.

#ifndef C2POOL_DASHBLS_ABI_H
#define C2POOL_DASHBLS_ABI_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#  if defined(C2DBLS_BUILDING_DLL)
#    define C2DBLS_API __declspec(dllexport)
#  else
#    define C2DBLS_API __declspec(dllimport)
#  endif
#elif defined(C2DBLS_BUILDING_DLL)
   /* Non-Windows builds of the shim exist only to cross-check it against the
    * native library; export just the C ABI from such a shared object. */
#  define C2DBLS_API __attribute__((visibility("default")))
#else
#  define C2DBLS_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define C2DBLS_OK        0
#define C2DBLS_EXCEPTION 1
#define C2DBLS_BAD_ARG   2

#define C2DBLS_G1_SIZE 48
#define C2DBLS_G2_SIZE 96

typedef struct c2dbls_g1 c2dbls_g1;   /* bls::G1Element  */
typedef struct c2dbls_g2 c2dbls_g2;   /* bls::G2Element  */
typedef struct c2dbls_sk c2dbls_sk;   /* bls::PrivateKey */

/* Message of the last C2DBLS_EXCEPTION on the calling thread. */
C2DBLS_API const char* c2dbls_last_error(void);

/* "dashbls <dash tag> ARITH=<backend> gmp <version> <compiler>": what the DLL
 * was built from, for logs and the release guard. */
C2DBLS_API const char* c2dbls_build_info(void);

/* ── G1Element ─────────────────────────────────────────────────────────── */
C2DBLS_API int  c2dbls_g1_new(c2dbls_g1** out);                    /* G1Element() */
C2DBLS_API int  c2dbls_g1_copy(const c2dbls_g1* in, c2dbls_g1** out);
C2DBLS_API void c2dbls_g1_free(c2dbls_g1* p);
C2DBLS_API int  c2dbls_g1_from_bytes(const uint8_t* data, size_t len, int legacy,
                                     c2dbls_g1** out);              /* G1Element::FromBytes */
C2DBLS_API int  c2dbls_g1_is_valid(const c2dbls_g1* p, int* out);
C2DBLS_API int  c2dbls_g1_serialize(const c2dbls_g1* p, int legacy,
                                    uint8_t out[C2DBLS_G1_SIZE]);
C2DBLS_API int  c2dbls_g1_equal(const c2dbls_g1* a, const c2dbls_g1* b, int* out);

/* ── G2Element ─────────────────────────────────────────────────────────── */
C2DBLS_API int  c2dbls_g2_new(c2dbls_g2** out);                    /* G2Element() */
C2DBLS_API int  c2dbls_g2_copy(const c2dbls_g2* in, c2dbls_g2** out);
C2DBLS_API void c2dbls_g2_free(c2dbls_g2* p);
C2DBLS_API int  c2dbls_g2_from_bytes(const uint8_t* data, size_t len, int legacy,
                                     c2dbls_g2** out);              /* G2Element::FromBytes */
C2DBLS_API int  c2dbls_g2_is_valid(const c2dbls_g2* p, int* out);
C2DBLS_API int  c2dbls_g2_serialize(const c2dbls_g2* p, int legacy,
                                    uint8_t out[C2DBLS_G2_SIZE]);
C2DBLS_API int  c2dbls_g2_equal(const c2dbls_g2* a, const c2dbls_g2* b, int* out);

/* ── PrivateKey (KATs only; production never signs) ────────────────────── */
C2DBLS_API int  c2dbls_sk_copy(const c2dbls_sk* in, c2dbls_sk** out);
C2DBLS_API void c2dbls_sk_free(c2dbls_sk* p);
C2DBLS_API int  c2dbls_sk_get_g1(const c2dbls_sk* p, c2dbls_g1** out);   /* GetG1Element */

/* ── BasicSchemeMPL ────────────────────────────────────────────────────── */
C2DBLS_API int c2dbls_basic_keygen(const uint8_t* seed, size_t len, c2dbls_sk** out);
C2DBLS_API int c2dbls_basic_sign(const c2dbls_sk* sk, const uint8_t* msg, size_t len,
                                 c2dbls_g2** out);
C2DBLS_API int c2dbls_basic_verify(const c2dbls_g1* pk, const uint8_t* msg, size_t len,
                                   const c2dbls_g2* sig, int* out);
C2DBLS_API int c2dbls_basic_aggregate_secure(const c2dbls_g1* const* pks, size_t n_pks,
                                             const c2dbls_g2* const* sigs, size_t n_sigs,
                                             const uint8_t* msg, size_t len,
                                             c2dbls_g2** out);
C2DBLS_API int c2dbls_basic_verify_secure(const c2dbls_g1* const* pks, size_t n_pks,
                                          const c2dbls_g2* sig,
                                          const uint8_t* msg, size_t len, int* out);

#ifdef __cplusplus
}
#endif

#endif /* C2POOL_DASHBLS_ABI_H */
