// SPDX-License-Identifier: AGPL-3.0-or-later
//
// MSVC-side stand-in for <dashbls/elements.hpp> (and util.hpp/privatekey.hpp).
//
// Used ONLY by the Windows/MSVC build, where the real dashbls lives in
// c2pool_dashbls.dll (see ../../c2pool_dashbls_abi.h for why). It declares the
// subset of the dashbls API that c2pool (bls_verify.{hpp,cpp}) and the BLS KAT
// test_dash_bls_verify use, with the same names and signatures, so that code
// compiles unchanged. There is NO crypto here: every object is an owning
// handle to a real dashbls object inside the DLL, and every method is one call
// into the DLL that runs the dashbls method of the same name on it. A dashbls
// exception comes back as std::runtime_error.
//
// Linux and macOS never see this directory; they compile against the real
// headers installed by scripts/build_dashbls.sh.

#ifndef C2POOL_DASHBLS_FACADE_ELEMENTS_HPP
#define C2POOL_DASHBLS_FACADE_ELEMENTS_HPP

#include "../../c2pool_dashbls_abi.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace bls {

namespace c2dbls_detail {

inline void check(int rc)
{
    if (rc == C2DBLS_OK) return;
    if (rc == C2DBLS_EXCEPTION) throw std::runtime_error(c2dbls_last_error());
    throw std::invalid_argument("c2pool_dashbls: invalid argument at the ABI boundary");
}

} // namespace c2dbls_detail

class BasicSchemeMPL;
class PrivateKey;

// Same shape as dashbls util.hpp Bytes: a non-owning view.
class Bytes {
    const uint8_t* pData;
    const size_t nSize;

public:
    Bytes(const uint8_t* pDataIn, const size_t nSizeIn) : pData(pDataIn), nSize(nSizeIn) {}
    Bytes(const std::vector<uint8_t>& vecBytes) : pData(vecBytes.data()), nSize(vecBytes.size()) {}
    template <size_t N>
    Bytes(const std::array<uint8_t, N>& a) : pData(a.data()), nSize(N) {}

    inline const uint8_t* begin() const { return pData; }
    inline const uint8_t* end() const { return pData + nSize; }
    inline size_t size() const { return nSize; }
    const uint8_t& operator[](const int nIndex) const { return pData[nIndex]; }
};

class G1Element {
public:
    static const size_t SIZE = C2DBLS_G1_SIZE;

    G1Element() { c2dbls_detail::check(c2dbls_g1_new(&h_)); }
    G1Element(const G1Element& o) { c2dbls_detail::check(c2dbls_g1_copy(o.h_, &h_)); }
    G1Element& operator=(const G1Element& o)
    {
        if (this != &o) {
            c2dbls_g1* n = nullptr;
            c2dbls_detail::check(c2dbls_g1_copy(o.h_, &n));
            c2dbls_g1_free(h_);
            h_ = n;
        }
        return *this;
    }
    ~G1Element() { c2dbls_g1_free(h_); }

    static G1Element FromBytes(Bytes bytes, bool fLegacy = false)
    {
        c2dbls_g1* h = nullptr;
        c2dbls_detail::check(c2dbls_g1_from_bytes(bytes.begin(), bytes.size(), fLegacy ? 1 : 0, &h));
        return G1Element(h);
    }

    bool IsValid() const
    {
        int r = 0;
        c2dbls_detail::check(c2dbls_g1_is_valid(h_, &r));
        return r != 0;
    }

    std::vector<uint8_t> Serialize(bool fLegacy = false) const
    {
        std::vector<uint8_t> v(SIZE);
        c2dbls_detail::check(c2dbls_g1_serialize(h_, fLegacy ? 1 : 0, v.data()));
        return v;
    }

    std::array<uint8_t, SIZE> SerializeToArray(bool fLegacy = false) const
    {
        std::array<uint8_t, SIZE> a{};
        c2dbls_detail::check(c2dbls_g1_serialize(h_, fLegacy ? 1 : 0, a.data()));
        return a;
    }

    friend bool operator==(const G1Element& a, const G1Element& b)
    {
        int r = 0;
        c2dbls_detail::check(c2dbls_g1_equal(a.h_, b.h_, &r));
        return r != 0;
    }
    friend bool operator!=(const G1Element& a, const G1Element& b) { return !(a == b); }

private:
    friend class BasicSchemeMPL;
    friend class PrivateKey;
    explicit G1Element(c2dbls_g1* h) : h_(h) {}
    c2dbls_g1* h_ = nullptr;
};

class G2Element {
public:
    static const size_t SIZE = C2DBLS_G2_SIZE;

    G2Element() { c2dbls_detail::check(c2dbls_g2_new(&h_)); }
    G2Element(const G2Element& o) { c2dbls_detail::check(c2dbls_g2_copy(o.h_, &h_)); }
    G2Element& operator=(const G2Element& o)
    {
        if (this != &o) {
            c2dbls_g2* n = nullptr;
            c2dbls_detail::check(c2dbls_g2_copy(o.h_, &n));
            c2dbls_g2_free(h_);
            h_ = n;
        }
        return *this;
    }
    ~G2Element() { c2dbls_g2_free(h_); }

    static G2Element FromBytes(Bytes bytes, bool fLegacy = false)
    {
        c2dbls_g2* h = nullptr;
        c2dbls_detail::check(c2dbls_g2_from_bytes(bytes.begin(), bytes.size(), fLegacy ? 1 : 0, &h));
        return G2Element(h);
    }

    bool IsValid() const
    {
        int r = 0;
        c2dbls_detail::check(c2dbls_g2_is_valid(h_, &r));
        return r != 0;
    }

    std::vector<uint8_t> Serialize(bool fLegacy = false) const
    {
        std::vector<uint8_t> v(SIZE);
        c2dbls_detail::check(c2dbls_g2_serialize(h_, fLegacy ? 1 : 0, v.data()));
        return v;
    }

    std::array<uint8_t, SIZE> SerializeToArray(bool fLegacy = false) const
    {
        std::array<uint8_t, SIZE> a{};
        c2dbls_detail::check(c2dbls_g2_serialize(h_, fLegacy ? 1 : 0, a.data()));
        return a;
    }

    friend bool operator==(const G2Element& a, const G2Element& b)
    {
        int r = 0;
        c2dbls_detail::check(c2dbls_g2_equal(a.h_, b.h_, &r));
        return r != 0;
    }
    friend bool operator!=(const G2Element& a, const G2Element& b) { return !(a == b); }

private:
    friend class BasicSchemeMPL;
    explicit G2Element(c2dbls_g2* h) : h_(h) {}
    c2dbls_g2* h_ = nullptr;
};

// Only what the KATs need: a key produced by BasicSchemeMPL::KeyGen, copied,
// and asked for its public key. Production code never signs.
class PrivateKey {
public:
    PrivateKey(const PrivateKey& o) { c2dbls_detail::check(c2dbls_sk_copy(o.h_, &h_)); }
    PrivateKey& operator=(const PrivateKey& o)
    {
        if (this != &o) {
            c2dbls_sk* n = nullptr;
            c2dbls_detail::check(c2dbls_sk_copy(o.h_, &n));
            c2dbls_sk_free(h_);
            h_ = n;
        }
        return *this;
    }
    ~PrivateKey() { c2dbls_sk_free(h_); }

    G1Element GetG1Element() const
    {
        c2dbls_g1* g = nullptr;
        c2dbls_detail::check(c2dbls_sk_get_g1(h_, &g));
        return G1Element(g);
    }

private:
    friend class BasicSchemeMPL;
    explicit PrivateKey(c2dbls_sk* h) : h_(h) {}
    c2dbls_sk* h_ = nullptr;
};

} // namespace bls

#endif // C2POOL_DASHBLS_FACADE_ELEMENTS_HPP
