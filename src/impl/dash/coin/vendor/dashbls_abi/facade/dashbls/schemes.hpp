// SPDX-License-Identifier: AGPL-3.0-or-later
//
// MSVC-side stand-in for <dashbls/schemes.hpp>: BasicSchemeMPL, the only
// scheme c2pool uses (post-V19 basic scheme). Each method runs the dashbls
// CoreMPL method of the same name inside c2pool_dashbls.dll. See elements.hpp.

#ifndef C2POOL_DASHBLS_FACADE_SCHEMES_HPP
#define C2POOL_DASHBLS_FACADE_SCHEMES_HPP

#include "elements.hpp"

#include <vector>

namespace bls {

class BasicSchemeMPL {
public:
    PrivateKey KeyGen(const Bytes& seed)
    {
        c2dbls_sk* h = nullptr;
        c2dbls_detail::check(c2dbls_basic_keygen(seed.begin(), seed.size(), &h));
        return PrivateKey(h);
    }

    G2Element Sign(const PrivateKey& seckey, const Bytes& message)
    {
        c2dbls_g2* h = nullptr;
        c2dbls_detail::check(c2dbls_basic_sign(seckey.h_, message.begin(), message.size(), &h));
        return G2Element(h);
    }

    bool Verify(const G1Element& pubkey, const Bytes& message, const G2Element& signature)
    {
        int r = 0;
        c2dbls_detail::check(c2dbls_basic_verify(pubkey.h_, message.begin(), message.size(),
                                                 signature.h_, &r));
        return r != 0;
    }

    G2Element AggregateSecure(const std::vector<G1Element>& vecPublicKeys,
                              const std::vector<G2Element>& vecSignatures,
                              const Bytes& message)
    {
        std::vector<const c2dbls_g1*> pks;
        pks.reserve(vecPublicKeys.size());
        for (const auto& pk : vecPublicKeys) pks.push_back(pk.h_);
        std::vector<const c2dbls_g2*> sigs;
        sigs.reserve(vecSignatures.size());
        for (const auto& s : vecSignatures) sigs.push_back(s.h_);
        c2dbls_g2* h = nullptr;
        c2dbls_detail::check(c2dbls_basic_aggregate_secure(pks.data(), pks.size(),
                                                           sigs.data(), sigs.size(),
                                                           message.begin(), message.size(), &h));
        return G2Element(h);
    }

    bool VerifySecure(const std::vector<G1Element>& vecPublicKeys,
                      const G2Element& signature,
                      const Bytes& message)
    {
        std::vector<const c2dbls_g1*> pks;
        pks.reserve(vecPublicKeys.size());
        for (const auto& pk : vecPublicKeys) pks.push_back(pk.h_);
        int r = 0;
        c2dbls_detail::check(c2dbls_basic_verify_secure(pks.data(), pks.size(), signature.h_,
                                                        message.begin(), message.size(), &r));
        return r != 0;
    }
};

} // namespace bls

#endif // C2POOL_DASHBLS_FACADE_SCHEMES_HPP
