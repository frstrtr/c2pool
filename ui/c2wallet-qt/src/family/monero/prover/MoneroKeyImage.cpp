// Copyright (c) 2014-2026, The Monero Project  (BSD-3-Clause)
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED. Full BSD-3 text: xmr_derivation.cpp.
//
// Port of monero-project/monero src/crypto/crypto.cpp
// (generate_ring_signature, check_ring_signature) and the wallet2.cpp
// export_key_images artifact, over Bytes32 and the vendored ed25519 engine.
// See MoneroKeyImage.hpp for full provenance.

#include "family/monero/prover/MoneroKeyImage.hpp"

#include <cstring>

#include "family/monero/addr/MoneroAddress.hpp"   // derive_subaddress (subaddress secret m)
#include "family/monero/scan/MoneroScanOps.hpp"   // key_derivation, derive_secret_key, generate_key_image
#include "secure/SecureString.hpp"                // c2w::secure::secure_wipe
#include "xmr_rct_ops.hpp"                         // hash_to_scalar, hash_to_p3, random, in_main_subgroup

extern "C" {
#include "vendor/crypto-ops.h"
}

namespace xr = c2pool::xmr::native::rct;

namespace c2wallet::monero::prover {

namespace {

// image_pre = ge_dsm_precomp(image). False if image is not a point.
struct GeDsmp { ge_cached k[8]; };

} // namespace

bool generate_ring_signature(const Bytes32& prefix_hash, const Bytes32& image,
                             const std::vector<Bytes32>& pubs,
                             const Bytes32& sec, std::size_t sec_index,
                             std::vector<RingSigElem>& sigs) {
    const std::size_t n = pubs.size();
    if (n == 0 || sec_index >= n) return false;

    ge_p3 image_unp;
    if (ge_frombytes_vartime(&image_unp, image.data()) != 0) return false;
    GeDsmp image_pre;
    ge_dsm_precomp(image_pre.k, &image_unp);

    // Hash buffer: prefix_hash || (a_i || b_i) for each ring member.
    std::vector<std::uint8_t> buf(32 + n * 64);
    std::memcpy(buf.data(), prefix_hash.data(), 32);

    Bytes32 sum{};
    sc_0(sum.data());
    Bytes32 k{};   // the nonce at sec_index
    sigs.assign(n, RingSigElem{});

    for (std::size_t i = 0; i < n; ++i) {
        std::uint8_t* a = buf.data() + 32 + i * 64;
        std::uint8_t* b = a + 32;
        if (i == sec_index) {
            k = xr::random_scalar_nonzero();
            ge_p3 tmp3;
            ge_scalarmult_base(&tmp3, k.data());
            ge_p3_tobytes(a, &tmp3);
            ge_p3 hp;
            xr::hash_to_p3(hp, pubs[i]);
            ge_p2 tmp2;
            ge_scalarmult(&tmp2, k.data(), &hp);
            ge_tobytes(b, &tmp2);
        } else {
            const Bytes32 ci = xr::random_scalar_nonzero();
            const Bytes32 ri = xr::random_scalar_nonzero();
            ge_p3 pub3;
            if (ge_frombytes_vartime(&pub3, pubs[i].data()) != 0) {
                c2w::secure::secure_wipe(k.data(), k.size());
                return false;
            }
            ge_p2 tmp2;
            ge_double_scalarmult_base_vartime(&tmp2, ci.data(), &pub3, ri.data());
            ge_tobytes(a, &tmp2);
            ge_p3 hp;
            xr::hash_to_p3(hp, pubs[i]);
            ge_double_scalarmult_precomp_vartime(&tmp2, ri.data(), &hp, ci.data(), image_pre.k);
            ge_tobytes(b, &tmp2);
            sc_add(sum.data(), sum.data(), ci.data());
            std::memcpy(sigs[i].data(), ci.data(), 32);
            std::memcpy(sigs[i].data() + 32, ri.data(), 32);
        }
    }

    const Bytes32 h = xr::hash_to_scalar(buf.data(), buf.size());
    Bytes32 c_sec{}, r_sec{};
    sc_sub(c_sec.data(), h.data(), sum.data());              // c = h - sum
    sc_mulsub(r_sec.data(), c_sec.data(), sec.data(), k.data()); // r = k - c*sec
    std::memcpy(sigs[sec_index].data(), c_sec.data(), 32);
    std::memcpy(sigs[sec_index].data() + 32, r_sec.data(), 32);

    c2w::secure::secure_wipe(k.data(), k.size());
    return true;
}

bool check_ring_signature(const Bytes32& prefix_hash, const Bytes32& image,
                          const std::vector<Bytes32>& pubs,
                          const std::vector<RingSigElem>& sigs) {
    const std::size_t n = pubs.size();
    if (n == 0 || sigs.size() != n) return false;

    ge_p3 image_unp;
    if (ge_frombytes_vartime(&image_unp, image.data()) != 0) return false;
    GeDsmp image_pre;
    ge_dsm_precomp(image_pre.k, &image_unp);

    std::vector<std::uint8_t> buf(32 + n * 64);
    std::memcpy(buf.data(), prefix_hash.data(), 32);

    Bytes32 sum{};
    sc_0(sum.data());
    for (std::size_t i = 0; i < n; ++i) {
        Bytes32 ci{}, ri{};
        std::memcpy(ci.data(), sigs[i].data(), 32);
        std::memcpy(ri.data(), sigs[i].data() + 32, 32);
        if (sc_check(ci.data()) != 0 || sc_check(ri.data()) != 0) return false;
        ge_p3 pub3;
        if (ge_frombytes_vartime(&pub3, pubs[i].data()) != 0) return false;
        std::uint8_t* a = buf.data() + 32 + i * 64;
        std::uint8_t* b = a + 32;
        ge_p2 tmp2;
        ge_double_scalarmult_base_vartime(&tmp2, ci.data(), &pub3, ri.data());
        ge_tobytes(a, &tmp2);
        ge_p3 hp;
        xr::hash_to_p3(hp, pubs[i]);
        ge_double_scalarmult_precomp_vartime(&tmp2, ri.data(), &hp, ci.data(), image_pre.k);
        ge_tobytes(b, &tmp2);
        sc_add(sum.data(), sum.data(), ci.data());
    }

    Bytes32 h = xr::hash_to_scalar(buf.data(), buf.size());
    sc_sub(h.data(), h.data(), sum.data());
    return sc_isnonzero(h.data()) == 0;
}

KeyImageExportResult export_key_images(const MoneroKeys& keys,
                                       const std::vector<ExportedOutput>& outs) {
    KeyImageExportResult res;
    if (!keys.can_sign()) {
        res.ok = false;
        res.error = "view-only wallet cannot export key images (no spend secret)";
        return res;
    }

    res.images.reserve(outs.size());
    for (const ExportedOutput& o : outs) {
        // D = 8 * k_v * R.
        Bytes32 D{};
        if (!scanops::key_derivation(o.tx_pubkey, keys.view_priv, D)) {
            res.error = "bad tx pubkey in exported output";
            return res;
        }
        // x_i = H_s(D||i) + k_s (+ subaddress secret m).
        Bytes32 x = scanops::derive_secret_key(D, o.output_index, keys.spend_priv);
        if (!(o.subaddr.major == 0 && o.subaddr.minor == 0)) {
            SubaddressResult sub =
                derive_subaddress(keys.view_priv, keys.spend_pub, o.subaddr.major, o.subaddr.minor);
            if (!sub.ok) {
                c2w::secure::secure_wipe(x.data(), x.size());
                res.error = "subaddress secret derivation failed";
                return res;
            }
            x = mcrypto::scalar_add(x, sub.m);
        }

        ExportedKeyImage e;
        e.one_time_pub = o.one_time_pub;
        if (!scanops::generate_key_image(o.one_time_pub, x, e.image)) {
            c2w::secure::secure_wipe(x.data(), x.size());
            res.error = "key image generation failed (non-canonical secret or bad P)";
            return res;
        }

        std::vector<RingSigElem> sigs;
        const std::vector<Bytes32> ring{o.one_time_pub};
        const bool ok = generate_ring_signature(e.image, e.image, ring, x, 0, sigs);
        c2w::secure::secure_wipe(x.data(), x.size());
        if (!ok || sigs.size() != 1) {
            res.error = "key image ownership signature failed";
            return res;
        }
        e.signature = sigs[0];
        res.images.push_back(e);
    }

    res.ok = true;
    return res;
}

bool check_exported_key_image(const ExportedKeyImage& e) {
    // Key-image domain: must be in the prime-order subgroup (monerod's
    // check_tx_inputs_keyimages_domain). This is the in-tree ops check.
    if (!xr::in_main_subgroup(e.image)) return false;
    const std::vector<Bytes32> ring{e.one_time_pub};
    const std::vector<RingSigElem> sigs{e.signature};
    return check_ring_signature(e.image, e.image, ring, sigs);
}

} // namespace c2wallet::monero::prover
