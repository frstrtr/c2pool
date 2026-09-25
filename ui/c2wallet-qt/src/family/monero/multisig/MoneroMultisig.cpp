// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// Monero N/M multisig key exchange -- see MoneroMultisig.hpp for scope,
// faithfulness notes, and the EXPERIMENTAL banner. No curve/hash math is
// reimplemented here: it drives the already-vendored ed25519/Keccak engine
// through MoneroCrypto's Bytes32 wrappers.

#include "family/monero/multisig/MoneroMultisig.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#include "secure/SecureString.hpp"   // secure_wipe
#include "family/monero/prover/MoneroProverRng.hpp"  // csprng_scalar_nonzero (money-safe)

namespace c2wallet::monero::multisig {

namespace mc = c2wallet::monero::mcrypto;
using c2w::secure::secure_wipe;

namespace {

// H_s("Multisig" || k). The tag matches monerod config::HASH_KEY_MULTISIG.
Bytes32 hs_tagged(const char* tag, const Bytes32& k) {
    const std::size_t tlen = std::strlen(tag);
    std::vector<std::uint8_t> buf(tlen + 32);
    std::memcpy(buf.data(), tag, tlen);
    std::memcpy(buf.data() + tlen, k.data(), 32);
    Bytes32 out = mc::hash_to_scalar(buf.data(), buf.size());
    secure_wipe(buf.data(), buf.size());
    return out;
}

// Canonical unordered pair key so a subset {i,j} sorts and dedups the same way
// no matter which member reports it.
std::vector<std::uint32_t> pair_subset(std::uint32_t a, std::uint32_t b) {
    std::vector<std::uint32_t> s{a, b};
    std::sort(s.begin(), s.end());
    return s;
}

} // namespace

bool config_supported(const MultisigConfig& cfg) {
    if (cfg.total < 2 || cfg.threshold < 1 || cfg.threshold > cfg.total) return false;
    // Shipped shapes: N-of-N (subset size 1) and (N-1)-of-N (subset size 2).
    const std::uint32_t subset = cfg.total - cfg.threshold + 1;
    return subset == 1 || subset == 2;
}

std::uint32_t kex_rounds(const MultisigConfig& cfg) {
    return cfg.total - cfg.threshold + 1;   // == subset size == #rounds
}

Bytes32 blinded_secret(const Bytes32& k) {
    return hs_tagged("Multisig", k);
}

BaseSecrets generate_base_secrets() {
    // Reuse the prover CSPRNG for a money-safe base spend secret; view = H_s(spend),
    // the standard Monero deterministic view key.
    BaseSecrets b;
    b.spend_sec = prover::csprng_scalar_nonzero();
    b.view_sec  = mc::hash_to_scalar(b.spend_sec.data(), b.spend_sec.size());
    return b;
}

KexRound1 make_round1(std::uint32_t signer_index, const BaseSecrets& base) {
    KexRound1 r;
    r.signer_index = signer_index;
    Bytes32 bs = blinded_secret(base.spend_sec);   // blinded spend secret
    mc::secret_to_public(bs, r.spend_pub_share);    // published: bs * G
    r.view_sec_share = blinded_secret(base.view_sec);  // shared view secret share
    secure_wipe(bs.data(), bs.size());
    return r;
}

KexRound2 make_round2(std::uint32_t signer_index,
                      const BaseSecrets& base,
                      const std::vector<KexRound1>& round1,
                      SignerShares& out_local_shares) {
    KexRound2 r;
    r.signer_index = signer_index;
    out_local_shares.signer_index = signer_index;
    out_local_shares.spend_key_shares.clear();
    out_local_shares.shares_subset.clear();

    Bytes32 my_share = blinded_secret(base.spend_sec);   // scalar (SECRET)
    for (const KexRound1& other : round1) {
        if (other.signer_index == signer_index) continue;
        // Pairwise DH point = my_share * (other_share * G). Both members of the
        // pair compute the identical point, so d_ij is common to exactly {i,j}.
        Bytes32 dh{};
        if (!mc::point_scalarmult(my_share, other.spend_pub_share, dh)) continue;
        Bytes32 d_ij = mc::hash_to_scalar(dh.data(), dh.size());   // subset secret
        Bytes32 D_ij{};
        mc::secret_to_public(d_ij, D_ij);                          // published point

        r.partner_index.push_back(other.signer_index);
        r.subset_pub.push_back(D_ij);

        out_local_shares.spend_key_shares.push_back(d_ij);
        out_local_shares.shares_subset.push_back(pair_subset(signer_index, other.signer_index));

        secure_wipe(dh.data(), dh.size());
        secure_wipe(d_ij.data(), d_ij.size());
    }
    secure_wipe(my_share.data(), my_share.size());
    return r;
}

SetupResult finalize(const MultisigConfig& cfg,
                     std::uint32_t local_index,
                     const BaseSecrets& local_base,
                     const std::vector<KexRound1>& round1,
                     const std::vector<KexRound2>& round2) {
    SetupResult res;
    if (!config_supported(cfg)) { res.error = "unsupported M-of-N (ships N/N and (N-1)/N only)"; return res; }
    if (round1.size() != cfg.total) { res.error = "round1 message count != N"; return res; }
    if (local_index >= cfg.total) { res.error = "local_index out of range"; return res; }

    res.info.cfg = cfg;

    // ---- common view secret = Sum of blinded view shares -------------------
    Bytes32 vsec{};   // zero
    for (const KexRound1& r1 : round1) vsec = mc::scalar_add(vsec, r1.view_sec_share);
    res.info.view_sec = vsec;
    if (!mc::secret_to_public(vsec, res.info.view_pub)) { res.error = "view pub derive failed"; return res; }

    const std::uint32_t subset = cfg.total - cfg.threshold + 1;

    // ---- multisig spend PUBLIC key ----------------------------------------
    if (subset == 1) {
        // N-of-N: K_s = Sum of blinded spend public shares.
        Bytes32 acc{}; bool first = true;
        for (const KexRound1& r1 : round1) {
            if (first) { acc = r1.spend_pub_share; first = false; }
            else if (!mc::point_add(acc, r1.spend_pub_share, acc)) { res.error = "spend pub sum failed"; return res; }
        }
        res.info.spend_pub = acc;

        // Local share = blinded(local spend secret).
        Bytes32 my = blinded_secret(local_base.spend_sec);
        res.shares.signer_index = local_index;
        res.shares.spend_key_shares = { my };
        res.shares.shares_subset = { std::vector<std::uint32_t>{ local_index } };
        secure_wipe(my.data(), my.size());
    } else {
        // (N-1)-of-N: K_s = Sum over UNIQUE pairs of the published D_ij points.
        if (round2.size() != cfg.total) { res.error = "round2 message count != N"; return res; }
        std::vector<std::vector<std::uint32_t>> seen;
        Bytes32 acc{}; bool first = true;
        for (const KexRound2& r2 : round2) {
            for (std::size_t k = 0; k < r2.subset_pub.size(); ++k) {
                std::vector<std::uint32_t> key = pair_subset(r2.signer_index, r2.partner_index[k]);
                if (std::find(seen.begin(), seen.end(), key) != seen.end()) continue;  // dedup pair
                seen.push_back(key);
                if (first) { acc = r2.subset_pub[k]; first = false; }
                else if (!mc::point_add(acc, r2.subset_pub[k], acc)) { res.error = "subset pub sum failed"; return res; }
            }
        }
        // Sanity: a complete (N-1)/N exchange has exactly C(N,2) unique pairs.
        const std::size_t expect = static_cast<std::size_t>(cfg.total) * (cfg.total - 1) / 2;
        if (seen.size() != expect) { res.error = "incomplete pairwise exchange"; return res; }
        res.info.spend_pub = acc;

        // Local private shares: recompute the pairwise secrets this signer holds.
        SignerShares local;
        make_round2(local_index, local_base, round1, local);   // fills local.spend_key_shares
        res.shares = local;
    }

    if (!mc::secret_to_public(res.info.view_sec, res.info.view_pub)) { res.error = "view pub derive failed"; return res; }
    res.info.address = make_standard(res.info.spend_pub, res.info.view_pub, cfg.net);
    res.ok = true;
    return res;
}

} // namespace c2wallet::monero::multisig
