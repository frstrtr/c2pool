// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// ui/c2wallet-qt/src/family/monero/multisig/MoneroMultisig.hpp
//
// Family B (Monero) N/M MULTISIG key exchange -- design §4.2 phase M4-X-MMS.
//
//   *** EXPERIMENTAL ***  Monero multisig is a large, stateful, multi-round
//   interactive protocol and a historically frequent bug source. This module
//   is NOT wired to the signer UI and MUST have an independent cryptographic
//   review before it guards real funds. It is delivered here as the key layer
//   plus a construct->verify KAT, per the design's strong-correctness harness.
//
// WHAT THIS IS (and is not):
//   This is the KEY-SETUP / KEY-EXCHANGE layer of Monero multisig. It derives,
//   from the per-participant round messages, the SHARED multisig spend public
//   key, each signer's private key SHARE(s), the SHARED (common) view key, and
//   the multisig address -- for the two configurations this PR ships:
//       * N-of-N  (2-of-2, 3-of-3): one kex round.
//       * M=(N-1)-of-N (2-of-3, 3-of-4): two kex rounds.
//   Cooperative (partial) CLSAG signing over these shares is MoneroMultisigSign.
//   The wire messages participants pass are MoneroMmsMessage.
//
// FAITHFULNESS TO monero-project:
//   * The per-participant secret BLINDING  blinded(k)=H_s("Multisig" || k)  is
//     byte-faithful to monerod's get_multisig_blinded_secret_key
//     (config::HASH_KEY_MULTISIG), so the key-cancellation defence matches.
//   * The N-of-N spend key = Sum of blinded spend shares, and the common view
//     secret = Sum of blinded view shares, are exactly monerod's N/N scheme.
//   * The M=(N-1)/N threshold uses subset secrets of size (N-M+1)=2 (pairwise):
//     the pair {i,j} shares d_ij = H_s(share_i * (share_j*G)), the multisig
//     spend secret is Sum over pairs of d_ij, and any M signers jointly hold
//     every subset secret. This is monerod's additive-threshold PRINCIPLE; the
//     ON-THE-WIRE MMS message bytes are faithful+documented here (see
//     MoneroMmsMessage), not yet byte-verbatim monero MMS -- interop with a
//     stock monero-wallet-cli MMS exchange, and general N/M with subset size
//     >=3 (>2 kex rounds), are the documented follow-on.
//
// MONEY-SAFETY (the M3-X lesson): every fresh secret scalar this module needs
// (only the optional base-key generator here) is drawn from the wallet-local
// CSPRNG csprng_scalar_nonzero(); NEVER random_scalar_nonzero()/mt19937. Secret
// scalars live in SecureBytes / are secure_wipe()'d. The blinding and subset
// derivations are deterministic functions of already-existing secrets and add
// no new nonce.
// ===========================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "family/monero/MoneroCrypto.hpp"          // Bytes32
#include "family/monero/addr/MoneroAddress.hpp"     // MoneroAddress, Network

namespace c2wallet::monero::multisig {

using c2wallet::monero::Bytes32;

// ---------------------------------------------------------------------------
// Configuration of the group: M-of-N. Only the two shipped shapes are accepted
// by the setup functions; everything else returns an error (documented
// follow-on), so a caller can never silently get a wrong-threshold key.
// ---------------------------------------------------------------------------
struct MultisigConfig {
    std::uint32_t threshold{2};   // M -- signatures required
    std::uint32_t total{2};       // N -- participants
    Network net{Network::Mainnet};
};

// True for the shapes this PR implements: N-of-N, or (N-1)-of-N.
bool config_supported(const MultisigConfig& cfg);

// Number of key-exchange rounds this shape needs (N-M+1). 1 for N/N, 2 for
// (N-1)/N. (General subset size >=3 -> >2 rounds is the deferred follow-on.)
std::uint32_t kex_rounds(const MultisigConfig& cfg);

// ---------------------------------------------------------------------------
// Round 1 message a participant broadcasts: its blinded spend PUBLIC key share
// and its blinded view SECRET share (the view key is common/shared in Monero
// multisig, so the view secret share is exchanged in the clear within the
// group -- it is not a spend secret). Public / semi-public: safe to serialize.
// ---------------------------------------------------------------------------
struct KexRound1 {
    std::uint32_t signer_index{0};  // 0-based position in the sorted group
    Bytes32       spend_pub_share{};// blinded(k_s) * G
    Bytes32       view_sec_share{}; // blinded(k_v)   (shared view secret share)
};

// Round 2 message (only for M=(N-1)/N): the PUBLIC points of the pairwise
// subset secrets this participant is a member of, D_ij = d_ij * G, one per
// partner. The scalars d_ij themselves never leave the two holders.
struct KexRound2 {
    std::uint32_t signer_index{0};
    // For each partner p (p != signer_index): the point D_{signer,p}. Keyed by
    // the *partner's* index so the coordinator can dedup a pair reported twice.
    std::vector<std::uint32_t> partner_index;
    std::vector<Bytes32>       subset_pub;   // D_{signer,partner}
};

// ---------------------------------------------------------------------------
// A participant's private multisig key material, produced by the setup. Held
// only on the offline signer. `spend_key_shares` is one scalar for N/N, or the
// set of pairwise subset secrets this participant holds for (N-1)/N. All are
// SECRET and are stored zeroizing.
// ---------------------------------------------------------------------------
struct SignerShares {
    std::uint32_t              signer_index{0};
    // Secret scalars this signer contributes to the multisig spend key. For
    // N/N: exactly {blinded(k_s)}. For (N-1)/N: the pairwise d_ij for every
    // pair (i,j) this signer belongs to. Stored as 32-byte scalars; the caller
    // wipes them (they are also copied into SecureBytes inside the signer).
    std::vector<Bytes32>       spend_key_shares;
    // Which subset each share covers, as a sorted member-index list. Used by
    // cooperative signing to partition subsets across the signing quorum with
    // no double counting. shares_subset[k] pairs with spend_key_shares[k].
    std::vector<std::vector<std::uint32_t>> shares_subset;
};

// The public result of a completed key exchange: everyone agrees on this.
struct MultisigInfo {
    MultisigConfig cfg;
    Bytes32        spend_pub{};    // multisig spend PUBLIC key  K_s
    Bytes32        view_sec{};     // common view SECRET key     k_v  (shared)
    Bytes32        view_pub{};     // multisig view PUBLIC key   K_v = k_v*G
    MoneroAddress address{}; // standard multisig address
};

struct SetupResult {
    bool         ok{false};
    std::string  error;
    MultisigInfo info;
    // The local signer's private shares (only meaningful for the local index).
    SignerShares shares;
};

// ---------------------------------------------------------------------------
// Base per-participant secrets fed into the exchange. In a real wallet these
// come from the participant's own seed; the KAT can also generate them via
// generate_base_secrets() below (CSPRNG).
// ---------------------------------------------------------------------------
struct BaseSecrets {
    Bytes32 spend_sec{};   // k_s,i   (SECRET)
    Bytes32 view_sec{};    // k_v,i   (SECRET; standard k_v = H_s(k_s))
};

// Draw a fresh base keypair from the wallet CSPRNG (money-safe). view = H_s(spend).
BaseSecrets generate_base_secrets();

// blinded(k) = H_s("Multisig" || k)  (monerod get_multisig_blinded_secret_key).
Bytes32 blinded_secret(const Bytes32& k);

// ---- Round 1 -------------------------------------------------------------
// Produce this participant's Round-1 broadcast from its base secrets.
KexRound1 make_round1(std::uint32_t signer_index, const BaseSecrets& base);

// ---- Round 2 (only for (N-1)/N) ------------------------------------------
// Given this participant's base spend secret and everyone's Round-1 spend
// public shares, produce the pairwise subset points this participant can form.
// Also fills `out_local_shares` with the secret pairwise scalars this
// participant holds (for the local signer only).
KexRound2 make_round2(std::uint32_t signer_index,
                      const BaseSecrets& base,
                      const std::vector<KexRound1>& round1,
                      SignerShares& out_local_shares);

// ---- Finalize ------------------------------------------------------------
// Combine all participants' messages into the shared MultisigInfo, and fill in
// the local signer's private shares. For N/N, `round2` is ignored/empty; for
// (N-1)/N it must carry every participant's Round-2 message. `local_index` is
// the position whose private shares are returned. `local_base` supplies the
// local participant's base secrets so its own spend/view shares are known.
SetupResult finalize(const MultisigConfig& cfg,
                     std::uint32_t local_index,
                     const BaseSecrets& local_base,
                     const std::vector<KexRound1>& round1,
                     const std::vector<KexRound2>& round2);

} // namespace c2wallet::monero::multisig
