// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// ui/c2wallet-qt/src/family/monero/addr/MoneroAddress.hpp
//
// Monero address derivation + codec (design §3.2):
//   standard    = base58(varint(tag) || K_s || K_v || keccak(...)[0:4])
//   integrated  = base58(varint(tag) || K_s || K_v || payment_id[8] || checksum)
//   subaddress  = base58(varint(tag) || K_s^(i,j) || K_v^(i,j) || checksum)
// where the subaddress keys derive from a view pair (private view key + public
// spend key) via  m = H_s("SubAddr\0" || k_v || major || minor),
// K_s^(i,j) = K_s + m*G,  K_v^(i,j) = k_v * K_s^(i,j).
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "../MoneroCrypto.hpp"   // Bytes32

namespace c2wallet::monero {

enum class Network { Mainnet, Testnet, Stagenet };
enum class AddressType { Standard, Integrated, Subaddress };

struct MoneroAddress {
    Network                    net{Network::Mainnet};
    AddressType                type{AddressType::Standard};
    Bytes32                    spend_pub{};
    Bytes32                    view_pub{};
    std::array<std::uint8_t, 8> payment_id{};   // integrated only
    bool                       has_payment_id{false};
};

// Network prefix bytes (varint tags): mainnet {18,19,42}, testnet {53,54,63},
// stagenet {24,25,36}.
std::uint64_t address_tag(Network net, AddressType type);

// Encode / decode.
std::string address_encode(const MoneroAddress& a);
bool address_decode(const std::string& s, MoneroAddress& out, std::string& err);

// Constructors from public keys.
MoneroAddress make_standard(const Bytes32& spend_pub, const Bytes32& view_pub,
                            Network net = Network::Mainnet);
MoneroAddress make_integrated(const Bytes32& spend_pub, const Bytes32& view_pub,
                              const std::array<std::uint8_t, 8>& payment_id,
                              Network net = Network::Mainnet);

// Subaddress derivation from a view pair.
struct SubaddressResult {
    bool         ok{false};
    std::string  error;
    MoneroAddress addr;
    Bytes32      sub_spend_pub{};   // K_s^(i,j)
    Bytes32      sub_view_pub{};    // K_v^(i,j)
    Bytes32      m{};               // the subaddress secret scalar (for testing)
};

SubaddressResult derive_subaddress(const Bytes32& view_priv, const Bytes32& spend_pub,
                                   std::uint32_t major, std::uint32_t minor,
                                   Network net = Network::Mainnet);

} // namespace c2wallet::monero
