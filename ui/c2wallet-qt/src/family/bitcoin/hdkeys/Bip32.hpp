// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// BIP32 hierarchical deterministic keys: master-from-seed, CKD (hardened +
// normal, private and public), xprv/xpub serialize/parse. SLIP-132 variants
// (yprv/zprv/…, per-coin analogues) are handled through the version-byte pair,
// resolved by CoinParams. Design §3.1 (BIP32 xprv/xpub + SLIP-132) and §3.3.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace c2w::hdkeys {

// BIP32 hardened offset. A child index >= this is a hardened derivation.
inline constexpr uint32_t kHardened = 0x80000000u;

// The 4-byte version prefixes for the private/public extended key of a
// (coin, script-type) pair. e.g. BTC xprv/xpub = 0x0488ADE4 / 0x0488B21E;
// SLIP-132 zprv/zpub (P2WPKH) = 0x04B2430C / 0x04B24746.
struct Bip32Versions {
    uint32_t priv = 0x0488ADE4u;
    uint32_t pub  = 0x0488B21Eu;
    bool operator==(const Bip32Versions& o) const { return priv == o.priv && pub == o.pub; }
};

class HDKey {
public:
    // Zeroizes the private scalar and chaincode on every destruction path
    // (design §5.3): the master node and every short-lived parent/child
    // built during path derivation must not leave secret material in freed
    // memory. Defined out-of-line in Bip32.cpp via secure::secure_wipe.
    ~HDKey();

    // I = HMAC-SHA512("Bitcoin seed", seed); master priv=I[0:32], chaincode=I[32:64].
    // nullopt if I[0:32] is not a valid scalar (probability ~2^-127).
    static std::optional<HDKey> from_seed(const uint8_t* seed, size_t seed_len,
                                          Bip32Versions versions = {});

    // Parse an extended key (base58check, 78 bytes). Fills `is_private` and
    // `versions` from the recognised prefix. nullopt on bad checksum/length.
    static std::optional<HDKey> parse(const std::string& ext_key);

    // Derive one child. Rejects hardened derivation on a public-only node.
    // nullopt if the (rare) resulting scalar/point is invalid — caller tries i+1.
    std::optional<HDKey> derive_child(uint32_t index) const;

    // Derive an absolute path from this node. `path` are raw child numbers with
    // the hardened bit already set. nullopt if any step fails.
    std::optional<HDKey> derive_path(const std::vector<uint32_t>& path) const;

    // Public-only copy (strips the private scalar). Keeps the pub version bytes.
    HDKey neuter() const;

    // base58check-serialized xprv (private node) or xpub (public node),
    // using this node's version bytes.
    std::string serialize() const;

    // First 4 bytes of hash160(pubkey).
    std::array<uint8_t, 4> fingerprint() const;

    bool has_private() const { return has_private_; }
    const std::array<uint8_t, 32>& privkey() const { return privkey_; }
    const std::vector<uint8_t>& pubkey() const { return pubkey_; }  // 33-byte compressed
    const std::array<uint8_t, 32>& chaincode() const { return chaincode_; }
    uint8_t depth() const { return depth_; }
    uint32_t child_number() const { return child_number_; }
    const std::array<uint8_t, 4>& parent_fingerprint() const { return parent_fp_; }
    Bip32Versions versions() const { return versions_; }
    void set_versions(Bip32Versions v) { versions_ = v; }

private:
    bool has_private_ = false;
    std::array<uint8_t, 32> privkey_{};
    std::array<uint8_t, 32> chaincode_{};
    std::vector<uint8_t> pubkey_;      // always the 33-byte compressed form
    uint8_t depth_ = 0;
    std::array<uint8_t, 4> parent_fp_{};
    uint32_t child_number_ = 0;
    Bip32Versions versions_{};
};

// hash160 = RIPEMD160(SHA256(data)). Exposed for the address layer.
std::array<uint8_t, 20> hash160(const uint8_t* data, size_t n);

} // namespace c2w::hdkeys
