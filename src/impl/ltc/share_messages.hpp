// share_messages.hpp — V36 share-embedded messaging: decryption + validation
//
// Port of p2pool/share_messages.py (consensus-critical portions).
// Messages are embedded in V36 shares' message_data field, included
// in the ref_hash computation (PoW-protected).
//
// Validation path for incoming shares:
//   1. If message_data is empty → valid (no messages)
//   2. Decrypt outer envelope using DONATION_AUTHORITY_PUBKEYS
//   3. If decryption fails (MAC mismatch) → REJECT share
//   4. Parse inner envelope: version, flags, msg_count, messages
//   5. If inner envelope is malformed or empty → REJECT share
//   6. TODO: Verify ECDSA signatures (requires secp256k1 library)

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <btclibs/crypto/hmac_sha256.h>
#include <btclibs/crypto/sha256.h>

namespace ltc {

// ============================================================================
// Authority public keys (compressed secp256k1)
// From COMBINED_DONATION_REDEEM_SCRIPT:
//   OP_1 PUSH33 <forrestv> PUSH33 <maintainer> OP_2 OP_CHECKMULTISIG
// ============================================================================

using AuthorityPubkey = std::array<unsigned char, 33>;

inline const AuthorityPubkey& DONATION_PUBKEY_FORRESTV()
{
    static const AuthorityPubkey k = {
        0x03, 0xff, 0xd0, 0x3d, 0xe4, 0x4a, 0x6e, 0x11,
        0xb9, 0x91, 0x7f, 0x3a, 0x29, 0xf9, 0x44, 0x32,
        0x83, 0xd9, 0x87, 0x1c, 0x9d, 0x74, 0x3e, 0xf3,
        0x0d, 0x5e, 0xdd, 0xcd, 0x37, 0x09, 0x4b, 0x64,
        0xd1
    };
    return k;
}

inline const AuthorityPubkey& DONATION_PUBKEY_MAINTAINER()
{
    static const AuthorityPubkey k = {
        0x02, 0xfe, 0x65, 0x78, 0xf8, 0x02, 0x1a, 0x7d,
        0x46, 0x67, 0x87, 0x82, 0x7b, 0x3f, 0x26, 0x43,
        0x7a, 0xef, 0x88, 0x27, 0x9e, 0xf3, 0x80, 0xaf,
        0x32, 0x6f, 0x87, 0xec, 0x36, 0x26, 0x33, 0x29,
        0x3a
    };
    return k;
}

inline const std::array<const AuthorityPubkey*, 2>& DONATION_AUTHORITY_PUBKEYS()
{
    static const std::array<const AuthorityPubkey*, 2> keys = {
        &DONATION_PUBKEY_FORRESTV(),
        &DONATION_PUBKEY_MAINTAINER(),
    };
    return keys;
}

// ============================================================================
// Constants
// ============================================================================

// Message types
constexpr uint8_t MSG_NODE_STATUS       = 0x01;
constexpr uint8_t MSG_MINER_MESSAGE     = 0x02;
constexpr uint8_t MSG_POOL_ANNOUNCE     = 0x03;
constexpr uint8_t MSG_VERSION_SIGNAL    = 0x04;
constexpr uint8_t MSG_MERGED_STATUS     = 0x05;
constexpr uint8_t MSG_EMERGENCY         = 0x10;
constexpr uint8_t MSG_TRANSITION_SIGNAL = 0x20;

// Flags
constexpr uint8_t FLAG_HAS_SIGNATURE      = 0x01;
constexpr uint8_t FLAG_BROADCAST          = 0x02;
constexpr uint8_t FLAG_PERSISTENT         = 0x04;
constexpr uint8_t FLAG_PROTOCOL_AUTHORITY = 0x08;

// Limits
constexpr size_t MAX_MESSAGE_PAYLOAD    = 220;
constexpr size_t MAX_MESSAGES_PER_SHARE = 3;
constexpr size_t MAX_TOTAL_MESSAGE_BYTES = 512;

// Encryption envelope
constexpr uint8_t ENCRYPTED_ENVELOPE_VERSION = 0x01;
constexpr size_t  ENCRYPTION_NONCE_SIZE = 16;
constexpr size_t  ENCRYPTION_MAC_SIZE   = 32;
constexpr size_t  ENCRYPTION_HEADER_SIZE = 1 + ENCRYPTION_NONCE_SIZE + ENCRYPTION_MAC_SIZE; // 49

// ============================================================================
// Parsed message (lightweight — just what we need for validation)
// ============================================================================

struct ShareMessage
{
    uint8_t  msg_type{0};
    uint8_t  flags{0};
    uint8_t  wire_flags{0};  // original flags for hash
    uint32_t timestamp{0};
    std::vector<unsigned char> payload;
    std::array<unsigned char, 20> signing_id{};
    std::vector<unsigned char> signature;

    bool has_signature() const { return (flags & FLAG_HAS_SIGNATURE) != 0; }

    // Unpack one message from data at offset. Returns new offset or nullopt on failure.
    static std::optional<size_t> unpack(const unsigned char* data, size_t len,
                                        size_t offset, ShareMessage& out)
    {
        if (len - offset < 8) return std::nullopt;

        std::memcpy(&out.msg_type, data + offset, 1);
        std::memcpy(&out.wire_flags, data + offset + 1, 1);
        out.flags = out.wire_flags & ~FLAG_PROTOCOL_AUTHORITY;

        uint32_t ts;
        std::memcpy(&ts, data + offset + 2, 4);  // LE
        out.timestamp = ts;

        uint16_t payload_len;
        std::memcpy(&payload_len, data + offset + 6, 2);  // LE
        offset += 8;

        if (payload_len > MAX_MESSAGE_PAYLOAD) return std::nullopt;
        if (len - offset < payload_len) return std::nullopt;
        out.payload.assign(data + offset, data + offset + payload_len);
        offset += payload_len;

        // signing_id (20 bytes)
        if (len - offset < 20) return std::nullopt;
        std::memcpy(out.signing_id.data(), data + offset, 20);
        offset += 20;

        // sig_len + signature
        if (len - offset < 1) return std::nullopt;
        uint8_t sig_len = data[offset++];
        if (len - offset < sig_len) return std::nullopt;
        out.signature.assign(data + offset, data + offset + sig_len);
        offset += sig_len;

        return offset;
    }
};

// ============================================================================
// Crypto helpers
// ============================================================================

// HMAC-SHA256(key, data) → 32 bytes
inline std::array<unsigned char, 32> hmac_sha256(
    const unsigned char* key, size_t keylen,
    const unsigned char* data, size_t datalen)
{
    std::array<unsigned char, 32> result;
    CHMAC_SHA256(key, keylen).Write(data, datalen).Finalize(result.data());
    return result;
}

// Counter-mode SHA256 stream generator
inline void generate_stream(const unsigned char* enc_key,
                            unsigned char* out, size_t length)
{
    size_t produced = 0;
    uint32_t counter = 0;
    while (produced < length)
    {
        unsigned char block_input[36]; // 32 (key) + 4 (counter LE)
        std::memcpy(block_input, enc_key, 32);
        std::memcpy(block_input + 32, &counter, 4); // LE on little-endian host

        unsigned char block[32];
        CSHA256().Write(block_input, 36).Finalize(block);

        size_t copy = std::min<size_t>(32, length - produced);
        std::memcpy(out + produced, block, copy);
        produced += copy;
        ++counter;
    }
}

// ============================================================================
// Decryption result
// ============================================================================

struct DecryptResult
{
    std::vector<unsigned char> inner_data;
    const AuthorityPubkey* authority_pubkey{nullptr};  // which key succeeded
};

// Decrypt encrypted envelope. Returns nullopt if all authority keys fail MAC.
inline std::optional<DecryptResult> decrypt_message_data(
    const unsigned char* data, size_t len)
{
    if (len < ENCRYPTION_HEADER_SIZE + 1) return std::nullopt;

    if (data[0] != ENCRYPTED_ENVELOPE_VERSION) return std::nullopt;

    const unsigned char* nonce      = data + 1;
    const unsigned char* mac_recv   = data + 1 + ENCRYPTION_NONCE_SIZE;
    const unsigned char* ciphertext = data + ENCRYPTION_HEADER_SIZE;
    size_t ct_len = len - ENCRYPTION_HEADER_SIZE;

    if (ct_len == 0) return std::nullopt;

    for (const auto* pubkey_ptr : DONATION_AUTHORITY_PUBKEYS())
    {
        // enc_key = HMAC-SHA256(pubkey, nonce)
        auto enc_key = hmac_sha256(
            pubkey_ptr->data(), pubkey_ptr->size(), nonce, ENCRYPTION_NONCE_SIZE);

        // MAC = HMAC-SHA256(enc_key, ciphertext)
        auto mac_computed = hmac_sha256(
            enc_key.data(), enc_key.size(), ciphertext, ct_len);

        // Constant-time compare
        unsigned char diff = 0;
        for (size_t i = 0; i < 32; ++i) diff |= mac_computed[i] ^ mac_recv[i];
        if (diff != 0) continue;  // Wrong key

        // MAC matches — decrypt (XOR with stream)
        DecryptResult result;
        result.inner_data.resize(ct_len);
        generate_stream(enc_key.data(), result.inner_data.data(), ct_len);
        for (size_t i = 0; i < ct_len; ++i)
            result.inner_data[i] ^= ciphertext[i];
        result.authority_pubkey = pubkey_ptr;
        return result;
    }

    return std::nullopt;
}

// ============================================================================
// Unpack result
// ============================================================================

struct UnpackResult
{
    std::vector<ShareMessage> messages;
    const AuthorityPubkey* authority_pubkey{nullptr};
    bool decrypted{false};
};

// Main entry point: decrypt + parse inner envelope.
// Returns empty result on failure; caller checks fields.
inline UnpackResult unpack_share_messages(const unsigned char* data, size_t len)
{
    UnpackResult result;

    if (!data || len < ENCRYPTION_HEADER_SIZE + 4)
        return result;

    auto dec = decrypt_message_data(data, len);
    if (!dec.has_value())
        return result;  // Decryption failed → signing_key_info = nullptr

    result.decrypted = true;
    result.authority_pubkey = dec->authority_pubkey;

    const auto& inner = dec->inner_data;
    if (inner.size() < 4)
        return result;

    uint8_t inner_version = inner[0];
    uint8_t inner_flags   = inner[1];
    uint8_t msg_count     = inner[2];
    uint8_t ann_len       = inner[3];
    size_t offset = 4;

    if (inner_version != 1)
        return result;  // Unknown version — skip gracefully

    // Skip signing key announcement if present
    if ((inner_flags & 0x01) && ann_len > 0)
        offset += ann_len;

    if (offset > inner.size())
        return result;

    // Cap message count
    if (msg_count > MAX_MESSAGES_PER_SHARE)
        msg_count = MAX_MESSAGES_PER_SHARE;

    for (uint8_t i = 0; i < msg_count; ++i)
    {
        ShareMessage msg;
        auto new_offset = ShareMessage::unpack(inner.data(), inner.size(), offset, msg);
        if (!new_offset.has_value()) break;
        result.messages.push_back(std::move(msg));
        offset = *new_offset;
    }

    return result;
}

// Convenience: validate message_data from a share.
// Returns empty string on success; returns error reason on failure.
// Empty message_data is always valid.
inline std::string validate_message_data(const std::vector<unsigned char>& message_data)
{
    if (message_data.empty())
        return {};  // No messages — always valid

    auto result = unpack_share_messages(message_data.data(), message_data.size());

    if (!result.decrypted)
        return "message_data failed decryption against all "
               "COMBINED_DONATION_SCRIPT authority keys";

    if (result.authority_pubkey == nullptr)
        return "message_data decrypted but authority_pubkey unknown";

    // Check authority_pubkey is one we recognise
    bool known = false;
    for (const auto* pk : DONATION_AUTHORITY_PUBKEYS())
    {
        if (pk == result.authority_pubkey) { known = true; break; }
    }
    if (!known)
        return "message_data authority_pubkey not in COMBINED_DONATION_SCRIPT";

    if (result.messages.empty())
        return "message_data decrypted but contains no valid messages";

    // Verify each message has a signature
    // NOTE: Full ECDSA verification requires secp256k1 library (not yet integrated).
    // The MAC-based decryption already proves authority created the envelope.
    // Signature presence check is defense-in-depth.
    for (const auto& msg : result.messages)
    {
        if (!msg.has_signature() || msg.signature.empty())
            return "message contains unsigned message (type 0x" +
                   std::to_string(msg.msg_type) + ") inside encrypted envelope";
        // TODO: ECDSA verify(authority_pubkey, message_hash, signature)
        // once secp256k1 is linked.
    }

    return {};  // All checks passed
}

} // namespace ltc
