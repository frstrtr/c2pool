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
//   6. Verify ECDSA signatures via libsecp256k1

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include <btclibs/crypto/hmac_sha256.h>
#include <btclibs/crypto/ripemd160.h>
#include <btclibs/crypto/sha256.h>
#include <secp256k1.h>

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
// secp256k1 context (singleton, thread-safe after init)
// ============================================================================

inline const secp256k1_context* get_secp256k1_context()
{
    static const secp256k1_context* ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    return ctx;
}

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

// Double-SHA256 of message content for ECDSA signing/verification.
// Matches Python: SHA256(SHA256(pack('<BBI', msg_type, wire_flags, timestamp) + payload))
inline std::array<unsigned char, 32> compute_message_hash(
    uint8_t msg_type, uint8_t wire_flags, uint32_t timestamp,
    const unsigned char* payload, size_t payload_len)
{
    unsigned char header[6];
    header[0] = msg_type;
    header[1] = wire_flags;
    std::memcpy(header + 2, &timestamp, 4); // LE

    unsigned char first[32];
    CSHA256().Write(header, 6).Write(payload, payload_len).Finalize(first);

    std::array<unsigned char, 32> result;
    CSHA256().Write(first, 32).Finalize(result.data());
    return result;
}

// Verify ECDSA signature against a compressed secp256k1 public key.
// pubkey_compressed: 33 bytes (0x02/0x03 prefix)
// msghash32: 32-byte double-SHA256 (from compute_message_hash)
// sig_der: DER-encoded ECDSA signature
// Returns true if signature is valid.
inline bool ecdsa_verify(const unsigned char* pubkey_compressed, size_t pubkey_len,
                         const unsigned char* msghash32,
                         const unsigned char* sig_der, size_t sig_len)
{
    const auto* ctx = get_secp256k1_context();

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkey_compressed, pubkey_len))
        return false;

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_der(ctx, &sig, sig_der, sig_len))
        return false;

    // Normalize to lower-S form (secp256k1_ecdsa_verify requires this)
    secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);

    return secp256k1_ecdsa_verify(ctx, &sig, msghash32, &pubkey) == 1;
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

    // Verify each message has a valid ECDSA signature from the authority key
    // that encrypted the envelope. This is defense-in-depth on top of the
    // MAC-based decryption (which already proves authority created the envelope).
    for (const auto& msg : result.messages)
    {
        if (!msg.has_signature() || msg.signature.empty())
            return "message contains unsigned message (type 0x" +
                   std::to_string(msg.msg_type) + ") inside encrypted envelope";

        auto msg_hash = compute_message_hash(
            msg.msg_type, msg.wire_flags, msg.timestamp,
            msg.payload.data(), msg.payload.size());

        if (!ecdsa_verify(result.authority_pubkey->data(), result.authority_pubkey->size(),
                          msg_hash.data(), msg.signature.data(), msg.signature.size()))
            return "message ECDSA signature verification failed (type 0x" +
                   std::to_string(msg.msg_type) + ")";
    }

    return {};  // All checks passed
}

// ============================================================================
// Message creation: signing, packing, encryption
// ============================================================================

// ECDSA sign a 32-byte hash with a 32-byte private key.
// Returns DER-encoded signature, empty on failure.
inline std::vector<unsigned char> ecdsa_sign(
    const unsigned char* msghash32,
    const unsigned char* seckey32)
{
    const auto* ctx = get_secp256k1_context();

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, msghash32, seckey32, nullptr, nullptr))
        return {};

    unsigned char der[72];
    size_t der_len = sizeof(der);
    if (!secp256k1_ecdsa_signature_serialize_der(ctx, der, &der_len, &sig))
        return {};

    return {der, der + der_len};
}

// HASH160 = RIPEMD160(SHA256(data)) — standard Bitcoin hash160.
inline std::array<unsigned char, 20> hash160(
    const unsigned char* data, size_t len)
{
    unsigned char sha256_buf[32];
    CSHA256().Write(data, len).Finalize(sha256_buf);

    std::array<unsigned char, 20> result;
    CRIPEMD160().Write(sha256_buf, 32).Finalize(result.data());
    return result;
}

// Serialize a ShareMessage to wire format.
// Wire: [type:1][flags:1][timestamp:4 LE][payload_len:2 LE][payload:N]
//       [signing_id:20][sig_len:1][signature:M]
inline std::vector<unsigned char> pack_message(const ShareMessage& msg)
{
    std::vector<unsigned char> buf;
    buf.reserve(8 + msg.payload.size() + 20 + 1 + msg.signature.size());

    buf.push_back(msg.msg_type);
    buf.push_back(msg.wire_flags);

    uint32_t ts = msg.timestamp;
    buf.push_back(static_cast<unsigned char>(ts));
    buf.push_back(static_cast<unsigned char>(ts >> 8));
    buf.push_back(static_cast<unsigned char>(ts >> 16));
    buf.push_back(static_cast<unsigned char>(ts >> 24));

    uint16_t pl = static_cast<uint16_t>(msg.payload.size());
    buf.push_back(static_cast<unsigned char>(pl));
    buf.push_back(static_cast<unsigned char>(pl >> 8));

    buf.insert(buf.end(), msg.payload.begin(), msg.payload.end());
    buf.insert(buf.end(), msg.signing_id.begin(), msg.signing_id.end());

    buf.push_back(static_cast<unsigned char>(msg.signature.size()));
    buf.insert(buf.end(), msg.signature.begin(), msg.signature.end());

    return buf;
}

// Encrypt inner envelope data with an authority public key.
// Returns encrypted blob: [0x01][nonce:16][mac:32][ciphertext:N]
inline std::vector<unsigned char> encrypt_message_envelope(
    const std::vector<unsigned char>& inner,
    const AuthorityPubkey& authority_pubkey)
{
    // 16-byte random nonce
    std::array<unsigned char, ENCRYPTION_NONCE_SIZE> nonce;
    std::random_device rd;
    for (size_t i = 0; i < ENCRYPTION_NONCE_SIZE; i += 4)
    {
        auto val = rd();
        auto bytes = std::min<size_t>(4, ENCRYPTION_NONCE_SIZE - i);
        std::memcpy(nonce.data() + i, &val, bytes);
    }

    // enc_key = HMAC-SHA256(authority_pubkey, nonce)
    auto enc_key = hmac_sha256(
        authority_pubkey.data(), authority_pubkey.size(),
        nonce.data(), nonce.size());

    // stream = counter-mode SHA256
    std::vector<unsigned char> stream(inner.size());
    generate_stream(enc_key.data(), stream.data(), inner.size());

    // ciphertext = inner XOR stream
    std::vector<unsigned char> ciphertext(inner.size());
    for (size_t i = 0; i < inner.size(); ++i)
        ciphertext[i] = inner[i] ^ stream[i];

    // mac = HMAC-SHA256(enc_key, ciphertext)
    auto mac = hmac_sha256(
        enc_key.data(), enc_key.size(),
        ciphertext.data(), ciphertext.size());

    // Assemble: [0x01][nonce:16][mac:32][ciphertext]
    std::vector<unsigned char> result;
    result.reserve(1 + ENCRYPTION_NONCE_SIZE + ENCRYPTION_MAC_SIZE + ciphertext.size());
    result.push_back(ENCRYPTED_ENVELOPE_VERSION);
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), mac.begin(), mac.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    return result;
}

// Create encrypted message_data blob for embedding in a V36 share.
//
// seckey:           32-byte private key
// authority_pubkey: 33-byte compressed pubkey corresponding to seckey
// messages:         ShareMessages with msg_type, wire_flags, timestamp, payload set.
//                   signature and signing_id are computed and filled in.
//
// Returns the complete encrypted message_data blob, or empty on failure.
inline std::vector<unsigned char> create_message_data(
    const unsigned char* seckey,
    const AuthorityPubkey& authority_pubkey,
    std::vector<ShareMessage>& messages)
{
    if (messages.empty() || messages.size() > MAX_MESSAGES_PER_SHARE)
        return {};

    // Compute signing_id = HASH160(authority_pubkey)
    auto signing_id = hash160(authority_pubkey.data(), authority_pubkey.size());

    // Sign each message and serialize
    std::vector<unsigned char> packed_messages;
    for (auto& msg : messages)
    {
        msg.signing_id = signing_id;

        auto msg_hash = compute_message_hash(
            msg.msg_type, msg.wire_flags, msg.timestamp,
            msg.payload.data(), msg.payload.size());

        msg.signature = ecdsa_sign(msg_hash.data(), seckey);
        if (msg.signature.empty())
            return {};

        auto packed = pack_message(msg);
        packed_messages.insert(packed_messages.end(), packed.begin(), packed.end());
    }

    // Inner envelope: [version=1][flags=0][msg_count][reserved=0] + packed_messages
    std::vector<unsigned char> inner;
    inner.reserve(4 + packed_messages.size());
    inner.push_back(0x01);
    inner.push_back(0x00);
    inner.push_back(static_cast<unsigned char>(messages.size()));
    inner.push_back(0x00);
    inner.insert(inner.end(), packed_messages.begin(), packed_messages.end());

    if (inner.size() > MAX_TOTAL_MESSAGE_BYTES)
        return {};

    return encrypt_message_envelope(inner, authority_pubkey);
}

} // namespace ltc
