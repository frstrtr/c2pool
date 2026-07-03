#include <gtest/gtest.h>

#include <impl/dash/share_messages.hpp>

namespace {

std::vector<unsigned char> make_unsigned_test_blob_with_key(const dash::AuthorityPubkey& key)
{
    dash::ShareMessage msg;
    msg.msg_type = dash::MSG_TRANSITION_SIGNAL;
    msg.wire_flags = dash::FLAG_PROTOCOL_AUTHORITY;
    msg.timestamp = 1710000000;
    msg.payload = {0x01, 0x02, 0x03, 0x04};
    msg.signing_id.fill(0x11);
    msg.signature.clear();

    auto packed = dash::pack_message(msg);

    // Inner envelope: [version=1][flags=0][msg_count=1][announcement_len=0] + packed msg
    std::vector<unsigned char> inner = {0x01, 0x00, 0x01, 0x00};
    inner.insert(inner.end(), packed.begin(), packed.end());

    return dash::encrypt_message_envelope(inner, key);
}

} // namespace

TEST(DashShareMessages, DecryptsWithKnownAuthorityKey)
{
    auto blob = make_unsigned_test_blob_with_key(dash::DONATION_PUBKEY_FORRESTV());
    ASSERT_FALSE(blob.empty());

    auto unpacked = dash::unpack_share_messages(blob.data(), blob.size());
    EXPECT_TRUE(unpacked.decrypted);
    ASSERT_NE(unpacked.authority_pubkey, nullptr);
    EXPECT_EQ(*unpacked.authority_pubkey, dash::DONATION_PUBKEY_FORRESTV());

    ASSERT_EQ(unpacked.messages.size(), 1u);
    EXPECT_EQ(unpacked.messages[0].msg_type, dash::MSG_TRANSITION_SIGNAL);
}

TEST(DashShareMessages, ValidationRejectsUnsignedMessage)
{
    auto blob = make_unsigned_test_blob_with_key(dash::DONATION_PUBKEY_FORRESTV());
    ASSERT_FALSE(blob.empty());

    // Decrypts with known authority key, but fails signature policy (expected).
    auto err = dash::validate_message_data(blob);
    EXPECT_FALSE(err.empty());
}

TEST(DashShareMessages, UnknownAuthorityKeyCannotDecrypt)
{
    dash::AuthorityPubkey unknown{};
    unknown[0] = 0x02;
    for (size_t i = 1; i < unknown.size(); ++i)
        unknown[i] = static_cast<unsigned char>(i);

    auto blob = make_unsigned_test_blob_with_key(unknown);
    ASSERT_FALSE(blob.empty());

    auto unpacked = dash::unpack_share_messages(blob.data(), blob.size());
    EXPECT_FALSE(unpacked.decrypted);
    EXPECT_EQ(unpacked.authority_pubkey, nullptr);
    EXPECT_TRUE(unpacked.messages.empty());
}

// ---- Maintainer (frstrtr) key tests ----

TEST(DashShareMessages, MaintainerKeyDecryptsCorrectly)
{
    // DONATION_PUBKEY_MAINTAINER is the c2pool/frstrtr authority key.
    // Envelope encrypted to this key must decrypt and identify it.
    auto blob = make_unsigned_test_blob_with_key(dash::DONATION_PUBKEY_MAINTAINER());
    ASSERT_FALSE(blob.empty());

    auto unpacked = dash::unpack_share_messages(blob.data(), blob.size());
    EXPECT_TRUE(unpacked.decrypted);
    ASSERT_NE(unpacked.authority_pubkey, nullptr);
    EXPECT_EQ(*unpacked.authority_pubkey, dash::DONATION_PUBKEY_MAINTAINER());

    ASSERT_EQ(unpacked.messages.size(), 1u);
    EXPECT_EQ(unpacked.messages[0].msg_type, dash::MSG_TRANSITION_SIGNAL);
}

TEST(DashShareMessages, MaintainerKeyNotMistakenForForrestv)
{
    // Encrypt to MAINTAINER — must NOT be attributed to FORRESTV.
    auto blob = make_unsigned_test_blob_with_key(dash::DONATION_PUBKEY_MAINTAINER());

    auto unpacked = dash::unpack_share_messages(blob.data(), blob.size());
    ASSERT_TRUE(unpacked.decrypted);
    EXPECT_NE(unpacked.authority_pubkey, &dash::DONATION_PUBKEY_FORRESTV());
    EXPECT_EQ(unpacked.authority_pubkey,  &dash::DONATION_PUBKEY_MAINTAINER());
}

// ---- MAC integrity (built-in checksum) ----
//
// The envelope stores a 32-byte HMAC-SHA256 MAC at bytes [17..48].
//   enc_key = HMAC-SHA256(authority_pubkey, nonce)
//   mac     = HMAC-SHA256(enc_key, ciphertext)
// A single bit-flip anywhere in the ciphertext invalidates the MAC and
// makes decrypt_message_data() return nullopt — no garbage plaintext can
// pass through silently.

TEST(DashShareMessages, TamperedCiphertextRejectedByMAC)
{
    auto blob = make_unsigned_test_blob_with_key(dash::DONATION_PUBKEY_FORRESTV());
    ASSERT_GE(blob.size(), dash::ENCRYPTION_HEADER_SIZE + 1u);

    // Flip one bit in the very first ciphertext byte (byte 49, right after header).
    blob[dash::ENCRYPTION_HEADER_SIZE] ^= 0x01;

    auto unpacked = dash::unpack_share_messages(blob.data(), blob.size());
    EXPECT_FALSE(unpacked.decrypted)
        << "Tampered ciphertext must be rejected by HMAC-SHA256 MAC check";
}

TEST(DashShareMessages, TamperedMACFieldRejected)
{
    auto blob = make_unsigned_test_blob_with_key(dash::DONATION_PUBKEY_MAINTAINER());
    ASSERT_GE(blob.size(), dash::ENCRYPTION_HEADER_SIZE);

    // MAC is stored at bytes [1 + NONCE_SIZE .. 1 + NONCE_SIZE + MAC_SIZE).
    // Corrupt the first byte of the stored MAC.
    constexpr size_t mac_offset = 1 + dash::ENCRYPTION_NONCE_SIZE;  // byte 17
    blob[mac_offset] ^= 0xFF;

    auto unpacked = dash::unpack_share_messages(blob.data(), blob.size());
    EXPECT_FALSE(unpacked.decrypted)
        << "Corrupted MAC field must be rejected; no valid authority key will match";
}

TEST(DashShareMessages, TruncatedBlobRejected)
{
    auto blob = make_unsigned_test_blob_with_key(dash::DONATION_PUBKEY_FORRESTV());
    // Truncate to header size exactly — no ciphertext bytes.
    blob.resize(dash::ENCRYPTION_HEADER_SIZE);

    auto unpacked = dash::unpack_share_messages(blob.data(), blob.size());
    EXPECT_FALSE(unpacked.decrypted)
        << "Truncated blob (ct_len == 0) must be rejected";
}

TEST(DashShareMessages, EmptyBlobIsAlwaysValid)
{
    // Empty message_data means 'no messages' — validate_message_data must accept it.
    std::vector<unsigned char> empty;
    auto err = dash::validate_message_data(empty);
    EXPECT_TRUE(err.empty())
        << "Empty message_data must be valid (no messages): " << err;
}
