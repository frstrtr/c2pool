// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Bip38.hpp"

#include "Aes256.hpp"
#include "Address.hpp"
#include "Bip32.hpp"     // hash160 (unused here but keeps the address helpers coherent)
#include "Scrypt.hpp"
#include "Secp.hpp"

#include <btclibs/base58.h>
#include <btclibs/crypto/sha256.h>

#include <cstring>

namespace c2w::hdkeys {

namespace {

void sha256d(const uint8_t* in, size_t n, uint8_t out[32])
{
    uint8_t t[32];
    CSHA256().Write(in, n).Finalize(t);
    CSHA256().Write(t, 32).Finalize(out);
}

// The BIP38 address-hash: first 4 bytes of SHA256d over the ASCII P2PKH address
// string (BTC mainnet version byte 0x00), using the compressed/uncompressed
// pubkey per the flag byte. Returns true iff it matches the embedded 4 bytes.
bool address_hash_ok(const uint8_t scalar[32], bool compressed, const uint8_t want[4])
{
    auto pub = Secp::instance().pubkey_create(scalar, compressed);
    if (pub.empty()) return false;
    auto h = hash160(pub.data(), pub.size());
    std::string addr = encode_p2pkh(0x00, h);   // BIP38 checksum is defined over the BTC address
    uint8_t chk[32];
    sha256d(reinterpret_cast<const uint8_t*>(addr.data()), addr.size(), chk);
    return std::memcmp(chk, want, 4) == 0;
}

} // namespace

Bip38Decode decode_bip38(const std::string& encrypted, const std::string& passphrase)
{
    Bip38Decode r;
    std::vector<unsigned char> data;
    if (!DecodeBase58Check(encrypted, data, 43)) { r.error = "not valid base58check"; return r; }
    if (data.size() != 39) { r.error = "wrong BIP38 payload length"; return r; }

    const uint8_t prefix0 = data[0], prefix1 = data[1], flag = data[2];
    const uint8_t* addresshash = data.data() + 3;

    auto& secp = Secp::instance();

    if (prefix0 == 0x01 && prefix1 == 0x42) {
        // ── non-EC-multiply ──────────────────────────────────────────────
        r.compressed = (flag & 0x20) != 0;
        const uint8_t* eh1 = data.data() + 7;    // 16
        const uint8_t* eh2 = data.data() + 23;   // 16
        auto derived = scrypt_general(reinterpret_cast<const uint8_t*>(passphrase.data()),
                                      passphrase.size(), addresshash, 4, 16384, 8, 8, 64);
        const uint8_t* dh1 = derived.data();
        const uint8_t* dh2 = derived.data() + 32;
        Aes256 aes(dh2);
        uint8_t sk[32];
        aes.decrypt_block(eh1, sk);
        aes.decrypt_block(eh2, sk + 16);
        for (int i = 0; i < 32; ++i) sk[i] ^= dh1[i];
        std::memset(derived.data(), 0, derived.size());

        if (!secp.seckey_verify(sk)) { r.error = "decrypted scalar out of range"; secure::secure_wipe(sk, 32); return r; }
        if (!address_hash_ok(sk, r.compressed, addresshash)) {
            r.error = "wrong passphrase (address-hash checksum mismatch)";
            secure::secure_wipe(sk, 32); return r;
        }
        r.scalar.assign(sk, 32);
        secure::secure_wipe(sk, 32);
        r.ok = true;
        return r;
    }

    if (prefix0 == 0x01 && prefix1 == 0x43) {
        // ── EC-multiply ─────────────────────────────────────────────────
        r.ec_multiply = true;
        r.compressed = (flag & 0x20) != 0;
        r.lot_sequence = (flag & 0x04) != 0;
        const uint8_t* ownerentropy = data.data() + 7;         // 8
        const uint8_t* encryptedpart1_half = data.data() + 15; // 8
        const uint8_t* encryptedpart2 = data.data() + 23;      // 16

        const size_t ownersalt_len = r.lot_sequence ? 4 : 8;
        auto prefactor = scrypt_general(reinterpret_cast<const uint8_t*>(passphrase.data()),
                                        passphrase.size(), ownerentropy, ownersalt_len, 16384, 8, 8, 32);
        uint8_t passfactor[32];
        if (r.lot_sequence) {
            uint8_t buf[40];
            std::memcpy(buf, prefactor.data(), 32);
            std::memcpy(buf + 32, ownerentropy, 8);
            sha256d(buf, 40, passfactor);
            secure::secure_wipe(buf, sizeof(buf));
        } else {
            std::memcpy(passfactor, prefactor.data(), 32);
        }
        std::memset(prefactor.data(), 0, prefactor.size());

        auto passpoint = secp.pubkey_create(passfactor, /*compressed=*/true);
        if (passpoint.size() != 33) { r.error = "invalid passpoint"; secure::secure_wipe(passfactor, 32); return r; }

        uint8_t salt2[12];
        std::memcpy(salt2, addresshash, 4);
        std::memcpy(salt2 + 4, ownerentropy, 8);
        auto derived = scrypt_general(passpoint.data(), 33, salt2, 12, 1024, 1, 1, 64);
        const uint8_t* dh1 = derived.data();
        const uint8_t* dh2 = derived.data() + 32;
        Aes256 aes(dh2);

        // decryptedpart2 = AES_dec(encryptedpart2) XOR dh1[16:32]
        uint8_t dp2[16];
        aes.decrypt_block(encryptedpart2, dp2);
        for (int i = 0; i < 16; ++i) dp2[i] ^= dh1[16 + i];
        // dp2[0:8] = encryptedpart1[8:16]; dp2[8:16] = seedb[16:24]
        uint8_t ep1full[16];
        std::memcpy(ep1full, encryptedpart1_half, 8);
        std::memcpy(ep1full + 8, dp2, 8);
        uint8_t dp1[16];
        aes.decrypt_block(ep1full, dp1);
        for (int i = 0; i < 16; ++i) dp1[i] ^= dh1[i];   // = seedb[0:16]

        uint8_t seedb[24];
        std::memcpy(seedb, dp1, 16);
        std::memcpy(seedb + 16, dp2 + 8, 8);
        uint8_t factorb[32];
        sha256d(seedb, 24, factorb);

        // privkey = passfactor * factorb mod N
        uint8_t sk[32];
        std::memcpy(sk, passfactor, 32);
        bool mul_ok = secp.seckey_tweak_mul(sk, factorb);

        std::memset(derived.data(), 0, derived.size());
        secure::secure_wipe(dp1, 16); secure::secure_wipe(dp2, 16);
        secure::secure_wipe(seedb, 24); secure::secure_wipe(factorb, 32);
        secure::secure_wipe(passfactor, 32); secure::secure_wipe(ep1full, 16);

        if (!mul_ok || !secp.seckey_verify(sk)) { r.error = "decrypted scalar out of range"; secure::secure_wipe(sk, 32); return r; }
        if (!address_hash_ok(sk, r.compressed, addresshash)) {
            r.error = "wrong passphrase (address-hash checksum mismatch)";
            secure::secure_wipe(sk, 32); return r;
        }
        r.scalar.assign(sk, 32);
        secure::secure_wipe(sk, 32);
        r.ok = true;
        return r;
    }

    r.error = "unrecognised BIP38 prefix (expect 0x0142 or 0x0143)";
    return r;
}

} // namespace c2w::hdkeys
