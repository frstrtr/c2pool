// SPDX-License-Identifier: AGPL-3.0-or-later
#include "DashMessage.hpp"

#include "DashAddress.hpp"
#include "DashError.hpp"

// System libsecp256k1 recovery module (design §2.4) + btclibs base64 + hdkeys
// hash160. NO dashscript headers here.
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include <hash.h>
#include <util/strencodings.h>

#include "../hdkeys/Bip32.hpp" // hdkeys::hash160

#include <array>
#include <cstring>
#include <vector>

namespace c2w::dash {

namespace {

// Dash keeps the legacy DarkCoin message magic (chainparams.cpp strMessageMagic).
const std::string kMessageMagic = "DarkCoin Signed Message:\n";

std::vector<uint8_t> varstr(const std::string& s)
{
    std::vector<uint8_t> out;
    const uint64_t n = s.size();
    if (n < 0xFD) {
        out.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xFFFF) {
        out.push_back(0xFD);
        out.push_back(static_cast<uint8_t>(n & 0xFF));
        out.push_back(static_cast<uint8_t>((n >> 8) & 0xFF));
    } else {
        out.push_back(0xFE);
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((n >> (8 * i)) & 0xFF));
    }
    out.insert(out.end(), s.begin(), s.end());
    return out;
}

std::array<uint8_t, 32> message_hash(const std::string& message)
{
    std::vector<uint8_t> data = varstr(kMessageMagic);
    std::vector<uint8_t> m = varstr(message);
    data.insert(data.end(), m.begin(), m.end());
    std::array<uint8_t, 32> h{};
    legacy::CHash256().Write(data).Finalize(h);
    return h;
}

// A private secp context for the recovery ops (the signer's Crypto wrapper does
// not expose recovery, and this TU stays off the dashscript closure).
secp256k1_context* ctx()
{
    static secp256k1_context* c = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return c;
}

std::array<uint8_t, 20> pubkey_h160(const std::array<uint8_t, 33>& pub33)
{
    return hdkeys::hash160(pub33.data(), pub33.size());
}

} // namespace

std::string sign_message(const secure::SecureBytes& priv32,
                         const std::string& message,
                         const std::string& address,
                         bool testnet)
{
    if (priv32.size() != 32)
        throw DashAbort("private scalar must be 32 bytes");
    const std::array<uint8_t, 32> h = message_hash(message);

    secp256k1_ecdsa_recoverable_signature rsig;
    // nullptr noncefp => RFC6979 deterministic nonce; libsecp normalizes to
    // low-S for recoverable signatures.
    if (!secp256k1_ecdsa_sign_recoverable(ctx(), &rsig, h.data(), priv32.data(), nullptr, nullptr))
        throw DashAbort("recoverable signing failed (invalid scalar?)");

    std::array<uint8_t, 64> compact{};
    int recid = 0;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx(), compact.data(), &recid, &rsig);

    // 65-byte compact: header ‖ r ‖ s. +4 marks a compressed pubkey (Dash P2PKH
    // addresses use compressed keys).
    std::vector<uint8_t> sig65;
    sig65.reserve(65);
    sig65.push_back(static_cast<uint8_t>(27 + recid + 4));
    sig65.insert(sig65.end(), compact.begin(), compact.end());

    // SELF-VERIFY: recover the pubkey and confirm it hashes to THIS address —
    // never emit a signature that would not verify.
    secp256k1_pubkey rec;
    if (!secp256k1_ecdsa_recover(ctx(), &rec, &rsig, h.data()))
        throw DashAbort("self-verify FAILED: signature does not recover a pubkey");
    std::array<uint8_t, 33> pub33{};
    size_t publen = pub33.size();
    secp256k1_ec_pubkey_serialize(ctx(), pub33.data(), &publen, &rec, SECP256K1_EC_COMPRESSED);
    const std::string rec_addr = h160_to_addr(pubkey_h160(pub33), testnet);
    if (rec_addr != address)
        throw DashAbort("self-verify FAILED: signature recovers to " + rec_addr + ", not " +
                        address + " — refusing to emit (wrong derivation/passphrase?)");

    const std::string s(reinterpret_cast<const char*>(sig65.data()), sig65.size());
    return EncodeBase64(s);
}

bool verify_message(const std::string& address,
                    const std::string& message,
                    const std::string& sig_b64,
                    bool testnet)
{
    auto decoded = DecodeBase64(sig_b64);
    if (!decoded || decoded->size() != 65) return false;
    const std::vector<unsigned char>& sig65 = *decoded;

    const int header = sig65[0];
    if (header < 27 || header > 34) return false;
    const int recid = (header - 27) & 0x03;

    secp256k1_ecdsa_recoverable_signature rsig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx(), &rsig, sig65.data() + 1, recid))
        return false;

    std::array<uint8_t, 20> want_h160;
    try {
        want_h160 = addr_to_h160(address, testnet);
    } catch (const DashAbort&) {
        return false;
    }
    const std::array<uint8_t, 32> h = message_hash(message);

    secp256k1_pubkey rec;
    if (!secp256k1_ecdsa_recover(ctx(), &rec, &rsig, h.data())) return false;
    std::array<uint8_t, 33> pub33{};
    size_t publen = pub33.size();
    secp256k1_ec_pubkey_serialize(ctx(), pub33.data(), &publen, &rec, SECP256K1_EC_COMPRESSED);
    if (pubkey_h160(pub33) != want_h160) return false;

    // Independent leg: the standard-ECDSA form of the recovered sig must verify
    // under the recovered pubkey (defends against a malformed recid slipping
    // through recovery yet not being a valid signature).
    secp256k1_ecdsa_signature std_sig;
    secp256k1_ecdsa_recoverable_signature_convert(ctx(), &std_sig, &rsig);
    return secp256k1_ecdsa_verify(ctx(), &std_sig, h.data(), &rec) == 1;
}

} // namespace c2w::dash
