// SPDX-License-Identifier: AGPL-3.0-or-later
#include "DashMessage.hpp"

#include "DashAddress.hpp"
#include "DashError.hpp"

// System libsecp256k1 recovery module (design §2.4) + btclibs base64 + hdkeys
// hash160 and the CoinParams P2PKH SSOT. NO dashscript headers here.
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include <hash.h>
#include <util/strencodings.h>

#include "../hdkeys/Bip32.hpp" // hdkeys::hash160
#include "../hdkeys/CoinParams.hpp"

#include <array>
#include <cstring>
#include <vector>

namespace c2w::dash {

namespace {

// Mainnet P2PKH byte from the hdkeys CoinParams table (which mirrors the
// address_encoding.hpp SSOT); never re-hardcoded here.
uint8_t ssot_p2pkh(const char* ticker)
{
    const hdkeys::CoinParams* c = hdkeys::coin_by_ticker(ticker);
    return c ? c->p2pkh_version : 0xff;
}

void append_varstr(std::vector<uint8_t>& out, const uint8_t* p, size_t n64)
{
    const uint64_t n = n64;
    if (n < 0xFD) {
        out.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xFFFF) {
        out.push_back(0xFD);
        out.push_back(static_cast<uint8_t>(n & 0xFF));
        out.push_back(static_cast<uint8_t>((n >> 8) & 0xFF));
    } else if (n <= 0xFFFFFFFFull) {
        out.push_back(0xFE);
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((n >> (8 * i)) & 0xFF));
    } else {
        out.push_back(0xFF);
        for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>((n >> (8 * i)) & 0xFF));
    }
    out.insert(out.end(), p, p + n64);
}

// A private secp context for the recovery ops (the signer's Crypto wrapper does
// not expose recovery, and this TU stays off the dashscript closure).
secp256k1_context* ctx()
{
    static secp256k1_context* c = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return c;
}

// The pubkey in the encoding the header bit selects: 33 bytes compressed, 65
// uncompressed (Core: CPubKey::RecoverCompact with fComp).
std::vector<uint8_t> serialize_pub(const secp256k1_pubkey& pk, bool compressed)
{
    std::vector<uint8_t> out(compressed ? 33 : 65);
    size_t len = out.size();
    secp256k1_ec_pubkey_serialize(ctx(), out.data(), &len, &pk,
                                  compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    out.resize(len);
    return out;
}

uint8_t version_for(const MessageCoin& coin, bool testnet)
{
    return testnet ? coin.p2pkh_testnet : coin.p2pkh_mainnet;
}

std::string unproven_reason(const MessageCoin& coin)
{
    return std::string(coin.ticker) + " message signing is refused: no node vector proves its magic yet "
                                      "(a signmessagewithprivkey vector from the coin's own node must be "
                                      "committed to msg_vectors.hpp first)";
}

bool fail(VerifyReport* r, const std::string& why)
{
    if (r) {
        r->valid = false;
        r->why = why;
    }
    return false;
}

} // namespace

// ── the coin table ──────────────────────────────────────────────────────────

const std::vector<MessageCoin>& message_coins()
{
    // Magics of the unproven rows are each chain's strMessageMagic as published
    // in its Core fork; they stay refused until a node vector exists. Testnet
    // P2PKH bytes are not in CoinParams (mainnet-only table) and are pinned here
    // to each Core's chainparams. BCH is left out on purpose: its legacy-address
    // signing needs the CashAddr -> legacy mapping decision first.
    static const std::vector<MessageCoin> coins = {
        {"DASH", "DarkCoin Signed Message:\n", kMainnetP2PKHVersion, kTestnetP2PKHVersion, true},
        {"BTC", "Bitcoin Signed Message:\n", ssot_p2pkh("BTC"), 0x6f, false},
        {"LTC", "Litecoin Signed Message:\n", ssot_p2pkh("LTC"), 0x6f, false},
        {"DGB", "DigiByte Signed Message:\n", ssot_p2pkh("DGB"), 0x7e, false},
        {"DOGE", "Dogecoin Signed Message:\n", ssot_p2pkh("DOGE"), 0x71, false},
    };
    return coins;
}

const MessageCoin& message_coin(const std::string& ticker)
{
    for (const MessageCoin& c : message_coins())
        if (ticker == c.ticker) return c;
    throw DashAbort("unknown message-signing coin \"" + ticker + "\"");
}

std::array<uint8_t, 32> message_digest(const MessageCoin& coin, const std::vector<uint8_t>& message)
{
    const size_t mlen = std::strlen(coin.magic);
    std::vector<uint8_t> data;
    data.reserve(mlen + message.size() + 12);
    append_varstr(data, reinterpret_cast<const uint8_t*>(coin.magic), mlen);
    append_varstr(data, message.data(), message.size());
    std::array<uint8_t, 32> h{};
    legacy::CHash256().Write(data).Finalize(h);
    return h;
}

// ── sign ────────────────────────────────────────────────────────────────────

std::string sign_message(const MessageCoin& coin,
                         const secure::SecureBytes& priv32,
                         bool compressed,
                         const std::vector<uint8_t>& message,
                         const std::string& address,
                         bool testnet)
{
    if (!coin.kat_proven) throw DashAbort(unproven_reason(coin));
    if (priv32.size() != 32) throw DashAbort("private scalar must be 32 bytes");
    const uint8_t version = version_for(coin, testnet);
    const std::array<uint8_t, 20> want = p2pkh_to_h160(address, version);
    const std::array<uint8_t, 32> h = message_digest(coin, message);

    secp256k1_ecdsa_recoverable_signature rsig;
    // nullptr noncefp => RFC6979 deterministic nonce; libsecp normalizes to
    // low-S for recoverable signatures.
    if (!secp256k1_ecdsa_sign_recoverable(ctx(), &rsig, h.data(), priv32.data(), nullptr, nullptr))
        throw DashAbort("recoverable signing failed (invalid scalar?)");

    std::array<uint8_t, 64> compact{};
    int recid = 0;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx(), compact.data(), &recid, &rsig);

    // 65-byte compact: header ‖ r ‖ s. +4 marks a compressed pubkey (Core
    // MessageSign -> CKey::SignCompact: 27 + recid + (fCompressed ? 4 : 0)).
    std::vector<uint8_t> sig65;
    sig65.reserve(65);
    sig65.push_back(static_cast<uint8_t>(27 + recid + (compressed ? 4 : 0)));
    sig65.insert(sig65.end(), compact.begin(), compact.end());

    // SELF-VERIFY 1: recover the pubkey, serialize it in the SAME encoding the
    // header claims, and confirm it hashes to THIS address.
    secp256k1_pubkey rec;
    if (!secp256k1_ecdsa_recover(ctx(), &rec, &rsig, h.data()))
        throw DashAbort("self-verify FAILED: signature does not recover a pubkey");
    const std::vector<uint8_t> pub = serialize_pub(rec, compressed);
    const std::array<uint8_t, 20> got = hdkeys::hash160(pub.data(), pub.size());
    if (got != want) {
        const std::string rec_addr = h160_to_p2pkh(got, version);
        throw DashAbort("self-verify FAILED: the " + std::string(compressed ? "compressed" : "uncompressed") +
                        " signature recovers to " + rec_addr + ", not " + address +
                        " — refusing to emit (wrong key, derivation, passphrase or key encoding?)");
    }

    const std::string s(reinterpret_cast<const char*>(sig65.data()), sig65.size());
    const std::string b64 = EncodeBase64(s);

    // SELF-VERIFY 2: the emitted base64 through the very verifier a third party
    // runs (decode, header, recover, hash160, independent ECDSA verify).
    VerifyReport vr;
    if (!verify_message(coin, address, message, b64, testnet, &vr))
        throw DashAbort("self-verify FAILED on the emitted signature (" + vr.why + ") — refusing to emit");
    return b64;
}

std::string sign_message(const MessageCoin& coin,
                         const FoundKey& key,
                         const std::vector<uint8_t>& message,
                         bool testnet)
{
    if (key.pub.size() != (key.compressed ? 33u : 65u))
        throw DashAbort("the key is malformed (pubkey length does not match its encoding) — refusing to sign");
    return sign_message(coin, key.priv, key.compressed, message, key.address, testnet);
}

// ── verify ──────────────────────────────────────────────────────────────────

bool verify_message(const MessageCoin& coin,
                    const std::string& address,
                    const std::vector<uint8_t>& message,
                    const std::string& sig_b64,
                    bool testnet,
                    VerifyReport* report)
{
    if (report) *report = VerifyReport{};
    if (!coin.kat_proven) return fail(report, unproven_reason(coin));
    if (sig_b64.empty()) return fail(report, "empty signature");
    auto decoded = DecodeBase64(sig_b64);
    if (!decoded) return fail(report, "bad base64");
    if (decoded->size() != 65)
        return fail(report, "not 65 bytes (decodes to " + std::to_string(decoded->size()) + ")");
    const std::vector<unsigned char>& sig65 = *decoded;

    // Core's RecoverCompact masks the header without a range check; a Core
    // signature is always 27..34. Anything else (BIP137 segwit headers 35..42
    // included, a non-goal) is refused here.
    const int header = sig65[0];
    if (header < 27 || header > 34)
        return fail(report, "header " + std::to_string(header) + " out of 27..34");
    const int recid = (header - 27) & 0x03;
    const bool compressed = ((header - 27) & 0x04) != 0;
    if (report) {
        report->recid = recid;
        report->header_compressed = compressed;
    }

    secp256k1_ecdsa_recoverable_signature rsig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx(), &rsig, sig65.data() + 1, recid))
        return fail(report, "r or s does not parse (out of range)");

    std::array<uint8_t, 20> want_h160;
    const uint8_t version = version_for(coin, testnet);
    try {
        want_h160 = p2pkh_to_h160(address, version);
    } catch (const DashAbort& e) {
        return fail(report, e.what());
    }
    const std::array<uint8_t, 32> h = message_digest(coin, message);

    secp256k1_pubkey rec;
    if (!secp256k1_ecdsa_recover(ctx(), &rec, &rsig, h.data()))
        return fail(report, "no public key recovers from this signature and message");
    const std::vector<uint8_t> pub = serialize_pub(rec, compressed);
    const std::array<uint8_t, 20> got = hdkeys::hash160(pub.data(), pub.size());
    if (report) report->recovered_address = h160_to_p2pkh(got, version);
    if (got != want_h160)
        return fail(report, "recovers to " + h160_to_p2pkh(got, version) + ", not " + address);

    // Independent leg: the standard-ECDSA form of the recovered sig must verify
    // under the recovered pubkey (defends against a malformed recid slipping
    // through recovery yet not being a valid signature). Normalized first:
    // libsecp's verify requires low-S, Core's message verify does not (it only
    // recovers), so a high-S signature Core accepts is accepted here too.
    secp256k1_ecdsa_signature std_sig;
    secp256k1_ecdsa_recoverable_signature_convert(ctx(), &std_sig, &rsig);
    secp256k1_ecdsa_signature_normalize(ctx(), &std_sig, &std_sig);
    if (secp256k1_ecdsa_verify(ctx(), &std_sig, h.data(), &rec) != 1)
        return fail(report, "the ECDSA verify under the recovered key failed");

    if (report) {
        report->valid = true;
        report->why.clear();
    }
    return true;
}

// ── the original entry points ───────────────────────────────────────────────

std::string sign_message(const secure::SecureBytes& priv32,
                         const std::string& message,
                         const std::string& address,
                         bool testnet)
{
    return sign_message(message_coin("DASH"), priv32, /*compressed=*/true,
                        std::vector<uint8_t>(message.begin(), message.end()), address, testnet);
}

bool verify_message(const std::string& address,
                    const std::string& message,
                    const std::string& sig_b64,
                    bool testnet)
{
    return verify_message(message_coin("DASH"), address, std::vector<uint8_t>(message.begin(), message.end()),
                          sig_b64, testnet);
}

} // namespace c2w::dash
