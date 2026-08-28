// SPDX-License-Identifier: AGPL-3.0-or-later
// AddressValidator — in-UI payout-address flavor check (QP-B).
//
// c2pool-qt is coin-generic: the same launch form serves LTC/BTC/DOGE/
// DASH/DGB/BCH. A payout address pasted into the wrong coin's profile is
// a silent money mistake — miners paid to an address the winning coin's
// nodes reject, or worse, an address that decodes to a DIFFERENT live
// chain. This validator catches the unambiguous case: a base58check
// address whose version byte belongs to a *known other coin*.
//
// Design (deliberately low false-positive so it never blocks a valid
// launch):
//   • Only base58check (25-byte, checksum-verified) addresses are judged.
//     bech32 / cashaddr / anything else decode-fails here and is passed
//     through UNJUDGED (NotBase58Check) — we do not model those yet and
//     must not reject a valid segwit/cashaddr address.
//   • WrongCoin — and only WrongCoin — is a hard launch blocker. It fires
//     when the version byte matches NO network of the active coin but DOES
//     match some other coin in the CoinProfiles table (e.g. a DASH 'X…'
//     address, version 76, typed into a Litecoin profile).
//   • Version-byte collisions between coins (BTC/BCH share 0/5; DOGE/DGB
//     share 30) resolve in the user's favour: if the version is valid for
//     the active coin under ANY network, the verdict is Ok.
//
// Qt Core only (QString / QByteArray / QCryptographicHash) — no Widgets,
// no WebEngine — so it is unit-testable without a display.

#pragma once

#include "CoinProfiles.hpp"

#include <QByteArray>
#include <QCryptographicHash>
#include <QLatin1String>
#include <QString>

#include <cstdint>
#include <cstring>
#include <vector>

namespace c2pool_qt {

enum class AddressVerdict {
    Ok,             ///< base58check valid; version belongs to the active coin
    WrongCoin,      ///< base58check valid; version belongs to a DIFFERENT coin
    UnknownVersion, ///< base58check valid; version not in our coin table
    NotBase58Check, ///< empty / bech32 / cashaddr / not a 25-byte b58check payload
};

struct AddressCheck {
    AddressVerdict verdict{AddressVerdict::NotBase58Check};
    QString        detectedCoinLabel;  ///< set when WrongCoin (the coin it belongs to)
    QString        message;            ///< human-readable; empty on Ok / empty input

    /// The ONLY blocking condition — a positively-identified wrong-coin
    /// address. Everything else is advisory so a valid launch is never
    /// stopped by a coin we simply do not model.
    bool blocksLaunch() const { return verdict == AddressVerdict::WrongCoin; }
};

namespace detail {

/// Decode a base58 string into raw bytes (big-endian). Returns false on any
/// character outside the base58 alphabet (which cleanly rejects bech32 —
/// '0','1','O','I','l' are not in the alphabet — and cashaddr's ':').
inline bool decodeBase58(const QString& in, std::vector<uint8_t>& out)
{
    static const char kAlphabet[] =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    out.clear();
    if (in.isEmpty()) return false;

    std::vector<uint8_t> num;  // big-endian base-256 accumulator
    num.reserve(in.size());
    for (QChar qc : in) {
        const char c = qc.toLatin1();
        if (c == 0) return false;  // non-latin1 => not base58
        const char* p = std::strchr(kAlphabet, c);
        if (p == nullptr || c == '\0') return false;
        int carry = static_cast<int>(p - kAlphabet);
        for (auto it = num.rbegin(); it != num.rend(); ++it) {
            carry += 58 * (*it);
            *it = static_cast<uint8_t>(carry & 0xFF);
            carry >>= 8;
        }
        while (carry > 0) {
            num.insert(num.begin(), static_cast<uint8_t>(carry & 0xFF));
            carry >>= 8;
        }
    }
    // Each leading '1' is a leading zero byte.
    int leadingOnes = 0;
    for (QChar qc : in) {
        if (qc == QLatin1Char('1')) ++leadingOnes; else break;
    }
    out.assign(static_cast<size_t>(leadingOnes), 0);
    out.insert(out.end(), num.begin(), num.end());
    return true;
}

/// True when `version` is a valid base58 address prefix for `p` on ANY
/// network (mainnet or testnet, P2PKH or P2SH). -1 fields never match.
inline bool versionMatchesCoin(const CoinProfile& p, int version)
{
    return version == p.p2pkhVersionMainnet
        || version == p.p2shVersionMainnet
        || version == p.p2pkhVersionTestnet
        || version == p.p2shVersionTestnet;
}

} // namespace detail

/// Validate a payout address for the coin identified by `activeSymbol`.
/// `testnet` currently only shapes messaging; matching accepts either
/// network of the active coin so a mainnet/testnet slip is not blocked.
inline AddressCheck validatePayoutAddress(const QString& address,
                                          const QString& activeSymbol,
                                          bool /*testnet*/ = false)
{
    AddressCheck result;
    const QString addr = address.trimmed();
    if (addr.isEmpty()) {
        // Empty is fine — PageLaunch only emits --address when non-empty
        // (and can auto-detect from the wallet).
        result.verdict = AddressVerdict::NotBase58Check;
        return result;
    }

    std::vector<uint8_t> raw;
    if (!detail::decodeBase58(addr, raw) || raw.size() != 25) {
        // Not a base58check address (bech32 / cashaddr / malformed). We do
        // not model those, so pass through unjudged.
        result.verdict = AddressVerdict::NotBase58Check;
        return result;
    }

    // base58check = 1 version byte + 20 payload bytes + 4 checksum bytes.
    // checksum = first 4 bytes of SHA256d(version||payload).
    const QByteArray body(reinterpret_cast<const char*>(raw.data()), 21);
    const QByteArray h1 = QCryptographicHash::hash(body, QCryptographicHash::Sha256);
    const QByteArray h2 = QCryptographicHash::hash(h1, QCryptographicHash::Sha256);
    if (std::memcmp(h2.constData(), raw.data() + 21, 4) != 0) {
        // Looks base58 but the checksum fails — most likely a typo. Advisory
        // only (never a hard block, to stay low false-positive).
        result.verdict = AddressVerdict::NotBase58Check;
        return result;
    }

    const int version = raw[0];
    const CoinProfile& active = coinProfile(activeSymbol);

    if (detail::versionMatchesCoin(active, version)) {
        result.verdict = AddressVerdict::Ok;
        return result;
    }

    // Version does not belong to the active coin. Does it belong to a
    // known other coin? If so this is the money-mistake we must block.
    int count = 0;
    const CoinProfile* profiles = coinProfiles(count);
    for (int i = 0; i < count; ++i) {
        const CoinProfile& p = profiles[i];
        if (p.symbol == active.symbol) continue;
        if (detail::versionMatchesCoin(p, version)) {
            result.verdict = AddressVerdict::WrongCoin;
            result.detectedCoinLabel = p.displayLabel;
            result.message = QStringLiteral(
                "This is a %1 address (base58 version %2), but the active coin "
                "is %3. Enter a %3 payout address or switch profiles.")
                .arg(p.displayLabel)
                .arg(version)
                .arg(active.displayLabel);
            return result;
        }
    }

    // Valid base58check, but a version we do not model. Advisory only.
    result.verdict = AddressVerdict::UnknownVersion;
    result.message = QStringLiteral(
        "Unrecognised address version %1 — cannot confirm this is a valid %2 "
        "address.")
        .arg(version)
        .arg(active.displayLabel);
    return result;
}

} // namespace c2pool_qt
