// SPDX-License-Identifier: AGPL-3.0-or-later
// AddressValidator — in-UI payout-address flavor check (QP-B).
//
// c2pool-qt is coin-generic: the same launch form serves LTC/BTC/DOGE/DASH/DGB/
// BCH. A payout address pasted into the wrong coin's profile is a silent money
// mistake — miners paid to an address the winning coin's nodes reject, or worse,
// an address that decodes to a DIFFERENT live chain (issue #961). This validator
// catches the unambiguous case and BLOCKS launch on it.
//
// ★ NO DRIFT TABLE. The accepted version bytes / bech32 HRPs are read from the
// SAME node registry the stratum money-path uses — each coin's
// <coin>::address_acceptance() (issue #961), hoisted into leaf headers
// (src/impl/<coin>/address_encoding.hpp) that carry ONLY the encoding SSOT so
// they link into this standalone Qt build without the node's pow/config graph.
// There is exactly one place each coin's bytes live; the Qt check can never drift
// from the node's acceptance set (which was the pre-#961 bug: this validator's
// old private table blocked valid LTC 3.../Q... P2SH addresses the node accepts).
//
// Verdict mapping mirrors the node's core::classify_address_for_coin():
//   • Own-coin address (any of its networks) → Ok.
//   • Well-formed address of a DIFFERENT known coin → WrongCoin (the ONLY hard
//     launch blocker), naming the coin it belongs to.
//   • Well-formed but unmodelled version/HRP → UnknownVersion (advisory).
//   • Undecodable (checksum fail / not an address we parse) → NotBase58Check
//     (advisory) so a valid launch is never blocked by a flavor we cannot judge.
//
// base58check, bech32/bech32m and BCH CashAddr are all decoded here, so a
// segwit or cashaddr address in a wrong-coin profile is caught the same way the
// node would (bech32 HRP mismatch / cashaddr prefix mismatch), not waved through.
//
// Qt Core only (QString / QByteArray / QCryptographicHash) — no Widgets, no
// WebEngine — so it is unit-testable without a display.

#pragma once

#include "CoinProfiles.hpp"

#include <impl/dash/address_encoding.hpp>
#include <impl/ltc/address_encoding.hpp>
#include <impl/btc/address_encoding.hpp>
#include <impl/bch/address_encoding.hpp>
#include <impl/dgb/address_encoding.hpp>
#include <impl/doge/coin/address_encoding.hpp>
#include <core/address_utils.hpp>   // core::CoinAddressAcceptance

#include <QByteArray>
#include <QCryptographicHash>
#include <QLatin1String>
#include <QString>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace c2pool_qt {

enum class AddressVerdict {
    Ok,             ///< valid; version/HRP belongs to the active coin
    WrongCoin,      ///< valid; version/HRP belongs to a DIFFERENT coin
    UnknownVersion, ///< valid; version/HRP not in our coin registry
    NotBase58Check, ///< empty / undecodable / checksum failure (advisory)
};

struct AddressCheck {
    AddressVerdict verdict{AddressVerdict::NotBase58Check};
    QString        detectedCoinLabel;  ///< set when WrongCoin (the coin it belongs to)
    QString        message;            ///< human-readable; empty on Ok / empty input

    /// The ONLY blocking condition — a positively-identified wrong-coin address.
    bool blocksLaunch() const { return verdict == AddressVerdict::WrongCoin; }
};

namespace detail {

/// Union of a coin's mainnet ∪ testnet ∪ regtest acceptance sets, read straight
/// from the node registry leaf headers. Any-network membership favours the user
/// (a mainnet/testnet slip is not a wrong-coin block).
inline core::CoinAddressAcceptance registryAcceptance(const QString& symbol)
{
    auto merge = [](core::CoinAddressAcceptance& into,
                    const core::CoinAddressAcceptance& src) {
        for (auto v : src.p2pkh_versions) into.p2pkh_versions.push_back(v);
        for (auto v : src.p2sh_versions)  into.p2sh_versions.push_back(v);
        for (const auto& h : src.bech32_hrps) into.bech32_hrps.push_back(h);
    };
    core::CoinAddressAcceptance acc;
    if (symbol == QLatin1String("litecoin")) {
        merge(acc, ltc::address_acceptance(false));
        merge(acc, ltc::address_acceptance(true));
    } else if (symbol == QLatin1String("bitcoin")) {
        merge(acc, btc::address_acceptance(false, false));
        merge(acc, btc::address_acceptance(true,  false));
        merge(acc, btc::address_acceptance(false, true));
    } else if (symbol == QLatin1String("dogecoin")) {
        merge(acc, doge::address_acceptance(false));
        merge(acc, doge::address_acceptance(true));
    } else if (symbol == QLatin1String("dash")) {
        merge(acc, dash::address_acceptance(false, false));
        merge(acc, dash::address_acceptance(true,  false));
    } else if (symbol == QLatin1String("digibyte")) {
        merge(acc, dgb::address_acceptance(false, false));
        merge(acc, dgb::address_acceptance(true,  false));
        merge(acc, dgb::address_acceptance(false, true));
    } else if (symbol == QLatin1String("bitcoincash")) {
        merge(acc, bch::address_acceptance(false, false));
        merge(acc, bch::address_acceptance(true,  false));
    }
    return acc;
}

inline bool versionAccepted(const core::CoinAddressAcceptance& acc, int version)
{
    const auto v = static_cast<uint8_t>(version);
    return std::find(acc.p2pkh_versions.begin(), acc.p2pkh_versions.end(), v)
               != acc.p2pkh_versions.end()
        || std::find(acc.p2sh_versions.begin(), acc.p2sh_versions.end(), v)
               != acc.p2sh_versions.end();
}

inline bool hrpAccepted(const core::CoinAddressAcceptance& acc, const std::string& hrp)
{
    return std::find(acc.bech32_hrps.begin(), acc.bech32_hrps.end(), hrp)
               != acc.bech32_hrps.end();
}

/// Decode a base58 string into raw bytes (big-endian). Returns false on any
/// character outside the base58 alphabet (cleanly rejecting bech32 / cashaddr).
inline bool decodeBase58(const QString& in, std::vector<uint8_t>& out)
{
    static const char kAlphabet[] =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    out.clear();
    if (in.isEmpty()) return false;

    std::vector<uint8_t> num;
    num.reserve(in.size());
    for (QChar qc : in) {
        const char c = qc.toLatin1();
        if (c == 0) return false;
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
    int leadingOnes = 0;
    for (QChar qc : in) {
        if (qc == QLatin1Char('1')) ++leadingOnes; else break;
    }
    out.assign(static_cast<size_t>(leadingOnes), 0);
    out.insert(out.end(), num.begin(), num.end());
    return true;
}

// ── bech32 / bech32m decode (BIP-173 / BIP-350), HRP extraction ──────────────
inline uint32_t bech32Polymod(const std::vector<uint8_t>& values)
{
    static const uint32_t GEN[5] = {
        0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u};
    uint32_t chk = 1;
    for (uint8_t v : values) {
        uint8_t top = static_cast<uint8_t>(chk >> 25);
        chk = ((chk & 0x1ffffffu) << 5) ^ v;
        for (int i = 0; i < 5; ++i)
            if ((top >> i) & 1) chk ^= GEN[i];
    }
    return chk;
}

/// Structurally decode a bech32/bech32m address; on success set `hrp` (lowered)
/// and return true (checksum verified against either constant). Low-false-
/// positive: a typo that breaks the checksum returns false → treated as
/// undecodable, never a wrong-coin block.
inline bool decodeBech32(const QString& in, std::string& hrp)
{
    static const char* CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const std::string s = in.trimmed().toStdString();
    if (s.size() < 8 || s.size() > 100) return false;

    // Reject mixed case (BIP-173) and normalise to lower.
    bool hasLower = false, hasUpper = false;
    for (char c : s) {
        if (c >= 'a' && c <= 'z') hasLower = true;
        else if (c >= 'A' && c <= 'Z') hasUpper = true;
        else if (c < 33 || c > 126) return false;
    }
    if (hasLower && hasUpper) return false;
    std::string ls;
    ls.reserve(s.size());
    for (char c : s) ls.push_back((c >= 'A' && c <= 'Z') ? char(c + 32) : c);

    const auto sep = ls.rfind('1');
    if (sep == std::string::npos || sep == 0 || sep + 7 > ls.size()) return false;
    const std::string hrpPart = ls.substr(0, sep);
    const std::string data = ls.substr(sep + 1);

    std::vector<uint8_t> values;
    values.reserve(hrpPart.size() * 2 + 1 + data.size());
    for (char c : hrpPart) values.push_back(static_cast<uint8_t>(c) >> 5);
    values.push_back(0);
    for (char c : hrpPart) values.push_back(static_cast<uint8_t>(c) & 0x1f);
    for (char c : data) {
        const char* p = std::strchr(CHARSET, c);
        if (!p) return false;
        values.push_back(static_cast<uint8_t>(p - CHARSET));
    }
    const uint32_t chk = bech32Polymod(values);
    if (chk != 1u && chk != 0x2bc830a3u) return false;  // bech32 or bech32m
    hrp = hrpPart;
    return true;
}

/// A BCH CashAddr carries an explicit or implicit prefix. We recognise the three
/// canonical BCH prefixes; membership is enough for a low-false-positive UI
/// verdict (the node reaches the same Own/Foreign split via its CashAddr codec).
inline bool isCashAddr(const QString& in, std::string& prefix)
{
    const std::string s = in.trimmed().toStdString();
    const auto colon = s.find(':');
    if (colon == std::string::npos) return false;
    std::string pfx = s.substr(0, colon);
    for (char& c : pfx) if (c >= 'A' && c <= 'Z') c = char(c + 32);
    if (pfx == "bitcoincash" || pfx == "bchtest" || pfx == "bchreg") {
        prefix = pfx;
        return true;
    }
    return false;
}

} // namespace detail

/// Validate a payout address for the coin identified by `activeSymbol`.
inline AddressCheck validatePayoutAddress(const QString& address,
                                          const QString& activeSymbol,
                                          bool /*testnet*/ = false)
{
    AddressCheck result;
    const QString addr = address.trimmed();
    if (addr.isEmpty()) {
        result.verdict = AddressVerdict::NotBase58Check;
        return result;
    }

    const CoinProfile& active = coinProfile(activeSymbol);
    const core::CoinAddressAcceptance activeAcc =
        detail::registryAcceptance(active.symbol);

    int profileCount = 0;
    const CoinProfile* profiles = coinProfiles(profileCount);

    // ── BCH CashAddr (distinct format; no base58 version / bech32 HRP) ────────
    {
        std::string cashPrefix;
        if (detail::isCashAddr(addr, cashPrefix)) {
            if (active.symbol == QLatin1String("bitcoincash")) {
                result.verdict = AddressVerdict::Ok;
                return result;
            }
            result.verdict = AddressVerdict::WrongCoin;
            result.detectedCoinLabel = QStringLiteral("Bitcoin Cash");
            result.message = QStringLiteral(
                "This is a Bitcoin Cash CashAddr (%1:…), but the active coin is "
                "%2. Enter a %2 payout address or switch profiles.")
                .arg(QString::fromStdString(cashPrefix), active.displayLabel);
            return result;
        }
    }

    // ── bech32 / bech32m (segwit) ─────────────────────────────────────────────
    {
        std::string hrp;
        if (detail::decodeBech32(addr, hrp)) {
            if (detail::hrpAccepted(activeAcc, hrp)) {
                result.verdict = AddressVerdict::Ok;
                return result;
            }
            for (int i = 0; i < profileCount; ++i) {
                const CoinProfile& p = profiles[i];
                if (p.symbol == active.symbol) continue;
                if (detail::hrpAccepted(detail::registryAcceptance(p.symbol), hrp)) {
                    result.verdict = AddressVerdict::WrongCoin;
                    result.detectedCoinLabel = p.displayLabel;
                    result.message = QStringLiteral(
                        "This is a %1 bech32 address (hrp \"%2\"), but the active "
                        "coin is %3. Enter a %3 payout address or switch profiles.")
                        .arg(p.displayLabel, QString::fromStdString(hrp),
                             active.displayLabel);
                    return result;
                }
            }
            result.verdict = AddressVerdict::UnknownVersion;
            result.message = QStringLiteral(
                "Unrecognised bech32 prefix \"%1\" — cannot confirm this is a "
                "valid %2 address.")
                .arg(QString::fromStdString(hrp), active.displayLabel);
            return result;
        }
    }

    // ── base58check ──────────────────────────────────────────────────────────
    std::vector<uint8_t> raw;
    if (!detail::decodeBase58(addr, raw) || raw.size() != 25) {
        result.verdict = AddressVerdict::NotBase58Check;
        return result;
    }

    // base58check = 1 version byte + 20 payload bytes + 4 checksum bytes.
    const QByteArray body(reinterpret_cast<const char*>(raw.data()), 21);
    const QByteArray h1 = QCryptographicHash::hash(body, QCryptographicHash::Sha256);
    const QByteArray h2 = QCryptographicHash::hash(h1, QCryptographicHash::Sha256);
    if (std::memcmp(h2.constData(), raw.data() + 21, 4) != 0) {
        result.verdict = AddressVerdict::NotBase58Check;
        return result;
    }

    const int version = raw[0];
    if (detail::versionAccepted(activeAcc, version)) {
        result.verdict = AddressVerdict::Ok;
        return result;
    }

    for (int i = 0; i < profileCount; ++i) {
        const CoinProfile& p = profiles[i];
        if (p.symbol == active.symbol) continue;
        if (detail::versionAccepted(detail::registryAcceptance(p.symbol), version)) {
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

    result.verdict = AddressVerdict::UnknownVersion;
    result.message = QStringLiteral(
        "Unrecognised address version %1 — cannot confirm this is a valid %2 "
        "address.")
        .arg(version)
        .arg(active.displayLabel);
    return result;
}

} // namespace c2pool_qt
