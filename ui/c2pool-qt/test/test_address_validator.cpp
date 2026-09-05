// SPDX-License-Identifier: AGPL-3.0-or-later
// test_address_validator — QP-B acceptance gate.
//
// Proves the in-UI payout-address flavor check now reads the SAME node registry
// the stratum money-path uses (each coin's <coin>::address_acceptance(), issue
// #961, via the src/impl/<coin>/address_encoding.hpp leaf headers). The gate:
//   • EVERY accepted base58 version byte for a coin (all networks) → Ok — this is
//     the registry-match property that was RED on master, where the old private
//     table blocked valid LTC legacy P2SH (version 5) and testnet P2SH (196);
//   • a base58 address of a DIFFERENT known coin → WrongCoin (naming it);
//   • bech32 own-HRP → Ok, foreign HRP → WrongCoin;
//   • BCH CashAddr → Ok in bitcoincash, WrongCoin elsewhere;
//   • DOGE/DGB 0x1e collision → Ok in both (favour the user);
//   • checksum-fail / empty / bech32-checksum-fail → NotBase58Check (advisory).
//
// Links Qt6::Core only (no Widgets / WebEngine) so it runs headless in CI.

#include "../src/AddressValidator.hpp"
#include "../src/CoinProfiles.hpp"

#include <impl/dash/address_encoding.hpp>
#include <impl/ltc/address_encoding.hpp>
#include <impl/btc/address_encoding.hpp>
#include <impl/bch/address_encoding.hpp>
#include <impl/dgb/address_encoding.hpp>
#include <impl/doge/coin/address_encoding.hpp>

#include <QByteArray>
#include <QCryptographicHash>
#include <QString>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using c2pool_qt::AddressVerdict;
using c2pool_qt::validatePayoutAddress;

namespace {

int failures = 0;

void check(bool cond, const char* what)
{
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) ++failures;
}

QString encodeBase58(const std::vector<uint8_t>& in)
{
    static const char kAlphabet[] =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::vector<uint8_t> digits;
    for (uint8_t byte : in) {
        int carry = byte;
        for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
            carry += 256 * (*it);
            *it = static_cast<uint8_t>(carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            digits.insert(digits.begin(), static_cast<uint8_t>(carry % 58));
            carry /= 58;
        }
    }
    QString out;
    for (uint8_t b : in) { if (b == 0) out.append(QLatin1Char('1')); else break; }
    for (uint8_t d : digits) out.append(QLatin1Char(kAlphabet[d]));
    return out;
}

// Valid base58check: version || 20-byte payload || sha256d[:4].
QString makeAddress(int version, uint8_t fill = 0x11)
{
    std::vector<uint8_t> body;
    body.push_back(static_cast<uint8_t>(version));
    for (int i = 0; i < 20; ++i) body.push_back(fill);
    const QByteArray bodyBa(reinterpret_cast<const char*>(body.data()),
                            static_cast<int>(body.size()));
    const QByteArray h1 = QCryptographicHash::hash(bodyBa, QCryptographicHash::Sha256);
    const QByteArray h2 = QCryptographicHash::hash(h1, QCryptographicHash::Sha256);
    std::vector<uint8_t> full = body;
    for (int i = 0; i < 4; ++i) full.push_back(static_cast<uint8_t>(h2[i]));
    return encodeBase58(full);
}

// Minimal BIP-173 bech32 v0 encoder (20-byte program) for a given HRP, so the
// validator's decoder is exercised against a checksum-correct address.
uint32_t bech32Polymod(const std::vector<uint8_t>& v)
{
    static const uint32_t GEN[5] = {
        0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u};
    uint32_t chk = 1;
    for (uint8_t p : v) {
        uint8_t top = static_cast<uint8_t>(chk >> 25);
        chk = ((chk & 0x1ffffffu) << 5) ^ p;
        for (int i = 0; i < 5; ++i) if ((top >> i) & 1) chk ^= GEN[i];
    }
    return chk;
}

QString makeBech32(const std::string& hrp)
{
    static const char* CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    // 20-byte program (all 0x11) → 5-bit groups.
    std::vector<uint8_t> prog(20, 0x11);
    std::vector<uint8_t> data;
    data.push_back(0);   // witness version 0
    int acc = 0, bits = 0;
    for (uint8_t b : prog) {
        acc = (acc << 8) | b; bits += 8;
        while (bits >= 5) { bits -= 5; data.push_back((acc >> bits) & 0x1f); }
    }
    if (bits > 0) data.push_back((acc << (5 - bits)) & 0x1f);
    // checksum
    std::vector<uint8_t> values;
    for (char c : hrp) values.push_back(static_cast<uint8_t>(c) >> 5);
    values.push_back(0);
    for (char c : hrp) values.push_back(static_cast<uint8_t>(c) & 0x1f);
    for (uint8_t d : data) values.push_back(d);
    for (int i = 0; i < 6; ++i) values.push_back(0);
    const uint32_t mod = bech32Polymod(values) ^ 1u;
    std::vector<uint8_t> checksum;
    for (int i = 0; i < 6; ++i) checksum.push_back((mod >> (5 * (5 - i))) & 0x1f);
    QString out = QString::fromStdString(hrp) + QLatin1Char('1');
    for (uint8_t d : data)     out.append(QLatin1Char(CHARSET[d]));
    for (uint8_t d : checksum) out.append(QLatin1Char(CHARSET[d]));
    return out;
}

std::vector<int> acceptedVersions(const QString& symbol)
{
    const core::CoinAddressAcceptance a =
        c2pool_qt::detail::registryAcceptance(symbol);
    std::vector<int> vs;
    for (auto v : a.p2pkh_versions) vs.push_back(v);
    for (auto v : a.p2sh_versions)  vs.push_back(v);
    return vs;
}

} // namespace

int main()
{
    std::printf("test_address_validator\n");

    // ── Registry-match: EVERY accepted version of a coin → Ok (all networks). ──
    // Directly exercises the drift fix (LTC 5 / 196 / 58 were blocked on master).
    {
        int n = 0;
        const c2pool_qt::CoinProfile* profs = c2pool_qt::coinProfiles(n);
        for (int i = 0; i < n; ++i) {
            const QString sym = profs[i].symbol;
            for (int v : acceptedVersions(sym)) {
                const QString addr = makeAddress(v);
                auto r = validatePayoutAddress(addr, sym, false);
                char msg[128];
                std::snprintf(msg, sizeof(msg),
                    "%s: accepted version %d ⇒ Ok",
                    sym.toStdString().c_str(), v);
                check(r.verdict == AddressVerdict::Ok && !r.blocksLaunch(), msg);
            }
        }
    }

    // ── LTC legacy P2SH (version 5) + testnet P2SH (196) — RED on master. ──
    {
        auto r5 = validatePayoutAddress(makeAddress(5), "litecoin", false);
        check(r5.verdict == AddressVerdict::Ok,
              "LTC legacy P2SH (version 5) ⇒ Ok (was WrongCoin on master)");
        auto r196 = validatePayoutAddress(makeAddress(196), "litecoin", false);
        check(r196.verdict == AddressVerdict::Ok,
              "LTC testnet P2SH (version 196) ⇒ Ok (was WrongCoin on master)");
    }

    // ── Core QP-B: a DASH address in a Litecoin profile → WrongCoin. ──
    {
        auto r = validatePayoutAddress(makeAddress(76), "litecoin", false);
        check(r.verdict == AddressVerdict::WrongCoin, "DASH addr in LTC profile → WrongCoin");
        check(r.blocksLaunch(), "wrong-coin addr BLOCKS launch");
        check(r.detectedCoinLabel == QStringLiteral("Dash"), "wrong-coin detected as Dash");
    }
    // Symmetric: LTC address in a DASH profile → WrongCoin.
    {
        auto r = validatePayoutAddress(makeAddress(48), "dash", false);
        check(r.verdict == AddressVerdict::WrongCoin, "LTC addr in DASH profile → WrongCoin");
        check(r.detectedCoinLabel == QStringLiteral("Litecoin"), "detected as Litecoin");
    }

    // ── DASH testnet-version addr in a mainnet DASH profile → Ok (any-network). ──
    {
        auto r = validatePayoutAddress(makeAddress(140), "dash", false);
        check(r.verdict == AddressVerdict::Ok,
              "DASH testnet-version addr in mainnet DASH profile → Ok");
    }

    // ── DOGE/DGB 0x1e (30) collision → Ok in BOTH. ──
    {
        auto rd = validatePayoutAddress(makeAddress(30), "dogecoin", false);
        auto rg = validatePayoutAddress(makeAddress(30), "digibyte", false);
        check(rd.verdict == AddressVerdict::Ok, "version 30 in dogecoin → Ok (collision)");
        check(rg.verdict == AddressVerdict::Ok, "version 30 in digibyte → Ok (collision)");
    }

    // ── BTC/BCH shared version (0) → Ok in BCH profile (favour user). ──
    {
        auto r = validatePayoutAddress(makeAddress(0), "bitcoincash", false);
        check(r.verdict == AddressVerdict::Ok,
              "BTC-version addr in BCH profile → Ok (shared version)");
    }

    // ── bech32 own HRP → Ok; foreign HRP → WrongCoin. ──
    {
        auto lok = validatePayoutAddress(makeBech32("ltc"), "litecoin", false);
        check(lok.verdict == AddressVerdict::Ok, "ltc1… bech32 in LTC profile → Ok");
        auto lwrong = validatePayoutAddress(makeBech32("ltc"), "bitcoin", false);
        check(lwrong.verdict == AddressVerdict::WrongCoin,
              "ltc1… bech32 in BTC profile → WrongCoin");
        check(lwrong.detectedCoinLabel == QStringLiteral("Litecoin"),
              "ltc bech32 detected as Litecoin");
        auto bok = validatePayoutAddress(makeBech32("bc"), "bitcoin", false);
        check(bok.verdict == AddressVerdict::Ok, "bc1… bech32 in BTC profile → Ok");
        auto bwrong = validatePayoutAddress(makeBech32("bc"), "litecoin", false);
        check(bwrong.verdict == AddressVerdict::WrongCoin,
              "bc1… bech32 in LTC profile → WrongCoin");
        auto dok = validatePayoutAddress(makeBech32("dgb"), "digibyte", false);
        check(dok.verdict == AddressVerdict::Ok, "dgb1… bech32 in DGB profile → Ok");
    }

    // ── bech32 with a broken checksum → NotBase58Check (advisory, never a block). ──
    {
        QString b = makeBech32("ltc");
        b[b.size() - 1] = (b[b.size() - 1] == QLatin1Char('q')) ? QLatin1Char('p')
                                                                : QLatin1Char('q');
        auto r = validatePayoutAddress(b, "litecoin", false);
        check(r.verdict == AddressVerdict::NotBase58Check,
              "bech32 with broken checksum → NotBase58Check (not blocked)");
        check(!r.blocksLaunch(), "broken bech32 does not block launch");
    }

    // ── BCH CashAddr → Ok in bitcoincash, WrongCoin elsewhere. ──
    {
        const QString cash = "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a";
        auto ok = validatePayoutAddress(cash, "bitcoincash", false);
        check(ok.verdict == AddressVerdict::Ok, "cashaddr in bitcoincash profile → Ok");
        auto wrong = validatePayoutAddress(cash, "bitcoin", false);
        check(wrong.verdict == AddressVerdict::WrongCoin,
              "cashaddr in bitcoin profile → WrongCoin");
        check(wrong.detectedCoinLabel == QStringLiteral("Bitcoin Cash"),
              "cashaddr detected as Bitcoin Cash");
    }

    // ── Unknown version: advisory, never a hard block. ──
    {
        auto r = validatePayoutAddress(makeAddress(99), "dash", false);
        check(r.verdict == AddressVerdict::UnknownVersion, "unmodelled version → UnknownVersion");
        check(!r.blocksLaunch(), "unknown version does not block launch");
    }

    // ── Empty input → NotBase58Check, no block. ──
    {
        auto r = validatePayoutAddress("   ", "dash", false);
        check(r.verdict == AddressVerdict::NotBase58Check, "empty addr → NotBase58Check");
        check(!r.blocksLaunch(), "empty addr does not block launch");
    }

    // ── Checksum failure (valid DASH addr with one char mangled) → unjudged. ──
    {
        QString dashAddr = makeAddress(76);
        const int mid = dashAddr.size() / 2;
        dashAddr[mid] = (dashAddr[mid] == QLatin1Char('A')) ? QLatin1Char('B')
                                                            : QLatin1Char('A');
        auto r = validatePayoutAddress(dashAddr, "dash", false);
        check(r.verdict == AddressVerdict::NotBase58Check,
              "checksum-broken addr → NotBase58Check (advisory)");
        check(!r.blocksLaunch(), "checksum-broken addr does not block launch");
    }

    std::printf("%s (%d failure%s)\n", failures == 0 ? "ALL PASS" : "FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
