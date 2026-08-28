// SPDX-License-Identifier: AGPL-3.0-or-later
// test_address_validator — QP-B acceptance gate.
//
// Proves the in-UI payout-address flavor check:
//   • accepts an address whose base58 version belongs to the active coin
//     (either network — mainnet/testnet slips are not blocked);
//   • BLOCKS a base58 address that belongs to a DIFFERENT known coin
//     (the "DASH address typed into a Litecoin profile" case), naming the
//     coin it actually belongs to;
//   • passes bech32 / cashaddr / malformed / checksum-failing input through
//     UNJUDGED (NotBase58Check) so a valid launch is never blocked by a
//     flavor we do not model;
//   • treats cross-coin version-byte collisions (BTC/BCH 0/5, DOGE/DGB 30)
//     in the user's favour.
//
// Links Qt6::Core only (no Widgets / WebEngine) so it runs headless in CI.
// Test addresses are generated in-process by base58check-ENCODING a known
// payload with each coin's version byte — self-consistent, no external
// fixture strings that could rot.

#include "../src/AddressValidator.hpp"
#include "../src/CoinProfiles.hpp"

#include <QByteArray>
#include <QCryptographicHash>
#include <QString>

#include <cstdint>
#include <cstdio>
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

// base58 encode raw bytes (big-endian). Mirror of Bitcoin's EncodeBase58.
QString encodeBase58(const std::vector<uint8_t>& in)
{
    static const char kAlphabet[] =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::vector<uint8_t> digits;  // big-endian base-58
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
    for (uint8_t b : in) {
        if (b == 0) out.append(QLatin1Char('1')); else break;
    }
    for (uint8_t d : digits) out.append(QLatin1Char(kAlphabet[d]));
    return out;
}

// Build a valid base58check address: version || 20-byte payload || sha256d[:4].
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

} // namespace

int main()
{
    std::printf("test_address_validator\n");

    // ── Sanity: version bytes loaded into CoinProfiles are the expected ones.
    check(c2pool_qt::coinProfile("dash").p2pkhVersionMainnet == 76,
          "CoinProfiles: DASH mainnet P2PKH version == 76");
    check(c2pool_qt::coinProfile("dash").p2shVersionMainnet == 16,
          "CoinProfiles: DASH mainnet P2SH version == 16");
    check(c2pool_qt::coinProfile("litecoin").p2pkhVersionMainnet == 48,
          "CoinProfiles: LTC mainnet P2PKH version == 48");

    // ── Ok: right coin.
    {
        const QString dashAddr = makeAddress(76);
        auto r = validatePayoutAddress(dashAddr, "dash", false);
        check(r.verdict == AddressVerdict::Ok, "DASH P2PKH addr in DASH profile → Ok");
        check(!r.blocksLaunch(), "DASH addr in DASH profile does not block launch");
    }

    // ── ★ Core QP-B case: DASH address typed into a Litecoin profile.
    {
        const QString dashAddr = makeAddress(76);
        auto r = validatePayoutAddress(dashAddr, "litecoin", false);
        check(r.verdict == AddressVerdict::WrongCoin,
              "DASH addr in LTC profile → WrongCoin");
        check(r.blocksLaunch(), "wrong-coin addr BLOCKS launch");
        check(r.detectedCoinLabel == QStringLiteral("Dash"),
              "wrong-coin detected as Dash");
        check(!r.message.isEmpty(), "wrong-coin carries a message");
    }

    // ── Symmetric: LTC address typed into a DASH profile.
    {
        const QString ltcAddr = makeAddress(48);
        auto r = validatePayoutAddress(ltcAddr, "dash", false);
        check(r.verdict == AddressVerdict::WrongCoin,
              "LTC addr in DASH profile → WrongCoin");
        check(r.detectedCoinLabel == QStringLiteral("Litecoin"),
              "wrong-coin detected as Litecoin");
    }

    // ── DASH P2SH ('7…', version 16) in DASH profile → Ok.
    {
        const QString dashScript = makeAddress(16);
        auto r = validatePayoutAddress(dashScript, "dash", false);
        check(r.verdict == AddressVerdict::Ok, "DASH P2SH addr in DASH profile → Ok");
    }

    // ── Any-network acceptance: DASH testnet version (140) in a mainnet
    //    (testnet=false) DASH profile is NOT blocked.
    {
        const QString dashTestnet = makeAddress(140);
        auto r = validatePayoutAddress(dashTestnet, "dash", false);
        check(r.verdict == AddressVerdict::Ok,
              "DASH testnet-version addr in mainnet DASH profile → Ok (not blocked)");
    }

    // ── Collision favours the user: BTC version (0) in a BCH profile → Ok
    //    (BCH legacy addresses share BTC's version bytes).
    {
        const QString btcAddr = makeAddress(0);
        auto r = validatePayoutAddress(btcAddr, "bitcoincash", false);
        check(r.verdict == AddressVerdict::Ok,
              "BTC-version addr in BCH profile → Ok (shared version, favour user)");
    }

    // ── Unknown version: never a hard block, only advisory.
    {
        const QString weird = makeAddress(99);
        auto r = validatePayoutAddress(weird, "dash", false);
        check(r.verdict == AddressVerdict::UnknownVersion,
              "unmodelled version → UnknownVersion");
        check(!r.blocksLaunch(), "unknown version does not block launch");
    }

    // ── Empty input → NotBase58Check, no block.
    {
        auto r = validatePayoutAddress("   ", "dash", false);
        check(r.verdict == AddressVerdict::NotBase58Check, "empty addr → NotBase58Check");
        check(!r.blocksLaunch(), "empty addr does not block launch");
    }

    // ── bech32 (contains '0', outside base58) → passed through unjudged.
    {
        auto r = validatePayoutAddress(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "bitcoin", false);
        check(r.verdict == AddressVerdict::NotBase58Check,
              "bech32 addr → NotBase58Check (not blocked)");
        check(!r.blocksLaunch(), "bech32 addr does not block launch");
    }

    // ── Checksum failure (valid DASH addr with one char mangled) → unjudged.
    {
        QString dashAddr = makeAddress(76);
        // Flip a middle character to a different base58 digit.
        const int mid = dashAddr.size() / 2;
        dashAddr[mid] = (dashAddr[mid] == QLatin1Char('A')) ? QLatin1Char('B')
                                                            : QLatin1Char('A');
        auto r = validatePayoutAddress(dashAddr, "dash", false);
        check(r.verdict == AddressVerdict::NotBase58Check,
              "checksum-broken addr → NotBase58Check (advisory, not a block)");
        check(!r.blocksLaunch(), "checksum-broken addr does not block launch");
    }

    std::printf("%s (%d failure%s)\n", failures == 0 ? "ALL PASS" : "FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
