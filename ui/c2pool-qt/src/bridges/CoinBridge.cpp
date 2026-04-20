#include "CoinBridge.hpp"

#include "../SettingsStore.hpp"

#include <QJsonArray>
#include <QJsonObject>

namespace {

// Per-coin constants. c2pool-qt is a thin HTTP client so it can't
// pull these from the daemon's C++ enums at startup — hard-coding
// here keeps the bridge self-contained and means JS can render the
// dashboard before a daemon is even reachable. Values mirror
// p2pool/networks/<chain>.py defaults; merged-mining coins come from
// the active profile's mergedChains[] list (passed through from the
// launch form) and aren't fixed here.
struct CoinConstants {
    const char* symbol;
    const char* displayLabel;
    int         p2pkhVersionMainnet;
    int         p2shVersionMainnet;
    int         p2pkhVersionTestnet;
    int         p2shVersionTestnet;
    const char* blockExplorerMainnet;
    const char* blockExplorerTestnet;
    int         shareVersion;   // sharechain share format version floor
    int         windowSize;     // PPLNS window share count
};

constexpr CoinConstants kKnownCoins[] = {
    // litecoin — share v36, 3-hour PPLNS window (8640 shares @ 1.25 s)
    {"litecoin",  "Litecoin",  48, 50, 111, 58,
     "https://blockchair.com/litecoin/block/",
     "https://sochain.com/block/LTCTEST/",
     36, 8640},
    // bitcoin — share v36, 3-hour PPLNS window
    {"bitcoin",   "Bitcoin",   0,  5,  111, 196,
     "https://blockchair.com/bitcoin/block/",
     "https://blockstream.info/testnet/block/",
     36, 8640},
    // dogecoin — share v36, merged-mined with LTC typically
    {"dogecoin",  "Dogecoin",  30, 22, 113, 196,
     "https://blockchair.com/dogecoin/block/",
     "https://sochain.com/block/DOGETEST/",
     36, 8640},
    // digibyte — share v36
    {"digibyte",  "DigiByte",  30, 63, 126, 140,
     "https://digiexplorer.info/block/",
     "https://testnetexplorer.digibyteservers.io/block/",
     36, 8640},
};

const CoinConstants* findCoin(const QString& chain)
{
    for (const auto& c : kKnownCoins) {
        if (chain == QLatin1String(c.symbol)) return &c;
    }
    return nullptr;
}

} // namespace

CoinBridge::CoinBridge(SettingsStore* settings, QObject* parent)
    : QObject(parent), settings_(settings)
{
    setObjectName(QStringLiteral("coin"));

    // Emit coinChanged whenever the active profile flips or the
    // current profile's chain/testnet launch value is edited. The
    // JS bundle uses this to rebind its CoinDescriptor without a
    // page reload (§4.4 — "profile switch instantly rebinds the
    // dashboard to new coin").
    connect(settings_, &SettingsStore::profileChanged, this, [this]() {
        emit coinChanged(currentCoinDescriptor());
    });
    connect(settings_, &SettingsStore::changed, this, [this](const QString& key) {
        // Only fire for launch/chain or launch/testnet under the
        // active profile. Path shape is
        // "profiles/<active>/launch/chain". Avoid spamming JS for
        // unrelated writes (window geometry, view state, etc.).
        if (key.endsWith(QStringLiteral("/launch/chain"))
            || key.endsWith(QStringLiteral("/launch/testnet"))) {
            emit coinChanged(currentCoinDescriptor());
        }
    });
}

QJsonObject CoinBridge::currentCoinDescriptor() const
{
    const QString chain = settings_->launchValue(
        QStringLiteral("chain"), QStringLiteral("litecoin")).toString();
    const bool testnet = settings_->launchValue(
        QStringLiteral("testnet"), true).toBool();
    return buildDescriptor(chain, testnet);
}

QJsonArray CoinBridge::availableCoins() const
{
    QJsonArray out;
    for (const auto& c : kKnownCoins) {
        QJsonObject entry;
        entry.insert(QStringLiteral("symbol"),
                     QString::fromLatin1(c.symbol));
        entry.insert(QStringLiteral("displayLabel"),
                     QString::fromLatin1(c.displayLabel));
        out.append(entry);
    }
    return out;
}

QJsonObject CoinBridge::buildDescriptor(const QString& chain, bool testnet)
{
    const CoinConstants* c = findCoin(chain);
    if (!c) {
        // Unknown coin — return a minimal descriptor so JS can still
        // render a placeholder rather than crashing. Values here
        // match litecoin defaults.
        c = &kKnownCoins[0];
    }

    QJsonObject d;
    d.insert(QStringLiteral("symbol"),       QString::fromLatin1(c->symbol));
    d.insert(QStringLiteral("displayLabel"),
             QString::fromLatin1(c->displayLabel)
             + (testnet ? QStringLiteral(" (testnet)") : QString()));
    d.insert(QStringLiteral("testnet"),      testnet);
    d.insert(QStringLiteral("shareVersion"), c->shareVersion);
    d.insert(QStringLiteral("windowSize"),   c->windowSize);
    d.insert(QStringLiteral("p2pkhVersion"),
             testnet ? c->p2pkhVersionTestnet : c->p2pkhVersionMainnet);
    d.insert(QStringLiteral("p2shVersion"),
             testnet ? c->p2shVersionTestnet  : c->p2shVersionMainnet);
    d.insert(QStringLiteral("blockExplorer"),
             QString::fromLatin1(testnet ? c->blockExplorerTestnet
                                         : c->blockExplorerMainnet));
    // mergedChains[] is populated by the native launch UI via the
    // mergedTable; the JS bundle reads it through SettingsBridge
    // (profiles/<active>/launch/mergedChains) rather than here,
    // since it's a profile-editable list. Empty placeholder keeps
    // the shape stable.
    d.insert(QStringLiteral("mergedChains"), QJsonArray{});
    return d;
}
