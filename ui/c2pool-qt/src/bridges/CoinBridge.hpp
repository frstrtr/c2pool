// CoinBridge — exposes a CoinDescriptor-shaped JSON object to JS over
// QtWebChannel so the embedded Explorer / PPLNS View bundles pull
// coin params from c2pool authoritatively instead of reading
// per-coin static JS files. Unlocks profile-switch-instantly-
// rebinds-the-dashboard-to-new-coin per §4.4 of the hybrid-
// architecture doc.
//
// c2pool-qt is a thin client (talks to c2pool daemon over HTTP);
// the bridge derives the descriptor from the active profile's
// launch values in SettingsStore (chain, testnet). Per-coin
// constants (address-version bytes, block explorer URLs, default
// share-version threshold) are hard-coded in a compile-time table
// so a fresh daemon isn't required to bootstrap the page.

#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QObject>
#include <QString>

class SettingsStore;

class CoinBridge : public QObject {
    Q_OBJECT
public:
    explicit CoinBridge(SettingsStore* settings, QObject* parent = nullptr);

    /** Full CoinDescriptor for the active profile's chain+testnet.
     *  Shape: {symbol, displayLabel, testnet, shareVersion,
     *  windowSize, p2pkhVersion, p2shVersion, blockExplorer,
     *  mergedChains[]}. */
    Q_INVOKABLE QJsonObject currentCoinDescriptor() const;

    /** List of coin symbols c2pool-qt can mine against. Shape:
     *  [{symbol, displayLabel}]. */
    Q_INVOKABLE QJsonArray availableCoins() const;

signals:
    /** Emitted when the active coin (or testnet flag) changes —
     *  either via a profile switch or a per-profile chain edit. */
    void coinChanged(const QJsonObject& descriptor);

private:
    /** Build a CoinDescriptor-shaped object from (chain, testnet). */
    static QJsonObject buildDescriptor(const QString& chain, bool testnet);

    SettingsStore* settings_;
};
