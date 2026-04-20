#pragma once

#include "ApiClient.hpp"

#include <QLabel>
#include <QLineEdit>
#include <QList>
#include <QObject>
#include <QPushButton>
#include <QWidget>

class PageEmbedded;

/// PageMining — hybrid split per §7 step 11 of
/// c2pool-qt-hybrid-architecture.md. Native top bar owns the
/// imperative actions (start/stop/ban/unban + aggregate stats);
/// the miner-list view is the embedded PPLNS View bundle —
/// delegated to PageEmbedded so the JS treemap / drill-down /
/// plugin surface work identically to the standalone PPLNS tab.
class PageMining : public QWidget
{
    Q_OBJECT
public:
    /** `embedBridges` must outlive PageMining — typically
     *  MainWindow owns them. The list is forwarded verbatim to
     *  PageEmbedded::Config::bridges for pplns-embed.html. When
     *  the list is empty the embedded panel is suppressed. */
    explicit PageMining(QList<QObject*> embedBridges,
                        QWidget* parent = nullptr);

    /** Pulls /stratum_stats + /connected_miners into the native
     *  stats panel. The embedded PPLNS view self-refreshes via
     *  PplnsBridge — no action needed here. */
    void refresh(ApiClient* api);

private slots:
    void onStartMining();
    void onStopMining();
    void onRestartMining();
    void onBanMiner();
    void onUnbanMiner();

private:
    void invokeControl(ApiClient* api, const QString& path, const QString& successLabel);

    ApiClient* api_{nullptr};
    QLabel* statusValue_;
    QLabel* connectedMinersValue_;
    QLabel* miningStateValue_;
    QLabel* acceptedValue_;
    QLabel* rejectedValue_;
    QLabel* hashrateValue_;
    QLabel* sharesPerMinValue_;
    QLabel* difficultyValue_;

    QPushButton* startButton_;
    QPushButton* stopButton_;
    QPushButton* restartButton_;

    QLineEdit* minerInput_;
    QPushButton* banButton_;
    QPushButton* unbanButton_;

    /** Embedded pplns-embed.html host — null when no bridges were
     *  supplied (e.g. tests that don't wire the JS surface). */
    PageEmbedded* pplnsEmbed_{nullptr};
};
