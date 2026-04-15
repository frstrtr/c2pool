#pragma once

#include "ApiClient.hpp"

#include <QLabel>
#include <QPushButton>
#include <QTabWidget>
#include <QTableWidget>
#include <QWidget>

/// P2P peer monitoring page with tabs for p2pool, LTC, and DOGE peers.
class PagePeers : public QWidget
{
    Q_OBJECT
public:
    explicit PagePeers(QWidget* parent = nullptr);
    void refresh(ApiClient* api);

private:
    void refreshP2poolPeers(ApiClient* api);
    void refreshLtcPeers(ApiClient* api);
    void refreshDogePeers(ApiClient* api);

    QTabWidget* tabWidget_;

    // P2Pool peers tab
    QTableWidget* p2poolTable_;
    QLabel* p2poolCountLabel_;

    // LTC peers tab
    QTableWidget* ltcTable_;
    QLabel* ltcCountLabel_;

    // DOGE peers tab
    QTableWidget* dogeTable_;
    QLabel* dogeCountLabel_;

    QLabel* statusLabel_;
};
