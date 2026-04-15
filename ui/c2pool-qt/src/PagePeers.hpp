#pragma once

#include "ApiClient.hpp"

#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QWidget>

/// P2P peer monitoring page.
///
/// Displays connected peers from /peer_list, /pings, /peer_versions
/// in a sortable table.
class PagePeers : public QWidget
{
    Q_OBJECT
public:
    explicit PagePeers(QWidget* parent = nullptr);
    void refresh(ApiClient* api);

private:
    QTableWidget* peerTable_;
    QLabel* totalPeersLabel_;
    QLabel* statusLabel_;
};
