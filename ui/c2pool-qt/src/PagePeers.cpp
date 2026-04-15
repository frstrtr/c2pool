#include "PagePeers.hpp"

#include <QHeaderView>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QVBoxLayout>

PagePeers::PagePeers(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);

    totalPeersLabel_ = new QLabel("Peers: -", this);
    totalPeersLabel_->setStyleSheet("font-weight: bold; font-size: 14px;");
    layout->addWidget(totalPeersLabel_);

    peerTable_ = new QTableWidget(this);
    peerTable_->setColumnCount(5);
    peerTable_->setHorizontalHeaderLabels({"Address", "Version", "Ping (ms)", "Tx Pool", "Direction"});
    peerTable_->horizontalHeader()->setStretchLastSection(true);
    peerTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    peerTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    peerTable_->setSortingEnabled(true);
    layout->addWidget(peerTable_);

    statusLabel_ = new QLabel("Idle", this);
    layout->addWidget(statusLabel_);
}

void PagePeers::refresh(ApiClient* api)
{
    statusLabel_->setText("Refreshing...");

    // Peer list with addresses
    api->getJson("/peer_list",
        [this](const QJsonDocument& doc) {
            if (!doc.isArray()) return;
            const auto arr = doc.array();
            peerTable_->setRowCount(arr.size());
            totalPeersLabel_->setText(QString("Peers: %1").arg(arr.size()));

            for (int i = 0; i < arr.size(); ++i) {
                const auto peer = arr[i].toObject();
                peerTable_->setItem(i, 0, new QTableWidgetItem(
                    peer.value("addr").toString()));
                peerTable_->setItem(i, 1, new QTableWidgetItem(
                    peer.value("sub_version").toString()));
                peerTable_->setItem(i, 2, new QTableWidgetItem(
                    QString::number(peer.value("ping").toDouble() * 1000.0, 'f', 0)));
                peerTable_->setItem(i, 3, new QTableWidgetItem(
                    QString::number(peer.value("txpool_size").toInt())));
                peerTable_->setItem(i, 4, new QTableWidgetItem(
                    peer.value("incoming").toBool() ? "inbound" : "outbound"));
            }
            statusLabel_->setText("OK");
        },
        [this](const QString& err) {
            statusLabel_->setText(err);
        }
    );
}
