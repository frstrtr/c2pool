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

    tabWidget_ = new QTabWidget(this);

    // ── P2Pool peers tab ─────────────────────────────────────────────
    auto* p2poolTab = new QWidget(this);
    auto* p2poolLay = new QVBoxLayout(p2poolTab);
    p2poolCountLabel_ = new QLabel("P2Pool Peers: -", this);
    p2poolCountLabel_->setStyleSheet("font-weight: bold; font-size: 13px;");
    p2poolLay->addWidget(p2poolCountLabel_);

    p2poolTable_ = new QTableWidget(this);
    p2poolTable_->setColumnCount(4);
    p2poolTable_->setHorizontalHeaderLabels({"Address", "Version", "Uptime", "Direction"});
    p2poolTable_->horizontalHeader()->setStretchLastSection(true);
    p2poolTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    p2poolTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    p2poolTable_->setSortingEnabled(true);
    p2poolLay->addWidget(p2poolTable_);
    tabWidget_->addTab(p2poolTab, "P2Pool");

    // ── LTC daemon peers tab ─────────────────────────────────────────
    auto* ltcTab = new QWidget(this);
    auto* ltcLay = new QVBoxLayout(ltcTab);
    ltcCountLabel_ = new QLabel("LTC Peers: -", this);
    ltcCountLabel_->setStyleSheet("font-weight: bold; font-size: 13px;");
    ltcLay->addWidget(ltcCountLabel_);

    ltcTable_ = new QTableWidget(this);
    ltcTable_->setColumnCount(4);
    ltcTable_->setHorizontalHeaderLabels({"Address", "Version", "Height", "Direction"});
    ltcTable_->horizontalHeader()->setStretchLastSection(true);
    ltcTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ltcTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    ltcTable_->setSortingEnabled(true);
    ltcLay->addWidget(ltcTable_);
    tabWidget_->addTab(ltcTab, "LTC Daemon");

    // ── DOGE daemon peers tab ────────────────────────────────────────
    auto* dogeTab = new QWidget(this);
    auto* dogeLay = new QVBoxLayout(dogeTab);
    dogeCountLabel_ = new QLabel("DOGE Chain: -", this);
    dogeCountLabel_->setStyleSheet("font-weight: bold; font-size: 13px;");
    dogeLay->addWidget(dogeCountLabel_);

    dogeTable_ = new QTableWidget(this);
    dogeTable_->setColumnCount(3);
    dogeTable_->setHorizontalHeaderLabels({"Property", "Value", "Details"});
    dogeTable_->horizontalHeader()->setStretchLastSection(true);
    dogeTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    dogeLay->addWidget(dogeTable_);
    tabWidget_->addTab(dogeTab, "DOGE Merged");

    layout->addWidget(tabWidget_);

    statusLabel_ = new QLabel("Idle", this);
    layout->addWidget(statusLabel_);
}

void PagePeers::refresh(ApiClient* api)
{
    statusLabel_->setText("Refreshing...");
    refreshP2poolPeers(api);
    refreshLtcPeers(api);
    refreshDogePeers(api);
}

void PagePeers::refreshP2poolPeers(ApiClient* api)
{
    api->getJson("/peer_list",
        [this](const QJsonDocument& doc) {
            if (!doc.isArray()) return;
            const auto arr = doc.array();
            p2poolTable_->setSortingEnabled(false);
            p2poolTable_->setRowCount(arr.size());
            p2poolCountLabel_->setText(QString("P2Pool Peers: %1").arg(arr.size()));

            for (int i = 0; i < arr.size(); ++i) {
                const auto peer = arr[i].toObject();
                p2poolTable_->setItem(i, 0, new QTableWidgetItem(
                    peer.value("address").toString()));
                p2poolTable_->setItem(i, 1, new QTableWidgetItem(
                    peer.value("version").toString()));
                const int uptime = peer.value("uptime").toInt();
                const QString uptimeStr = uptime >= 3600
                    ? QString("%1h %2m").arg(uptime / 3600).arg((uptime % 3600) / 60)
                    : QString("%1m").arg(uptime / 60);
                p2poolTable_->setItem(i, 2, new QTableWidgetItem(uptimeStr));
                p2poolTable_->setItem(i, 3, new QTableWidgetItem(
                    peer.value("incoming").toBool() ? "inbound" : "outbound"));
            }
            p2poolTable_->setSortingEnabled(true);
            statusLabel_->setText("OK");
        },
        [this](const QString& err) {
            statusLabel_->setText(err);
        }
    );
}

void PagePeers::refreshLtcPeers(ApiClient* api)
{
    api->getJson("/broadcaster_status",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();
            const auto peers = obj.value("peers").toArray();

            ltcTable_->setSortingEnabled(false);
            ltcTable_->setRowCount(peers.size());
            ltcCountLabel_->setText(QString("LTC Peers: %1").arg(peers.size()));

            for (int i = 0; i < peers.size(); ++i) {
                const auto peer = peers[i].toObject();
                ltcTable_->setItem(i, 0, new QTableWidgetItem(
                    peer.value("addr").toString()));
                ltcTable_->setItem(i, 1, new QTableWidgetItem(
                    peer.value("subver").toString()));
                ltcTable_->setItem(i, 2, new QTableWidgetItem(
                    QString::number(peer.value("startingheight").toInt())));
                ltcTable_->setItem(i, 3, new QTableWidgetItem(
                    peer.value("inbound").toBool() ? "inbound" : "outbound"));
            }
            ltcTable_->setSortingEnabled(true);
        },
        [](const QString&) { }
    );
}

void PagePeers::refreshDogePeers(ApiClient* api)
{
    // Use /merged_broadcaster_status which has DOGE peers (like /broadcaster_status has LTC peers)
    api->getJson("/merged_broadcaster_status",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();
            const auto peers = obj.value("peers").toArray();
            const auto chains = obj.value("chains").toObject();

            // Show DOGE chain info + peers
            QString label = "DOGE Peers: " + QString::number(peers.size());
            if (chains.contains("DOGE")) {
                const auto doge = chains.value("DOGE").toObject();
                label += QString(" | height %1 | %2 blocks found")
                    .arg(doge.value("current_height").toInt())
                    .arg(doge.value("blocks_found").toInt());
            }
            dogeCountLabel_->setText(label);

            // Table matches LTC peer format
            dogeTable_->setColumnCount(4);
            dogeTable_->setHorizontalHeaderLabels({"Address", "Version", "Height", "Status"});
            dogeTable_->horizontalHeader()->setStretchLastSection(true);
            dogeTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

            dogeTable_->setSortingEnabled(false);
            dogeTable_->setRowCount(peers.size());
            for (int i = 0; i < peers.size(); ++i) {
                const auto peer = peers[i].toObject();
                dogeTable_->setItem(i, 0, new QTableWidgetItem(
                    peer.value("addr").toString()));
                dogeTable_->setItem(i, 1, new QTableWidgetItem(
                    peer.value("subver").toString()));
                dogeTable_->setItem(i, 2, new QTableWidgetItem(
                    QString::number(peer.value("startingheight").toInt())));
                const bool connected = peer.value("connected").toBool();
                auto* statusItem = new QTableWidgetItem(connected ? "connected" : "disconnected");
                statusItem->setForeground(connected ? QColor(74, 222, 128) : QColor(239, 68, 68));
                dogeTable_->setItem(i, 3, statusItem);
            }
            dogeTable_->setSortingEnabled(true);
        },
        [this](const QString&) {
            dogeCountLabel_->setText("DOGE: no data");
        }
    );
}
