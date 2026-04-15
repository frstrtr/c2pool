#include "PageOverview.hpp"

#include <QFormLayout>
#include <QGroupBox>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QVBoxLayout>

PageOverview::PageOverview(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);

    // Network / Pool stats
    auto* poolGroup = new QGroupBox("Pool Statistics", this);
    auto* poolForm = new QFormLayout(poolGroup);
    uptimeValue_ = new QLabel("-");
    poolForm->addRow("Uptime:", uptimeValue_);
    poolHashrateValue_ = new QLabel("-");
    poolForm->addRow("Pool Hashrate:", poolHashrateValue_);
    staleRateValue_ = new QLabel("-");
    poolForm->addRow("Pool Stale Ratio:", staleRateValue_);
    networkDiffValue_ = new QLabel("-");
    poolForm->addRow("Network Difficulty:", networkDiffValue_);
    layout->addWidget(poolGroup);

    // Sharechain stats
    auto* chainGroup = new QGroupBox("Sharechain", this);
    auto* chainForm = new QFormLayout(chainGroup);
    chainHeightValue_ = new QLabel("-");
    chainForm->addRow("Chain Height:", chainHeightValue_);
    sharesValue_ = new QLabel("-");
    chainForm->addRow("Total Shares:", sharesValue_);
    uniqueMinersValue_ = new QLabel("-");
    chainForm->addRow("Unique Miners:", uniqueMinersValue_);
    peersValue_ = new QLabel("-");
    chainForm->addRow("P2P Connections:", peersValue_);
    layout->addWidget(chainGroup);

    // Enhanced stats
    auto* extraGroup = new QGroupBox("Extended Status", this);
    auto* extraForm = new QFormLayout(extraGroup);
    luckValue_ = new QLabel("-");
    extraForm->addRow("Pool Luck:", luckValue_);
    v36StatusValue_ = new QLabel("-");
    extraForm->addRow("V36 Status:", v36StatusValue_);
    broadcasterValue_ = new QLabel("-");
    extraForm->addRow("Broadcaster:", broadcasterValue_);
    mergedStatsValue_ = new QLabel("-");
    extraForm->addRow("Merged Mining:", mergedStatsValue_);
    layout->addWidget(extraGroup);

    statusValue_ = new QLabel("Idle");
    layout->addWidget(statusValue_);
    layout->addStretch();
}

static QString formatHashrate(double hr) {
    if (hr >= 1e15) return QString("%1 PH/s").arg(hr / 1e15, 0, 'f', 2);
    if (hr >= 1e12) return QString("%1 TH/s").arg(hr / 1e12, 0, 'f', 2);
    if (hr >= 1e9)  return QString("%1 GH/s").arg(hr / 1e9, 0, 'f', 2);
    if (hr >= 1e6)  return QString("%1 MH/s").arg(hr / 1e6, 0, 'f', 2);
    if (hr >= 1e3)  return QString("%1 KH/s").arg(hr / 1e3, 0, 'f', 2);
    return QString("%1 H/s").arg(hr, 0, 'f', 2);
}

void PageOverview::refresh(ApiClient* api)
{
    statusValue_->setText("Refreshing...");

    // Global stats: hashrate, stale ratio, difficulty, miners, uptime
    api->getJson("/global_stats",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();

            // Pool hashrate (field: pool_hash_rate)
            const double hashrate = obj.value("pool_hash_rate").toDouble();
            poolHashrateValue_->setText(formatHashrate(hashrate));

            // Stale ratio (field: pool_stale_prop)
            staleRateValue_->setText(
                QString::number(obj.value("pool_stale_prop").toDouble(), 'f', 4));

            // Network difficulty (field: network_block_difficulty)
            const double netDiff = obj.value("network_block_difficulty").toDouble();
            if (netDiff >= 1e6)
                networkDiffValue_->setText(QString("%1 M").arg(netDiff / 1e6, 0, 'f', 2));
            else
                networkDiffValue_->setText(QString::number(netDiff, 'f', 2));

            // Unique miners
            uniqueMinersValue_->setText(
                QString::number(obj.value("unique_miners").toInt()));

            // Uptime
            const double uptime = obj.value("uptime_seconds").toDouble();
            if (uptime < 3600)
                uptimeValue_->setText(QString("%1 min").arg(uptime / 60.0, 0, 'f', 1));
            else
                uptimeValue_->setText(QString("%1 h").arg(uptime / 3600.0, 0, 'f', 1));

            statusValue_->setText("OK");
        },
        [this](const QString& err) {
            statusValue_->setText(err);
        }
    );

    // Sharechain stats (height, shares, chain length)
    api->getJson("/sharechain/stats",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();
            chainHeightValue_->setText(
                QString::number(obj.value("chain_height").toInt()));
            sharesValue_->setText(
                QString("%1 / %2")
                    .arg(obj.value("chain_length").toInt())
                    .arg(obj.value("chain_height").toInt()));
        },
        [](const QString&) { }
    );

    // P2P peer count
    api->getJson("/peer_list",
        [this](const QJsonDocument& doc) {
            if (!doc.isArray()) return;
            peersValue_->setText(QString::number(doc.array().size()));
        },
        [](const QString&) { }
    );

    // Luck stats
    api->getJson("/luck_stats",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();
            if (obj.value("luck_available").toBool()) {
                const auto trend = obj.value("current_luck_trend");
                if (!trend.isNull())
                    luckValue_->setText(QString("%1%").arg(trend.toDouble() * 100.0, 0, 'f', 1));
                else
                    luckValue_->setText("calculating...");
            } else {
                luckValue_->setText("no blocks yet");
            }
        },
        [](const QString&) { }
    );

    // V36 status
    api->getJson("/v36_status",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();
            const auto ratchet = obj.value("auto_ratchet").toObject();
            const QString state = ratchet.value("state").toString("unknown");
            const auto sc = obj.value("share_chain").toObject();
            const double v36pct = sc.value("v36_percentage").toDouble();
            v36StatusValue_->setText(
                QString("%1 (v36: %2%)").arg(state).arg(v36pct, 0, 'f', 1));
        },
        [](const QString&) { }
    );

    // Broadcaster status (LTC embedded node health)
    api->getJson("/broadcaster_status",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();
            const bool running = obj.value("running").toBool();
            const int chains = obj.value("chains").toInt();
            const auto peers = obj.value("peers").toArray();
            const int found = obj.value("total_blocks_found").toInt();
            if (running) {
                broadcasterValue_->setText(
                    QString("LTC: %1 peers, %2 blocks found")
                        .arg(peers.size()).arg(found));
                broadcasterValue_->setStyleSheet("color: green;");
            } else {
                broadcasterValue_->setText("disconnected");
                broadcasterValue_->setStyleSheet("color: red;");
            }
        },
        [](const QString&) { }
    );

    // Merged mining stats (DOGE)
    api->getJson("/merged_stats",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();
            const auto networks = obj.value("networks").toObject();
            const int totalBlocks = obj.value("total_blocks").toInt();
            const QString symbol = obj.value("symbol").toString();
            if (networks.isEmpty()) {
                mergedStatsValue_->setText("no merged chains");
            } else {
                QStringList parts;
                for (auto it = networks.begin(); it != networks.end(); ++it) {
                    const auto net = it.value().toObject();
                    parts << QString("%1: h=%2, %3 blocks")
                        .arg(it.key())
                        .arg(net.value("current_height").toInt())
                        .arg(net.value("blocks_found").toInt());
                }
                mergedStatsValue_->setText(parts.join("; "));
            }
        },
        [](const QString&) { }
    );
}
