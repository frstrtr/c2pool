#include "PageOverview.hpp"

#include <QFormLayout>
#include <QGroupBox>
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

void PageOverview::refresh(ApiClient* api)
{
    statusValue_->setText("Refreshing...");

    // Uptime (plain text)
    api->getText("/uptime",
        [this](const QString& text) {
            bool ok = false;
            const double seconds = text.trimmed().toDouble(&ok);
            if (ok) {
                if (seconds < 3600)
                    uptimeValue_->setText(QString("%1 min").arg(seconds / 60.0, 0, 'f', 1));
                else
                    uptimeValue_->setText(QString("%1 h").arg(seconds / 3600.0, 0, 'f', 1));
            }
        },
        [](const QString&) { }
    );

    // Global stats (pool hashrate, stale ratio)
    api->getJson("/global_stats",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();
            const double hashrate = obj.value("pool_hashrate").toDouble();
            poolHashrateValue_->setText(hashrate > 0
                ? QString("%1 MH/s").arg(hashrate / 1e6, 0, 'f', 2)
                : "0.00");
            staleRateValue_->setText(
                QString::number(obj.value("pool_stale_ratio").toDouble(), 'f', 6));
            statusValue_->setText("OK");
        },
        [this](const QString& err) {
            statusValue_->setText(err);
        }
    );

    // Local stats (network difficulty, connections)
    api->getJson("/local_stats",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();
            networkDiffValue_->setText(
                QString::number(obj.value("difficulty").toDouble(), 'f', 4));
            peersValue_->setText(
                QString::number(obj.value("connections").toInt()));
        },
        [](const QString&) { }
    );

    // Sharechain stats (height, shares, miners)
    api->getJson("/sharechain/stats",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();
            chainHeightValue_->setText(
                QString::number(obj.value("chain_height").toInt()));
            sharesValue_->setText(
                QString::number(obj.value("total_shares").toInt()));
            const auto miners = obj.value("shares_by_miner").toObject();
            uniqueMinersValue_->setText(QString::number(miners.size()));
        },
        [](const QString&) { }
    );

    // Luck stats
    api->getJson("/luck_stats",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();
            const double luck = obj.value("luck_percent").toDouble();
            luckValue_->setText(QString("%1%").arg(luck, 0, 'f', 1));
        },
        [](const QString&) { }
    );

    // V36 status
    api->getJson("/v36_status",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();
            const QString phase = obj.value("phase").toString("unknown");
            v36StatusValue_->setText(phase);
        },
        [](const QString&) { }
    );

    // Broadcaster status
    api->getJson("/broadcaster_status",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();
            const bool ok = obj.value("connected").toBool();
            broadcasterValue_->setText(ok ? "connected" : "disconnected");
            broadcasterValue_->setStyleSheet(ok ? "color: green;" : "color: red;");
        },
        [](const QString&) { }
    );

    // Merged mining stats
    api->getJson("/merged_stats",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();
            const int chains = obj.value("chains").toInt();
            const int blocks = obj.value("total_blocks").toInt();
            mergedStatsValue_->setText(
                QString("%1 chain(s), %2 blocks found").arg(chains).arg(blocks));
        },
        [](const QString&) { }
    );
}
