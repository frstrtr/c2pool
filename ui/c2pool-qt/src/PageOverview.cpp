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
}
