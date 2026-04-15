#include "PageOverview.hpp"

#include <QChart>
#include <QFormLayout>
#include <QGroupBox>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QValueAxis>
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
    layout->addWidget(extraGroup);

    // Daemon health
    auto* daemonGroup = new QGroupBox("Daemon Health", this);
    auto* daemonForm = new QFormLayout(daemonGroup);
    ltcDaemonValue_ = new QLabel("-");
    daemonForm->addRow("LTC Node:", ltcDaemonValue_);
    ltcHeightValue_ = new QLabel("-");
    daemonForm->addRow("LTC Peers / Height:", ltcHeightValue_);
    dogeDaemonValue_ = new QLabel("-");
    daemonForm->addRow("DOGE Node:", dogeDaemonValue_);
    dogeHeightValue_ = new QLabel("-");
    daemonForm->addRow("DOGE Height / Blocks:", dogeHeightValue_);
    layout->addWidget(daemonGroup);

    // Hashrate chart
    hashrateSeries_ = new QLineSeries();
    hashrateSeries_->setName("Pool Hashrate");
    hashrateSeries_->setColor(QColor(74, 222, 128));

    auto* chart = new QChart();
    chart->addSeries(hashrateSeries_);
    chart->setAnimationOptions(QChart::SeriesAnimations);
    chart->setBackgroundBrush(QBrush(QColor(15, 23, 42)));
    chart->setTitle("Pool Hashrate (GH/s)");
    chart->setTitleBrush(QBrush(QColor(226, 232, 240)));
    chart->legend()->setVisible(false);

    auto* axisX = new QValueAxis();
    axisX->setRange(0, 60);
    axisX->setTitleText("Samples");
    axisX->setLabelsColor(QColor(148, 163, 184));
    axisX->setGridLineColor(QColor(51, 65, 85));
    chart->addAxis(axisX, Qt::AlignBottom);
    hashrateSeries_->attachAxis(axisX);

    auto* axisY = new QValueAxis();
    axisY->setTitleText("GH/s");
    axisY->setLabelsColor(QColor(148, 163, 184));
    axisY->setGridLineColor(QColor(51, 65, 85));
    chart->addAxis(axisY, Qt::AlignLeft);
    hashrateSeries_->attachAxis(axisY);

    hashrateChartView_ = new QChartView(chart, this);
    hashrateChartView_->setRenderHint(QPainter::Antialiasing);
    hashrateChartView_->setMinimumHeight(150);
    hashrateChartView_->setStyleSheet("background: #0f172a; border: 1px solid #1e293b; border-radius: 6px;");
    layout->addWidget(hashrateChartView_);

    statusValue_ = new QLabel("Idle");
    layout->addWidget(statusValue_);
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

            // Append to hashrate chart
            const double hrGhs = hashrate / 1e9;
            hashrateSeries_->append(hashrateTickCount_++, hrGhs);
            // Keep last 60 samples
            while (hashrateSeries_->count() > 60)
                hashrateSeries_->remove(0);
            // Update axes
            auto axes = hashrateChartView_->chart()->axes();
            if (axes.size() >= 2) {
                auto* axisX = static_cast<QValueAxis*>(axes[0]);
                axisX->setRange(std::max(0, hashrateTickCount_ - 60), hashrateTickCount_);
                // Auto-scale Y
                double maxY = 0;
                for (auto& pt : hashrateSeries_->points())
                    if (pt.y() > maxY) maxY = pt.y();
                auto* axisY = static_cast<QValueAxis*>(axes[1]);
                axisY->setRange(0, maxY * 1.1 + 1);
            }

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

    // LTC daemon health (from broadcaster_status)
    api->getJson("/broadcaster_status",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();
            const bool running = obj.value("running").toBool();
            const auto peers = obj.value("peers").toArray();
            const int found = obj.value("total_blocks_found").toInt();

            if (running && !peers.isEmpty()) {
                ltcDaemonValue_->setText(
                    QString("<span style='color:#4ade80'>connected</span> (%1 blocks found)")
                        .arg(found));
                // Extract height from first peer
                int maxHeight = 0;
                for (const auto& p : peers) {
                    const int h = p.toObject().value("startingheight").toInt();
                    if (h > maxHeight) maxHeight = h;
                }
                ltcHeightValue_->setText(
                    QString("%1 peers, height %2").arg(peers.size()).arg(maxHeight));
            } else {
                ltcDaemonValue_->setText("<span style='color:#ef4444'>disconnected</span>");
                ltcHeightValue_->setText("-");
            }
        },
        [](const QString&) { }
    );

    // DOGE daemon health (from merged_stats)
    api->getJson("/merged_stats",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();
            const auto networks = obj.value("networks").toObject();

            if (networks.contains("DOGE")) {
                const auto doge = networks.value("DOGE").toObject();
                const int height = doge.value("current_height").toInt();
                const int blocks = doge.value("blocks_found").toInt();
                const double diff = doge.value("difficulty").toDouble();

                dogeDaemonValue_->setText(
                    QString("<span style='color:#4ade80'>connected</span> (chain_id: %1)")
                        .arg(doge.value("chain_id").toInt()));
                dogeHeightValue_->setText(
                    QString("height %1, diff %2M, %3 blocks found")
                        .arg(height)
                        .arg(diff / 1e6, 0, 'f', 1)
                        .arg(blocks));
            } else {
                dogeDaemonValue_->setText("<span style='color:#94a3b8'>not configured</span>");
                dogeHeightValue_->setText("-");
            }
        },
        [](const QString&) { }
    );
}
