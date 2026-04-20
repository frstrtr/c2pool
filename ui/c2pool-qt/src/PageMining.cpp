#include "PageMining.hpp"

#include "PageEmbedded.hpp"

#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSplitter>
#include <QVBoxLayout>

PageMining::PageMining(QList<QObject*> embedBridges, QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    // Vertical splitter — native controls + stats on top, embedded
    // PPLNS miner-list view on bottom. User can drag the handle to
    // resize either half; default 40/60 favours the miner list.
    auto* splitter = new QSplitter(Qt::Vertical, this);
    layout->addWidget(splitter, 1);

    // ── Top: native controls + aggregate stats ──────────────────────
    auto* topWidget = new QWidget(splitter);
    auto* topLayout = new QVBoxLayout(topWidget);
    topLayout->setContentsMargins(8, 8, 8, 4);

    auto* controlsLayout = new QHBoxLayout();
    startButton_ = new QPushButton("Start Mining", topWidget);
    stopButton_ = new QPushButton("Stop Mining", topWidget);
    restartButton_ = new QPushButton("Restart Mining", topWidget);
    controlsLayout->addWidget(startButton_);
    controlsLayout->addWidget(stopButton_);
    controlsLayout->addWidget(restartButton_);
    controlsLayout->addStretch();
    topLayout->addLayout(controlsLayout);

    auto* banLayout = new QHBoxLayout();
    minerInput_ = new QLineEdit(topWidget);
    minerInput_->setPlaceholderText("Miner address or worker id");
    banButton_ = new QPushButton("Ban", topWidget);
    unbanButton_ = new QPushButton("Unban", topWidget);
    banLayout->addWidget(minerInput_, 1);
    banLayout->addWidget(banButton_);
    banLayout->addWidget(unbanButton_);
    topLayout->addLayout(banLayout);

    auto* statsGroup = new QGroupBox("Stratum Statistics", topWidget);
    auto* statsForm = new QFormLayout(statsGroup);
    connectedMinersValue_ = new QLabel("-");
    statsForm->addRow("Connected miners:", connectedMinersValue_);
    miningStateValue_ = new QLabel("unknown");
    statsForm->addRow("Mining state:", miningStateValue_);
    acceptedValue_ = new QLabel("-");
    statsForm->addRow("Accepted shares:", acceptedValue_);
    rejectedValue_ = new QLabel("-");
    statsForm->addRow("Rejected shares:", rejectedValue_);
    hashrateValue_ = new QLabel("-");
    statsForm->addRow("Pool hashrate:", hashrateValue_);
    sharesPerMinValue_ = new QLabel("-");
    statsForm->addRow("Shares/min:", sharesPerMinValue_);
    difficultyValue_ = new QLabel("-");
    statsForm->addRow("Share difficulty:", difficultyValue_);
    topLayout->addWidget(statsGroup);

    statusValue_ = new QLabel("Idle", topWidget);
    topLayout->addWidget(statusValue_);

    splitter->addWidget(topWidget);

    // ── Bottom: embedded PPLNS View — miner list, sort/filter,
    // drill-down, plugin slots. Same bundle as the standalone PPLNS
    // tab; the bridges are shared by MainWindow so both surfaces
    // see the same bridge state.
    if (!embedBridges.isEmpty()) {
        PageEmbedded::Config cfg;
        cfg.qrcUrl = QStringLiteral(
            "qrc:///sharechain-explorer/pplns-embed.html");
        cfg.bridges = embedBridges;
        cfg.bridgeObjectName = QStringLiteral("qtBridge");
#ifdef C2POOL_QT_DEV_BUNDLE
        cfg.devReloadEnabled = true;
#endif
        pplnsEmbed_ = new PageEmbedded(cfg, splitter);
        splitter->addWidget(pplnsEmbed_);
        splitter->setStretchFactor(0, 2);   // controls: 40 %
        splitter->setStretchFactor(1, 3);   // miner list: 60 %
    } else {
        splitter->setStretchFactor(0, 1);
    }

    connect(startButton_, &QPushButton::clicked, this, &PageMining::onStartMining);
    connect(stopButton_, &QPushButton::clicked, this, &PageMining::onStopMining);
    connect(restartButton_, &QPushButton::clicked, this, &PageMining::onRestartMining);
    connect(banButton_, &QPushButton::clicked, this, &PageMining::onBanMiner);
    connect(unbanButton_, &QPushButton::clicked, this, &PageMining::onUnbanMiner);
}

void PageMining::refresh(ApiClient* api)
{
    api_ = api;
    statusValue_->setText("Refreshing...");

    api->getJson("/connected_miners",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto obj = doc.object();
            connectedMinersValue_->setText(
                QString::number(obj.value("total_connected").toInt()));
        },
        [](const QString&) { }
    );

    api->getJson("/stratum_stats",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) {
                statusValue_->setText("Unexpected /stratum_stats payload");
                return;
            }

            const auto root = doc.object();
            const bool miningEnabled = root.value("mining_enabled").toBool(true);
            miningStateValue_->setText(miningEnabled ? "running" : "stopped");

            acceptedValue_->setText(QString::number(root.value("accepted_shares").toInt()));
            rejectedValue_->setText(QString::number(root.value("rejected_shares").toInt()));

            const double hashrate = root.value("hashrate").toDouble();
            hashrateValue_->setText(hashrate > 0
                ? QString("%1 MH/s").arg(hashrate / 1e6, 0, 'f', 2)
                : "0.00");

            sharesPerMinValue_->setText(
                QString::number(root.value("shares_per_minute").toDouble(), 'f', 2));
            difficultyValue_->setText(
                QString::number(root.value("difficulty").toDouble(), 'f', 4));

            const int active = root.value("active_workers").toInt();
            statusValue_->setText(QString("%1 active worker(s)").arg(active));
        },
        [this](const QString& error) {
            statusValue_->setText(error);
        }
    );
}

void PageMining::invokeControl(ApiClient* api, const QString& path, const QString& successLabel)
{
    if (!api) {
        statusValue_->setText("No API client");
        return;
    }
    statusValue_->setText("Applying control action...");
    api->getJson(path,
        [this, successLabel](const QJsonDocument&) {
            statusValue_->setText(successLabel);
            if (api_) {
                refresh(api_);
            }
        },
        [this](const QString& error) {
            statusValue_->setText(error);
        }
    );
}

void PageMining::onStartMining()
{
    invokeControl(api_, "/control/mining/start", "Mining started");
}

void PageMining::onStopMining()
{
    invokeControl(api_, "/control/mining/stop", "Mining stopped");
}

void PageMining::onRestartMining()
{
    invokeControl(api_, "/control/mining/restart", "Mining restarted");
}

void PageMining::onBanMiner()
{
    if (!api_) {
        statusValue_->setText("No API client");
        return;
    }
    const QString target = minerInput_->text().trimmed();
    if (target.isEmpty()) {
        statusValue_->setText("Enter miner address or worker id");
        return;
    }
    invokeControl(api_, QString("/control/mining/ban?target=%1").arg(target), "Miner ban applied");
}

void PageMining::onUnbanMiner()
{
    if (!api_) {
        statusValue_->setText("No API client");
        return;
    }
    const QString target = minerInput_->text().trimmed();
    if (target.isEmpty()) {
        statusValue_->setText("Enter miner address or worker id");
        return;
    }
    invokeControl(api_, QString("/control/mining/unban?target=%1").arg(target), "Miner unbanned");
}
