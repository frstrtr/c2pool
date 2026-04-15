#include "PageMining.hpp"

#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QVBoxLayout>

PageMining::PageMining(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);

    auto* controlsLayout = new QHBoxLayout();
    startButton_ = new QPushButton("Start Mining", this);
    stopButton_ = new QPushButton("Stop Mining", this);
    restartButton_ = new QPushButton("Restart Mining", this);
    controlsLayout->addWidget(startButton_);
    controlsLayout->addWidget(stopButton_);
    controlsLayout->addWidget(restartButton_);
    controlsLayout->addStretch();
    layout->addLayout(controlsLayout);

    auto* banLayout = new QHBoxLayout();
    minerInput_ = new QLineEdit(this);
    minerInput_->setPlaceholderText("Miner address or worker id");
    banButton_ = new QPushButton("Ban", this);
    unbanButton_ = new QPushButton("Unban", this);
    banLayout->addWidget(minerInput_, 1);
    banLayout->addWidget(banButton_);
    banLayout->addWidget(unbanButton_);
    layout->addLayout(banLayout);

    // Aggregate stratum stats
    auto* statsGroup = new QGroupBox("Stratum Statistics", this);
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
    layout->addWidget(statsGroup);

    // Per-worker table (populated when workers connect)
    layout->addWidget(new QLabel("Workers:", this));
    workersTable_ = new QTableWidget(this);
    workersTable_->setColumnCount(6);
    workersTable_->setHorizontalHeaderLabels({
        "Worker", "Accepted", "Rejected", "Hashrate", "AutoConv", "Redistrib"
    });
    workersTable_->horizontalHeader()->setStretchLastSection(true);
    workersTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    layout->addWidget(workersTable_);

    statusValue_ = new QLabel("Idle");
    layout->addWidget(statusValue_);

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
            if (doc.isArray()) {
                connectedMinersValue_->setText(QString::number(doc.array().size()));
            } else if (doc.isObject()) {
                connectedMinersValue_->setText(
                    QString::number(doc.object().value("total_connected").toInt()));
            }
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
            // Response has nested "pool" object with aggregate stats
            const auto pool = root.value("pool").toObject();

            const int workers = pool.value("workers").toInt();
            miningStateValue_->setText(workers > 0 ? "running" : "idle");
            connectedMinersValue_->setText(QString::number(pool.value("connections").toInt()));

            acceptedValue_->setText(QString::number(pool.value("total_accepted").toInt()));
            rejectedValue_->setText(QString::number(pool.value("total_rejected").toInt()));

            const double hashrate = pool.value("hashrate").toDouble();
            if (hashrate >= 1e9)
                hashrateValue_->setText(QString("%1 GH/s").arg(hashrate / 1e9, 0, 'f', 2));
            else if (hashrate >= 1e6)
                hashrateValue_->setText(QString("%1 MH/s").arg(hashrate / 1e6, 0, 'f', 2));
            else
                hashrateValue_->setText(QString("%1 H/s").arg(hashrate, 0, 'f', 2));

            sharesPerMinValue_->setText(
                QString::number(pool.value("submission_rate").toDouble(), 'f', 2));
            difficultyValue_->setText(
                QString::number(pool.value("unique_addresses").toInt()));

            // Per-worker breakdown
            const auto workerMap = root.value("workers").toObject();
            workersTable_->setRowCount(workerMap.size());
            int row = 0;
            for (auto it = workerMap.begin(); it != workerMap.end(); ++it, ++row) {
                const auto w = it.value().toObject();
                workersTable_->setItem(row, 0, new QTableWidgetItem(it.key()));
                workersTable_->setItem(row, 1, new QTableWidgetItem(QString::number(w.value("accepted").toInt())));
                workersTable_->setItem(row, 2, new QTableWidgetItem(QString::number(w.value("rejected").toInt())));
                workersTable_->setItem(row, 3, new QTableWidgetItem(QString::number(w.value("hashrate").toDouble(), 'f', 2)));
                workersTable_->setItem(row, 4, new QTableWidgetItem(w.value("auto_converted").toBool() ? "yes" : "no"));
                workersTable_->setItem(row, 5, new QTableWidgetItem(w.value("redistributed").toBool() ? "yes" : "no"));
            }

            statusValue_->setText(QString("%1 worker(s), %2 unique addresses")
                .arg(workers).arg(pool.value("unique_addresses").toInt()));
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
