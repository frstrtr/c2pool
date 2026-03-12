#include "PageMining.hpp"

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

    connectedMinersValue_ = new QLabel("Connected miners: -");
    layout->addWidget(connectedMinersValue_);

    miningStateValue_ = new QLabel("Mining state: unknown");
    layout->addWidget(miningStateValue_);

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
            if (doc.isObject()) {
                const auto obj = doc.object();
                const int total = obj.value("total_connected").toInt();
                connectedMinersValue_->setText(QString("Connected miners: %1").arg(total));
            } else if (doc.isArray()) {
                connectedMinersValue_->setText(QString("Connected miners: %1").arg(doc.array().size()));
            }
        },
        [this](const QString&) {
            // Keep last value
        }
    );

    api->getJson("/stratum_stats",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) {
                statusValue_->setText("Unexpected /stratum_stats payload");
                return;
            }

            const auto root = doc.object();
            const bool miningEnabled = root.value("mining_enabled").toBool(true);
            miningStateValue_->setText(QString("Mining state: %1").arg(miningEnabled ? "running" : "stopped"));
            const auto workers = root.value("workers").toObject();
            workersTable_->setRowCount(workers.size());

            int row = 0;
            for (auto it = workers.begin(); it != workers.end(); ++it, ++row) {
                const auto w = it.value().toObject();

                workersTable_->setItem(row, 0, new QTableWidgetItem(it.key()));
                workersTable_->setItem(row, 1, new QTableWidgetItem(QString::number(w.value("accepted").toInt())));
                workersTable_->setItem(row, 2, new QTableWidgetItem(QString::number(w.value("rejected").toInt())));
                workersTable_->setItem(row, 3, new QTableWidgetItem(QString::number(w.value("hash_rate").toDouble(), 'f', 2)));
                workersTable_->setItem(row, 4, new QTableWidgetItem(w.value("merged_auto_converted").toBool() ? "yes" : "no"));
                workersTable_->setItem(row, 5, new QTableWidgetItem(w.value("merged_redistributed").toBool() ? "yes" : "no"));
            }

            statusValue_->setText(QString("Loaded %1 workers").arg(workers.size()));
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
