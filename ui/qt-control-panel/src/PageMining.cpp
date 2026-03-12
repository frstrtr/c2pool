#include "PageMining.hpp"

#include <QHeaderView>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QVBoxLayout>

PageMining::PageMining(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);

    connectedMinersValue_ = new QLabel("Connected miners: -");
    layout->addWidget(connectedMinersValue_);

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
}

void PageMining::refresh(ApiClient* api)
{
    statusValue_->setText("Refreshing...");

    api->getJson("/connected_miners",
        [this](const QJsonDocument& doc) {
            if (doc.isArray()) {
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
