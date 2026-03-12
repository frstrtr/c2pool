#include "PageOverview.hpp"

#include <QGridLayout>
#include <QJsonDocument>
#include <QJsonObject>

PageOverview::PageOverview(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QGridLayout(this);

    layout->addWidget(new QLabel("Uptime:"), 0, 0);
    uptimeValue_ = new QLabel("-");
    layout->addWidget(uptimeValue_, 0, 1);

    layout->addWidget(new QLabel("Pool Hashrate:"), 1, 0);
    poolHashrateValue_ = new QLabel("-");
    layout->addWidget(poolHashrateValue_, 1, 1);

    layout->addWidget(new QLabel("Pool Stale Ratio:"), 2, 0);
    staleRateValue_ = new QLabel("-");
    layout->addWidget(staleRateValue_, 2, 1);

    layout->addWidget(new QLabel("Network Difficulty:"), 3, 0);
    networkDiffValue_ = new QLabel("-");
    layout->addWidget(networkDiffValue_, 3, 1);

    layout->addWidget(new QLabel("Status:"), 4, 0);
    statusValue_ = new QLabel("Idle");
    layout->addWidget(statusValue_, 4, 1);

    layout->setColumnStretch(2, 1);
}

void PageOverview::refresh(ApiClient* api)
{
    statusValue_->setText("Refreshing...");

    api->getJson("/global_stats",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) {
                statusValue_->setText("Unexpected /global_stats payload");
                return;
            }
            const auto obj = doc.object();
            poolHashrateValue_->setText(QString::number(obj.value("pool_hash_rate").toDouble(), 'f', 2));
            staleRateValue_->setText(QString::number(obj.value("pool_stale_prop").toDouble(), 'f', 6));
            networkDiffValue_->setText(QString::number(obj.value("network_block_difficulty").toDouble(), 'f', 2));
            statusValue_->setText("Global stats OK");
        },
        [this](const QString& error) {
            statusValue_->setText(error);
        }
    );

    api->getText("/uptime",
        [this](const QString& text) {
            bool ok = false;
            const double seconds = text.trimmed().toDouble(&ok);
            if (ok) {
                uptimeValue_->setText(QString::number(seconds, 'f', 1) + " s");
            }
        },
        [this](const QString&) {
            // Keep last value
        }
    );
}
