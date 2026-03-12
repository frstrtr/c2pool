#include "PageSharechain.hpp"
#include "ApiClient.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QFileDialog>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFont>
#include <cmath>
#include <ctime>
#include <iomanip>
#include <sstream>

PageSharechain::PageSharechain(std::shared_ptr<ApiClient> api, QWidget* parent)
    : QWidget(parent), api_(api) 
{
    setupUI();
}

void PageSharechain::setupUI()
{
    auto* mainLayout = new QVBoxLayout(this);
    
    // Top metrics section
    auto* metricsLayout = new QHBoxLayout();
    
    statusValue_ = new QLabel("Loading...", this);
    chainMetricsLabel_ = new QLabel("Height: 0 | Forks: 0", this);
    forkCountLabel_ = new QLabel("Heaviest Fork: 0.0%", this);
    difficultyLabel_ = new QLabel("Avg Difficulty: 1.0", this);
    
    metricsLayout->addWidget(new QLabel("Status:", this));
    metricsLayout->addWidget(statusValue_);
    metricsLayout->addSpacing(20);
    metricsLayout->addWidget(chainMetricsLabel_);
    metricsLayout->addSpacing(20);
    metricsLayout->addWidget(forkCountLabel_);
    metricsLayout->addSpacing(20);
    metricsLayout->addWidget(difficultyLabel_);
    metricsLayout->addStretch();
    
    mainLayout->addLayout(metricsLayout);
    
    // View mode selector
    auto* viewLayout = new QHBoxLayout();
    viewLayout->addWidget(new QLabel("View Mode:", this));
    viewModeBox_ = new QComboBox(this);
    viewModeBox_->addItems({"Timeline", "Miners", "Versions"});
    viewLayout->addWidget(viewModeBox_);
    viewLayout->addStretch();
    
    exportButton_ = new QPushButton("Export Data", this);
    viewLayout->addWidget(exportButton_);
    
    mainLayout->addLayout(viewLayout);
    
    // Timeline chart (ASCII bars showing shares over time)
    timelineTable_ = new QTableWidget(this);
    timelineTable_->setColumnCount(3);
    timelineTable_->setHorizontalHeaderLabels({"Time", "Shares", "Distribution"});
    timelineTable_->horizontalHeader()->setStretchLastSection(true);
    timelineTable_->setMaximumHeight(200);
    mainLayout->addWidget(new QLabel("Share Timeline (10-min intervals):", this));
    mainLayout->addWidget(timelineTable_);
    
    // Miner distribution table
    minerTable_ = new QTableWidget(this);
    minerTable_->setColumnCount(4);
    minerTable_->setHorizontalHeaderLabels({"Miner Address", "Shares", "Percentage", "Trend"});
    minerTable_->horizontalHeader()->setStretchLastSection(true);
    mainLayout->addWidget(new QLabel("Miners in Sharechain:", this));
    mainLayout->addWidget(minerTable_);
    
    // Version distribution table
    versionTable_ = new QTableWidget(this);
    versionTable_->setColumnCount(4);
    versionTable_->setHorizontalHeaderLabels({"Share Version", "Count", "Percentage", "Bar Chart"});
    versionTable_->horizontalHeader()->setStretchLastSection(true);
    mainLayout->addWidget(new QLabel("Share Versions:", this));
    mainLayout->addWidget(versionTable_);
    
    // Connect signals
    connect(exportButton_, &QPushButton::clicked, this, [this]() {
        QString filename = QFileDialog::getSaveFileName(this, "Export Sharechain Data", 
                                                       "sharechain_data.json", "JSON (*.json)");
        if (!filename.isEmpty()) {
            // Export functionality to be implemented
            QMessageBox::information(this, "Export", "Sharechain data export pending implementation");
        }
    });
    
    setLayout(mainLayout);
}

void PageSharechain::refresh()
{
    if (!api_) return;
    
    api_->getJson("/sharechain/stats",
        [this](const QJsonDocument& data) {
            if (data.isObject()) {
                updateChartData(data.object());
                statusValue_->setText("✓ Updated");
                statusValue_->setStyleSheet("color: green;");
            }
        },
        [this](const QString& err) {
            statusValue_->setText(QString("✗ Error: ") + err);
            statusValue_->setStyleSheet("color: red;");
        });
}

void PageSharechain::updateChartData(const QJsonObject& stats)
{
    // Parse sharechain metrics
    try {
        // Clear existing tables
        timelineTable_->setRowCount(0);
        minerTable_->setRowCount(0);
        versionTable_->setRowCount(0);
        
        // Update basic metrics
        int chain_height = stats.contains("chain_height") ? stats.value("chain_height").toInt() : 0;
        int fork_count = stats.contains("fork_count") ? stats.value("fork_count").toInt() : 0;
        double heaviest_fork = stats.contains("heaviest_fork_weight") ? stats.value("heaviest_fork_weight").toDouble() : 0.0;
        double avg_difficulty = stats.contains("average_difficulty") ? stats.value("average_difficulty").toDouble() : 1.0;
        
        chainMetricsLabel_->setText(
            QString("Height: %1 | Forks: %2").arg(chain_height).arg(fork_count)
        );
        forkCountLabel_->setText(
            QString("Heaviest Fork: %1%").arg(heaviest_fork * 100, 0, 'f', 2)
        );
        difficultyLabel_->setText(
            QString("Avg Difficulty: %1").arg(avg_difficulty, 0, 'f', 4)
        );
        
        // Update timeline
        if (stats.contains("timeline") && stats["timeline"].isArray()) {
            const auto timeline = stats["timeline"].toArray();
            int max_shares = 1;
            
            // First pass: find max
            for (const auto& val : timeline) {
                if (val.isObject()) {
                    auto o = val.toObject();
                    int sc = o.contains("share_count") ? o.value("share_count").toInt() : 0;
                    max_shares = std::max(max_shares, sc);
                }
            }
            
            // Second pass: display
            for (const auto& val : timeline) {
                if (!val.isObject()) continue;
                
                auto obj = val.toObject();
                auto row = timelineTable_->rowCount();
                timelineTable_->insertRow(row);
                
                // Format timestamp
                auto ts = obj.contains("timestamp") ? obj.value("timestamp").toInt() : 0;
                std::time_t t = ts;
                std::tm* tm_info = std::localtime(&t);
                char buf[20];
                std::strftime(buf, sizeof(buf), "%H:%M", tm_info);
                
                auto* timeItem = new QTableWidgetItem(QString(buf));
                timelineTable_->setItem(row, 0, timeItem);
                
                int share_count = obj.contains("share_count") ? obj.value("share_count").toInt() : 0;
                auto* countItem = new QTableWidgetItem(QString::number(share_count));
                timelineTable_->setItem(row, 1, countItem);
                
                // ASCII bar chart
                std::string bar;
                if (max_shares > 0) {
                    int bar_width = (share_count * 20) / max_shares;
                    bar = std::string(bar_width, '#');
                    bar += " " + std::to_string(share_count);
                } else {
                    bar = "-";
                }
                auto* barItem = new QTableWidgetItem(QString::fromStdString(bar));
                barItem->setFont(QFont("Courier", 9));
                timelineTable_->setItem(row, 2, barItem);
            }
        }
        
        // Update miner distribution
        if (stats.contains("shares_by_miner") && stats["shares_by_miner"].isObject()) {
            const auto miners = stats["shares_by_miner"].toObject();
            int total_shares = stats.contains("total_shares") ? stats.value("total_shares").toInt() : 1;
            
            for (auto it = miners.begin(); it != miners.end(); ++it) {
                auto row = minerTable_->rowCount();
                minerTable_->insertRow(row);
                
                auto miner_addr = it.key();
                if (miner_addr.length() > 20) {
                    miner_addr = miner_addr.left(17) + "...";
                }
                
                int count = it.value().toInt();
                double pct = (count * 100.0) / std::max(total_shares, 1);
                
                auto* addrItem = new QTableWidgetItem(miner_addr);
                minerTable_->setItem(row, 0, addrItem);
                
                auto* countItem = new QTableWidgetItem(QString::number(count));
                minerTable_->setItem(row, 1, countItem);
                
                auto* pctItem = new QTableWidgetItem(QString::number(pct, 'f', 2) + "%");
                minerTable_->setItem(row, 2, pctItem);
                
                std::string bar = std::string(static_cast<int>(pct / 5), '█');
                auto* barItem = new QTableWidgetItem(QString::fromStdString(bar));
                barItem->setFont(QFont("Courier", 9));
                minerTable_->setItem(row, 3, barItem);
            }
        }
        
        // Update version distribution
        if (stats.contains("shares_by_version") && stats["shares_by_version"].isObject()) {
            const auto versions = stats["shares_by_version"].toObject();
            int total_shares = stats.contains("total_shares") ? stats.value("total_shares").toInt() : 1;
            
            for (auto it = versions.begin(); it != versions.end(); ++it) {
                auto row = versionTable_->rowCount();
                versionTable_->insertRow(row);
                
                auto version_str = QString("v%1").arg(it.key());
                int count = it.value().toInt();
                double pct = (count * 100.0) / std::max(total_shares, 1);
                
                auto* verItem = new QTableWidgetItem(version_str);
                versionTable_->setItem(row, 0, verItem);
                
                auto* countItem = new QTableWidgetItem(QString::number(count));
                versionTable_->setItem(row, 1, countItem);
                
                auto* pctItem = new QTableWidgetItem(QString::number(pct, 'f', 2) + "%");
                versionTable_->setItem(row, 2, pctItem);
                
                std::string bar = std::string(static_cast<int>(pct / 5), '#');
                auto* barItem = new QTableWidgetItem(QString::fromStdString(bar));
                barItem->setFont(QFont("Courier", 9));
                versionTable_->setItem(row, 3, barItem);
            }
        }
        
    } catch (const std::exception& e) {
        statusValue_->setText(QString("✗ Parse error"));
        statusValue_->setStyleSheet("color: red;");
    }
}

void PageSharechain::displayMinerDistribution(const QJsonObject& miner_data)
{
    // Handled in updateChartData
}

void PageSharechain::displayVersionDistribution(const QJsonObject& version_data)
{
    // Handled in updateChartData
}

void PageSharechain::displayMetrics(const QJsonObject& metrics)
{
    // Handled in updateChartData
}

void PageSharechain::drawTimelineChart()
{
    // ASCII-based chart drawing (handled in table visualization)
}
