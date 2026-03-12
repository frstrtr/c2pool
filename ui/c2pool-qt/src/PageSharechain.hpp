#pragma once

#include <QWidget>
#include <QTableWidget>
#include <QLabel>
#include <QPushButton>
#include <QComboBox>
#include <QProgressBar>
#include <QJsonDocument>
#include <memory>
#include <map>

class ApiClient;

namespace nlohmann {
    class json;  // Forward declare for method signatures
}


/**
 * @brief Sharechain visualization page showing share distribution by miner/version
 * 
 * Displays:
 * - Timeline bar chart (shares per 10-minute interval)
 * - Miner distribution table
 * - Share version distribution
 * - Sharechain metrics (height, forks, etc.)
 */
class PageSharechain : public QWidget {
    Q_OBJECT

public:
    explicit PageSharechain(QWidget* parent = nullptr);
    void refresh(ApiClient* api);

private:
    void setupUI();
    void updateChartData(const QJsonObject& stats);
    void displayMinerDistribution(const QJsonObject& miner_data);
    void displayVersionDistribution(const QJsonObject& version_data);
    void displayMetrics(const QJsonObject& metrics);
    void drawTimelineChart();
    
    // UI Components
    QLabel* statusValue_;
    QLabel* chainMetricsLabel_;
    QLabel* forkCountLabel_;
    QLabel* difficultyLabel_;
    
    QTableWidget* minerTable_;
    QTableWidget* versionTable_;
    QTableWidget* timelineTable_;
    
    QWidget* chartContainer_;
    QComboBox* viewModeBox_;
    QPushButton* exportButton_;
    
    // Data storage
    struct TimelineSlot {
        uint64_t timestamp;
        int share_count;
        std::map<std::string, int> miner_distribution;
    };
    std::vector<TimelineSlot> timeline_data_;
    
    // Chart state
    int max_shares_in_slot_{0};
};
