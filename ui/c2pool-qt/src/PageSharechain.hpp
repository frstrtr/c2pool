#pragma once

#include <QCheckBox>
#include <QJsonDocument>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QWidget>

#include <map>
#include <set>
#include <vector>

class ApiClient;

/// Per-share data received from the /sharechain/window endpoint.
struct ShareEntry {
    QString hash;       // truncated hex
    QString miner;      // hex pubkey_hash or address
    uint32_t timestamp{0};
    int stale{0};       // 0=none, 253=orphan, 254=doa
    int version{0};
    bool verified{false};
    int pos{0};         // position in chain (0 = newest)
};

/// Custom QWidget that renders the defragmenter-style grid.
class DefragWidget : public QWidget {
    Q_OBJECT
public:
    explicit DefragWidget(QWidget* parent = nullptr);

    void setShares(std::vector<ShareEntry> shares, const QStringList& heads);
    void setHiddenMiners(const std::set<QString>& hidden);

    int cellSize() const { return cellSize_; }
    void setCellSize(int sz);

    QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent* event) override;
    bool event(QEvent* event) override;   // for tooltip

private:
    int cellAt(QPoint pos) const;

    std::vector<ShareEntry> shares_;
    QStringList heads_;
    std::set<QString> hiddenMiners_;
    int cellSize_{6};
};

/// Main sharechain page with defragmenter grid, miner checkboxes, and stats.
class PageSharechain : public QWidget {
    Q_OBJECT
public:
    explicit PageSharechain(QWidget* parent = nullptr);
    void refresh(ApiClient* api);

    /// Return a stable color for a given miner address.
    static QColor colorForMiner(const QString& miner);

private:
    void setupUI();
    void updateFromJson(const QJsonObject& obj);
    void rebuildMinerList();

    // Stats labels
    QLabel* statusValue_;
    QLabel* totalSharesLabel_;
    QLabel* verifiedLabel_;
    QLabel* headsLabel_;
    QLabel* windowAgeLabel_;

    // Legend / miner list
    QWidget* minerListWidget_;
    std::map<QString, QCheckBox*> minerChecks_;

    // Grid
    DefragWidget* defragWidget_;
    QScrollArea*  scrollArea_;
    QPushButton*  selectAllBtn_;
    QPushButton*  deselectAllBtn_;

    // Data
    std::vector<ShareEntry> shares_;
    QStringList heads_;
    std::map<QString, int> minerCounts_;
};
