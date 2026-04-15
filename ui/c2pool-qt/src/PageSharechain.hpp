#pragma once

#include <QCheckBox>
#include <QJsonDocument>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QWidget>

#include <QTableWidget>
#include "TreemapWidget.hpp"

#include <map>
#include <set>
#include <vector>

class ApiClient;

/// Per-share data received from the /sharechain/window endpoint.
/// API uses compact keys: H=hash, h=short_hash, m=miner, t=timestamp,
/// s=stale, V=version, v=verified, a=target_bits, b=target, dv=desired_version
struct ShareEntry {
    QString hash;       // H: full 64-char hex hash
    QString shortHash;  // h: first 16-char hex
    QString miner;      // m: miner address (ltc1q.../M.../L...)
    uint32_t timestamp{0}; // t: unix epoch
    int stale{0};       // s: 0=valid, 253=orphan, 254=doa
    int version{0};     // V: share protocol version (35/36)
    int desiredVersion{0}; // dv: desired version for signaling
    bool verified{false};  // v: verified by local node
    uint32_t targetBits{0}; // a: target in compact bits
    uint32_t target{0};    // b: target value
    int pos{0};         // computed position in display order
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

signals:
    void shareHovered(int index, const ShareEntry& share);
    void shareClicked(int index, const ShareEntry& share);

protected:
    void paintEvent(QPaintEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    bool event(QEvent* event) override;   // for tooltip

private:
    int cellAt(QPoint pos) const;

    QLabel* floatingTip_{nullptr};
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

    // PPLNS payout visualization
    QTableWidget* pplnsTable_;
    TreemapWidget* pplnsTreemap_;

    // Share detail display (shown on hover/click)
    QLabel* shareDetailLabel_;

    // Data
    std::vector<ShareEntry> shares_;
    QStringList heads_;
    std::map<QString, int> minerCounts_;
    QString lastTipHash_;  // for delta-based incremental updates
    bool initialLoadDone_{false};
};
