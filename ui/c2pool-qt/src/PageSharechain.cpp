#include "PageSharechain.hpp"
#include "ApiClient.hpp"

#include <QDateTime>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QMouseEvent>
#include <QPainter>
#include <QPieSeries>
#include <QChart>
#include <QToolTip>
#include <QVBoxLayout>
#include <QHelpEvent>
#include <QFont>

#include <algorithm>
#include <cmath>
#include <functional>

// ── Deterministic colour palette ────────────────────────────────────────
static const QColor kPalette[] = {
    QColor(74, 222, 128),   // green
    QColor(34, 211, 238),   // cyan
    QColor(168,  85, 247),  // purple
    QColor(249, 115,  22),  // orange
    QColor( 59, 130, 246),  // blue
    QColor(244,  63,  94),  // rose
    QColor(132, 204,  22),  // lime
    QColor(236,  72, 153),  // pink
    QColor(234, 179,   8),  // yellow
    QColor( 20, 184, 166),  // teal
    QColor(239,  68,  68),  // red
    QColor(147, 197, 253),  // light blue
};
static constexpr int kPaletteSize = sizeof(kPalette) / sizeof(kPalette[0]);

static const QColor kNetworkGray(51, 65, 85);   // for "hidden" / network shares
static const QColor kOrphanMark(239, 68, 68);    // red X
static const QColor kDoaMark(251, 191, 36);       // yellow cross
static const QColor kHeadGlow(255, 255, 255);     // white ring for chain heads


// ══════════════════════════════════════════════════════════════════════════
//  DefragWidget
// ══════════════════════════════════════════════════════════════════════════

DefragWidget::DefragWidget(QWidget* parent)
    : QWidget(parent)
{
    setMouseTracking(true);

    // Custom floating tooltip parented to top-level window (follows cursor)
    floatingTip_ = new QLabel(window());
    floatingTip_->setTextFormat(Qt::RichText);
    floatingTip_->setStyleSheet(
        "QLabel { background: rgba(30,41,59,0.95); color: #e2e8f0; "
        "border: 1px solid #475569; border-radius: 6px; padding: 8px; "
        "font-size: 11px; }");
    floatingTip_->setAttribute(Qt::WA_TransparentForMouseEvents);
    floatingTip_->hide();
}

void DefragWidget::setShares(std::vector<ShareEntry> shares, const QStringList& heads)
{
    shares_ = std::move(shares);
    heads_ = heads;
    updateGeometry();
    update();
}

void DefragWidget::setHiddenMiners(const std::set<QString>& hidden)
{
    hiddenMiners_ = hidden;
    update();
}

void DefragWidget::setCellSize(int sz)
{
    cellSize_ = std::max(3, sz);
    updateGeometry();
    update();
}

QSize DefragWidget::sizeHint() const
{
    if (shares_.empty()) return QSize(200, 100);
    int w = width() > 0 ? width() : 800;
    int cols = std::max(1, w / (cellSize_ + 1));
    int rows = (static_cast<int>(shares_.size()) + cols - 1) / cols;
    return QSize(w, rows * (cellSize_ + 1) + 2);
}

int DefragWidget::cellAt(QPoint pos) const
{
    int gap = 1;
    int step = cellSize_ + gap;
    int cols = std::max(1, width() / step);
    int col = pos.x() / step;
    int row = pos.y() / step;
    if (col >= cols) return -1;
    int idx = row * cols + col;
    if (idx < 0 || idx >= static_cast<int>(shares_.size())) return -1;
    return idx;
}

bool DefragWidget::event(QEvent* event)
{
    if (event->type() == QEvent::Leave) {
        floatingTip_->hide();
    }
    return QWidget::event(event);
}

void DefragWidget::mouseMoveEvent(QMouseEvent* event)
{
    int idx = cellAt(event->pos());
    if (idx >= 0 && idx < static_cast<int>(shares_.size())) {
        auto& s = shares_[idx];
        emit shareHovered(idx, s);

        // Position floating tooltip near cursor
        auto dt = QDateTime::fromSecsSinceEpoch(s.timestamp);
        const double diff = s.targetBits > 0 ? static_cast<double>(s.targetBits) / 65536.0 : 0;
        QString status = s.stale == 253 ? "<span style='color:#ef4444'>ORPHAN</span>"
            : s.stale == 254 ? "<span style='color:#fbbf24'>DOA</span>"
            : s.verified ? "<span style='color:#4ade80'>verified</span>"
            : "<span style='color:#94a3b8'>unverified</span>";

        // PPLNS enrichment for this miner
        QString pplnsLine;
        if (payoutCache_) {
            auto pit = payoutCache_->find(s.miner);
            if (pit != payoutCache_->end()) {
                pplnsLine = QString("<br><b>PPLNS:</b> %1% weight")
                    .arg(pit->second.first, 0, 'f', 2);
                if (pit->second.second > 0)
                    pplnsLine += QString(" | %1 DOGE").arg(pit->second.second, 0, 'f', 1);
            }
        }

        floatingTip_->setText(
            QString("<b>%1</b><br>"
                    "<b>Miner:</b> %2<br>"
                    "<b>Time:</b> %3 | <b>v%4</b> | diff %5<br>"
                    "<b>Status:</b> %6%7")
                .arg(s.shortHash)
                .arg(s.miner)
                .arg(dt.toString("hh:mm:ss"))
                .arg(s.version)
                .arg(diff, 0, 'f', 1)
                .arg(status)
                .arg(pplnsLine));
        floatingTip_->adjustSize();
        // Map cursor position to the tooltip's parent (main window)
        QPoint inParent = mapTo(floatingTip_->parentWidget(), event->pos());
        floatingTip_->move(inParent.x() + 14, inParent.y() + 14);
        floatingTip_->raise();
        floatingTip_->show();
    } else {
        floatingTip_->hide();
    }
}

void DefragWidget::mousePressEvent(QMouseEvent* event)
{
    if (event->button() != Qt::LeftButton) return;
    int idx = cellAt(event->pos());
    if (idx >= 0 && idx < static_cast<int>(shares_.size()))
        emit shareClicked(idx, shares_[idx]);
}

void DefragWidget::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, false);

    int gap = 1;
    int step = cellSize_ + gap;
    int cols = std::max(1, width() / step);
    int total = static_cast<int>(shares_.size());

    // Build head set for O(1) lookup
    std::set<QString> headSet;
    for (auto& h : heads_) headSet.insert(h);

    for (int i = 0; i < total; ++i) {
        auto& s = shares_[i];
        int col = i % cols;
        int row = i / cols;
        int x = col * step;
        int y = row * step;

        bool hidden = hiddenMiners_.count(s.miner) > 0;

        // Age-based opacity: newest (pos=0) is brightest, oldest fades
        double age = static_cast<double>(s.pos) / std::max(1, total);
        double opacity = 1.0 - age * 0.7;

        QColor cellColor;
        if (hidden) {
            cellColor = kNetworkGray;
            cellColor.setAlphaF(opacity * 0.3);
        } else {
            cellColor = PageSharechain::colorForMiner(s.miner);
            cellColor.setAlphaF(opacity);
        }

        p.fillRect(x, y, cellSize_, cellSize_, cellColor);

        // Stale marks
        if (s.stale == 253) {
            // Orphan: red X
            p.setPen(QPen(kOrphanMark, 1));
            p.drawLine(x, y, x + cellSize_ - 1, y + cellSize_ - 1);
            p.drawLine(x + cellSize_ - 1, y, x, y + cellSize_ - 1);
        } else if (s.stale == 254) {
            // DOA: yellow diagonal
            p.setPen(QPen(kDoaMark, 1));
            p.drawLine(x, y, x + cellSize_ - 1, y + cellSize_ - 1);
        }

        // Head marker: white dot (heads use short 16-char hex)
        if (headSet.count(s.shortHash) > 0 || headSet.count(s.hash) > 0) {
            p.setPen(Qt::NoPen);
            p.setBrush(kHeadGlow);
            int r = std::max(1, cellSize_ / 3);
            p.drawEllipse(QPoint(x + cellSize_ / 2, y + cellSize_ / 2), r, r);
        }
    }
}


// ══════════════════════════════════════════════════════════════════════════
//  PageSharechain
// ══════════════════════════════════════════════════════════════════════════

PageSharechain::PageSharechain(QWidget* parent)
    : QWidget(parent)
{
    setupUI();
}

QColor PageSharechain::colorForMiner(const QString& miner)
{
    // Stable hash → palette index
    uint32_t h = 0;
    for (auto ch : miner) h = h * 31 + ch.unicode();
    return kPalette[h % kPaletteSize];
}

void PageSharechain::setupUI()
{
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(8, 8, 8, 8);

    // ── Top stats bar ────────────────────────────────────────────────
    auto* statsBar = new QHBoxLayout();
    auto makeStatBox = [&](const QString& label) -> QLabel* {
        auto* box = new QWidget(this);
        auto* bl = new QVBoxLayout(box);
        bl->setContentsMargins(8, 4, 8, 4);
        auto* lbl = new QLabel(label, box);
        lbl->setStyleSheet("color: #64748b; font-size: 9px; font-weight: bold;");
        auto* val = new QLabel("—", box);
        val->setStyleSheet("font-size: 16px; font-weight: bold;");
        bl->addWidget(lbl);
        bl->addWidget(val);
        box->setStyleSheet("background: #0f172a; border: 1px solid #1e293b; border-radius: 6px;");
        statsBar->addWidget(box);
        return val;
    };

    totalSharesLabel_ = makeStatBox("TOTAL SHARES");
    verifiedLabel_    = makeStatBox("VERIFIED");
    headsLabel_       = makeStatBox("CHAIN HEADS");
    windowAgeLabel_   = makeStatBox("WINDOW SPAN");
    statusValue_      = makeStatBox("STATUS");

    mainLayout->addLayout(statsBar);

    // ── Controls bar ─────────────────────────────────────────────────
    auto* controlBar = new QHBoxLayout();
    auto* gridLabel = new QLabel("SHARECHAIN DEFRAGMENTER", this);
    gridLabel->setStyleSheet("font-size: 11px; font-weight: bold; color: #e2e8f0;");
    controlBar->addWidget(gridLabel);
    controlBar->addStretch();

    selectAllBtn_ = new QPushButton("Select All", this);
    deselectAllBtn_ = new QPushButton("Deselect All", this);
    selectAllBtn_->setFixedHeight(24);
    deselectAllBtn_->setFixedHeight(24);
    controlBar->addWidget(selectAllBtn_);
    controlBar->addWidget(deselectAllBtn_);

    mainLayout->addLayout(controlBar);

    // ── Main content: grid + miner list side by side ─────────────────
    auto* contentLayout = new QHBoxLayout();

    // Defrag grid inside scroll area
    defragWidget_ = new DefragWidget(this);
    scrollArea_ = new QScrollArea(this);
    scrollArea_->setWidget(defragWidget_);
    scrollArea_->setWidgetResizable(true);
    scrollArea_->setStyleSheet(
        "QScrollArea { background: #020617; border: 1px solid #334155; border-radius: 8px; }"
    );
    contentLayout->addWidget(scrollArea_, 1);

    // Miner list panel (right side)
    auto* minerPanel = new QWidget(this);
    auto* minerPanelLay = new QVBoxLayout(minerPanel);
    minerPanelLay->setContentsMargins(4, 4, 4, 4);
    auto* minerTitle = new QLabel("MINERS", minerPanel);
    minerTitle->setStyleSheet("font-size: 10px; font-weight: bold; color: #64748b;");
    minerPanelLay->addWidget(minerTitle);

    auto* minerScroll = new QScrollArea(minerPanel);
    minerListWidget_ = new QWidget(minerScroll);
    minerListWidget_->setLayout(new QVBoxLayout(minerListWidget_));
    minerListWidget_->layout()->setContentsMargins(0, 0, 0, 0);
    minerListWidget_->layout()->setSpacing(2);
    minerScroll->setWidget(minerListWidget_);
    minerScroll->setWidgetResizable(true);
    minerScroll->setFixedWidth(200);
    minerPanelLay->addWidget(minerScroll, 1);

    minerPanel->setStyleSheet(
        "background: #0f172a; border: 1px solid #1e293b; border-radius: 6px;"
    );
    minerPanel->setFixedWidth(210);
    contentLayout->addWidget(minerPanel);

    mainLayout->addLayout(contentLayout, 3);

    // ── PPLNS payout summary ────────────────────────────────────────
    pplnsTable_ = new QTableWidget(this);
    pplnsTable_->setColumnCount(4);
    pplnsTable_->setHorizontalHeaderLabels({"Miner", "Shares", "Weight %", "Est. Payout"});
    pplnsTable_->horizontalHeader()->setStretchLastSection(true);
    pplnsTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    pplnsTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    pplnsTable_->setSortingEnabled(true);
    pplnsTable_->setMaximumHeight(200);
    pplnsTable_->setStyleSheet("QTableWidget { background: #0f172a; border: 1px solid #1e293b; }");

    // PPLNS treemap (squarified layout, proportional to miner weight)
    pplnsTreemap_ = new TreemapWidget(this);
    pplnsTreemap_->setMinimumHeight(120);
    pplnsTreemap_->setStyleSheet("background: #020617; border: 1px solid #334155;");

    // PPLNS pie chart (QtCharts)
    auto* pplnsChart = new QChart();
    pplnsChart->setAnimationOptions(QChart::SeriesAnimations);
    pplnsChart->setBackgroundBrush(QBrush(QColor(15, 23, 42)));
    pplnsChart->setTitle("PPLNS Weight Distribution");
    pplnsChart->setTitleBrush(QBrush(QColor(226, 232, 240)));
    pplnsChart->legend()->setVisible(false);
    pplnsPieView_ = new QChartView(pplnsChart, this);
    pplnsPieView_->setRenderHint(QPainter::Antialiasing);
    pplnsPieView_->setMinimumHeight(120);
    pplnsPieView_->setStyleSheet("background: #0f172a; border: 1px solid #1e293b;");

    // Layout: treemap left, pie center, table right
    auto* pplnsLayout = new QHBoxLayout();
    pplnsLayout->addWidget(pplnsTreemap_, 2);
    pplnsLayout->addWidget(pplnsPieView_, 2);
    pplnsLayout->addWidget(pplnsTable_, 1);
    mainLayout->addLayout(pplnsLayout, 1);

    // ── Share detail on hover/click ─────────────────────────────────
    shareDetailLabel_ = new QLabel(this);
    shareDetailLabel_->setWordWrap(true);
    shareDetailLabel_->setTextFormat(Qt::RichText);
    shareDetailLabel_->setStyleSheet(
        "background: #1e293b; border: 1px solid #334155; border-radius: 4px; "
        "padding: 6px; font-size: 11px; color: #e2e8f0;");
    shareDetailLabel_->setText("Hover or click a share cell for details");
    shareDetailLabel_->setMaximumHeight(60);
    mainLayout->addWidget(shareDetailLabel_);

    // Wire share hover/click signals
    connect(defragWidget_, &DefragWidget::shareHovered, this, [this](int, const ShareEntry& s) {
        auto dt = QDateTime::fromSecsSinceEpoch(s.timestamp);
        const double diff = s.targetBits > 0 ? static_cast<double>(s.targetBits) / 65536.0 : 0;
        QString status = s.stale == 253 ? "ORPHAN" : s.stale == 254 ? "DOA"
            : s.verified ? "verified" : "unverified";
        shareDetailLabel_->setText(
            QString("<b>%1</b> | Miner: %2 | %3 | v%4 | diff %5 | %6")
                .arg(s.hash.left(16) + "...")
                .arg(s.miner)
                .arg(dt.toString("hh:mm:ss"))
                .arg(s.version)
                .arg(diff, 0, 'f', 2)
                .arg(status));
    });

    connect(defragWidget_, &DefragWidget::shareClicked, this, [this](int, const ShareEntry& s) {
        auto dt = QDateTime::fromSecsSinceEpoch(s.timestamp);
        const double diff = s.targetBits > 0 ? static_cast<double>(s.targetBits) / 65536.0 : 0;
        QString status = s.stale == 253 ? "<span style='color:#ef4444'>ORPHAN</span>"
            : s.stale == 254 ? "<span style='color:#fbbf24'>DOA</span>"
            : s.verified ? "<span style='color:#4ade80'>verified</span>"
            : "<span style='color:#94a3b8'>unverified</span>";
        shareDetailLabel_->setText(
            QString("<b>Share #%1</b><br>"
                    "Hash: %2<br>"
                    "Miner: <b>%3</b> | Time: %4 | Version: v%5 (dv%6) | Difficulty: %7 | %8")
                .arg(s.pos)
                .arg(s.hash)
                .arg(s.miner)
                .arg(dt.toString("yyyy-MM-dd hh:mm:ss"))
                .arg(s.version).arg(s.desiredVersion)
                .arg(diff, 0, 'f', 2)
                .arg(status));
    });

    // ── Legend bar ───────────────────────────────────────────────────
    auto* legendLayout = new QHBoxLayout();
    auto makeLegendItem = [&](const QColor& color, const QString& label) {
        auto* item = new QWidget(this);
        auto* il = new QHBoxLayout(item);
        il->setContentsMargins(4, 2, 4, 2);
        auto* swatch = new QLabel(item);
        swatch->setFixedSize(10, 10);
        swatch->setStyleSheet(QString("background: %1; border-radius: 2px;").arg(color.name()));
        il->addWidget(swatch);
        auto* txt = new QLabel(label, item);
        txt->setStyleSheet("font-size: 9px; color: #94a3b8;");
        il->addWidget(txt);
        legendLayout->addWidget(item);
    };

    makeLegendItem(kOrphanMark, "Orphan (red X)");
    makeLegendItem(kDoaMark, "DOA (yellow stripe)");
    makeLegendItem(kHeadGlow, "Chain head (dot)");
    makeLegendItem(kNetworkGray, "Hidden miner");
    legendLayout->addStretch();
    auto* ageNote = new QLabel("← Newest   |   Oldest →", this);
    ageNote->setStyleSheet("font-size: 9px; color: #475569;");
    legendLayout->addWidget(ageNote);

    mainLayout->addLayout(legendLayout);

    // ── Signals ──────────────────────────────────────────────────────
    connect(selectAllBtn_, &QPushButton::clicked, this, [this]() {
        for (auto& [_, cb] : minerChecks_) cb->setChecked(true);
        defragWidget_->setHiddenMiners({});
    });
    connect(deselectAllBtn_, &QPushButton::clicked, this, [this]() {
        std::set<QString> all;
        for (auto& [m, cb] : minerChecks_) { cb->setChecked(false); all.insert(m); }
        defragWidget_->setHiddenMiners(all);
    });
}

void PageSharechain::refresh(ApiClient* api)
{
    if (!api) return;

    // Fetch PPLNS payouts for treemap (lightweight endpoint)
    api->getJson("/current_merged_payouts",
        [this](const QJsonDocument& doc) {
            if (!doc.isObject()) return;
            const auto payouts = doc.object();
            double totalLtc = 0;
            struct RawEntry { QString addr; double ltc; double doge; QString dogeAddr; };
            std::vector<RawEntry> raw;
            for (auto it = payouts.begin(); it != payouts.end(); ++it) {
                RawEntry e;
                e.addr = it.key();
                const auto val = it.value();
                // Handle both {amount: N, merged: [...]} and plain number
                if (val.isDouble()) {
                    e.ltc = val.toDouble();
                } else {
                    e.ltc = val.toObject().value("amount").toDouble();
                }
                e.doge = 0; e.dogeAddr = "";
                if (val.isObject()) {
                    const auto merged = val.toObject().value("merged").toArray();
                    for (const auto& m : merged) {
                        const auto mo = m.toObject();
                        if (mo.value("symbol").toString() == "DOGE") {
                            e.doge = mo.value("amount").toDouble();
                            e.dogeAddr = mo.value("address").toString();
                        }
                    }
                }
                totalLtc += e.ltc;
                raw.push_back(e);
            }
            // Sort by LTC amount descending
            std::sort(raw.begin(), raw.end(), [](auto& a, auto& b) {
                return a.ltc > b.ltc;
            });
            // Build treemap entries weighted by LTC share
            std::vector<TreemapEntry> entries;
            for (auto& r : raw) {
                TreemapEntry te;
                te.address = r.addr;
                te.ltcAmount = r.ltc;
                te.ltcPercent = totalLtc > 0 ? r.ltc / totalLtc : 0;
                te.dogeAmount = r.doge;
                te.dogeAddress = r.dogeAddr;
                // Use miner color from palette (same as defrag grid)
                te.color = PageSharechain::colorForMiner(r.addr);
                // Darken slightly for treemap background
                te.color.setHsv(te.color.hsvHue(), te.color.hsvSaturation() * 0.7,
                                te.color.value() * 0.5);
                entries.push_back(te);
            }
            pplnsTreemap_->setEntries(std::move(entries));

            // Build pie chart
            auto* pie = new QPieSeries();
            for (auto& r : raw) {
                double pct = totalLtc > 0 ? r.ltc / totalLtc : 0;
                if (pct < 0.01) continue;  // skip tiny slices
                auto* slice = pie->append(
                    QString("%1 %2%").arg(r.addr.left(8)).arg(pct * 100, 0, 'f', 1),
                    r.ltc);
                slice->setColor(PageSharechain::colorForMiner(r.addr));
                slice->setBorderColor(QColor(30, 41, 59));
                slice->setLabelVisible(pct > 0.05);
                slice->setLabelColor(QColor(148, 163, 184));
            }
            auto* chart = pplnsPieView_->chart();
            chart->removeAllSeries();
            chart->addSeries(pie);

            // Cache payouts for share tooltip enrichment
            cachedPayouts_.clear();
            payoutCacheForDefrag_.clear();
            for (auto& r : raw) {
                MinerPayout mp;
                mp.ltc = r.ltc;
                mp.doge = r.doge;
                mp.pct = totalLtc > 0 ? r.ltc / totalLtc * 100.0 : 0;
                cachedPayouts_[r.addr] = mp;
                payoutCacheForDefrag_[r.addr] = {mp.pct, mp.doge};
            }
            defragWidget_->setPayoutCache(&payoutCacheForDefrag_);
        },
        [](const QString&) { }
    );

    // Fetch full sharechain window (25MB+). Use 60s timeout for large payload.
    // Only re-fetch if we have no shares yet or explicitly refreshing.
    if (shares_.empty()) {
        statusValue_->setText("LOADING");
        statusValue_->setStyleSheet("color: #fbbf24; font-size: 16px; font-weight: bold;");
    }

    api->getJson("/sharechain/window",
        [this](const QJsonDocument& data) {
            if (data.isObject()) {
                updateFromJson(data.object());
            }
            statusValue_->setText("OK");
            statusValue_->setStyleSheet("color: #4ade80; font-size: 16px; font-weight: bold;");
        },
        [this](const QString&) {
            // On failure, keep existing data
            if (shares_.empty()) {
                statusValue_->setText("ERR");
                statusValue_->setStyleSheet("color: #ef4444; font-size: 16px; font-weight: bold;");
            }
        },
        60000);  // 60s timeout for 25MB+ response
}

void PageSharechain::updateFromJson(const QJsonObject& obj)
{
    shares_.clear();
    minerCounts_.clear();

    auto arr = obj.value("shares").toArray();
    shares_.reserve(arr.size());

    for (int i = 0; i < arr.size(); ++i) {
        auto o = arr[i].toObject();
        ShareEntry e;
        // Compact API keys: H=hash, h=short, m=miner, t=time, s=stale, V=ver, v=verified
        e.hash           = o.value("H").toString();
        e.shortHash      = o.value("h").toString();
        e.miner          = o.value("m").toString();
        e.timestamp      = static_cast<uint32_t>(o.value("t").toDouble());
        e.stale          = o.value("s").toInt();
        e.version        = o.value("V").toInt();
        e.desiredVersion = o.value("dv").toInt();
        e.verified       = o.value("v").toInt() != 0;
        e.targetBits     = static_cast<uint32_t>(o.value("a").toDouble());
        e.target         = static_cast<uint32_t>(o.value("b").toDouble());
        e.pos            = i;
        shares_.push_back(e);
        minerCounts_[e.miner]++;
    }

    heads_.clear();
    auto headsArr = obj.value("heads").toArray();
    for (auto&& v : headsArr)
        heads_.push_back(v.toString());

    // Save tip hash for delta-based updates
    lastTipHash_ = obj.value("best_hash").toString();

    // Stats
    int total = obj.value("total").toInt();
    totalSharesLabel_->setText(QString::number(total));

    int verifiedCount = 0;
    for (auto& s : shares_)
        if (s.verified) verifiedCount++;
    verifiedLabel_->setText(QString::number(verifiedCount));

    headsLabel_->setText(QString::number(heads_.size()));

    // Window age: difference between newest and oldest timestamp
    if (!shares_.empty()) {
        uint32_t newest = shares_.front().timestamp;
        uint32_t oldest = shares_.back().timestamp;
        int span = static_cast<int>(newest) - static_cast<int>(oldest);
        if (span > 3600)
            windowAgeLabel_->setText(QString("%1h %2m").arg(span / 3600).arg((span % 3600) / 60));
        else if (span > 60)
            windowAgeLabel_->setText(QString("%1m").arg(span / 60));
        else
            windowAgeLabel_->setText(QString("%1s").arg(span));
    } else {
        windowAgeLabel_->setText("—");
    }

    rebuildMinerList();
    defragWidget_->setShares(shares_, heads_);

    // Populate PPLNS summary table from miner share counts
    std::vector<std::pair<QString, int>> sorted(minerCounts_.begin(), minerCounts_.end());
    std::sort(sorted.begin(), sorted.end(),
              [](auto& a, auto& b) { return a.second > b.second; });

    pplnsTable_->setSortingEnabled(false);
    pplnsTable_->setRowCount(static_cast<int>(sorted.size()));
    const int totalInWindow = static_cast<int>(shares_.size());
    const double blockValue = 6.25;  // approximate LTC block reward

    for (int i = 0; i < static_cast<int>(sorted.size()); ++i) {
        auto& [miner, count] = sorted[i];
        const double weight = totalInWindow > 0 ? (count * 100.0 / totalInWindow) : 0;
        const double payout = blockValue * weight / 100.0;

        auto* minerItem = new QTableWidgetItem(miner);
        minerItem->setForeground(colorForMiner(miner));
        pplnsTable_->setItem(i, 0, minerItem);
        pplnsTable_->setItem(i, 1, new QTableWidgetItem(QString::number(count)));

        auto* weightItem = new QTableWidgetItem();
        weightItem->setData(Qt::DisplayRole, QString("%1%").arg(weight, 0, 'f', 2));
        weightItem->setData(Qt::UserRole, weight);  // for sorting
        pplnsTable_->setItem(i, 2, weightItem);

        auto* payoutItem = new QTableWidgetItem();
        payoutItem->setData(Qt::DisplayRole, QString("%1 LTC").arg(payout, 0, 'f', 4));
        payoutItem->setData(Qt::UserRole, payout);
        pplnsTable_->setItem(i, 3, payoutItem);
    }
    pplnsTable_->setSortingEnabled(true);
}

void PageSharechain::rebuildMinerList()
{
    // Sort miners by share count (descending)
    std::vector<std::pair<QString, int>> sorted(minerCounts_.begin(), minerCounts_.end());
    std::sort(sorted.begin(), sorted.end(),
              [](auto& a, auto& b) { return a.second > b.second; });

    // Preserve existing hidden state
    std::set<QString> wasHidden;
    for (auto& [m, cb] : minerChecks_)
        if (!cb->isChecked()) wasHidden.insert(m);

    // Clear old checkboxes
    auto* lay = minerListWidget_->layout();
    QLayoutItem* item;
    while ((item = lay->takeAt(0)) != nullptr) {
        delete item->widget();
        delete item;
    }
    minerChecks_.clear();

    int totalShares = static_cast<int>(shares_.size());

    for (auto& [miner, count] : sorted) {
        auto* cb = new QCheckBox(minerListWidget_);
        QColor col = colorForMiner(miner);
        double pct = totalShares > 0 ? (count * 100.0 / totalShares) : 0;

        cb->setText(QString("%1... (%2, %3%)")
                    .arg(miner.left(8))
                    .arg(count)
                    .arg(pct, 0, 'f', 1));
        cb->setChecked(!wasHidden.count(miner));
        cb->setStyleSheet(QString(
            "QCheckBox { color: %1; font-size: 10px; }"
            "QCheckBox::indicator { width: 10px; height: 10px; }"
        ).arg(col.name()));

        connect(cb, &QCheckBox::toggled, this, [this](bool) {
            std::set<QString> hidden;
            for (auto& [m, c] : minerChecks_)
                if (!c->isChecked()) hidden.insert(m);
            defragWidget_->setHiddenMiners(hidden);
        });

        lay->addWidget(cb);
        minerChecks_[miner] = cb;
    }

    // Apply initial hidden state
    std::set<QString> hidden;
    for (auto& [m, cb] : minerChecks_)
        if (!cb->isChecked()) hidden.insert(m);
    defragWidget_->setHiddenMiners(hidden);
}
