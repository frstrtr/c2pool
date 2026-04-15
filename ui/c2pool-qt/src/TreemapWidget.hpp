#pragma once

#include <QPainter>
#include <QWidget>
#include <QMouseEvent>
#include <QToolTip>

#include <vector>
#include <algorithm>
#include <numeric>

/// Entry for the PPLNS treemap.
struct TreemapEntry {
    QString address;
    double ltcAmount = 0;
    double ltcPercent = 0;
    double dogeAmount = 0;
    QString dogeAddress;
    QColor color;
};

/// Squarified treemap widget for PPLNS payout visualization.
/// Rectangles are proportional to each miner's PPLNS weight.
class TreemapWidget : public QWidget
{
public:
    explicit TreemapWidget(QWidget* parent = nullptr)
        : QWidget(parent) { setMouseTracking(true); }

    void setEntries(std::vector<TreemapEntry> entries) {
        entries_ = std::move(entries);
        layoutRects();
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        if (rects_.empty()) return;
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, false);

        for (size_t i = 0; i < rects_.size(); ++i) {
            auto& r = rects_[i];
            auto& e = entries_[i];

            // Fill
            p.fillRect(r, e.color);

            // Border
            p.setPen(QPen(QColor(30, 41, 59), 1));
            p.drawRect(r);

            // Labels (only if cell is large enough)
            p.setPen(Qt::white);
            if (r.width() > 50 && r.height() > 20) {
                QFont f = font();
                int fsz = std::min(int(r.width() / 6), int(r.height() / 4));
                f.setPixelSize(std::clamp(fsz, 8, 18));
                f.setBold(true);
                p.setFont(f);
                p.drawText(r.adjusted(4, 2, -2, -2), Qt::AlignLeft | Qt::AlignTop,
                           QString("%1%").arg(e.ltcPercent * 100, 0, 'f', 1));
            }
            if (r.width() > 80 && r.height() > 35) {
                QFont f = font();
                f.setPixelSize(std::clamp(int(r.width() / 12), 7, 10));
                p.setFont(f);
                p.drawText(r.adjusted(4, 0, -2, -4), Qt::AlignLeft | Qt::AlignBottom,
                           e.address.left(14) + "...");
            }
            if (r.width() > 60 && r.height() > 50 && e.dogeAmount > 0) {
                QFont f = font();
                f.setPixelSize(std::clamp(int(r.width() / 8), 7, 11));
                p.setFont(f);
                p.setPen(QColor(0, 229, 255));
                p.drawText(r.adjusted(4, 18, -2, -2), Qt::AlignLeft | Qt::AlignTop,
                           QString("%1 DOGE").arg(e.dogeAmount, 0, 'f', 1));
                p.setPen(Qt::white);
            }
        }
    }

    void mouseMoveEvent(QMouseEvent* event) override {
        for (size_t i = 0; i < rects_.size(); ++i) {
            if (rects_[i].contains(event->pos())) {
                auto& e = entries_[i];
                QString tip = QString(
                    "<b>%1</b><br>"
                    "LTC: %2% (%3 LTC)<br>"
                    "DOGE: %4")
                    .arg(e.address)
                    .arg(e.ltcPercent * 100, 0, 'f', 2)
                    .arg(e.ltcAmount, 0, 'f', 4)
                    .arg(e.dogeAmount > 0 ? QString("%1 DOGE").arg(e.dogeAmount, 0, 'f', 2) : "-");
                QToolTip::showText(event->globalPosition().toPoint(), tip, this);
                return;
            }
        }
        QToolTip::hideText();
    }

private:
    void layoutRects() {
        rects_.clear();
        if (entries_.empty() || width() <= 0 || height() <= 0) return;
        rects_.resize(entries_.size());
        squarify(0, entries_.size(), 0, 0, width(), height());
    }

    void resizeEvent(QResizeEvent*) override { layoutRects(); }
    void showEvent(QShowEvent*) override { layoutRects(); }

    // Squarified treemap algorithm
    void squarify(int start, int end, double x, double y, double w, double h) {
        if (start >= end || w <= 0 || h <= 0) return;

        double total = 0;
        for (int i = start; i < end; ++i)
            total += entries_[i].ltcPercent;
        if (total <= 0) return;

        bool vert = w >= h;
        double mainLen = vert ? h : w;
        double crossLen = vert ? w : h;

        int rowEnd = start;
        double rowArea = 0;
        double bestRatio = 1e18;

        for (int i = start; i < end; ++i) {
            double testArea = rowArea + entries_[i].ltcPercent;
            double strip = (testArea / total) * crossLen;
            if (strip <= 0) { rowEnd = i + 1; rowArea = testArea; continue; }

            double worst = 0;
            double acc = 0;
            for (int j = start; j <= i; ++j) {
                double sz = (entries_[j].ltcPercent / testArea) * mainLen;
                double ratio = std::max(sz / strip, strip / sz);
                if (ratio > worst) worst = ratio;
            }

            if (worst <= bestRatio) {
                bestRatio = worst;
                rowEnd = i + 1;
                rowArea = testArea;
            } else {
                break;
            }
        }

        double strip = (rowArea / total) * crossLen;
        double off = 0;
        for (int i = start; i < rowEnd; ++i) {
            double sz = (entries_[i].ltcPercent / rowArea) * mainLen;
            if (vert)
                rects_[i] = QRectF(x, y + off, strip, sz).toAlignedRect();
            else
                rects_[i] = QRectF(x + off, y, sz, strip).toAlignedRect();
            off += sz;
        }

        if (rowEnd < end) {
            if (vert) squarify(rowEnd, end, x + strip, y, w - strip, h);
            else squarify(rowEnd, end, x, y + strip, w, h - strip);
        }
    }

    std::vector<TreemapEntry> entries_;
    std::vector<QRect> rects_;
};
