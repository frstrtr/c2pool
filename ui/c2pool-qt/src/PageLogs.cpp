#include "PageLogs.hpp"

#include <QDateTime>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QFont>
#include <QMessageBox>
#include <QScrollBar>
#include <QStandardPaths>
#include <QUrlQuery>
#include <QVBoxLayout>

PageLogs::PageLogs(QWidget* parent)
    : QWidget(parent)
{
    auto* root = new QVBoxLayout(this);
    auto* controls = new QHBoxLayout();

    controls->addWidget(new QLabel("Scope:"));
    scopeBox_ = new QComboBox(this);
    scopeBox_->addItems({"node", "stratum", "security", "all"});
    controls->addWidget(scopeBox_);

    controls->addWidget(new QLabel("Format:"));
    formatBox_ = new QComboBox(this);
    formatBox_->addItems({"txt", "csv", "jsonl"});
    controls->addWidget(formatBox_);

    controls->addWidget(new QLabel("Range:"));
    rangeBox_ = new QComboBox(this);
    rangeBox_->addItems({"15m", "1h", "6h", "24h"});
    controls->addWidget(rangeBox_);

    exportButton_ = new QPushButton("Export Logs", this);
    controls->addWidget(exportButton_);

    controls->addWidget(new QLabel("  |  "));

    liveTailBtn_ = new QPushButton("Live Tail: OFF", this);
    liveTailBtn_->setCheckable(true);
    controls->addWidget(liveTailBtn_);

    liveLevelFilter_ = new QComboBox(this);
    liveLevelFilter_->addItems({"all", "error", "warning", "info", "debug", "trace"});
    liveLevelFilter_->setToolTip("Client-side log level filter");
    controls->addWidget(liveLevelFilter_);

    controls->addStretch(1);
    root->addLayout(controls);

    logView_ = new QPlainTextEdit(this);
    logView_->setReadOnly(true);
    logView_->setMaximumBlockCount(10000);
    logView_->setFont(QFont("Monospace", 9));
    root->addWidget(logView_);

    // Live tail timer
    liveTailTimer_.setInterval(2000);
    connect(&liveTailTimer_, &QTimer::timeout, this, &PageLogs::fetchLiveLogs);

    connect(liveTailBtn_, &QPushButton::toggled, this, [this](bool checked) {
        liveTailActive_ = checked;
        if (checked) {
            liveTailBtn_->setText("Live Tail: ON");
            liveTailBtn_->setStyleSheet("color: #1d7f3b; font-weight: bold;");
            logView_->clear();
            liveTailTimer_.start();
            fetchLiveLogs();
        } else {
            liveTailBtn_->setText("Live Tail: OFF");
            liveTailBtn_->setStyleSheet("");
            liveTailTimer_.stop();
        }
    });

    connect(exportButton_, &QPushButton::clicked, this, [this]() {
        if (!api_) {
            return;
        }

        const QString output = buildExportPath();
        if (output.isEmpty()) {
            return;
        }

        const QString scope = scopeBox_->currentText();
        const QString format = formatBox_->currentText();

        const QDateTime now = QDateTime::currentDateTimeUtc();
        qint64 seconds = 3600;
        if (rangeBox_->currentText() == "15m") seconds = 900;
        if (rangeBox_->currentText() == "6h") seconds = 21600;
        if (rangeBox_->currentText() == "24h") seconds = 86400;

        const qint64 toTs = now.toSecsSinceEpoch();
        const qint64 fromTs = toTs - seconds;

        const QString path = QString("/logs/export?scope=%1&from=%2&to=%3&format=%4")
            .arg(scope)
            .arg(fromTs)
            .arg(toTs)
            .arg(format);

        api_->download(path, output,
            [this](const QString& msg) {
                QMessageBox::information(this, "Export complete", msg);
            },
            [this](const QString& err) {
                QMessageBox::warning(this, "Export failed", err);
            }
        );
    });
}

QString PageLogs::buildExportPath() const
{
    const QString downloads = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    const QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
    const QString suggested = QString("c2pool_%1_%2.%3")
        .arg(scopeBox_->currentText())
        .arg(timestamp)
        .arg(formatBox_->currentText());

    return QFileDialog::getSaveFileName(
        const_cast<PageLogs*>(this),
        "Save Log Export",
        downloads + "/" + suggested,
        "All Files (*)"
    );
}

void PageLogs::fetchLiveLogs()
{
    if (!api_ || !liveTailActive_) return;

    api_->getText("/web/log",
        [this](const QString& text) {
            const QString filter = liveLevelFilter_->currentText();
            if (filter == "all") {
                logView_->setPlainText(text);
            } else {
                // Client-side filter: show only lines containing the level keyword
                QStringList filtered;
                const auto lines = text.split('\n');
                for (const auto& line : lines) {
                    const auto upper = line.toUpper();
                    if (filter == "error" && upper.contains("ERROR"))
                        filtered << line;
                    else if (filter == "warning" && (upper.contains("WARN") || upper.contains("ERROR")))
                        filtered << line;
                    else if (filter == "info" && (upper.contains("INFO") || upper.contains("WARN") || upper.contains("ERROR")))
                        filtered << line;
                    else if (filter == "debug" && !upper.contains("TRACE"))
                        filtered << line;
                    else if (filter == "trace")
                        filtered << line;
                }
                logView_->setPlainText(filtered.join('\n'));
            }
            // Auto-scroll to bottom
            auto* sb = logView_->verticalScrollBar();
            sb->setValue(sb->maximum());
        },
        [](const QString&) { }
    );
}

void PageLogs::refresh(ApiClient* api)
{
    api_ = api;

    if (liveTailActive_)
        return;  // Don't overwrite live tail

    api->getText("/web/log",
        [this](const QString& text) {
            logView_->setPlainText(text);
        },
        [this](const QString& err) {
            logView_->setPlainText("Failed to load log feed: " + err);
        }
    );
}
