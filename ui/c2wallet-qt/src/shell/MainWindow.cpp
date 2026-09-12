// SPDX-License-Identifier: AGPL-3.0-or-later
#include "shell/MainWindow.hpp"

#include "shell/PageConstructConvert.hpp"
#include "shell/PageImport.hpp"
#include "shell/PageScan.hpp"

#include <QFont>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QStackedWidget>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QWidget>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle("c2wallet-qt (signer) — offline / network-incapable");
    resize(1100, 760);

    // ── Central area: sidebar nav + stacked pages ─────────────────────────
    auto* central = new QWidget(this);
    auto* layout = new QHBoxLayout(central);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    navList_ = new QListWidget(central);
    navList_->setFixedWidth(200);
    layout->addWidget(navList_);

    stack_ = new QStackedWidget(central);
    layout->addWidget(stack_, 1);

    // Functional (slice 1) screens — wired to the merged offline libraries.
    navList_->addItem(QStringLiteral("Import / Load Key"));
    stack_->addWidget(new PageImport(stack_));

    navList_->addItem(QStringLiteral("Construct + Convert"));
    stack_->addWidget(new PageConstructConvert(stack_));

    navList_->addItem(QStringLiteral("Scan (Monero view-only)"));
    stack_->addWidget(new PageScan(stack_));

    // Slice-2 (pending review) stubs — visible but not implemented here. No
    // money-path signing UX lands in slice 1.
    navList_->addItem(QStringLiteral("Sign & Self-Verify"));
    stack_->addWidget(makeStubPage(
        QStringLiteral("Sign & Self-Verify"),
        QStringLiteral("Confirm every output/amount/address, sign offline, and "
                       "self-verify before emitting the signed artifact "
                       "(RFC6979 / BIP340). Wires the merged signer + Monero "
                       "prover libraries.")));

    navList_->addItem(QStringLiteral("Build Transaction"));
    stack_->addWidget(makeStubPage(
        QStringLiteral("Build Transaction"),
        QStringLiteral("Coin-control and the unsigned transaction builder for "
                       "every script/output type (Family A) and RingCT spends "
                       "(Family B).")));

    navList_->addItem(QStringLiteral("Air-Gap Transfer"));
    stack_->addWidget(makeStubPage(
        QStringLiteral("Air-Gap Transfer"),
        QStringLiteral("PSBT-like / unsigned_txset import and signed-artifact "
                       "export over file or multi-frame QR, plus the c2pool "
                       "validate-seam dry-run.")));

    connect(navList_, &QListWidget::currentRowChanged,
            stack_, &QStackedWidget::setCurrentIndex);
    navList_->setCurrentRow(0);

    setCentralWidget(central);

    // ── Status bar: make the air-gap model visible at a glance ─────────────
    auto* offline = new QLabel(
        "OFFLINE — this build links no networking library (Qt Network / "
        "WebEngine / curl / asio). A socket call is a link error.",
        this);
    statusBar()->addWidget(offline);
}

QWidget* MainWindow::makeStubPage(const QString& title, const QString& note)
{
    auto* page = new QWidget(stack_);
    auto* v = new QVBoxLayout(page);
    v->setContentsMargins(24, 24, 24, 24);
    v->setSpacing(10);
    v->setAlignment(Qt::AlignTop);

    auto* heading = new QLabel(title, page);
    QFont f = heading->font();
    f.setPointSize(f.pointSize() + 6);
    f.setBold(true);
    heading->setFont(f);
    v->addWidget(heading);

    auto* badge = new QLabel(QStringLiteral("slice 2 — pending review"), page);
    QFont bf = badge->font();
    bf.setBold(true);
    badge->setFont(bf);
    badge->setStyleSheet(QStringLiteral(
        "color: #7a4a00; background: #ffe8b3; border: 1px solid #d9a520; "
        "border-radius: 4px; padding: 3px 8px;"));
    v->addWidget(badge, 0, Qt::AlignLeft);

    auto* body = new QLabel(note, page);
    body->setWordWrap(true);
    v->addWidget(body);

    return page;
}
