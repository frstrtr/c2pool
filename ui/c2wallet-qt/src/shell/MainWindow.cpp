// SPDX-License-Identifier: AGPL-3.0-or-later
#include "shell/MainWindow.hpp"

#include "shell/PageBuildTx.hpp"
#include "shell/PageAirGap.hpp"
#include "shell/PageBuildTxMonero.hpp"
#include "shell/PageConstructConvert.hpp"
#include "shell/PageImport.hpp"
#include "shell/PageScan.hpp"
#include "shell/PageSign.hpp"
#include "shell/PageSignMonero.hpp"

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

    // Slice-2a (Family A) — the key-free constructor and the offline signer are
    // now WIRED to the merged signer facade + artifact libraries. RingCT (Family
    // B) build/sign and multi-frame-QR air-gap transfer remain slice-2b/2c.
    navList_->addItem(QStringLiteral("Build Transaction"));
    stack_->addWidget(new PageBuildTx(stack_));

    navList_->addItem(QStringLiteral("Sign & Self-Verify"));
    stack_->addWidget(new PageSign(stack_));

    // Slice-2b (Family B — Monero / RingCT). The key-free composer and the
    // offline signer are WIRED to the merged Monero libraries (seed/key/address,
    // scan, prover, artifact) + the Qt-free compose money-gate. Real-funds use
    // is still blocked upstream (online ring/decoy selection + the v37 XMR seam
    // are unwired, and the artifact envelope is not monero-wallet-cli byte-parity)
    // — see the design G10 note; the sign path itself is complete + KAT-covered
    // with fixture rings.
    navList_->addItem(QStringLiteral("Build Transaction (Monero)"));
    stack_->addWidget(new PageBuildTxMonero(stack_));

    navList_->addItem(QStringLiteral("Sign & Self-Verify (Monero)"));
    stack_->addWidget(new PageSignMonero(stack_));

    // Slice-2c: the Air-Gap Transfer screen is now WIRED - file + multi-frame
    // animated QR (GAP-8) transport of the unsigned/signed artifacts in both
    // families, with the corruption ladder (GAP-3 R_DIGEST / Monero keccak
    // footer) and the unsigned<->signed confusion guard. It links only the
    // Qt-free artifact + Monero libraries, so the link-guard stays green.
    navList_->addItem(QStringLiteral("Air-Gap Transfer"));
    stack_->addWidget(new PageAirGap(stack_));

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
