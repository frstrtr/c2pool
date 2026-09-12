// SPDX-License-Identifier: AGPL-3.0-or-later
#include "shell/MainWindow.hpp"

#include <QFont>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QStackedWidget>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QWidget>

namespace {

// The sidebar sections for the signer shell, in Bitcoin-Core-like order.
// M0 wires them as empty placeholders only.
struct Section {
    const char* name;
    const char* note;
};

const Section kSections[] = {
    {"Wallets",
     "Import keys and enumerate candidate addresses (Family A: secp256k1; "
     "Family B: Monero). Arrives in phases M1-A / M1-X."},
    {"Construct",
     "Build unsigned transactions and spend every script/output type. "
     "Arrives in phases M2-A / M3-A / M4-A and M4-X."},
    {"Sign",
     "Confirm, sign, and self-verify offline before emitting the signed "
     "artifact. Arrives in phases M3 / M4."},
    {"Convert",
     "Cross-coin address conversion within Family A, with the #961 "
     "money-misdirection guard. Arrives in phase M2-A."},
    {"Settings",
     "Wallet preferences and the encrypted-store / ephemeral-seed modes. "
     "Arrives alongside key custody in M1."},
};

}  // namespace

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle("c2wallet-qt (signer) — offline / network-incapable");
    resize(1100, 720);

    // ── Central area: sidebar nav + stacked placeholder pages ──────────────
    auto* central = new QWidget(this);
    auto* layout = new QHBoxLayout(central);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    navList_ = new QListWidget(central);
    navList_->setFixedWidth(180);
    layout->addWidget(navList_);

    stack_ = new QStackedWidget(central);
    layout->addWidget(stack_, 1);

    for (const auto& s : kSections) {
        navList_->addItem(QString::fromLatin1(s.name));
        stack_->addWidget(makePlaceholderPage(QString::fromLatin1(s.name),
                                              QString::fromLatin1(s.note)));
    }

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

QWidget* MainWindow::makePlaceholderPage(const QString& title,
                                         const QString& note)
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

    auto* body = new QLabel(note, page);
    body->setWordWrap(true);
    v->addWidget(body);

    auto* stub = new QLabel(QStringLiteral("Not implemented in M0."), page);
    stub->setEnabled(false);
    v->addWidget(stub);

    return page;
}
