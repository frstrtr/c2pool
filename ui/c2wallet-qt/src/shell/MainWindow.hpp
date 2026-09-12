// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <QMainWindow>

class QListWidget;
class QStackedWidget;

// MainWindow — the family-agnostic Widgets shell for the air-gapped signer.
//
// Bitcoin-Core-like layout: a fixed-width sidebar nav (QListWidget) selecting
// among stacked Page* screens (QStackedWidget). This mirrors the shell PATTERN
// of ui/c2pool-qt/ (MainWindow + sidebar + stacked pages) WITHOUT reusing any
// of its networked dependencies — this window links only Qt Widgets/Gui/Core.
//
// M0 delivers an empty skeleton: the sidebar sections (Wallets / Construct /
// Sign / Convert / Settings) are present as placeholders with no functionality
// behind them. Real pages, key import, construction and signing land in later
// phases (see docs/design/c2wallet-qt.md §6).
class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

private:
    // Build one placeholder page for a sidebar section. M0 has no real screens
    // yet; each section shows its name and a short "not implemented in M0" note.
    QWidget* makePlaceholderPage(const QString& title, const QString& note);

    QListWidget*    navList_{nullptr};
    QStackedWidget* stack_{nullptr};
};
