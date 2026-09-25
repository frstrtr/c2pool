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
// M6 SLICE 1 wires the read/construct flows against the merged offline
// libraries: Import/Load key, Construct+Convert, and Scan (Monero view-only).
// The signing / tx-build / air-gap-transfer screens are visible stubs labelled
// "slice 2 — pending review" — no money-path signing UX in this slice.
class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

private:
    // Build a visible stub page for a slice-2 (pending-review) section.
    QWidget* makeStubPage(const QString& title, const QString& note);

    QListWidget*    navList_{nullptr};
    QStackedWidget* stack_{nullptr};
};
