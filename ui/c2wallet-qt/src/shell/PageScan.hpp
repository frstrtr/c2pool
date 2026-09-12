// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// PageScan — the "Scan (Monero view-only)" screen (design §4.2, M2-X).
//
// SLICE 1 (read-only; NO signing): wires the merged Monero output-scanning /
// view-only path (c2wallet_monero MoneroScanner). Load a view-only key set
// (public spend key + private view key) or a full 25-word seed, then scan a
// transaction (its tx pubkey R + candidate outputs) for owned enotes. The
// air-gap split is surfaced: a view-only account reports
// can_produce_key_images()==false; only a full wallet computes key images.

#include <QWidget>
#include <memory>

class QLineEdit;
class QLabel;
class QPlainTextEdit;
class QPushButton;

namespace c2wallet { namespace monero { class MoneroScanner; } }

class PageScan : public QWidget
{
    Q_OBJECT
public:
    explicit PageScan(QWidget* parent = nullptr);
    ~PageScan() override;

private slots:
    void onLoadViewOnly();
    void onLoadFull();
    void onScan();

private:
    QLineEdit*      spendPubEdit_{nullptr};
    QLineEdit*      viewPrivEdit_{nullptr};
    QLineEdit*      mnemonicEdit_{nullptr};
    QLabel*         statusLabel_{nullptr};

    QLineEdit*      txPubkeyEdit_{nullptr};
    QPlainTextEdit* outputsEdit_{nullptr};
    QPushButton*    scanBtn_{nullptr};
    QPlainTextEdit* out_{nullptr};

    std::unique_ptr<c2wallet::monero::MoneroScanner> scanner_;
};
