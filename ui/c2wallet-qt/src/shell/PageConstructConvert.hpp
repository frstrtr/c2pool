// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// PageConstructConvert — the "Construct + Convert" screen (design §4.1, M2-A).
//
// SLICE 1 (read-only address algebra; NO signing):
//   * CONVERT: cross-coin address conversion within Family A via the merged
//     #961-guarded engine (c2wallet-convert). Shows source vs target payload
//     side by side and the round-trip proof; REFUSES the cases the library
//     refuses (BCH prefix-swap, type absent on target, mainnet<->testnet,
//     foreign/invalid source) and surfaces the reason.
//   * CONSTRUCT: build the script-defined receive addresses the library
//     supports — a bare m-of-n multisig redeemScript wrapped as P2SH / P2WSH /
//     nested P2SH-P2WSH (the LTC+DOGE-donation pattern).

#include <QWidget>

class QComboBox;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;

class PageConstructConvert : public QWidget
{
    Q_OBJECT
public:
    explicit PageConstructConvert(QWidget* parent = nullptr);

private slots:
    void onConvert();
    void onConstruct();

private:
    // Convert panel
    QComboBox*      srcCombo_{nullptr};
    QComboBox*      dstCombo_{nullptr};
    QLineEdit*      convAddrEdit_{nullptr};
    QPushButton*    convertBtn_{nullptr};
    QPlainTextEdit* convOut_{nullptr};

    // Construct panel
    QSpinBox*       mSpin_{nullptr};
    QPlainTextEdit* pubkeysEdit_{nullptr};
    QComboBox*      coinCombo_{nullptr};
    QPushButton*    buildBtn_{nullptr};
    QPlainTextEdit* consOut_{nullptr};
};
