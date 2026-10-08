// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// PageBuildTx — the "Build Transaction" screen (design §4.1 construct matrix;
// M6 slice-2a, Family A). This is the KEY-FREE constructor side: it assembles an
// UNSIGNED transaction + the PSBT-like UnsignedContainer artifact (design §5.4)
// for the offline signer to consume. It never touches a private key.
//
// Money-safety (threat model): every amount renders in BOTH units (T-1); each
// output address is decoded→SPK→re-encoded and accepted only if the #961 engine
// classifies it Own for the selected coin (T-2, refusing Foreign/Invalid/
// net-mismatch); an output flagged OWN change is labelled with its derivation
// path, all others EXTERNAL, and a red line warns when no change returns to the
// operator (T-3); Assemble is disabled while the fee is negative, any output is
// dust, or the fee is absurd without explicit confirmation (T-4).
//
// The unsigned tx is serialized with a std-only byte writer (no dashscript
// header here) and the container is the std-only artifact library — so this TU
// includes ONLY the btclibs-side / std-only headers (G3 boundary).

#include <QWidget>

class QComboBox;
class QLineEdit;
class QCheckBox;
class QLabel;
class QPlainTextEdit;
class QPushButton;

class PageBuildTx : public QWidget
{
    Q_OBJECT
public:
    explicit PageBuildTx(QWidget* parent = nullptr);

private slots:
    void onRecalc();
    void onAssemble();
    void onSaveArtifact();

private:
    QComboBox*      coinCombo_{nullptr};
    QPlainTextEdit* inputsEdit_{nullptr};
    QPlainTextEdit* inputScriptsEdit_{nullptr};  // GAP-4 (slice-2c): optional redeem/witness scripts
    QPlainTextEdit* outputsEdit_{nullptr};
    QCheckBox*      confirmHighFee_{nullptr};
    QLabel*         summaryLabel_{nullptr};
    QPushButton*    assembleBtn_{nullptr};
    QPushButton*    saveBtn_{nullptr};
    QPlainTextEdit* artifactEdit_{nullptr};
    QPlainTextEdit* output_{nullptr};

    QString lastArtifact_;   // the assembled to_hex artifact (for save)
};
