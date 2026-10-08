// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// PageBuildTxMonero — the Family-B (Monero) "Build Transaction" screen (design
// §4.2; M6 slice-2b). The KEY-FREE / view-only composer side: it assembles a
// Monero `unsigned_txset` artifact (design §5.4) for the offline signer to
// consume. Ring/decoy selection is the ONLINE side's job (design §4.2 step 2),
// so the frozen sources (rings + commitments) are LOADED from an unsigned_txset
// the online wallet produced; this page recomposes destinations + fee over them
// and re-seals the unsigned_txset. View-only keys suffice to build.
//
// Money-safety (mirrors the Family-A slice-2a build gate for Monero): amounts
// render in BOTH units always (T-1, XMR 12-dp + piconero, integer-only); each
// destination address is decoded and accepted only when its network matches the
// composer's (T-2/T-12, the Monero #961 analog); the balance gate
// Σsources == Σdests + fee is shown live and Assemble is disabled until it
// holds (T-5 precondition). No key is used here; no network is linked.

#include <QWidget>

class QComboBox;
class QLabel;
class QPlainTextEdit;
class QPushButton;

class PageBuildTxMonero : public QWidget
{
    Q_OBJECT
public:
    explicit PageBuildTxMonero(QWidget* parent = nullptr);

private slots:
    void onRecalc();
    void onAssemble();
    void onSaveArtifact();

private:
    QComboBox*      netCombo_{nullptr};
    QPlainTextEdit* sourcesEdit_{nullptr};    // frozen unsigned_txset (rings, from online)
    QPlainTextEdit* outputsExportEdit_{nullptr}; // optional owned-outputs export (informational)
    QPlainTextEdit* destsEdit_{nullptr};      // address:amount[:change] per line
    QPlainTextEdit* feeEdit_{nullptr};        // fee, whole XMR (12-dp)
    QLabel*         summaryLabel_{nullptr};
    QPushButton*    assembleBtn_{nullptr};
    QPushButton*    saveBtn_{nullptr};
    QPlainTextEdit* artifactEdit_{nullptr};
    QPlainTextEdit* output_{nullptr};

    QString lastArtifact_;   // assembled unsigned_txset hex (for save)
};
