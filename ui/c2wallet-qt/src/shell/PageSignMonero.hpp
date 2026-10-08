// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// PageSignMonero — the Family-B (Monero) "Sign & Self-Verify" screen (design
// §4.2 / §5.3; M6 slice-2b). The OFFLINE, key-bearing RingCT flow, mirroring the
// Family-A slice-2a THREE-STAGE anti-misdirection gate so the operator sees the
// real per-destination OWN/EXTERNAL verdict BEFORE committing the spend secret:
//
//   1. Load + Parse  — decode the unsigned_txset (magic + keccak footer bounds =
//      tamper check; refused on error), show the confirm card (per source
//      ring-size/real_index/amount; per dest decoded address + amount in XMR AND
//      piconero; fee; the Σin == Σout+fee residual; the keccak digest). The
//      secret box stays disabled until this succeeds.
//   2. Bind keys + preview — the operator pastes a 25-word mnemonic or the dual
//      spend/view hex and clicks Bind; the page derives the key set, REFUSES a
//      view-only key set, RE-DERIVES each real ring member's one-time secret via
//      artifact::sources_to_spend_inputs (which refuses a wrong wallet), builds
//      the subaddress table, and RE-RENDERS the card with each destination tagged
//      OWN(change) / EXTERNAL and a LOUD RED "NO CHANGE RETURNS TO YOU" line when
//      nothing is owned. Only a successful preview arms stage 3.
//   3. Review -> SPEND -> Sign — the operator ticks "reviewed", types the literal
//      SPEND, then signs: assemble_ringct_tx(self_verify) + the explicit
//      belt-and-braces self_verify_tx_public + self_verify_key_images, then
//      produce_signed_txset and a parse_signed_txset round-trip equality check
//      before anything is shown.
//
// Secret hygiene (T-8 / GAP-6): the secret widget is read once at Bind and
// cleared the instant it is read; the derived MoneroKeys and the SpendInputs
// (carrying x_i) live behind an opaque pImpl and are wiped on sign, on any
// re-parse/re-bind, and on destruction (MoneroKeys' own dtor + SpendInput's own
// dtor + an explicit compose::wipe_spend_inputs). This page links NO network.

#include <QWidget>

#include <memory>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;

class PageSignMonero : public QWidget
{
    Q_OBJECT
public:
    explicit PageSignMonero(QWidget* parent = nullptr);
    ~PageSignMonero() override;

private slots:
    void onLoadFile();
    void onParse();
    void onArtifactChanged();
    void onBindPreview();
    void onGateChanged();
    void onSign();
    void onSaveSigned();

private:
    void invalidateParse();
    void invalidateBinding();
    void updateSignEnabled();

    // Load / parse
    QComboBox*      netCombo_{nullptr};
    QPlainTextEdit* artifactIn_{nullptr};
    QPushButton*    loadFileBtn_{nullptr};
    QPushButton*    parseBtn_{nullptr};
    QLabel*         cardLabel_{nullptr};

    // Bind (keys + preview)
    QComboBox*      secretType_{nullptr};
    QPlainTextEdit* keysEdit_{nullptr};
    QPushButton*    bindBtn_{nullptr};

    // Commit gate
    QCheckBox*      reviewedCheck_{nullptr};
    QLineEdit*      spendGate_{nullptr};
    QPushButton*    signBtn_{nullptr};

    // Output
    QPlainTextEdit* output_{nullptr};
    QPushButton*    saveBtn_{nullptr};

    bool     parsedOk_{false};
    bool     boundOk_{false};
    QString  containerHex_;
    QString  lastSigned_;

    // Opaque holder for the parsed txset + the derived secrets (MoneroKeys +
    // SpendInputs), kept out of this header so the library includes never reach
    // a Qt TU that other shell code includes.
    struct State;
    std::unique_ptr<State> st_;
};
