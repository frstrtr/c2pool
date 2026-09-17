// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// PageSign — the "Sign & Self-Verify" screen (design §4.1 / §5.3; M6 slice-2a,
// Family A). The OFFLINE, key-bearing flow: load an unsigned artifact, DISPLAY
// a full confirm card, then — only after the operator reviews it and types the
// literal SPEND — accept the private keys, sign every input through the std-only
// signer facade (GAP-1), self-verify via the facade's mandatory finalize, and
// emit the c2pool-loader signed artifact.
//
// Money-safety discipline enforced here:
//   * FAIL-BEFORE-SECRET (design §3): the key widget stays DISABLED until the
//     artifact is parsed AND the operator ticks "I have reviewed" (T-1 both-unit
//     amounts, OWN/CHANGE/EXTERNAL, fee + rate, TOTAL DEBIT are shown first).
//   * a typed literal SPEND gate (baseline parity) before Sign enables;
//   * secrets read through ScopedSecret; the key widget is clear()'d the instant
//     the text is read, and secrets are wiped on EVERY path (T-8);
//   * key↔input binding is proven by hdkeys address_candidates BEFORE any
//     sighash — a key that funds no input is refused (T-6); the facade re-checks
//     binding and finalize()-verifies every input before emit (T-5);
//   * the emitted txid is re-asserted against artifact::crossgap_txid.
//
// This TU includes ONLY btclibs-side / std-only headers (the facade, hdkeys,
// construct, artifact) — never a dashscript header (G3 boundary).

#include <QWidget>

class QCheckBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;

class PageSign : public QWidget
{
    Q_OBJECT
public:
    explicit PageSign(QWidget* parent = nullptr);

private slots:
    void onLoadFile();
    void onParse();
    void onGateChanged();
    void onSign();
    void onSaveSigned();

private:
    void resetSecretGate();

    // Load / parse
    QPlainTextEdit* artifactIn_{nullptr};
    QPushButton*    loadFileBtn_{nullptr};
    QPushButton*    parseBtn_{nullptr};
    QLabel*         cardLabel_{nullptr};

    // Secret gate (disabled until parsed + reviewed)
    QCheckBox*      reviewedCheck_{nullptr};
    QLineEdit*      spendGate_{nullptr};
    QPlainTextEdit* keysEdit_{nullptr};
    QPushButton*    signBtn_{nullptr};

    // Output
    QPlainTextEdit* output_{nullptr};
    QPushButton*    saveBtn_{nullptr};

    bool     parsedOk_{false};
    QString  containerHex_;    // the parsed artifact (re-decoded on sign)
    QString  coin_;            // ticker from the container
    QString  lastSigned_;      // signed artifact text (for save)
};
