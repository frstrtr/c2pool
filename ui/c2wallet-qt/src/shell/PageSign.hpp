// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// PageSign — the "Sign & Self-Verify" screen (design §4.1 / §5.3; M6 slice-2a,
// Family A). The OFFLINE, key-bearing flow, with a THREE-STAGE gate so the
// operator sees the real per-output OWN/EXTERNAL verdict BEFORE committing:
//
//   1. Load + Parse  — decode the artifact, cross-check, show the confirm card
//      (amounts in both units, fee + rate, TOTAL DEBIT, legacy-amount and
//      algebra-mismatch banners). Keys stay disabled until this succeeds.
//   2. Bind keys + preview — the operator pastes keys and clicks Bind; the page
//      derives PUBLIC keys, runs key<->input binding AND per-output own-detection,
//      then RE-RENDERS the card with each output tagged OWN / CHANGE(declared) /
//      EXTERNAL and a LOUD RED "NO CHANGE RETURNS TO YOU" line when nothing is
//      owned and the debit is large. Only a successful preview arms stage 3.
//   3. Review -> SPEND -> Sign — the operator ticks "reviewed", types the literal
//      SPEND (and confirms an absurd fee if one is present), then signs.
//
// The OWN/EXTERNAL verdict is thus shown BEFORE the secret is committed — the
// canonical compromised-online-host change-redirect fund-loss path is a visible
// abort point, not a post-emit surprise.
//
// Secret hygiene (T-8): the key widget is read once at Bind and cleared the
// instant it is read; the decoded private scalars live only in zeroizing
// SecureBytes held behind an opaque pImpl and are wiped on sign, on any
// re-parse/re-bind, and on destruction. This TU includes ONLY btclibs-side /
// std-only headers (never a dashscript header — the G3 boundary).

#include <QWidget>

#include <memory>

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
    ~PageSign() override;

private slots:
    void onLoadFile();
    void onParse();
    void onArtifactChanged();
    void onBindPreview();
    void onGateChanged();
    void onSign();
    void onSaveSigned();

private:
    void invalidateParse();     // artifact changed / not parsed
    void invalidateBinding();   // keys changed / not bound
    void updateSignEnabled();   // recompute the reviewed->SPEND->Sign gate

    // Load / parse
    QPlainTextEdit* artifactIn_{nullptr};
    QPushButton*    loadFileBtn_{nullptr};
    QPushButton*    parseBtn_{nullptr};
    QLabel*         cardLabel_{nullptr};

    // Bind (keys + preview)
    QPlainTextEdit* keysEdit_{nullptr};
    QPushButton*    bindBtn_{nullptr};

    // Commit gate
    QCheckBox*      reviewedCheck_{nullptr};
    QCheckBox*      confirmHighFee_{nullptr};   // shown only when fee > per-coin absurd ceiling
    QLineEdit*      spendGate_{nullptr};
    QPushButton*    signBtn_{nullptr};

    // Output
    QPlainTextEdit* output_{nullptr};
    QPushButton*    saveBtn_{nullptr};

    bool     parsedOk_{false};
    bool     boundOk_{false};
    QString  containerHex_;
    QString  coin_;
    QString  lastSigned_;

    // Opaque holder for the decoded private keys (zeroizing SecureBytes), kept
    // out of this header so the artifact/facade includes never reach a Qt TU.
    struct Bound;
    std::unique_ptr<Bound> bound_;
};
