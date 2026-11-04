// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// PageSignMessage — the "Sign / Verify Message" screen of the air-gapped
// signer (design A.5). A THIN Qt binding over the std-only
// c2w::dash::MessageModel (Sign tab) and c2w::dash::verify_message (Verify
// tab); every rule is KAT'd without Qt in c2wallet-dash-test against Dash Core
// signmessagewithprivkey vectors.
//
//   Sign tab     1. target coin + P2PKH address
//                2. the exact message bytes (typed, or loaded from a file;
//                   never trimmed; byte count, sha256 and whitespace warnings)
//                3. key: mnemonic / WIF / BIP38 / descriptor / JSON keystore
//                4. review -> type SIGN -> sign, self-verify, wipe the key;
//                   the three-line export equals the python stopgap's stdout
//   Verify tab   address + message + signature -> VALID / INVALID (why); it
//                has no secret widget at all
//
// Secret hygiene is PageDashInject's: secrets enter only through the shared
// password-mode KeyInputWidgets, the derived scalar lives only in the model's
// zeroizing FoundKey and dies at sign. The clipboard only ever receives the
// public base64 signature. No QSettings, no network, no clock; file I/O only
// on operator-chosen paths. This TU includes ONLY the std-only model header.

#include <QWidget>

#include <memory>

class QCheckBox;
class QComboBox;
class QGroupBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QTabWidget;
class KeyInputWidgets;

namespace c2w::dash { class MessageModel; }

class PageSignMessage : public QWidget
{
    Q_OBJECT
public:
    explicit PageSignMessage(QWidget* parent = nullptr);
    ~PageSignMessage() override;

    struct MessageEditor; // the exact-bytes editor (text or file bytes), one per tab

private slots:
    void onNetworkChanged();
    void onSetTarget();
    void onSetMessage();
    void onBindKey();
    void onGateChanged();
    void onSign();
    void onCopySignature();
    void onSaveSignature();
    void onSendToVerify();
    void onVerify();

private:
    QWidget* buildSignTab();
    QWidget* buildVerifyTab();
    void refresh();                                         // enable stages + render cards from the model
    void refreshSignMessageInfo();
    void report(const QString& stage, const QString& why);  // a refusal, in red
    void clearStatus();

    std::unique_ptr<c2w::dash::MessageModel> model_;
    std::unique_ptr<MessageEditor> signMsg_;
    std::unique_ptr<MessageEditor> verifyMsg_;

    QTabWidget*     tabs_{nullptr};
    QLabel*         status_{nullptr};

    // Sign tab
    QCheckBox*      testnetChk_{nullptr};
    QComboBox*      coinCombo_{nullptr};
    QLineEdit*      addrEdit_{nullptr};
    QPushButton*    targetBtn_{nullptr};
    QPlainTextEdit* targetCard_{nullptr};
    QGroupBox*      msgBox_{nullptr};
    QPushButton*    setMsgBtn_{nullptr};
    QLabel*         msgSetCard_{nullptr};
    QGroupBox*      keyBox_{nullptr};
    KeyInputWidgets* keyIn_{nullptr};
    QPushButton*    bindBtn_{nullptr};
    QLabel*         keyCard_{nullptr};
    QGroupBox*      signBox_{nullptr};
    QCheckBox*      reviewedChk_{nullptr};
    QLineEdit*      signWordEdit_{nullptr};
    QPushButton*    signBtn_{nullptr};
    QPlainTextEdit* signOut_{nullptr};
    QPushButton*    copyBtn_{nullptr};
    QPushButton*    saveBtn_{nullptr};
    QPushButton*    toVerifyBtn_{nullptr};

    // Verify tab
    QComboBox*      vCoinCombo_{nullptr};
    QCheckBox*      vTestnetChk_{nullptr};
    QLineEdit*      vAddrEdit_{nullptr};
    QLineEdit*      vSigEdit_{nullptr};
    QPushButton*    vBtn_{nullptr};
    QLabel*         vResult_{nullptr};
};
