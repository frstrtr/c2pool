// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// PageDashInject — the "DASH Inject / Collateral" screen of the air-gapped
// signer (c2wallet-qt slice 2, design §4). A THIN Qt binding over the std-only
// c2w::dash::DashInjectModel, where every money-relevant rule lives and is
// KAT'd without Qt (c2wallet-dash-test). Five stages, top to bottom; a stage's
// controls are enabled only once the model has finished the stage before it:
//
//   1. Import UTXO list   export v1 / dashd getaddressutxos (+ tip) / insight
//   2. Maturity screen    target landing height, min confirmations, dust floor
//   3. Output             consolidate (split knob, input limit) or governance
//                         collateral; zero fee (pin/inject) or relay fee rate
//   4. Key                mnemonic / WIF / BIP38 / descriptor / JSON keystore
//   5. Review -> SPEND -> Sign -> Export <name>.hex + <name>.manifest.json
//
// Secret hygiene: secrets enter only through password-mode line edits (or a
// keystore file read on demand), are moved into wiped holders and the widgets
// are cleared before the model derives anything; the derived scalar lives only
// in the model's zeroizing FoundKey and dies at sign. No QSettings, no
// clipboard, no network, no clock; file I/O only on operator-chosen paths.
// This TU includes ONLY std-only model headers (the G3 header-tree rule).

#include <QWidget>

#include <memory>

class QCheckBox;
class QComboBox;
class QGroupBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;

namespace c2w::dash { class DashInjectModel; }

class PageDashInject : public QWidget
{
    Q_OBJECT
public:
    explicit PageDashInject(QWidget* parent = nullptr);
    ~PageDashInject() override;

private slots:
    void onNetworkChanged();
    void onLoadUtxoFile();
    void onImport();
    void onRescreen();
    void onModeChanged();
    void onPlan();
    void onKeySourceChanged();
    void onBindKey();
    void onGateChanged();
    void onSign();
    void onSaveHex();
    void onSaveManifest();

private:
    void refresh();                                // enable stages + render cards from the model
    void report(const QString& stage, const QString& why);  // a refusal, in red
    void clearStatus();

    std::unique_ptr<c2w::dash::DashInjectModel> model_;

    QCheckBox*      testnetChk_{nullptr};
    QLabel*         status_{nullptr};

    // 1. import
    QPlainTextEdit* utxoIn_{nullptr};
    QPushButton*    loadUtxoBtn_{nullptr};
    QSpinBox*       tipSpin_{nullptr};
    QLineEdit*      expectAddr_{nullptr};
    QPushButton*    importBtn_{nullptr};
    QPlainTextEdit* importCard_{nullptr};

    // 2. screen
    QGroupBox*      screenBox_{nullptr};
    QSpinBox*       targetSpin_{nullptr};
    QSpinBox*       minConfSpin_{nullptr};
    QSpinBox*       dustSpin_{nullptr};
    QPushButton*    screenBtn_{nullptr};
    QPlainTextEdit* screenCard_{nullptr};

    // 3. output
    QGroupBox*      planBox_{nullptr};
    QComboBox*      modeCombo_{nullptr};
    QComboBox*      feeCombo_{nullptr};
    QSpinBox*       feeRateSpin_{nullptr};
    QLineEdit*      destEdit_{nullptr};
    QSpinBox*       maxPerTxSpin_{nullptr};
    QSpinBox*       inputLimitSpin_{nullptr};
    QLineEdit*      govHashEdit_{nullptr};
    QLineEdit*      changeEdit_{nullptr};
    QWidget*        consolidateFields_{nullptr};
    QWidget*        collateralFields_{nullptr};
    QPushButton*    planBtn_{nullptr};
    QLabel*         externalBadge_{nullptr};
    QPlainTextEdit* planOut_{nullptr};

    // 4. key
    QGroupBox*      keyBox_{nullptr};
    QComboBox*      keySrcCombo_{nullptr};
    QLineEdit*      secretEdit_{nullptr};
    QLineEdit*      passEdit_{nullptr};
    QSpinBox*       accountsSpin_{nullptr};
    QSpinBox*       indicesSpin_{nullptr};
    QCheckBox*      internalChk_{nullptr};
    QCheckBox*      uncompChk_{nullptr};
    QPushButton*    bindBtn_{nullptr};
    QLabel*         keyCard_{nullptr};

    // 5. review -> SPEND -> sign -> export
    QGroupBox*      signBox_{nullptr};
    QCheckBox*      reviewedChk_{nullptr};
    QCheckBox*      burnChk_{nullptr};
    QLineEdit*      spendEdit_{nullptr};
    QPushButton*    signBtn_{nullptr};
    QPlainTextEdit* signOut_{nullptr};
    QPushButton*    saveHexBtn_{nullptr};
    QPushButton*    saveManBtn_{nullptr};
    QString         lastHexPath_;
};
