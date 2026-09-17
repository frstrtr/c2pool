// SPDX-License-Identifier: AGPL-3.0-or-later
//
// PageTxInject — the #157 DASH tx-injection control page. A NATIVE QWidget (NOT
// a QWebEngine surface): the control token and the arm/submit actions must never
// be reachable from bundle JS, so this page is built from plain Qt Widgets and
// talks to the node's loopback control-plane over ApiClient only.
//
// It has three sections:
//   1. Status mirror — polls GET /api/tx-inject-status (read-only) and renders
//      wired / enabled / pool + rate_limit/sandbox (null => "not wired on this
//      build", never "0"). The armed badge reflects the NODE's `enabled`.
//   2. Control token — load-from-file or paste, stored as a SettingsStore secret
//      (excluded from export). A side-effect-free probe (POST apply with empty
//      changes) classifies the token: 400 "no changes" => accepted, 403 => wrong,
//      503 => apply not armed.
//   3. Arm/disarm + submit — the two-phase money-nonce arm (TxInjectArmFlow) with
//      a server-echoed-diff modal + type-to-confirm, and a submit-raw-tx form
//      with a client-side even-hex/flags/expiry precheck + decode preview. Both
//      are disabled until the token probe passes; submit additionally needs the
//      node's `enabled==true`.
//
// DASH-only: on any other coin the controls hide behind a "DASH feature" label.
#pragma once

#include "ApiClient.hpp"
#include "SettingsStore.hpp"
#include "TxInjectArmFlow.hpp"

#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QWidget>

class PageTxInject : public QWidget {
    Q_OBJECT
public:
    PageTxInject(ApiClient* api, SettingsStore* settings, QWidget* parent = nullptr);

    // Poll the read-only status endpoint and re-render the mirror + badge.
    void refresh(ApiClient* api);

    // DASH-only visibility. `symbol` is the CoinBridge descriptor symbol
    // (e.g. "dash"); anything else hides the controls behind a feature label.
    void setActiveCoin(const QString& symbol);

private:
    void buildUi();
    void loadTokenFromFile();
    void probeToken();          // side-effect-free apply-with-empty-changes probe
    void startArm(bool enable); // runs the two-phase TxInjectArmFlow
    void submitRawTx();
    void decodePreview();
    void updateEnablement();    // enable/disable controls from token + node state
    void renderStatus(const QJsonObject& obj);
    void applyControlTokenToBody(QJsonObject& body) const;

    ApiClient*     api_;        // borrowed
    SettingsStore* settings_;   // borrowed

    c2pool_qt::TxInjectArmFlow armFlow_;

    QString  activeCoin_;
    QString  controlToken_;     // in-memory session copy (also a stored secret)
    bool     tokenAccepted_ = false;
    bool     nodeEnabled_   = false;
    bool     nodeWired_     = false;

    // Top-level DASH gate.
    QLabel*  dashOnlyLabel_ = nullptr;
    QWidget* content_       = nullptr;

    // Status mirror.
    QLabel*  wiredLabel_     = nullptr;
    QLabel*  enabledLabel_   = nullptr;
    QLabel*  poolLabel_      = nullptr;
    QLabel*  rateLimitLabel_ = nullptr;
    QLabel*  sandboxLabel_   = nullptr;
    QLabel*  armBadge_       = nullptr;

    // Control token.
    QLineEdit* tokenEdit_       = nullptr;
    QPushButton* loadFileBtn_   = nullptr;
    QPushButton* probeBtn_      = nullptr;
    QLabel*    tokenStatusLabel_ = nullptr;

    // Arm/disarm.
    QPushButton* armBtn_    = nullptr;
    QPushButton* disarmBtn_ = nullptr;
    QLabel*    armStatusLabel_ = nullptr;

    // Submit raw tx.
    QPlainTextEdit* hexEdit_    = nullptr;
    QLineEdit* flagsEdit_       = nullptr;
    QLineEdit* expiryEdit_      = nullptr;
    QPushButton* decodeBtn_     = nullptr;
    QLabel*    decodeLabel_     = nullptr;
    QPushButton* submitBtn_     = nullptr;
    QLabel*    submitResultLabel_ = nullptr;
};
