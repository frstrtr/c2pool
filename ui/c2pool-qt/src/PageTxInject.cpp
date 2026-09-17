// SPDX-License-Identifier: AGPL-3.0-or-later
#include "PageTxInject.hpp"

#include "TxInjectSubmitPrecheck.hpp"

#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QMessageBox>
#include <QVBoxLayout>

#include <cstdint>
#include <string>

namespace {
constexpr const char* kSecretKey = "tx_inject_control_token";
constexpr const char* kApplyPath  = "/api/config/apply";
constexpr const char* kSubmitPath = "/api/tx-inject/submit";
constexpr const char* kStatusPath = "/api/tx-inject-status";

// Turn a parsed apply response body + HTTP status into the Qt-free flow Response.
c2pool_qt::TxInjectArmFlow::Response toFlowResponse(int status, const QJsonObject& o)
{
    c2pool_qt::TxInjectArmFlow::Response r;
    r.http_status  = status;
    r.status       = o.value("status").toString().toStdString();
    r.money_nonce  = o.value("money_nonce").toString().toStdString();
    r.need_confirm = o.value("need_confirm").toBool(false);
    r.error        = o.value("error").toString().toStdString();
    return r;
}
}  // namespace

PageTxInject::PageTxInject(ApiClient* api, SettingsStore* settings, QWidget* parent)
    : QWidget(parent), api_(api), settings_(settings)
{
    buildUi();

    // Rehydrate a previously stored token (secret store) so a returning operator
    // does not retype it; a probe still gates arming/submit.
    settings_->readSecret(kSecretKey, [this](QString v, bool ok) {
        if (ok && !v.isEmpty()) {
            controlToken_ = v;
            tokenEdit_->setText(v);
            tokenStatusLabel_->setText(
                tr("Token loaded from the secret store — probe to verify."));
        }
    });

    updateEnablement();
}

void PageTxInject::buildUi()
{
    auto* root = new QVBoxLayout(this);

    dashOnlyLabel_ = new QLabel(
        tr("Tx-injection is a DASH feature. Switch to a DASH profile to use it."),
        this);
    dashOnlyLabel_->setWordWrap(true);
    dashOnlyLabel_->setStyleSheet("color:#b04020; font-weight:bold;");
    dashOnlyLabel_->hide();
    root->addWidget(dashOnlyLabel_);

    content_ = new QWidget(this);
    auto* layout = new QVBoxLayout(content_);
    layout->setContentsMargins(0, 0, 0, 0);
    root->addWidget(content_);

    // ── 1) Status mirror ──────────────────────────────────────────────────
    auto* statusGroup = new QGroupBox(tr("Lane status (read-only)"), content_);
    auto* statusForm = new QFormLayout(statusGroup);
    armBadge_ = new QLabel(tr("DISARMED"));
    armBadge_->setStyleSheet("font-weight:bold; color:#666;");
    statusForm->addRow(tr("Arm state:"), armBadge_);
    wiredLabel_ = new QLabel("-");
    statusForm->addRow(tr("Wired:"), wiredLabel_);
    enabledLabel_ = new QLabel("-");
    statusForm->addRow(tr("Enabled (node):"), enabledLabel_);
    poolLabel_ = new QLabel("-");
    statusForm->addRow(tr("Inflight pool:"), poolLabel_);
    rateLimitLabel_ = new QLabel("-");
    statusForm->addRow(tr("Rate limit:"), rateLimitLabel_);
    sandboxLabel_ = new QLabel("-");
    statusForm->addRow(tr("Sandbox:"), sandboxLabel_);
    layout->addWidget(statusGroup);

    // ── 2) Control token ──────────────────────────────────────────────────
    auto* tokenGroup = new QGroupBox(tr("Control-plane token"), content_);
    auto* tokenLayout = new QVBoxLayout(tokenGroup);
    auto* tokenRow = new QHBoxLayout();
    tokenEdit_ = new QLineEdit();
    tokenEdit_->setEchoMode(QLineEdit::Password);
    tokenEdit_->setPlaceholderText(tr("paste the loopback control token"));
    tokenRow->addWidget(tokenEdit_, 1);
    loadFileBtn_ = new QPushButton(tr("Load from file…"));
    tokenRow->addWidget(loadFileBtn_);
    probeBtn_ = new QPushButton(tr("Save && probe"));
    tokenRow->addWidget(probeBtn_);
    tokenLayout->addLayout(tokenRow);
    tokenStatusLabel_ = new QLabel(tr("No token verified."));
    tokenStatusLabel_->setWordWrap(true);
    tokenLayout->addWidget(tokenStatusLabel_);
    layout->addWidget(tokenGroup);

    // ── 3a) Arm/disarm ────────────────────────────────────────────────────
    auto* armGroup = new QGroupBox(tr("Arm / disarm tx-injection"), content_);
    auto* armLayout = new QVBoxLayout(armGroup);
    auto* armRow = new QHBoxLayout();
    armBtn_ = new QPushButton(tr("Arm…"));
    disarmBtn_ = new QPushButton(tr("Disarm…"));
    armRow->addWidget(armBtn_);
    armRow->addWidget(disarmBtn_);
    armRow->addStretch();
    armLayout->addLayout(armRow);
    armStatusLabel_ = new QLabel(tr("Requires a verified token."));
    armStatusLabel_->setWordWrap(true);
    armLayout->addWidget(armStatusLabel_);
    layout->addWidget(armGroup);

    // ── 3b) Submit raw tx ─────────────────────────────────────────────────
    auto* submitGroup = new QGroupBox(tr("Submit raw transaction"), content_);
    auto* submitLayout = new QVBoxLayout(submitGroup);
    hexEdit_ = new QPlainTextEdit();
    hexEdit_->setPlaceholderText(tr("signed raw transaction hex"));
    hexEdit_->setMinimumHeight(90);
    submitLayout->addWidget(hexEdit_);
    auto* fieldsRow = new QHBoxLayout();
    fieldsRow->addWidget(new QLabel(tr("flags:")));
    flagsEdit_ = new QLineEdit("0");
    flagsEdit_->setMaximumWidth(120);
    fieldsRow->addWidget(flagsEdit_);
    fieldsRow->addWidget(new QLabel(tr("expiry height:")));
    expiryEdit_ = new QLineEdit("0");
    expiryEdit_->setMaximumWidth(140);
    fieldsRow->addWidget(expiryEdit_);
    fieldsRow->addStretch();
    submitLayout->addLayout(fieldsRow);
    auto* actionRow = new QHBoxLayout();
    decodeBtn_ = new QPushButton(tr("Decode preview"));
    submitBtn_ = new QPushButton(tr("Submit"));
    actionRow->addWidget(decodeBtn_);
    actionRow->addWidget(submitBtn_);
    actionRow->addStretch();
    submitLayout->addLayout(actionRow);
    decodeLabel_ = new QLabel();
    decodeLabel_->setWordWrap(true);
    decodeLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    submitLayout->addWidget(decodeLabel_);
    submitResultLabel_ = new QLabel();
    submitResultLabel_->setWordWrap(true);
    submitResultLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    submitLayout->addWidget(submitResultLabel_);
    layout->addWidget(submitGroup);

    layout->addStretch();

    // ── wiring ────────────────────────────────────────────────────────────
    connect(loadFileBtn_, &QPushButton::clicked, this, &PageTxInject::loadTokenFromFile);
    connect(probeBtn_,    &QPushButton::clicked, this, &PageTxInject::probeToken);
    connect(tokenEdit_, &QLineEdit::textEdited, this, [this](const QString&) {
        // Any edit invalidates the last probe result — force a re-probe.
        tokenAccepted_ = false;
        tokenStatusLabel_->setText(tr("Token changed — probe to verify."));
        updateEnablement();
    });
    connect(armBtn_,    &QPushButton::clicked, this, [this]() { startArm(true); });
    connect(disarmBtn_, &QPushButton::clicked, this, [this]() { startArm(false); });
    connect(decodeBtn_, &QPushButton::clicked, this, &PageTxInject::decodePreview);
    connect(submitBtn_, &QPushButton::clicked, this, &PageTxInject::submitRawTx);
}

void PageTxInject::setActiveCoin(const QString& symbol)
{
    activeCoin_ = symbol.trimmed().toLower();
    const bool isDash = activeCoin_.contains("dash");
    dashOnlyLabel_->setVisible(!isDash);
    content_->setVisible(isDash);
}

void PageTxInject::applyControlTokenToBody(QJsonObject& body) const
{
    body.insert("control_token", controlToken_);
}

void PageTxInject::loadTokenFromFile()
{
    const QString path = QFileDialog::getOpenFileName(
        this, tr("Open control-token file"));
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        tokenStatusLabel_->setText(tr("Cannot read %1").arg(path));
        return;
    }
    const QString tok = QString::fromUtf8(f.readAll()).trimmed();
    f.close();
    tokenEdit_->setText(tok);
    tokenAccepted_ = false;
    tokenStatusLabel_->setText(tr("Loaded from file — probe to verify."));
    updateEnablement();
}

void PageTxInject::probeToken()
{
    controlToken_ = tokenEdit_->text().trimmed();
    if (controlToken_.isEmpty()) {
        tokenStatusLabel_->setText(tr("Enter a token first."));
        return;
    }
    // Persist as a secret (excluded from settings export).
    settings_->writeSecret(kSecretKey, controlToken_, [](bool) {});

    // Side-effect-free probe: apply with an EMPTY changes object. The node
    // answers 400 "no changes" once the token passes (token accepted, nothing
    // mutated), 403 for a wrong token, 503 when the endpoint is not armed.
    QJsonObject body;
    applyControlTokenToBody(body);
    body.insert("changes", QJsonObject{});

    tokenStatusLabel_->setText(tr("Probing…"));
    api_->postJson(kApplyPath, body,
        [this](int status, const QJsonDocument& doc) {
            const QJsonObject o = doc.object();
            const QString err = o.value("error").toString();
            if (status == 400) {
                tokenAccepted_ = true;
                tokenStatusLabel_->setText(
                    tr("Token accepted (endpoint armed). You may arm/submit."));
            } else if (status == 403) {
                tokenAccepted_ = false;
                tokenStatusLabel_->setText(tr("Token rejected (403): %1").arg(err));
            } else if (status == 503) {
                tokenAccepted_ = false;
                tokenStatusLabel_->setText(tr(
                    "Control-plane apply is not armed on this node (503). Start "
                    "the node with --control-plane-token-file to enable it."));
            } else {
                tokenAccepted_ = false;
                tokenStatusLabel_->setText(
                    tr("Unexpected probe response (%1): %2").arg(status).arg(err));
            }
            updateEnablement();
        },
        [this](const QString& msg) {
            tokenAccepted_ = false;
            tokenStatusLabel_->setText(tr("Probe failed: %1").arg(msg));
            updateEnablement();
        });
}

void PageTxInject::startArm(bool enable)
{
    if (!tokenAccepted_) {
        armStatusLabel_->setText(tr("Verify a token first."));
        return;
    }
    controlToken_ = tokenEdit_->text().trimmed();

    // Phase 1 — issue. begin() returns the diff-only request (no nonce).
    c2pool_qt::TxInjectArmFlow::Request issue = armFlow_.begin(
        controlToken_.toStdString(), enable);

    QJsonObject changes;
    for (const auto& [k, v] : issue.changes)
        changes.insert(QString::fromStdString(k), QString::fromStdString(v));
    QJsonObject body;
    applyControlTokenToBody(body);
    body.insert("changes", changes);

    armStatusLabel_->setText(enable ? tr("Requesting arm confirmation…")
                                    : tr("Requesting disarm confirmation…"));

    api_->postJson(kApplyPath, body,
        [this, enable, changes](int status, const QJsonDocument& doc) {
            const QJsonObject o = doc.object();
            auto resp = toFlowResponse(status, o);
            c2pool_qt::TxInjectArmFlow::Request confirm;
            if (!armFlow_.on_issue_response(resp, &confirm)) {
                armStatusLabel_->setText(tr("Refused: %1")
                    .arg(QString::fromStdString(armFlow_.last_error())));
                return;
            }

            // Server-echoed diff for the modal (money_keys the node bound).
            QString diffText;
            for (auto it = changes.begin(); it != changes.end(); ++it)
                diffText += QString("  %1 -> %2\n")
                    .arg(it.key(), it.value().toString());

            const QString explain = tr(
                "Arming changes which consensus-valid transactions can enter the "
                "blocks THIS node mines. It does NOT change payouts, fees, or who "
                "gets paid.\n\nServer-echoed change:\n%1").arg(diffText);
            const auto btn = QMessageBox::warning(
                this, enable ? tr("Confirm ARM") : tr("Confirm DISARM"),
                explain, QMessageBox::Ok | QMessageBox::Cancel);
            if (btn != QMessageBox::Ok) { armFlow_.reset(); armStatusLabel_->setText(tr("Cancelled.")); return; }

            const QString want = enable ? "ARM" : "DISARM";
            bool ok = false;
            const QString typed = QInputDialog::getText(
                this, tr("Type to confirm"),
                tr("Type %1 to proceed:").arg(want),
                QLineEdit::Normal, QString(), &ok);
            if (!ok || typed.trimmed().toUpper() != want) {
                armFlow_.reset();
                armStatusLabel_->setText(tr("Confirmation text did not match — aborted."));
                return;
            }

            // Phase 2 — confirm with the SAME diff + the issued nonce.
            QJsonObject confirmBody;
            confirmBody.insert("control_token", QString::fromStdString(confirm.control_token));
            QJsonObject cchanges;
            for (const auto& [k, v] : confirm.changes)
                cchanges.insert(QString::fromStdString(k), QString::fromStdString(v));
            confirmBody.insert("changes", cchanges);
            confirmBody.insert("money_nonce", QString::fromStdString(confirm.money_nonce));

            api_->postJson(kApplyPath, confirmBody,
                [this](int cstatus, const QJsonDocument& cdoc) {
                    auto cresp = toFlowResponse(cstatus, cdoc.object());
                    armFlow_.on_confirm_response(cresp);
                    if (armFlow_.state() == c2pool_qt::TxInjectArmFlow::State::Applied)
                        armStatusLabel_->setText(tr("Applied. The badge follows the node's reported state."));
                    else
                        armStatusLabel_->setText(tr("Refused: %1")
                            .arg(QString::fromStdString(armFlow_.last_error())));
                    // The badge flips only when the NODE's `enabled` flips — so
                    // re-poll status rather than trusting the flow.
                    refresh(api_);
                },
                [this](const QString& msg) {
                    armStatusLabel_->setText(tr("Confirm failed: %1").arg(msg));
                });
        },
        [this](const QString& msg) {
            armStatusLabel_->setText(tr("Arm request failed: %1").arg(msg));
        });
}

void PageTxInject::decodePreview()
{
    std::string hex = hexEdit_->toPlainText().simplified().remove(' ').toStdString();
    auto pv = c2pool_qt::decode_preview(hex);
    if (!pv.ok) {
        decodeLabel_->setText(tr("Decode failed: %1")
            .arg(QString::fromStdString(pv.error)));
        return;
    }
    decodeLabel_->setText(tr(
        "version=%1  type=%2  vin=%3  vout=%4  size=%5 bytes")
        .arg(pv.version).arg(pv.type)
        .arg(static_cast<qulonglong>(pv.vin))
        .arg(static_cast<qulonglong>(pv.vout))
        .arg(static_cast<qulonglong>(pv.size_bytes)));
}

void PageTxInject::submitRawTx()
{
    if (!tokenAccepted_) { submitResultLabel_->setText(tr("Verify a token first.")); return; }
    if (!nodeEnabled_)   { submitResultLabel_->setText(tr("Node reports tx-inject disabled; arm it first.")); return; }

    const std::string hex =
        hexEdit_->toPlainText().simplified().remove(' ').toStdString();
    auto hc = c2pool_qt::even_hex_check(hex);
    if (!hc.ok) {
        submitResultLabel_->setText(tr("Bad raw tx: %1")
            .arg(QString::fromStdString(hc.error)));
        return;
    }
    uint32_t flags = 0;
    auto fc = c2pool_qt::parse_flags_u32(flagsEdit_->text().trimmed().toStdString(), flags);
    if (!fc.ok) {
        submitResultLabel_->setText(tr("Bad flags: %1")
            .arg(QString::fromStdString(fc.error)));
        return;
    }
    uint64_t expiry = 0;
    auto ec = c2pool_qt::parse_expiry_height(
        expiryEdit_->text().trimmed().toStdString(), expiry);
    if (!ec.ok) {
        submitResultLabel_->setText(tr("Bad expiry height: %1")
            .arg(QString::fromStdString(ec.error)));
        return;
    }

    QJsonObject body;
    applyControlTokenToBody(body);
    body.insert("raw_tx", QString::fromStdString(hex));
    body.insert("flags", static_cast<double>(flags));
    body.insert("expiry_height", static_cast<double>(expiry));

    submitResultLabel_->setText(tr("Submitting…"));
    api_->postJson(kSubmitPath, body,
        [this](int status, const QJsonDocument& doc) {
            const QJsonObject o = doc.object();
            const bool ok = o.value("ok").toBool(false);
            const QString cause = o.value("cause").toString();
            const QString txid  = o.value("txid").toString();
            if (ok) {
                submitResultLabel_->setText(tr("Accepted. txid=%1").arg(txid));
            } else {
                // Render the node's named refusal (inject-*) verbatim.
                submitResultLabel_->setText(
                    tr("Refused (%1): %2").arg(status).arg(cause));
            }
        },
        [this](const QString& msg) {
            submitResultLabel_->setText(tr("Submit failed: %1").arg(msg));
        });
}

void PageTxInject::renderStatus(const QJsonObject& obj)
{
    auto boolText = [](const QJsonValue& v) {
        return v.toBool() ? QStringLiteral("yes") : QStringLiteral("no");
    };

    nodeWired_ = obj.value("wired").toBool(false);
    nodeEnabled_ = obj.value("enabled").toBool(false);

    wiredLabel_->setText(nodeWired_ ? tr("yes")
                                    : tr("not wired on this build"));
    enabledLabel_->setText(nodeWired_ ? boolText(obj.value("enabled"))
                                      : tr("not wired on this build"));

    if (obj.value("pool").isObject()) {
        const QJsonObject p = obj.value("pool").toObject();
        poolLabel_->setText(tr("%1 entries / %2 bytes (max %3 entries, %4 bytes)")
            .arg(p.value("entries").toInt())
            .arg(static_cast<qlonglong>(p.value("bytes").toDouble()))
            .arg(p.value("max_entries").toInt())
            .arg(static_cast<qlonglong>(p.value("max_total_bytes").toDouble())));
    } else {
        poolLabel_->setText(tr("not wired on this build"));
    }

    // rate_limit / sandbox render null (not 0) until the M3 PR wires them.
    rateLimitLabel_->setText(obj.value("rate_limit").isObject()
        ? QString::fromUtf8(QJsonDocument(obj.value("rate_limit").toObject())
                                .toJson(QJsonDocument::Compact))
        : tr("not wired on this build"));
    sandboxLabel_->setText(obj.value("sandbox").isObject()
        ? QString::fromUtf8(QJsonDocument(obj.value("sandbox").toObject())
                                .toJson(QJsonDocument::Compact))
        : tr("not wired on this build"));

    // The badge reflects ONLY the node's reported enabled flag.
    if (!nodeWired_) {
        armBadge_->setText(tr("N/A"));
        armBadge_->setStyleSheet("font-weight:bold; color:#666;");
    } else if (nodeEnabled_) {
        armBadge_->setText(tr("ARMED"));
        armBadge_->setStyleSheet("font-weight:bold; color:#b04020;");
    } else {
        armBadge_->setText(tr("DISARMED"));
        armBadge_->setStyleSheet("font-weight:bold; color:#1d7f3b;");
    }
    updateEnablement();
}

void PageTxInject::refresh(ApiClient* api)
{
    if (!activeCoin_.isEmpty() && !activeCoin_.contains("dash"))
        return;  // non-DASH: nothing to poll
    api->getJson(kStatusPath,
        [this](const QJsonDocument& doc) {
            if (doc.isObject()) renderStatus(doc.object());
        },
        [this](const QString&) {
            wiredLabel_->setText(tr("not wired on this build"));
        });
}

void PageTxInject::updateEnablement()
{
    armBtn_->setEnabled(tokenAccepted_);
    disarmBtn_->setEnabled(tokenAccepted_);
    // Decode is a pure client-side preview — always available.
    decodeBtn_->setEnabled(true);
    submitBtn_->setEnabled(tokenAccepted_ && nodeEnabled_);
    if (!tokenAccepted_)
        armStatusLabel_->setText(tr("Requires a verified token."));
}
