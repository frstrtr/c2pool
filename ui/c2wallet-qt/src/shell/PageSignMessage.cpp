// SPDX-License-Identifier: AGPL-3.0-or-later
#include "shell/PageSignMessage.hpp"
#include "shell/KeyInputWidgets.hpp"

#include <QApplication>
#include <QByteArray>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QFile>
#include <QFileDialog>
#include <QFont>
#include <QFormLayout>
#include <QGroupBox>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QStandardItemModel>
#include <QString>
#include <QStringList>
#include <QTabWidget>
#include <QTextDocument>
#include <QVBoxLayout>

#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <vector>

// std-only model header ONLY (G3 boundary — no dashscript / btclibs header here).
#include "family/bitcoin/dash/MessageModel.hpp"

namespace dash = c2w::dash;

namespace {

QString qs(const std::string& s) { return QString::fromStdString(s); }

QPlainTextEdit* card(QWidget* parent, int max_height)
{
    auto* c = new QPlainTextEdit(parent);
    c->setReadOnly(true);
    c->setFont(QFont(QStringLiteral("monospace")));
    c->setMaximumHeight(max_height);
    return c;
}

// One row per MessageCoin; a row without a node vector is listed but disabled.
void fillCoins(QComboBox* c)
{
    for (const dash::MessageCoin& mc : dash::message_coins()) {
        const QString t = QString::fromLatin1(mc.ticker);
        c->addItem(mc.kat_proven ? t : t + QStringLiteral(" (no node vector yet)"), t);
        if (!mc.kat_proven)
            if (auto* m = qobject_cast<QStandardItemModel*>(c->model())) m->item(c->count() - 1)->setEnabled(false);
    }
    c->setCurrentIndex(0);
}

// The file-loaded bytes, shown escaped so every byte is visible.
QString escaped(const std::vector<uint8_t>& b)
{
    QString out;
    for (uint8_t c : b) {
        if (c == '\\') out += QStringLiteral("\\\\");
        else if (c == '\n') out += QStringLiteral("\\n\n");
        else if (c == '\r') out += QStringLiteral("\\r");
        else if (c == '\t') out += QStringLiteral("\\t");
        else if (c >= 0x20 && c < 0x7f) out += QChar(char16_t(c));
        else out += QString::asprintf("\\x%02x", unsigned(c));
    }
    return out;
}

QString banner_style(const char* bg)
{
    return QStringLiteral("color:#fff; background:%1; font-weight:bold; padding:6px; border-radius:4px;")
        .arg(QLatin1String(bg));
}

} // namespace

// ── the exact-bytes message editor (one per tab) ─────────────────────────────

struct PageSignMessage::MessageEditor {
    QPlainTextEdit* edit = nullptr;
    QLabel* info = nullptr;
    QLabel* warn = nullptr;
    QPushButton* loadBtn = nullptr;
    QPushButton* clearBtn = nullptr;
    std::optional<std::vector<uint8_t>> fileBytes; // set: the exact bytes come from a file

    void build(QWidget* parent, QVBoxLayout* into, const QString& placeholder)
    {
        edit = new QPlainTextEdit(parent);
        edit->setFont(QFont(QStringLiteral("monospace")));
        edit->setPlaceholderText(placeholder);
        edit->setMaximumHeight(120);
        edit->setTabChangesFocus(true); // a stray Tab never becomes a signed byte
        into->addWidget(edit);
        auto* note = new QLabel(QStringLiteral(
            "Typed text is signed as UTF-8 with LF line breaks; this box cannot hold a CR or NUL byte. "
            "For exact arbitrary bytes, load them from a file."), parent);
        note->setWordWrap(true);
        into->addWidget(note);
        info = new QLabel(parent);
        info->setWordWrap(true);
        info->setTextInteractionFlags(Qt::TextSelectableByMouse);
        into->addWidget(info);
        warn = new QLabel(parent);
        warn->setWordWrap(true);
        warn->setStyleSheet(QStringLiteral("color:#7a4a00; background:#ffe8b3; padding:3px; border-radius:4px;"));
        warn->setVisible(false);
        into->addWidget(warn);
        auto* row = new QHBoxLayout();
        loadBtn = new QPushButton(QStringLiteral("Load message bytes from file..."), parent);
        clearBtn = new QPushButton(QStringLiteral("Clear bytes"), parent);
        row->addWidget(loadBtn);
        row->addWidget(clearBtn);
        row->addStretch(1);
        into->addLayout(row);
    }

    // The bytes the operator means. Typed text: the document's raw text with
    // only the block separators mapped to LF (toPlainText would also turn a
    // no-break space into a space, silently changing the signed bytes).
    std::vector<uint8_t> bytes() const
    {
        if (fileBytes) return *fileBytes;
        QString raw = edit->document()->toRawText();
        for (QChar& c : raw) {
            const char16_t u = c.unicode();
            if (u == QChar::ParagraphSeparator || u == QChar::LineSeparator || u == 0xfdd0 || u == 0xfdd1)
                c = QLatin1Char('\n');
        }
        const QByteArray u8 = raw.toUtf8();
        return std::vector<uint8_t>(u8.begin(), u8.end());
    }

    void setFileBytes(std::vector<uint8_t> b)
    {
        fileBytes = std::move(b);
        edit->setReadOnly(true);
        edit->setPlainText(escaped(*fileBytes));
    }

    // Show `b` as text when the text box reproduces it exactly, else as file bytes.
    void setBytes(const std::vector<uint8_t>& b)
    {
        const QByteArray in(reinterpret_cast<const char*>(b.data()), qsizetype(b.size()));
        const QString s = QString::fromUtf8(in);
        bool textual = s.toUtf8() == in && !in.contains('\r') && !in.contains('\0');
        if (textual) {
            fileBytes.reset();
            edit->setReadOnly(false);
            edit->setPlainText(s);
            textual = bytes() == b;
        }
        if (!textual) setFileBytes(b);
    }

    bool loadFile(QWidget* dialogParent, QString* error)
    {
        const QString path = QFileDialog::getOpenFileName(dialogParent, QStringLiteral("Load the exact message bytes"));
        if (path.isEmpty()) return false;
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) {
            *error = QStringLiteral("could not read %1").arg(path);
            return false;
        }
        const QByteArray all = f.readAll();
        setFileBytes(std::vector<uint8_t>(all.begin(), all.end()));
        return true;
    }

    void clearBytes()
    {
        fileBytes.reset();
        edit->setReadOnly(false);
        edit->clear();
    }

    // The live counter + amber warnings. `committed`: the bytes set in the model
    // (Sign tab), to flag an editor that no longer matches them.
    void updateInfo(const std::vector<uint8_t>* committed)
    {
        const std::vector<uint8_t> b = bytes();
        const dash::MessageFlags f = dash::message_flags(b);
        const QChar dot(0x00B7);
        QString line = QStringLiteral("bytes: %1 (%2) %3 lines: %4 %3 sha256: %5")
                           .arg(qulonglong(f.bytes))
                           .arg(f.invalid_utf8 ? QStringLiteral("raw bytes, not valid UTF-8") : QStringLiteral("UTF-8"))
                           .arg(dot)
                           .arg(qulonglong(f.lines))
                           .arg(qs(dash::message_sha256_hex(b)));
        if (fileBytes) line += QStringLiteral(" %1 from a file (exact bytes; Clear bytes to type)").arg(dot);
        info->setText(line);
        QStringList w;
        if (f.empty) w << QStringLiteral("empty message");
        if (f.trailing_newline) w << QStringLiteral("ends with a newline");
        if (f.leading_ws || f.trailing_ws) w << QStringLiteral("leading/trailing whitespace");
        if (f.has_cr) w << QStringLiteral("contains CR");
        if (f.invalid_utf8) w << QStringLiteral("not valid UTF-8 (signed as-is)");
        if (f.long_form) w << QStringLiteral("long form (>=253 B)");
        if (committed && *committed != b)
            w << QStringLiteral("the box differs from the message set in step 2 (press 2) Set message again)");
        warn->setText(w.join(QStringLiteral("; ")));
        warn->setVisible(!w.isEmpty());
    }
};

// ── construction ─────────────────────────────────────────────────────────────

PageSignMessage::PageSignMessage(QWidget* parent)
    : QWidget(parent),
      model_(std::make_unique<dash::MessageModel>(false)),
      signMsg_(std::make_unique<MessageEditor>()),
      verifyMsg_(std::make_unique<MessageEditor>())
{
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    auto* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    outer->addWidget(scroll);
    auto* body = new QWidget(scroll);
    scroll->setWidget(body);
    auto* v = new QVBoxLayout(body);
    v->setContentsMargins(24, 24, 24, 24);
    v->setSpacing(10);

    auto* heading = new QLabel(QStringLiteral("Sign / Verify Message (offline)"), body);
    QFont hf = heading->font();
    hf.setPointSize(hf.pointSize() + 6);
    hf.setBold(true);
    heading->setFont(hf);
    v->addWidget(heading);
    auto* intro = new QLabel(QStringLiteral(
        "Sign an exact message with the key of a P2PKH address, in the Dash Core signmessage format "
        "(base64 compact signature, e.g. a DashCentral proposal-ownership claim), or verify someone "
        "else's signature. The signature is self-verified before it is shown. A message signature "
        "moves no money and can never be replayed as a transaction signature; the confirmation word "
        "is SIGN (SPEND stays the money word)."), body);
    intro->setWordWrap(true);
    v->addWidget(intro);
    status_ = new QLabel(body);
    status_->setWordWrap(true);
    status_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    v->addWidget(status_);

    tabs_ = new QTabWidget(body);
    tabs_->addTab(buildSignTab(), QStringLiteral("Sign"));
    tabs_->addTab(buildVerifyTab(), QStringLiteral("Verify"));
    v->addWidget(tabs_);
    v->addStretch(1);

    refresh();
}

PageSignMessage::~PageSignMessage() = default; // ~MessageModel wipes any key still held

QWidget* PageSignMessage::buildSignTab()
{
    auto* tab = new QWidget();
    auto* v = new QVBoxLayout(tab);
    testnetChk_ = new QCheckBox(QStringLiteral("testnet (changing this resets the Sign tab)"), tab);
    v->addWidget(testnetChk_);

    // ── 1. target ───────────────────────────────────────────────────────────
    auto* tBox = new QGroupBox(QStringLiteral("1. Target (public)"), tab);
    auto* tv = new QVBoxLayout(tBox);
    auto* tform = new QFormLayout();
    coinCombo_ = new QComboBox(tBox);
    fillCoins(coinCombo_);
    tform->addRow(QStringLiteral("coin:"), coinCombo_);
    addrEdit_ = new QLineEdit(tBox);
    addrEdit_->setPlaceholderText(QStringLiteral("the P2PKH address whose key signs (X... on DASH mainnet)"));
    tform->addRow(QStringLiteral("address:"), addrEdit_);
    tv->addLayout(tform);
    targetBtn_ = new QPushButton(QStringLiteral("1) Set target"), tBox);
    tv->addWidget(targetBtn_);
    targetCard_ = card(tBox, 90);
    tv->addWidget(targetCard_);
    v->addWidget(tBox);

    // ── 2. message ──────────────────────────────────────────────────────────
    msgBox_ = new QGroupBox(QStringLiteral("2. Message (the exact bytes; nothing is trimmed)"), tab);
    auto* mv = new QVBoxLayout(msgBox_);
    signMsg_->build(msgBox_, mv, QStringLiteral("e.g. dashcentral-proposal-1556 (exactly as the site asks)"));
    setMsgBtn_ = new QPushButton(QStringLiteral("2) Set message"), msgBox_);
    mv->addWidget(setMsgBtn_);
    msgSetCard_ = new QLabel(msgBox_);
    msgSetCard_->setWordWrap(true);
    msgSetCard_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    mv->addWidget(msgSetCard_);
    v->addWidget(msgBox_);

    // ── 3. key ──────────────────────────────────────────────────────────────
    keyBox_ = new QGroupBox(QStringLiteral("3. Key (secret: wiped from the widgets the moment it is read)"), tab);
    auto* kv = new QVBoxLayout(keyBox_);
    keyIn_ = new KeyInputWidgets(keyBox_, kv);
    bindBtn_ = new QPushButton(QStringLiteral("3) Bind key"), keyBox_);
    kv->addWidget(bindBtn_);
    keyCard_ = new QLabel(keyBox_);
    keyCard_->setWordWrap(true);
    keyCard_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    kv->addWidget(keyCard_);
    v->addWidget(keyBox_);

    // ── 4. review -> SIGN -> sign ───────────────────────────────────────────
    signBox_ = new QGroupBox(QStringLiteral("4. Review, type SIGN, sign"), tab);
    auto* gv = new QVBoxLayout(signBox_);
    reviewedChk_ = new QCheckBox(QStringLiteral("I reviewed the address and the exact message above"), signBox_);
    signWordEdit_ = new QLineEdit(signBox_);
    signWordEdit_->setPlaceholderText(QStringLiteral("type SIGN to arm signing"));
    signBtn_ = new QPushButton(QStringLiteral("4) Sign, self-verify, wipe the key"), signBox_);
    gv->addWidget(reviewedChk_);
    gv->addWidget(signWordEdit_);
    gv->addWidget(signBtn_);
    signOut_ = card(signBox_, 240);
    signOut_->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    gv->addWidget(signOut_);
    auto* ob = new QHBoxLayout();
    copyBtn_ = new QPushButton(QStringLiteral("Copy signature"), signBox_);
    saveBtn_ = new QPushButton(QStringLiteral("Save signature.txt..."), signBox_);
    toVerifyBtn_ = new QPushButton(QStringLiteral("Verify this in the Verify tab"), signBox_);
    ob->addWidget(copyBtn_);
    ob->addWidget(saveBtn_);
    ob->addWidget(toVerifyBtn_);
    gv->addLayout(ob);
    v->addWidget(signBox_);
    v->addStretch(1);

    connect(testnetChk_, &QCheckBox::toggled, this, &PageSignMessage::onNetworkChanged);
    connect(targetBtn_, &QPushButton::clicked, this, &PageSignMessage::onSetTarget);
    connect(signMsg_->edit, &QPlainTextEdit::textChanged, this, [this] { refreshSignMessageInfo(); });
    connect(signMsg_->loadBtn, &QPushButton::clicked, this, [this] {
        QString err;
        if (!signMsg_->loadFile(this, &err) && !err.isEmpty()) report(QStringLiteral("Load"), err);
        refreshSignMessageInfo();
    });
    connect(signMsg_->clearBtn, &QPushButton::clicked, this, [this] {
        signMsg_->clearBytes();
        refreshSignMessageInfo();
    });
    connect(setMsgBtn_, &QPushButton::clicked, this, &PageSignMessage::onSetMessage);
    connect(bindBtn_, &QPushButton::clicked, this, &PageSignMessage::onBindKey);
    connect(reviewedChk_, &QCheckBox::toggled, this, &PageSignMessage::onGateChanged);
    connect(signWordEdit_, &QLineEdit::textChanged, this, &PageSignMessage::onGateChanged);
    connect(signBtn_, &QPushButton::clicked, this, &PageSignMessage::onSign);
    connect(copyBtn_, &QPushButton::clicked, this, &PageSignMessage::onCopySignature);
    connect(saveBtn_, &QPushButton::clicked, this, &PageSignMessage::onSaveSignature);
    connect(toVerifyBtn_, &QPushButton::clicked, this, &PageSignMessage::onSendToVerify);
    return tab;
}

QWidget* PageSignMessage::buildVerifyTab()
{
    auto* tab = new QWidget();
    auto* v = new QVBoxLayout(tab);
    auto* note = new QLabel(QStringLiteral(
        "Check a signature against an address and the exact message bytes, as dash-cli verifymessage "
        "does. Public data only: there is no key on this tab."), tab);
    note->setWordWrap(true);
    v->addWidget(note);
    auto* form = new QFormLayout();
    vCoinCombo_ = new QComboBox(tab);
    fillCoins(vCoinCombo_);
    form->addRow(QStringLiteral("coin:"), vCoinCombo_);
    vTestnetChk_ = new QCheckBox(QStringLiteral("testnet"), tab);
    form->addRow(QString(), vTestnetChk_);
    vAddrEdit_ = new QLineEdit(tab);
    vAddrEdit_->setPlaceholderText(QStringLiteral("the address that claims to have signed"));
    form->addRow(QStringLiteral("address:"), vAddrEdit_);
    v->addLayout(form);
    auto* mlabel = new QLabel(QStringLiteral("message:"), tab);
    v->addWidget(mlabel);
    verifyMsg_->build(tab, v, QStringLiteral("the exact message that was signed"));
    auto* sform = new QFormLayout();
    vSigEdit_ = new QLineEdit(tab);
    vSigEdit_->setFont(QFont(QStringLiteral("monospace")));
    vSigEdit_->setPlaceholderText(QStringLiteral("base64 signature (88 characters)"));
    sform->addRow(QStringLiteral("signature:"), vSigEdit_);
    v->addLayout(sform);
    vBtn_ = new QPushButton(QStringLiteral("Verify"), tab);
    v->addWidget(vBtn_);
    vResult_ = new QLabel(tab);
    vResult_->setWordWrap(true);
    vResult_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    v->addWidget(vResult_);
    v->addStretch(1);

    // Any edit makes the last verdict stale.
    auto stale = [this] {
        vResult_->clear();
        vResult_->setStyleSheet(QString());
    };
    connect(vCoinCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, stale);
    connect(vTestnetChk_, &QCheckBox::toggled, this, stale);
    connect(vAddrEdit_, &QLineEdit::textChanged, this, stale);
    connect(vSigEdit_, &QLineEdit::textChanged, this, stale);
    connect(verifyMsg_->edit, &QPlainTextEdit::textChanged, this, [this, stale] {
        stale();
        verifyMsg_->updateInfo(nullptr);
    });
    connect(verifyMsg_->loadBtn, &QPushButton::clicked, this, [this] {
        QString err;
        if (!verifyMsg_->loadFile(this, &err) && !err.isEmpty()) report(QStringLiteral("Load"), err);
        verifyMsg_->updateInfo(nullptr);
    });
    connect(verifyMsg_->clearBtn, &QPushButton::clicked, this, [this] {
        verifyMsg_->clearBytes();
        verifyMsg_->updateInfo(nullptr);
    });
    connect(vBtn_, &QPushButton::clicked, this, &PageSignMessage::onVerify);
    verifyMsg_->updateInfo(nullptr);
    return tab;
}

// ── status + refresh ─────────────────────────────────────────────────────────

void PageSignMessage::clearStatus() { status_->clear(); }

void PageSignMessage::report(const QString& stage, const QString& why)
{
    status_->setText(QStringLiteral("<span style='color:#b00020;font-weight:bold'>%1 REFUSED:</span> %2")
                         .arg(stage.toHtmlEscaped(), why.toHtmlEscaped()));
    refresh();
}

void PageSignMessage::refreshSignMessageInfo()
{
    signMsg_->updateInfo(model_->has_message() ? &model_->message() : nullptr);
}

void PageSignMessage::refresh()
{
    const dash::MessageStage st = model_->stage();
    const bool targeted = st >= dash::MessageStage::Targeted;
    const bool keyed = st == dash::MessageStage::KeyBound;
    const bool signed_ = st == dash::MessageStage::Signed;

    targetCard_->setPlainText(qs(model_->target_card()));
    msgBox_->setEnabled(targeted);
    msgSetCard_->setText(model_->has_message()
                             ? QStringLiteral("set in step 2: %1 bytes, sha256 %2")
                                   .arg(qulonglong(model_->message().size()))
                                   .arg(qs(model_->message_sha256_hex()))
                             : QStringLiteral("no message set yet"));
    refreshSignMessageInfo();
    keyBox_->setEnabled(targeted && model_->has_message());
    keyCard_->setText(qs(model_->key_card()));

    signBox_->setEnabled(keyed || signed_);
    reviewedChk_->setEnabled(keyed);
    signWordEdit_->setEnabled(keyed);
    if (!keyed) {
        // The gate never carries over a stage change: re-arm by hand every time.
        const QSignalBlocker b1(reviewedChk_), b2(signWordEdit_);
        reviewedChk_->setChecked(false);
        signWordEdit_->clear();
    }
    signBtn_->setEnabled(model_->armed());
    signOut_->setPlainText(signed_ ? qs(model_->sign_card() + "\n" + model_->export_text()) : QString());
    copyBtn_->setEnabled(signed_);
    saveBtn_->setEnabled(signed_);
    toVerifyBtn_->setEnabled(signed_);
}

// ── Sign tab ─────────────────────────────────────────────────────────────────

void PageSignMessage::onNetworkChanged()
{
    model_ = std::make_unique<dash::MessageModel>(testnetChk_->isChecked()); // the old model wipes its key
    clearStatus();
    refresh();
}

void PageSignMessage::onSetTarget()
{
    clearStatus();
    try {
        model_->set_target(coinCombo_->currentData().toString().toStdString(),
                           addrEdit_->text().trimmed().toStdString());
    } catch (const std::exception& e) {
        report(QStringLiteral("Target"), QString::fromUtf8(e.what()));
        return;
    }
    refresh();
}

void PageSignMessage::onSetMessage()
{
    clearStatus();
    model_->set_message(signMsg_->bytes()); // exact bytes; drops a bound key
    refresh();
}

void PageSignMessage::onBindKey()
{
    clearStatus();
    dash::KeyInput k;
    KeyInputWipe wipe{k};
    QString err;
    if (!keyIn_->read(this, k, &err)) {
        if (!err.isEmpty()) report(QStringLiteral("Key"), err);
        return;
    }
    QApplication::setOverrideCursor(Qt::WaitCursor); // BIP38 / long scans are CPU-bound
    try {
        model_->load_key(k);
    } catch (const std::exception& e) {
        QApplication::restoreOverrideCursor();
        report(QStringLiteral("Key"), QString::fromUtf8(e.what()));
        return;
    }
    QApplication::restoreOverrideCursor();
    refresh();
}

void PageSignMessage::onGateChanged()
{
    model_->set_gate(reviewedChk_->isChecked(), signWordEdit_->text().toStdString());
    signBtn_->setEnabled(model_->armed());
}

void PageSignMessage::onSign()
{
    clearStatus();
    onGateChanged();
    if (!model_->armed()) {
        report(QStringLiteral("Sign"), QStringLiteral("not armed"));
        return;
    }
    QApplication::setOverrideCursor(Qt::WaitCursor);
    try {
        model_->sign();
    } catch (const std::exception& e) {
        QApplication::restoreOverrideCursor();
        report(QStringLiteral("Sign"), QString::fromUtf8(e.what()) +
                                           QStringLiteral(" (the key was wiped; bind it again to retry)"));
        return;
    }
    QApplication::restoreOverrideCursor();
    refresh();
}

void PageSignMessage::onCopySignature()
{
    if (model_->stage() != dash::MessageStage::Signed) return;
    QGuiApplication::clipboard()->setText(qs(model_->signature_b64())); // public data only
}

void PageSignMessage::onSaveSignature()
{
    if (model_->stage() != dash::MessageStage::Signed) return;
    const QString path = QFileDialog::getSaveFileName(this, QStringLiteral("Save the signature"),
                                                      QStringLiteral("signature.txt"),
                                                      QStringLiteral("text (*.txt);;All files (*)"));
    if (path.isEmpty()) return;
    QFile f(path);
    const std::string bytes = model_->export_text();
    if (!f.open(QIODevice::WriteOnly) || f.write(bytes.data(), qint64(bytes.size())) != qint64(bytes.size())) {
        report(QStringLiteral("Save"), QStringLiteral("could not write %1").arg(path));
        return;
    }
    f.close();
    signOut_->appendPlainText(QStringLiteral("saved %1").arg(path));
}

void PageSignMessage::onSendToVerify()
{
    if (model_->stage() != dash::MessageStage::Signed) return;
    const int idx = vCoinCombo_->findData(qs(model_->ticker()));
    if (idx >= 0) vCoinCombo_->setCurrentIndex(idx);
    vTestnetChk_->setChecked(model_->testnet());
    vAddrEdit_->setText(qs(model_->address()));
    verifyMsg_->setBytes(model_->message());
    vSigEdit_->setText(qs(model_->signature_b64()));
    tabs_->setCurrentIndex(1);
    onVerify();
}

// ── Verify tab (stateless; never touches a key) ──────────────────────────────

void PageSignMessage::onVerify()
{
    clearStatus();
    verifyMsg_->updateInfo(nullptr);
    dash::VerifyReport r;
    bool ok = false;
    try {
        ok = dash::verify_message(dash::message_coin(vCoinCombo_->currentData().toString().toStdString()),
                                  vAddrEdit_->text().trimmed().toStdString(), verifyMsg_->bytes(),
                                  vSigEdit_->text().trimmed().toStdString(), vTestnetChk_->isChecked(), &r);
    } catch (const std::exception& e) {
        r.why = e.what();
    }
    if (ok) {
        vResult_->setText(QStringLiteral("VALID \u2014 recovers to %1 (%2, recid %3)")
                              .arg(qs(r.recovered_address),
                                   r.header_compressed ? QStringLiteral("compressed") : QStringLiteral("uncompressed"))
                              .arg(r.recid));
        vResult_->setStyleSheet(banner_style("#1b7f3a"));
    } else {
        vResult_->setText(QStringLiteral("INVALID \u2014 %1").arg(qs(r.why)));
        vResult_->setStyleSheet(banner_style("#b00020"));
    }
}
