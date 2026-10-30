// SPDX-License-Identifier: AGPL-3.0-or-later
#include "shell/PageDashInject.hpp"
#include "shell/ScopedSecret.hpp"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFont>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QString>
#include <QVBoxLayout>

#include <exception>
#include <string>

// std-only model header ONLY (G3 boundary — no dashscript / btclibs header here).
#include "family/bitcoin/dash/DashInjectModel.hpp"

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

QSpinBox* spin(QWidget* parent, int lo, int hi, int value, const QString& special = {})
{
    auto* s = new QSpinBox(parent);
    s->setRange(lo, hi);
    s->setValue(value);
    if (!special.isEmpty()) s->setSpecialValueText(special);
    return s;
}

// Wipes a KeyInput's two secret strings when the bind attempt ends.
struct KeyInputWipe {
    dash::KeyInput& k;
    ~KeyInputWipe()
    {
        if (!k.secret.empty()) c2w::secure::secure_wipe(&k.secret[0], k.secret.size());
        if (!k.passphrase.empty()) c2w::secure::secure_wipe(&k.passphrase[0], k.passphrase.size());
        k.secret.clear();
        k.passphrase.clear();
    }
};

} // namespace

PageDashInject::PageDashInject(QWidget* parent)
    : QWidget(parent), model_(std::make_unique<dash::DashInjectModel>(false))
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

    auto* heading = new QLabel(QStringLiteral("DASH Inject / Collateral (offline, key-bearing)"), body);
    QFont hf = heading->font();
    hf.setPointSize(hf.pointSize() + 6);
    hf.setBold(true);
    heading->setFont(hf);
    v->addWidget(heading);
    auto* intro = new QLabel(QStringLiteral(
        "Consolidate the mature UTXOs of one DASH P2PKH address, or build a governance collateral, "
        "and sign it here. Zero-fee txs ride only a c2pool block (pin / inject lane); the relay "
        "mode pays a fee for dashd sendrawtransaction. Nothing leaves this machine but the two "
        "files you save."), body);
    intro->setWordWrap(true);
    v->addWidget(intro);
    testnetChk_ = new QCheckBox(QStringLiteral("testnet (changing this resets the page)"), body);
    v->addWidget(testnetChk_);
    status_ = new QLabel(body);
    status_->setWordWrap(true);
    status_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    v->addWidget(status_);

    // ── 1. import ───────────────────────────────────────────────────────────
    auto* importBox = new QGroupBox(QStringLiteral("1. Import the UTXO list (public data)"), body);
    auto* iv = new QVBoxLayout(importBox);
    utxoIn_ = new QPlainTextEdit(importBox);
    utxoIn_->setPlaceholderText(QStringLiteral(
        "paste export_utxos.py output (c2wallet-utxo-export/1), dashd getaddressutxos JSON, or an "
        "insight UTXO list - or load it from a file"));
    utxoIn_->setFont(QFont(QStringLiteral("monospace")));
    utxoIn_->setMaximumHeight(110);
    iv->addWidget(utxoIn_);
    auto* iform = new QFormLayout();
    tipSpin_ = spin(importBox, 0, 2000000000, 0, QStringLiteral("from the file"));
    iform->addRow(QStringLiteral("tip height (bare getaddressutxos array only):"), tipSpin_);
    expectAddr_ = new QLineEdit(importBox);
    expectAddr_->setPlaceholderText(QStringLiteral("optional: the funding address you expect"));
    iform->addRow(QStringLiteral("expected funding address:"), expectAddr_);
    iv->addLayout(iform);
    auto* ib = new QHBoxLayout();
    loadUtxoBtn_ = new QPushButton(QStringLiteral("Load UTXO file..."), importBox);
    importBtn_ = new QPushButton(QStringLiteral("1) Import"), importBox);
    ib->addWidget(loadUtxoBtn_);
    ib->addWidget(importBtn_);
    iv->addLayout(ib);
    importCard_ = card(importBox, 120);
    iv->addWidget(importCard_);
    v->addWidget(importBox);

    // ── 2. screen ───────────────────────────────────────────────────────────
    screenBox_ = new QGroupBox(QStringLiteral("2. Maturity at the target landing height"), body);
    auto* sv = new QVBoxLayout(screenBox_);
    auto* sform = new QFormLayout();
    targetSpin_ = spin(screenBox_, 0, 2000000000, 0, QStringLiteral("tip + 2"));
    minConfSpin_ = spin(screenBox_, 1, 100000, int(dash::kDefaultMinConf));
    dustSpin_ = spin(screenBox_, 0, 2000000000, int(dash::kDefaultPageDustFloor));
    sform->addRow(QStringLiteral("target landing height:"), targetSpin_);
    sform->addRow(QStringLiteral("min confirmations (coinbase never below 100):"), minConfSpin_);
    sform->addRow(QStringLiteral("dust floor (duffs):"), dustSpin_);
    sv->addLayout(sform);
    screenBtn_ = new QPushButton(QStringLiteral("2) Re-screen"), screenBox_);
    sv->addWidget(screenBtn_);
    screenCard_ = card(screenBox_, 160);
    sv->addWidget(screenCard_);
    v->addWidget(screenBox_);

    // ── 3. output ───────────────────────────────────────────────────────────
    planBox_ = new QGroupBox(QStringLiteral("3. Output (dry run: no key needed)"), body);
    auto* pv = new QVBoxLayout(planBox_);
    auto* pform = new QFormLayout();
    modeCombo_ = new QComboBox(planBox_);
    modeCombo_->addItem(QStringLiteral("Consolidate"));
    modeCombo_->addItem(QStringLiteral("Governance collateral (burns 1 DASH)"));
    pform->addRow(QStringLiteral("output:"), modeCombo_);
    feeCombo_ = new QComboBox(planBox_);
    feeCombo_->addItem(QStringLiteral("Zero fee - pin / inject lane (only a c2pool block carries it)"));
    feeCombo_->addItem(QStringLiteral("Fee-paying - relay via dashd sendrawtransaction"));
    pform->addRow(QStringLiteral("fee mode:"), feeCombo_);
    feeRateSpin_ = spin(planBox_, int(dash::kMinRelayFeePerByte), int(dash::kMaxRelayFeePerByte), 1);
    pform->addRow(QStringLiteral("relay fee rate (duffs/byte):"), feeRateSpin_);
    pv->addLayout(pform);

    consolidateFields_ = new QWidget(planBox_);
    auto* cform = new QFormLayout(consolidateFields_);
    cform->setContentsMargins(0, 0, 0, 0);
    destEdit_ = new QLineEdit(consolidateFields_);
    cform->addRow(QStringLiteral("destination:"), destEdit_);
    maxPerTxSpin_ = spin(consolidateFields_, 0, 1000, 0, QStringLiteral("node cap (1000)"));
    cform->addRow(QStringLiteral("max inputs per tx (split knob):"), maxPerTxSpin_);
    inputLimitSpin_ = spin(consolidateFields_, 0, 1000000, 0, QStringLiteral("every mature UTXO"));
    cform->addRow(QStringLiteral("input limit (the N oldest):"), inputLimitSpin_);
    pv->addWidget(consolidateFields_);

    collateralFields_ = new QWidget(planBox_);
    auto* gform = new QFormLayout(collateralFields_);
    gform->setContentsMargins(0, 0, 0, 0);
    govHashEdit_ = new QLineEdit(collateralFields_);
    govHashEdit_->setPlaceholderText(QStringLiteral("64-hex hash printed by `gobject check` / `gobject prepare`"));
    gform->addRow(QStringLiteral("collateral hash:"), govHashEdit_);
    changeEdit_ = new QLineEdit(collateralFields_);
    gform->addRow(QStringLiteral("change address:"), changeEdit_);
    pv->addWidget(collateralFields_);

    planBtn_ = new QPushButton(QStringLiteral("3) Plan (dry run)"), planBox_);
    pv->addWidget(planBtn_);
    externalBadge_ = new QLabel(QStringLiteral("EXTERNAL - the output does not return to the funding address"), planBox_);
    externalBadge_->setStyleSheet(QStringLiteral(
        "color:#fff; background:#b00020; font-weight:bold; padding:4px; border-radius:4px;"));
    externalBadge_->setVisible(false);
    pv->addWidget(externalBadge_);
    planOut_ = card(planBox_, 240);
    pv->addWidget(planOut_);
    v->addWidget(planBox_);

    // ── 4. key ──────────────────────────────────────────────────────────────
    keyBox_ = new QGroupBox(QStringLiteral("4. Key (secret: wiped from the widgets the moment it is read)"), body);
    auto* kv = new QVBoxLayout(keyBox_);
    auto* kform = new QFormLayout();
    keySrcCombo_ = new QComboBox(keyBox_);
    keySrcCombo_->addItem(QStringLiteral("BIP39 mnemonic"), int(dash::KeySource::Mnemonic));
    keySrcCombo_->addItem(QStringLiteral("WIF"), int(dash::KeySource::Wif));
    keySrcCombo_->addItem(QStringLiteral("BIP38 (6P...)"), int(dash::KeySource::Bip38));
    keySrcCombo_->addItem(QStringLiteral("descriptor pkh(...)"), int(dash::KeySource::Descriptor));
    keySrcCombo_->addItem(QStringLiteral("JSON keystore"), int(dash::KeySource::JsonKeystore));
    kform->addRow(QStringLiteral("format:"), keySrcCombo_);
    secretEdit_ = new QLineEdit(keyBox_);
    secretEdit_->setEchoMode(QLineEdit::Password);
    kform->addRow(QStringLiteral("secret:"), secretEdit_);
    passEdit_ = new QLineEdit(keyBox_);
    passEdit_->setEchoMode(QLineEdit::Password);
    kform->addRow(QStringLiteral("passphrase:"), passEdit_);
    accountsSpin_ = spin(keyBox_, 1, 100, 2);
    indicesSpin_ = spin(keyBox_, 1, 100000, 50);
    kform->addRow(QStringLiteral("scan accounts:"), accountsSpin_);
    kform->addRow(QStringLiteral("scan indices:"), indicesSpin_);
    kv->addLayout(kform);
    internalChk_ = new QCheckBox(QStringLiteral("scan the internal (change) chain too"), keyBox_);
    internalChk_->setChecked(true);
    uncompChk_ = new QCheckBox(QStringLiteral("try uncompressed keys too"), keyBox_);
    uncompChk_->setChecked(true);
    kv->addWidget(internalChk_);
    kv->addWidget(uncompChk_);
    bindBtn_ = new QPushButton(QStringLiteral("4) Bind key"), keyBox_);
    kv->addWidget(bindBtn_);
    keyCard_ = new QLabel(keyBox_);
    keyCard_->setWordWrap(true);
    keyCard_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    kv->addWidget(keyCard_);
    v->addWidget(keyBox_);

    // ── 5. review -> SPEND -> sign -> export ────────────────────────────────
    signBox_ = new QGroupBox(QStringLiteral("5. Review, type SPEND, sign, export"), body);
    auto* gv = new QVBoxLayout(signBox_);
    reviewedChk_ = new QCheckBox(QStringLiteral(
        "I reviewed the plan above: inputs, output address, amounts, fee and the skipped UTXOs."), signBox_);
    burnChk_ = new QCheckBox(QStringLiteral("I understand this irreversibly BURNS 1 DASH (governance collateral)."), signBox_);
    spendEdit_ = new QLineEdit(signBox_);
    spendEdit_->setPlaceholderText(QStringLiteral("type SPEND to arm signing"));
    signBtn_ = new QPushButton(QStringLiteral("5) Sign, re-verify, wipe the key"), signBox_);
    gv->addWidget(reviewedChk_);
    gv->addWidget(burnChk_);
    gv->addWidget(spendEdit_);
    gv->addWidget(signBtn_);
    signOut_ = card(signBox_, 200);
    gv->addWidget(signOut_);
    auto* eb = new QHBoxLayout();
    saveHexBtn_ = new QPushButton(QStringLiteral("Save <name>.hex..."), signBox_);
    saveManBtn_ = new QPushButton(QStringLiteral("Save <name>.manifest.json..."), signBox_);
    eb->addWidget(saveHexBtn_);
    eb->addWidget(saveManBtn_);
    gv->addLayout(eb);
    v->addWidget(signBox_);
    v->addStretch(1);

    connect(testnetChk_, &QCheckBox::toggled, this, &PageDashInject::onNetworkChanged);
    connect(loadUtxoBtn_, &QPushButton::clicked, this, &PageDashInject::onLoadUtxoFile);
    connect(importBtn_, &QPushButton::clicked, this, &PageDashInject::onImport);
    connect(screenBtn_, &QPushButton::clicked, this, &PageDashInject::onRescreen);
    connect(modeCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, &PageDashInject::onModeChanged);
    connect(feeCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, &PageDashInject::onModeChanged);
    connect(planBtn_, &QPushButton::clicked, this, &PageDashInject::onPlan);
    connect(keySrcCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, &PageDashInject::onKeySourceChanged);
    connect(bindBtn_, &QPushButton::clicked, this, &PageDashInject::onBindKey);
    connect(reviewedChk_, &QCheckBox::toggled, this, &PageDashInject::onGateChanged);
    connect(burnChk_, &QCheckBox::toggled, this, &PageDashInject::onGateChanged);
    connect(spendEdit_, &QLineEdit::textChanged, this, &PageDashInject::onGateChanged);
    connect(signBtn_, &QPushButton::clicked, this, &PageDashInject::onSign);
    connect(saveHexBtn_, &QPushButton::clicked, this, &PageDashInject::onSaveHex);
    connect(saveManBtn_, &QPushButton::clicked, this, &PageDashInject::onSaveManifest);

    onModeChanged();
    onKeySourceChanged();
    refresh();
}

PageDashInject::~PageDashInject() = default; // ~DashInjectModel wipes any key still held

void PageDashInject::clearStatus() { status_->clear(); }

void PageDashInject::report(const QString& stage, const QString& why)
{
    status_->setText(QStringLiteral("<span style='color:#b00020;font-weight:bold'>%1 REFUSED:</span> %2")
                         .arg(stage.toHtmlEscaped(), why.toHtmlEscaped()));
    refresh();
}

void PageDashInject::refresh()
{
    const dash::InjectStage st = model_->stage();
    const bool imported = st >= dash::InjectStage::Imported;
    const bool screened = st >= dash::InjectStage::Screened;
    const bool planned = st >= dash::InjectStage::Planned;
    const bool keyed = st == dash::InjectStage::KeyBound;
    const bool signed_ = st == dash::InjectStage::Signed;

    importCard_->setPlainText(qs(model_->import_card()));
    screenBox_->setEnabled(imported);
    screenCard_->setPlainText(qs(model_->screen_card()));
    planBox_->setEnabled(screened);
    planOut_->setPlainText(qs(model_->plan_summary()));
    externalBadge_->setVisible(planned && model_->destination_is_external());
    keyBox_->setEnabled(planned);
    keyCard_->setText(qs(model_->key_card()));

    const bool collateral = model_->collateral_plan() != nullptr;
    signBox_->setEnabled(keyed || signed_);
    burnChk_->setVisible(collateral);
    reviewedChk_->setEnabled(keyed);
    burnChk_->setEnabled(keyed);
    spendEdit_->setEnabled(keyed);
    if (!keyed) {
        // The gate never carries over a stage change: re-arm by hand every time.
        const QSignalBlocker b1(reviewedChk_), b2(burnChk_), b3(spendEdit_);
        reviewedChk_->setChecked(false);
        burnChk_->setChecked(false);
        spendEdit_->clear();
    }
    signBtn_->setEnabled(model_->armed());
    signOut_->setPlainText(signed_ ? qs(model_->sign_card()) : QString());
    saveHexBtn_->setEnabled(signed_);
    saveManBtn_->setEnabled(signed_);
}

void PageDashInject::onNetworkChanged()
{
    model_ = std::make_unique<dash::DashInjectModel>(testnetChk_->isChecked());
    lastHexPath_.clear();
    clearStatus();
    refresh();
}

void PageDashInject::onLoadUtxoFile()
{
    const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("Load UTXO list"), QString(),
                                                      QStringLiteral("JSON (*.json);;All files (*)"));
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        report(QStringLiteral("Load"), QStringLiteral("could not read %1").arg(path));
        return;
    }
    utxoIn_->setPlainText(QString::fromUtf8(f.readAll()));
}

void PageDashInject::onImport()
{
    clearStatus();
    try {
        model_->import_utxos(utxoIn_->toPlainText().toStdString(), tipSpin_->value(),
                             expectAddr_->text().trimmed().toStdString());
        const QString funding = qs(model_->utxo_import().address);
        destEdit_->setPlaceholderText(QStringLiteral("empty = the funding address %1").arg(funding));
        changeEdit_->setPlaceholderText(QStringLiteral("empty = the funding address %1").arg(funding));
    } catch (const std::exception& e) {
        report(QStringLiteral("Import"), QString::fromUtf8(e.what()));
        return;
    }
    refresh();
}

void PageDashInject::onRescreen()
{
    clearStatus();
    try {
        dash::ScreenParams p;
        p.target_height = targetSpin_->value();
        p.min_confirmations = minConfSpin_->value();
        p.dust_floor = dustSpin_->value();
        model_->rescreen(p);
    } catch (const std::exception& e) {
        report(QStringLiteral("Screen"), QString::fromUtf8(e.what()));
        return;
    }
    refresh();
}

void PageDashInject::onModeChanged()
{
    const bool collateral = modeCombo_->currentIndex() == 1;
    consolidateFields_->setVisible(!collateral);
    collateralFields_->setVisible(collateral);
    feeRateSpin_->setEnabled(feeCombo_->currentIndex() == 1);
}

void PageDashInject::onPlan()
{
    clearStatus();
    try {
        dash::PlanParams p;
        p.mode = modeCombo_->currentIndex() == 1 ? dash::OutputMode::Collateral : dash::OutputMode::Consolidate;
        const bool relay = feeCombo_->currentIndex() == 1;
        p.fee_mode = relay ? c2w::dash::FeeMode::Relay : c2w::dash::FeeMode::InjectOnlyZeroFee;
        p.fee_rate_per_byte = relay ? feeRateSpin_->value() : 0;
        if (p.mode == dash::OutputMode::Consolidate) {
            p.destination = destEdit_->text().trimmed().toStdString();
            p.max_inputs_per_tx = size_t(maxPerTxSpin_->value());
            p.input_limit = size_t(inputLimitSpin_->value());
        } else {
            p.gov_hash_display = govHashEdit_->text().trimmed().toStdString();
            p.change_address = changeEdit_->text().trimmed().toStdString();
        }
        model_->plan(p);
    } catch (const std::exception& e) {
        report(QStringLiteral("Plan"), QString::fromUtf8(e.what()));
        return;
    }
    refresh();
}

void PageDashInject::onKeySourceChanged()
{
    const auto src = dash::KeySource(keySrcCombo_->currentData().toInt());
    const bool scans = src == dash::KeySource::Mnemonic || src == dash::KeySource::JsonKeystore;
    switch (src) {
    case dash::KeySource::Mnemonic: secretEdit_->setPlaceholderText(QStringLiteral("12/15/18/21/24 BIP39 words")); break;
    case dash::KeySource::Wif: secretEdit_->setPlaceholderText(QStringLiteral("DASH WIF (X... / 7...)")); break;
    case dash::KeySource::Bip38: secretEdit_->setPlaceholderText(QStringLiteral("6P... encrypted key")); break;
    case dash::KeySource::Descriptor: secretEdit_->setPlaceholderText(QStringLiteral("pkh([fp/44'/5'/0']xprv.../0/*)#checksum")); break;
    case dash::KeySource::JsonKeystore:
        secretEdit_->setPlaceholderText(QStringLiteral("paste the keystore JSON, or leave empty to choose the file at Bind"));
        break;
    }
    passEdit_->setEnabled(src == dash::KeySource::Mnemonic || src == dash::KeySource::Bip38 ||
                          src == dash::KeySource::JsonKeystore);
    accountsSpin_->setEnabled(scans);
    indicesSpin_->setEnabled(scans || src == dash::KeySource::Descriptor);
    internalChk_->setEnabled(scans);
    uncompChk_->setEnabled(scans);
}

void PageDashInject::onBindKey()
{
    clearStatus();
    dash::KeyInput k;
    KeyInputWipe wipe{k};
    k.source = dash::KeySource(keySrcCombo_->currentData().toInt());
    {
        // Read each secret ONCE and clear its widget at once.
        ScopedSecret secret(secretEdit_->text().toStdString());
        ScopedSecret pass(passEdit_->text().toStdString());
        secretEdit_->clear();
        passEdit_->clear();
        k.secret.swap(secret.s);
        k.passphrase.swap(pass.s);
    }
    if (k.source == dash::KeySource::JsonKeystore && k.secret.empty()) {
        const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("Choose the JSON keystore"), QString(),
                                                          QStringLiteral("JSON (*.json);;All files (*)"));
        if (path.isEmpty()) return;
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) {
            report(QStringLiteral("Key"), QStringLiteral("could not read the keystore file"));
            return;
        }
        QByteArray bytes = f.readAll();
        k.secret.assign(bytes.constData(), size_t(bytes.size()));
        if (!bytes.isEmpty()) c2w::secure::secure_wipe(bytes.data(), size_t(bytes.size()));
    }
    k.range.accounts = uint32_t(accountsSpin_->value());
    k.range.indices = uint32_t(indicesSpin_->value());
    k.range.scan_internal = internalChk_->isChecked();
    k.range.try_uncompressed = uncompChk_->isChecked();

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

void PageDashInject::onGateChanged()
{
    model_->set_gate(reviewedChk_->isChecked(), burnChk_->isChecked(), spendEdit_->text().toStdString());
    signBtn_->setEnabled(model_->armed());
}

void PageDashInject::onSign()
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

void PageDashInject::onSaveHex()
{
    if (model_->stage() != dash::InjectStage::Signed) return;
    const QString path = QFileDialog::getSaveFileName(this, QStringLiteral("Save the signed tx file"),
                                                      QStringLiteral("dash_inject.hex"),
                                                      QStringLiteral("hex (*.hex);;All files (*)"));
    if (path.isEmpty()) return;
    QFile f(path);
    const std::string& bytes = model_->inject_file();
    if (!f.open(QIODevice::WriteOnly) || f.write(bytes.data(), qint64(bytes.size())) != qint64(bytes.size())) {
        report(QStringLiteral("Save"), QStringLiteral("could not write %1").arg(path));
        return;
    }
    f.close();
    lastHexPath_ = path;
    signOut_->appendPlainText(QStringLiteral("saved %1").arg(path));
}

void PageDashInject::onSaveManifest()
{
    if (model_->stage() != dash::InjectStage::Signed) return;
    QString suggested = QStringLiteral("dash_inject.manifest.json");
    if (!lastHexPath_.isEmpty()) {
        const QFileInfo fi(lastHexPath_);
        suggested = fi.dir().filePath(fi.completeBaseName() + QStringLiteral(".manifest.json"));
    }
    const QString path = QFileDialog::getSaveFileName(this, QStringLiteral("Save the manifest"), suggested,
                                                      QStringLiteral("manifest (*.manifest.json);;All files (*)"));
    if (path.isEmpty()) return;
    QFile f(path);
    const std::string& bytes = model_->manifest_json();
    if (!f.open(QIODevice::WriteOnly) || f.write(bytes.data(), qint64(bytes.size())) != qint64(bytes.size())) {
        report(QStringLiteral("Save"), QStringLiteral("could not write %1").arg(path));
        return;
    }
    f.close();
    signOut_->appendPlainText(QStringLiteral("saved %1").arg(path));
}
