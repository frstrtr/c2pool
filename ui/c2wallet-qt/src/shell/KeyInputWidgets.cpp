// SPDX-License-Identifier: AGPL-3.0-or-later
#include "shell/KeyInputWidgets.hpp"
#include "shell/ScopedSecret.hpp"

#include <QByteArray>
#include <QCheckBox>
#include <QComboBox>
#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QLineEdit>
#include <QSpinBox>
#include <QVBoxLayout>
#include <QWidget>

namespace dash = c2w::dash;

KeyInputWipe::~KeyInputWipe()
{
    if (!k.secret.empty()) c2w::secure::secure_wipe(&k.secret[0], k.secret.size());
    if (!k.passphrase.empty()) c2w::secure::secure_wipe(&k.passphrase[0], k.passphrase.size());
    k.secret.clear();
    k.passphrase.clear();
}

namespace {

QSpinBox* spin(QWidget* parent, int lo, int hi, int value)
{
    auto* s = new QSpinBox(parent);
    s->setRange(lo, hi);
    s->setValue(value);
    return s;
}

} // namespace

KeyInputWidgets::KeyInputWidgets(QWidget* parent, QVBoxLayout* into) : QObject(parent)
{
    auto* kform = new QFormLayout();
    srcCombo_ = new QComboBox(parent);
    srcCombo_->addItem(QStringLiteral("BIP39 mnemonic"), int(dash::KeySource::Mnemonic));
    srcCombo_->addItem(QStringLiteral("WIF"), int(dash::KeySource::Wif));
    srcCombo_->addItem(QStringLiteral("BIP38 (6P...)"), int(dash::KeySource::Bip38));
    srcCombo_->addItem(QStringLiteral("descriptor pkh(...)"), int(dash::KeySource::Descriptor));
    srcCombo_->addItem(QStringLiteral("JSON keystore"), int(dash::KeySource::JsonKeystore));
    kform->addRow(QStringLiteral("format:"), srcCombo_);
    secretEdit_ = new QLineEdit(parent);
    secretEdit_->setEchoMode(QLineEdit::Password);
    kform->addRow(QStringLiteral("secret:"), secretEdit_);
    passEdit_ = new QLineEdit(parent);
    passEdit_->setEchoMode(QLineEdit::Password);
    kform->addRow(QStringLiteral("passphrase:"), passEdit_);
    accountsSpin_ = spin(parent, 1, 100, 2);
    indicesSpin_ = spin(parent, 1, 100000, 50);
    kform->addRow(QStringLiteral("scan accounts:"), accountsSpin_);
    kform->addRow(QStringLiteral("scan indices:"), indicesSpin_);
    into->addLayout(kform);
    internalChk_ = new QCheckBox(QStringLiteral("scan the internal (change) chain too"), parent);
    internalChk_->setChecked(true);
    uncompChk_ = new QCheckBox(QStringLiteral("try uncompressed keys too"), parent);
    uncompChk_->setChecked(true);
    into->addWidget(internalChk_);
    into->addWidget(uncompChk_);

    // `this` is the context: the connection dies with this object.
    connect(srcCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this] { onSourceChanged(); });
    onSourceChanged();
}

void KeyInputWidgets::onSourceChanged()
{
    const auto src = dash::KeySource(srcCombo_->currentData().toInt());
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

bool KeyInputWidgets::read(QWidget* dialogParent, dash::KeyInput& k, QString* error)
{
    if (error) error->clear();
    k.source = dash::KeySource(srcCombo_->currentData().toInt());
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
        const QString path = QFileDialog::getOpenFileName(dialogParent, QStringLiteral("Choose the JSON keystore"),
                                                          QString(), QStringLiteral("JSON (*.json);;All files (*)"));
        if (path.isEmpty()) return false;
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) {
            if (error) *error = QStringLiteral("could not read the keystore file");
            return false;
        }
        QByteArray bytes = f.readAll();
        k.secret.assign(bytes.constData(), size_t(bytes.size()));
        if (!bytes.isEmpty()) c2w::secure::secure_wipe(bytes.data(), size_t(bytes.size()));
    }
    k.range.accounts = uint32_t(accountsSpin_->value());
    k.range.indices = uint32_t(indicesSpin_->value());
    k.range.scan_internal = internalChk_->isChecked();
    k.range.try_uncompressed = uncompChk_->isChecked();
    return true;
}
