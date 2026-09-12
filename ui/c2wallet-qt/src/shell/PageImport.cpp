// SPDX-License-Identifier: AGPL-3.0-or-later
#include "shell/PageImport.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QFont>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QString>
#include <QVBoxLayout>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

// Family A (Bitcoin-script) — c2wallet-hdkeys
#include "family/bitcoin/hdkeys/Address.hpp"
#include "family/bitcoin/hdkeys/Bip32.hpp"
#include "family/bitcoin/hdkeys/Bip39.hpp"
#include "family/bitcoin/hdkeys/CoinParams.hpp"
#include "family/bitcoin/hdkeys/Derivation.hpp"
#include "family/bitcoin/hdkeys/KeyImport.hpp"

// Family B (Monero) — c2wallet_monero
#include "family/monero/MoneroKey.hpp"
#include "family/monero/addr/MoneroAddress.hpp"
#include "family/monero/seed/MoneroMnemonic.hpp"

namespace hk = c2w::hdkeys;
namespace xm = c2wallet::monero;

namespace {

QString hint_label(hk::ScriptHint h)
{
    switch (h) {
        case hk::ScriptHint::P2PKH:        return "P2PKH";
        case hk::ScriptHint::P2SH_P2WPKH:  return "P2SH-P2WPKH";
        case hk::ScriptHint::P2WPKH:       return "P2WPKH";
        case hk::ScriptHint::P2TR:         return "P2TR";
        default:                           return "?";
    }
}

QString candidate_line(const hk::AddressCandidate& c)
{
    QString enc = c.encoding.empty() ? QString() : QString(" [%1]").arg(QString::fromStdString(c.encoding));
    QString addr = c.address.empty() ? QStringLiteral("(no address form)") : QString::fromStdString(c.address);
    return QString("    %1%2  %3").arg(QString::fromStdString(c.label), enc, addr);
}

}  // namespace

PageImport::PageImport(QWidget* parent) : QWidget(parent)
{
    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 24, 24, 24);
    v->setSpacing(10);

    auto* heading = new QLabel(QStringLiteral("Import / Load Key"), this);
    QFont hf = heading->font();
    hf.setPointSize(hf.pointSize() + 6);
    hf.setBold(true);
    heading->setFont(hf);
    v->addWidget(heading);

    auto* sub = new QLabel(
        QStringLiteral("Import a key and view its derived PUBLIC addresses. "
                       "Read-only (slice 1) — no signing. Secrets are held in "
                       "zeroizing buffers and never displayed."),
        this);
    sub->setWordWrap(true);
    v->addWidget(sub);

    auto* form = new QFormLayout();
    form->setLabelAlignment(Qt::AlignRight);

    formatCombo_ = new QComboBox(this);
    formatCombo_->addItem(QStringLiteral("BIP39 mnemonic (Family A)"));
    formatCombo_->addItem(QStringLiteral("WIF (Family A)"));
    formatCombo_->addItem(QStringLiteral("Raw hex privkey (Family A)"));
    formatCombo_->addItem(QStringLiteral("BIP32 xprv / xpub (Family A)"));
    formatCombo_->addItem(QStringLiteral("Monero 25-word seed (Family B)"));
    form->addRow(QStringLiteral("Format:"), formatCombo_);

    coinCombo_ = new QComboBox(this);
    for (const auto& c : hk::all_coins())
        coinCombo_->addItem(QString("%1  (%2)").arg(QString::fromLatin1(c.name),
                                                    QString::fromLatin1(c.ticker)),
                            QString::fromLatin1(c.ticker));
    coinLabel_ = new QLabel(QStringLiteral("Target coin:"), this);
    form->addRow(coinLabel_, coinCombo_);

    secretEdit_ = new QLineEdit(this);
    secretEdit_->setPlaceholderText(QStringLiteral("mnemonic words / WIF / hex / xprv…"));
    secretEdit_->setEchoMode(QLineEdit::Password);
    form->addRow(QStringLiteral("Secret / key:"), secretEdit_);

    passphraseLabel_ = new QLabel(QStringLiteral("BIP39 passphrase:"), this);
    passphraseEdit_ = new QLineEdit(this);
    passphraseEdit_->setEchoMode(QLineEdit::Password);
    passphraseEdit_->setPlaceholderText(QStringLiteral("optional — empty vs wrong both yield a valid, DIFFERENT wallet"));
    form->addRow(passphraseLabel_, passphraseEdit_);

    compressedCheck_ = new QCheckBox(QStringLiteral("compressed pubkey"), this);
    compressedCheck_->setChecked(true);
    form->addRow(QString(), compressedCheck_);

    v->addLayout(form);

    importBtn_ = new QPushButton(QStringLiteral("Import / Derive addresses"), this);
    v->addWidget(importBtn_);

    output_ = new QPlainTextEdit(this);
    output_->setReadOnly(true);
    output_->setFont(QFont(QStringLiteral("monospace")));
    v->addWidget(output_, 1);

    connect(formatCombo_, SIGNAL(currentIndexChanged(int)), this, SLOT(onFormatChanged()));
    connect(importBtn_, &QPushButton::clicked, this, &PageImport::onImport);

    onFormatChanged();
}

void PageImport::onFormatChanged()
{
    const int idx = formatCombo_->currentIndex();
    const bool isBip39 = (idx == 0);
    const bool isRaw   = (idx == 2);
    const bool isMonero = (idx == 4);

    passphraseLabel_->setVisible(isBip39);
    passphraseEdit_->setVisible(isBip39);
    compressedCheck_->setVisible(isRaw);
    coinLabel_->setVisible(!isMonero);
    coinCombo_->setVisible(!isMonero);
}

void PageImport::onImport()
{
    output_->clear();
    switch (formatCombo_->currentIndex()) {
        case 0: deriveFamilyA_bip39();  break;
        case 1: deriveFamilyA_wif();    break;
        case 2: deriveFamilyA_rawhex(); break;
        case 3: deriveFamilyA_extkey(); break;
        case 4: deriveFamilyB_monero(); break;
    }
}

void PageImport::deriveFamilyA_bip39()
{
    const std::string mnemonic = secretEdit_->text().trimmed().toStdString();
    if (mnemonic.empty()) { output_->appendPlainText(QStringLiteral("Enter a mnemonic.")); return; }

    hk::Bip39Error e = hk::Bip39::validate(mnemonic, hk::Language::English);
    if (e != hk::Bip39Error::Ok) {
        output_->appendPlainText(QString("Invalid BIP39 mnemonic: %1").arg(hk::to_string(e)));
        return;
    }

    const std::string ticker = coinCombo_->currentData().toString().toStdString();
    const hk::CoinParams* coin = hk::coin_by_ticker(ticker);
    if (!coin) { output_->appendPlainText(QStringLiteral("Unknown coin.")); return; }

    c2w::secure::SecureBytes seed =
        hk::Bip39::to_seed(mnemonic, passphraseEdit_->text().toStdString());

    output_->appendPlainText(QString("BIP39 mnemonic OK (checksum verified).  Coin: %1")
                                 .arg(QString::fromLatin1(coin->ticker)));
    output_->appendPlainText(QString("Seed fingerprint: %1  "
                                     "(changes with any passphrase — confirm it matches what you expect)")
                                 .arg(QString::fromStdString(hk::Bip39::seed_fingerprint(seed))));

    auto master = hk::HDKey::from_seed(seed.data(), seed.size(), coin->std_bip32);
    if (!master) { output_->appendPlainText(QStringLiteral("Master key derivation failed.")); return; }

    hk::ScanRange r;
    r.changes = {0};      // receiving chain only, for the on-screen summary
    r.index_lo = 0;
    r.index_hi = 4;       // first five addresses per purpose
    const auto paths = hk::enumerate(r, coin->slip44);

    output_->appendPlainText(QStringLiteral("\nDerived receiving addresses (BIP44 / 49 / 84 / 86):"));
    for (const auto& ep : paths) {
        auto child = master->derive_path(ep.path);
        if (!child) continue;
        const hk::ScriptHint want = hk::purpose_script(ep.purpose);
        const auto cands = hk::address_candidates_from_seckey(child->privkey().data(), *coin);
        QString line = QString("  %1  [%2]  ")
                           .arg(QString::fromStdString(hk::format_path(ep.path)), hint_label(want));
        bool found = false;
        for (const auto& c : cands) {
            if (c.type == want && !c.address.empty()) {
                line += QString::fromStdString(c.address);
                found = true;
                break;
            }
        }
        if (!found) line += QString("(type not available on %1)").arg(QString::fromLatin1(coin->ticker));
        output_->appendPlainText(line);
    }
}

void PageImport::deriveFamilyA_wif()
{
    const std::string wif = secretEdit_->text().trimmed().toStdString();
    hk::WifDecode d = hk::decode_wif(wif);
    if (!d.ok) { output_->appendPlainText(QString("Invalid WIF: %1").arg(QString::fromStdString(d.error))); return; }

    QStringList hints;
    for (const auto& t : d.coin_tickers) hints << QString::fromStdString(t);
    output_->appendPlainText(QString("WIF OK.  version=0x%1  compressed=%2  version matches: %3")
                                 .arg(QString::number(d.version, 16),
                                      d.compressed ? "yes" : "no",
                                      hints.isEmpty() ? QStringLiteral("(unknown)") : hints.join(", ")));

    const std::string ticker = coinCombo_->currentData().toString().toStdString();
    const hk::CoinParams* coin = hk::coin_by_ticker(ticker);
    if (!coin) { output_->appendPlainText(QStringLiteral("Unknown coin.")); return; }

    const auto cands = hk::address_candidates_from_seckey(d.scalar.data(), *coin);
    output_->appendPlainText(QString("\nAddress candidates on %1:").arg(QString::fromLatin1(coin->ticker)));
    for (const auto& c : cands) output_->appendPlainText(candidate_line(c));
}

void PageImport::deriveFamilyA_rawhex()
{
    const std::string hex = secretEdit_->text().trimmed().toStdString();
    hk::RawHexDecode d = hk::decode_raw_hex(hex, compressedCheck_->isChecked());
    if (!d.ok) { output_->appendPlainText(QString("Invalid raw key: %1").arg(QString::fromStdString(d.error))); return; }

    const std::string ticker = coinCombo_->currentData().toString().toStdString();
    const hk::CoinParams* coin = hk::coin_by_ticker(ticker);
    if (!coin) { output_->appendPlainText(QStringLiteral("Unknown coin.")); return; }

    output_->appendPlainText(QString("Raw hex key OK (1 <= k < N verified).  compressed=%1")
                                 .arg(d.compressed ? "yes" : "no"));
    const auto cands = hk::address_candidates_from_seckey(d.scalar.data(), *coin);
    output_->appendPlainText(QString("\nAddress candidates on %1:").arg(QString::fromLatin1(coin->ticker)));
    for (const auto& c : cands) output_->appendPlainText(candidate_line(c));
}

void PageImport::deriveFamilyA_extkey()
{
    const std::string ext = secretEdit_->text().trimmed().toStdString();
    auto node = hk::HDKey::parse(ext);
    if (!node) { output_->appendPlainText(QStringLiteral("Unrecognised or invalid extended key (bad prefix/checksum/length).")); return; }

    const std::string ticker = coinCombo_->currentData().toString().toStdString();
    const hk::CoinParams* coin = hk::coin_by_ticker(ticker);
    if (!coin) { output_->appendPlainText(QStringLiteral("Unknown coin.")); return; }

    const hk::Slip132Entry* se = hk::lookup_bip32_version(node->versions().pub);
    const hk::ScriptHint hint = se ? se->hint : hk::ScriptHint::P2PKH;

    output_->appendPlainText(QString("Parsed %1  depth=%2  script hint=%3%4")
                                 .arg(node->has_private() ? "xprv (private — can derive)"
                                                          : "xpub (public — WATCH-ONLY, cannot sign)")
                                 .arg(node->depth())
                                 .arg(hint_label(hint))
                                 .arg(se ? QString(" (%1)").arg(QString::fromLatin1(se->label)) : QString()));

    output_->appendPlainText(QStringLiteral("\nDerived addresses  node/0/0..4 (external chain):"));
    for (uint32_t i = 0; i <= 4; ++i) {
        auto child = node->derive_path({0u, i});
        if (!child) continue;
        const auto cands = hk::address_candidates(child->pubkey(), *coin);
        QString line = QString("  m/…/0/%1  [%2]  ").arg(i).arg(hint_label(hint));
        bool found = false;
        for (const auto& c : cands) {
            if (c.type == hint && !c.address.empty()) { line += QString::fromStdString(c.address); found = true; break; }
        }
        if (!found) {
            for (const auto& c : cands) {
                if (c.type == hk::ScriptHint::P2PKH && !c.address.empty()) {
                    line = QString("  m/…/0/%1  [P2PKH]  ").arg(i) + QString::fromStdString(c.address);
                    found = true;
                    break;
                }
            }
        }
        if (!found) line += QStringLiteral("(no address form)");
        output_->appendPlainText(line);
    }
}

void PageImport::deriveFamilyB_monero()
{
    const std::string phrase = secretEdit_->text().trimmed().toStdString();
    if (phrase.empty()) { output_->appendPlainText(QStringLiteral("Enter a 25-word Monero seed.")); return; }

    xm::KeyImportResult r = xm::keys_from_mnemonic(phrase);
    if (!r.ok) { output_->appendPlainText(QString("Invalid Monero seed: %1").arg(QString::fromStdString(r.error))); return; }

    output_->appendPlainText(QStringLiteral("Monero 25-word seed OK (checksum verified)."));
    output_->appendPlainText(QString("spend public: %1").arg(QString::fromStdString(xm::bytes32_to_hex(r.keys.spend_pub))));
    output_->appendPlainText(QString("view  public: %1").arg(QString::fromStdString(xm::bytes32_to_hex(r.keys.view_pub))));
    output_->appendPlainText(QString("can sign: %1").arg(r.keys.can_sign() ? "yes (full wallet)" : "no (view-only)"));

    const xm::MoneroAddress primary = xm::primary_address(r.keys, xm::Network::Mainnet);
    output_->appendPlainText(QString("\nPrimary address:\n  %1").arg(QString::fromStdString(xm::address_encode(primary))));

    output_->appendPlainText(QStringLiteral("\nSubaddresses (account 0):"));
    for (uint32_t minor = 1; minor <= 3; ++minor) {
        xm::SubaddressResult sub = xm::derive_subaddress(r.keys.view_priv, r.keys.spend_pub, 0, minor, xm::Network::Mainnet);
        if (!sub.ok) { output_->appendPlainText(QString("  (0,%1): %2").arg(minor).arg(QString::fromStdString(sub.error))); continue; }
        output_->appendPlainText(QString("  (0,%1): %2").arg(minor).arg(QString::fromStdString(xm::address_encode(sub.addr))));
    }
}
