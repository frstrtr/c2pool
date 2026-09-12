// SPDX-License-Identifier: AGPL-3.0-or-later
#include "shell/PageScan.hpp"

#include <QFont>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QString>
#include <QStringList>
#include <QVBoxLayout>

#include <cstdint>
#include <string>
#include <vector>

#include "family/monero/MoneroKey.hpp"
#include "family/monero/addr/MoneroAddress.hpp"
#include "family/monero/scan/MoneroScanner.hpp"

namespace xm = c2wallet::monero;

PageScan::PageScan(QWidget* parent) : QWidget(parent)
{
    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 24, 24, 24);
    v->setSpacing(12);

    auto* heading = new QLabel(QStringLiteral("Scan (Monero view-only)"), this);
    QFont hf = heading->font();
    hf.setPointSize(hf.pointSize() + 6);
    hf.setBold(true);
    heading->setFont(hf);
    v->addWidget(heading);

    // ── Key load ────────────────────────────────────────────────────────────
    auto* keyBox = new QGroupBox(QStringLiteral("Load account (view-only, or full seed)"), this);
    auto* kbv = new QVBoxLayout(keyBox);
    auto* kform = new QFormLayout();

    spendPubEdit_ = new QLineEdit(keyBox);
    spendPubEdit_->setPlaceholderText(QStringLiteral("public spend key (32-byte hex)"));
    kform->addRow(QStringLiteral("Spend PUBLIC key:"), spendPubEdit_);

    viewPrivEdit_ = new QLineEdit(keyBox);
    viewPrivEdit_->setEchoMode(QLineEdit::Password);
    viewPrivEdit_->setPlaceholderText(QStringLiteral("private view key (32-byte hex)"));
    kform->addRow(QStringLiteral("View PRIVATE key:"), viewPrivEdit_);
    kbv->addLayout(kform);

    auto* viewBtn = new QPushButton(QStringLiteral("Load view-only account"), keyBox);
    kbv->addWidget(viewBtn);

    auto* mform = new QFormLayout();
    mnemonicEdit_ = new QLineEdit(keyBox);
    mnemonicEdit_->setEchoMode(QLineEdit::Password);
    mnemonicEdit_->setPlaceholderText(QStringLiteral("25-word Monero seed (full wallet — also computes key images)"));
    mform->addRow(QStringLiteral("Or 25-word seed:"), mnemonicEdit_);
    kbv->addLayout(mform);

    auto* fullBtn = new QPushButton(QStringLiteral("Load full wallet from seed"), keyBox);
    kbv->addWidget(fullBtn);

    statusLabel_ = new QLabel(QStringLiteral("No account loaded."), keyBox);
    statusLabel_->setWordWrap(true);
    kbv->addWidget(statusLabel_);
    v->addWidget(keyBox);

    // ── Transaction scan ──────────────────────────────────────────────────
    auto* scanBox = new QGroupBox(QStringLiteral("Scan a transaction for owned outputs"), this);
    auto* sbv = new QVBoxLayout(scanBox);
    auto* sform = new QFormLayout();

    txPubkeyEdit_ = new QLineEdit(scanBox);
    txPubkeyEdit_->setPlaceholderText(QStringLiteral("tx pubkey R (32-byte hex, tx_extra 0x01)"));
    sform->addRow(QStringLiteral("Tx pubkey R:"), txPubkeyEdit_);
    sbv->addLayout(sform);

    outputsEdit_ = new QPlainTextEdit(scanBox);
    outputsEdit_->setPlaceholderText(QStringLiteral(
        "one output per line:\n"
        "  <one_time_pubkey_hex>[,<view_tag_dec>][,<clear_amount>]\n"
        "give a clear_amount for pre-RingCT / coinbase outputs; omit it for RingCT."));
    outputsEdit_->setMaximumHeight(110);
    sbv->addWidget(outputsEdit_);

    scanBtn_ = new QPushButton(QStringLiteral("Scan"), scanBox);
    sbv->addWidget(scanBtn_);

    out_ = new QPlainTextEdit(scanBox);
    out_->setReadOnly(true);
    out_->setFont(QFont(QStringLiteral("monospace")));
    sbv->addWidget(out_);
    v->addWidget(scanBox, 1);

    connect(viewBtn, &QPushButton::clicked, this, &PageScan::onLoadViewOnly);
    connect(fullBtn, &QPushButton::clicked, this, &PageScan::onLoadFull);
    connect(scanBtn_, &QPushButton::clicked, this, &PageScan::onScan);
}

PageScan::~PageScan() = default;

void PageScan::onLoadViewOnly()
{
    scanner_.reset();
    const std::string sp = spendPubEdit_->text().trimmed().toStdString();
    const std::string vp = viewPrivEdit_->text().trimmed().toStdString();
    xm::KeyImportResult r = xm::keys_view_only(sp, vp);
    if (!r.ok) {
        statusLabel_->setText(QString("View-only load FAILED: %1").arg(QString::fromStdString(r.error)));
        return;
    }
    scanner_ = std::make_unique<xm::MoneroScanner>(r.keys);
    scanner_->build_subaddress_table(1, 5);
    const xm::MoneroAddress primary = xm::primary_address(r.keys, xm::Network::Mainnet);
    statusLabel_->setText(QString("View-only account loaded.\nPrimary: %1\nCan produce key images: %2")
                              .arg(QString::fromStdString(xm::address_encode(primary)))
                              .arg(scanner_->can_produce_key_images() ? "yes" : "no (view-only, as expected)"));
}

void PageScan::onLoadFull()
{
    scanner_.reset();
    const std::string phrase = mnemonicEdit_->text().trimmed().toStdString();
    xm::KeyImportResult r = xm::keys_from_mnemonic(phrase);
    if (!r.ok) {
        statusLabel_->setText(QString("Full seed load FAILED: %1").arg(QString::fromStdString(r.error)));
        return;
    }
    scanner_ = std::make_unique<xm::MoneroScanner>(r.keys);
    scanner_->build_subaddress_table(1, 5);
    const xm::MoneroAddress primary = xm::primary_address(r.keys, xm::Network::Mainnet);
    statusLabel_->setText(QString("Full wallet loaded.\nPrimary: %1\nCan produce key images: %2")
                              .arg(QString::fromStdString(xm::address_encode(primary)))
                              .arg(scanner_->can_produce_key_images() ? "yes (full wallet)" : "no"));
}

void PageScan::onScan()
{
    out_->clear();
    if (!scanner_) { out_->appendPlainText(QStringLiteral("Load an account first.")); return; }

    xm::Bytes32 R{};
    if (!xm::hex_to_bytes32(txPubkeyEdit_->text().trimmed().toStdString(), R)) {
        out_->appendPlainText(QStringLiteral("Tx pubkey R must be 32-byte hex.")); return;
    }

    xm::TxToScan tx;
    tx.tx_pubkeys = {R};

    const QStringList lines = outputsEdit_->toPlainText().split('\n', Qt::SkipEmptyParts);
    for (const QString& raw : lines) {
        const QStringList f = raw.trimmed().split(',');
        if (f.isEmpty()) continue;
        xm::EnoteToScan e;
        if (!xm::hex_to_bytes32(f[0].trimmed().toStdString(), e.one_time_pub)) {
            out_->appendPlainText(QString("Bad one-time pubkey hex: %1").arg(f[0].trimmed())); return;
        }
        if (f.size() >= 2 && !f[1].trimmed().isEmpty()) {
            bool ok = false; uint tag = f[1].trimmed().toUInt(&ok);
            if (ok) { e.has_view_tag = true; e.view_tag = uint8_t(tag & 0xff); }
        }
        if (f.size() >= 3 && !f[2].trimmed().isEmpty()) {
            bool ok = false; qulonglong amt = f[2].trimmed().toULongLong(&ok);
            if (ok) { e.is_rct = false; e.clear_amount = amt; }
        }
        tx.outputs.push_back(e);
    }
    if (tx.outputs.empty()) { out_->appendPlainText(QStringLiteral("Enter at least one output line.")); return; }

    xm::ScanResult res = scanner_->scan_transaction(tx);
    out_->appendPlainText(QString("scanned: %1   view-tag rejected: %2   owned: %3")
                              .arg(res.scanned).arg(res.view_tag_rejected).arg(res.owned.size()));
    for (const auto& o : res.owned) {
        out_->appendPlainText(QString("  output #%1  amount=%2  subaddr=(%3,%4)  key_image=%5")
                                  .arg(o.output_index)
                                  .arg(o.amount)
                                  .arg(o.subaddr.major).arg(o.subaddr.minor)
                                  .arg(o.has_key_image ? QString::fromStdString(xm::bytes32_to_hex(o.key_image))
                                                       : QStringLiteral("(view-only: uncomputable)")));
    }
    out_->appendPlainText(QString("\nexportable outputs (online->offline artifact): %1")
                              .arg(scanner_->export_outputs().size()));
}
