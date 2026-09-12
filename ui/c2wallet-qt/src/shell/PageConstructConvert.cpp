// SPDX-License-Identifier: AGPL-3.0-or-later
#include "shell/PageConstructConvert.hpp"

#include <QComboBox>
#include <QFont>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QString>
#include <QStringList>
#include <QVBoxLayout>

#include <cstdint>
#include <string>
#include <vector>

#include "family/bitcoin/construct/AddressConstruct.hpp"
#include "family/bitcoin/construct/Convert.hpp"
#include "family/bitcoin/construct/ConvertCoins.hpp"
#include "family/bitcoin/hdkeys/CoinParams.hpp"

namespace cv = c2w::convert;
namespace ct = c2w::construct;
namespace hk = c2w::hdkeys;

namespace {

QString to_hex(const std::vector<uint8_t>& v)
{
    static const char* d = "0123456789abcdef";
    QString s;
    s.reserve(int(v.size()) * 2);
    for (uint8_t b : v) { s.append(QChar(d[b >> 4])); s.append(QChar(d[b & 0xf])); }
    return s;
}

bool from_hex(const QString& in, std::vector<uint8_t>& out)
{
    QString s = in.trimmed();
    if (s.size() % 2 != 0 || s.isEmpty()) return false;
    out.clear();
    out.reserve(s.size() / 2);
    for (int i = 0; i < s.size(); i += 2) {
        bool ok = false;
        int byte = s.mid(i, 2).toInt(&ok, 16);
        if (!ok) return false;
        out.push_back(uint8_t(byte));
    }
    return true;
}

}  // namespace

PageConstructConvert::PageConstructConvert(QWidget* parent) : QWidget(parent)
{
    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 24, 24, 24);
    v->setSpacing(12);

    auto* heading = new QLabel(QStringLiteral("Construct + Convert"), this);
    QFont hf = heading->font();
    hf.setPointSize(hf.pointSize() + 6);
    hf.setBold(true);
    heading->setFont(hf);
    v->addWidget(heading);

    // ── Convert panel ──────────────────────────────────────────────────────
    auto* convBox = new QGroupBox(QStringLiteral("Cross-coin address conversion (Family A, #961-guarded)"), this);
    auto* cbv = new QVBoxLayout(convBox);
    auto* cform = new QFormLayout();

    srcCombo_ = new QComboBox(convBox);
    dstCombo_ = new QComboBox(convBox);
    for (const auto& c : cv::convert_coins()) {
        srcCombo_->addItem(QString::fromStdString(c.ticker), QString::fromStdString(c.ticker));
        dstCombo_->addItem(QString::fromStdString(c.ticker), QString::fromStdString(c.ticker));
    }
    cform->addRow(QStringLiteral("Source coin:"), srcCombo_);
    cform->addRow(QStringLiteral("Target coin:"), dstCombo_);

    convAddrEdit_ = new QLineEdit(convBox);
    convAddrEdit_->setPlaceholderText(QStringLiteral("source-coin address to convert"));
    cform->addRow(QStringLiteral("Address:"), convAddrEdit_);
    cbv->addLayout(cform);

    convertBtn_ = new QPushButton(QStringLiteral("Convert"), convBox);
    cbv->addWidget(convertBtn_);

    convOut_ = new QPlainTextEdit(convBox);
    convOut_->setReadOnly(true);
    convOut_->setFont(QFont(QStringLiteral("monospace")));
    convOut_->setMaximumHeight(160);
    cbv->addWidget(convOut_);
    v->addWidget(convBox);

    // ── Construct panel ────────────────────────────────────────────────────
    auto* consBox = new QGroupBox(QStringLiteral("Construct a wrapped multisig receive address"), this);
    auto* xbv = new QVBoxLayout(consBox);
    auto* xform = new QFormLayout();

    mSpin_ = new QSpinBox(consBox);
    mSpin_->setRange(1, 16);
    mSpin_->setValue(2);
    xform->addRow(QStringLiteral("m (required signatures):"), mSpin_);

    pubkeysEdit_ = new QPlainTextEdit(consBox);
    pubkeysEdit_->setPlaceholderText(QStringLiteral("one compressed (33-byte) or uncompressed (65-byte) pubkey hex per line"));
    pubkeysEdit_->setMaximumHeight(90);
    xform->addRow(QStringLiteral("Pubkeys (n):"), pubkeysEdit_);

    coinCombo_ = new QComboBox(consBox);
    for (const auto& c : hk::all_coins())
        coinCombo_->addItem(QString::fromLatin1(c.ticker), QString::fromLatin1(c.ticker));
    xform->addRow(QStringLiteral("Coin:"), coinCombo_);
    xbv->addLayout(xform);

    buildBtn_ = new QPushButton(QStringLiteral("Build P2SH / P2WSH / nested addresses"), consBox);
    xbv->addWidget(buildBtn_);

    consOut_ = new QPlainTextEdit(consBox);
    consOut_->setReadOnly(true);
    consOut_->setFont(QFont(QStringLiteral("monospace")));
    consOut_->setMaximumHeight(180);
    xbv->addWidget(consOut_);
    v->addWidget(consBox);

    connect(convertBtn_, &QPushButton::clicked, this, &PageConstructConvert::onConvert);
    connect(buildBtn_,   &QPushButton::clicked, this, &PageConstructConvert::onConstruct);
}

void PageConstructConvert::onConvert()
{
    convOut_->clear();
    const std::string addr = convAddrEdit_->text().trimmed().toStdString();
    const std::string src  = srcCombo_->currentData().toString().toStdString();
    const std::string dst  = dstCombo_->currentData().toString().toStdString();
    if (addr.empty()) { convOut_->appendPlainText(QStringLiteral("Enter a source address.")); return; }

    cv::ConvertResult r = cv::convert_address(addr, src, dst);

    convOut_->appendPlainText(QString("status: %1").arg(QString::fromLatin1(cv::status_str(r.status))));
    convOut_->appendPlainText(QString("type  : %1").arg(QString::fromLatin1(cv::addr_type_str(r.type))));

    if (r.ok()) {
        convOut_->appendPlainText(QString("source: %1").arg(QString::fromStdString(r.source_address)));
        convOut_->appendPlainText(QString("target: %1").arg(QString::fromStdString(r.target_address)));
        convOut_->appendPlainText(QString("source payload: %1").arg(QString::fromStdString(r.source_payload_hex)));
        convOut_->appendPlainText(QString("target payload: %1").arg(QString::fromStdString(r.target_payload_hex)));
        const bool match = (r.source_payload_hex == r.target_payload_hex) && !r.source_payload_hex.empty();
        convOut_->appendPlainText(match ? QStringLiteral(">>> PAYLOAD MATCH — round-trip proven, conversion is a pure re-encoding")
                                        : QStringLiteral(">>> PAYLOAD MISMATCH — refused (this should not occur on ok)"));
    } else {
        convOut_->appendPlainText(QString("REFUSED: %1").arg(QString::fromStdString(r.reason)));
    }
}

void PageConstructConvert::onConstruct()
{
    consOut_->clear();

    std::vector<std::vector<uint8_t>> pubkeys;
    const QStringList lines = pubkeysEdit_->toPlainText().split('\n', Qt::SkipEmptyParts);
    for (const QString& ln : lines) {
        std::vector<uint8_t> pk;
        if (!from_hex(ln, pk)) {
            consOut_->appendPlainText(QString("Bad pubkey hex: %1").arg(ln.trimmed()));
            return;
        }
        pubkeys.push_back(std::move(pk));
    }
    if (pubkeys.empty()) { consOut_->appendPlainText(QStringLiteral("Enter at least one pubkey.")); return; }

    const int m = mSpin_->value();
    std::vector<uint8_t> redeem = ct::build_bare_multisig_script(m, pubkeys);
    if (redeem.empty()) {
        consOut_->appendPlainText(QStringLiteral("Refused: need 1 <= m <= n <= 16 and 33/65-byte pubkeys."));
        return;
    }
    consOut_->appendPlainText(QString("redeemScript (%1-of-%2): %3")
                                  .arg(m).arg(int(pubkeys.size())).arg(to_hex(redeem)));

    const std::string ticker = coinCombo_->currentData().toString().toStdString();
    const hk::CoinParams* coin = hk::coin_by_ticker(ticker);
    if (!coin) { consOut_->appendPlainText(QStringLiteral("Unknown coin.")); return; }

    ct::BuiltAddress p2sh = ct::build_p2sh(coin->p2sh_version, redeem);
    if (p2sh.ok())
        consOut_->appendPlainText(QString("\nP2SH        : %1").arg(QString::fromStdString(p2sh.address)));

    const std::string hrp = coin->bech32_hrp ? coin->bech32_hrp : "";
    if (!hrp.empty()) {
        ct::BuiltAddress p2wsh = ct::build_p2wsh(hrp, redeem);
        if (p2wsh.ok())
            consOut_->appendPlainText(QString("P2WSH       : %1").arg(QString::fromStdString(p2wsh.address)));
        ct::BuiltAddress nested = ct::build_p2sh_p2wsh(coin->p2sh_version, redeem);
        if (nested.ok())
            consOut_->appendPlainText(QString("P2SH-P2WSH  : %1").arg(QString::fromStdString(nested.address)));
    } else {
        consOut_->appendPlainText(QString("(P2WSH / nested skipped — %1 has no segwit HRP)")
                                      .arg(QString::fromLatin1(coin->ticker)));
    }
}
