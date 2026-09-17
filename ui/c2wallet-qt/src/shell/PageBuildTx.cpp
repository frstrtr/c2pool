// SPDX-License-Identifier: AGPL-3.0-or-later
#include "shell/PageBuildTx.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QFile>
#include <QFileDialog>
#include <QFont>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QString>
#include <QStringList>
#include <QVBoxLayout>

#include <cstdint>
#include <string>
#include <vector>

// The artifact library's SignedContainer::emit() collides with Qt's `emit`
// keyword-macro. This page emits no Qt signals, so drop the macro before the
// library headers (all Qt headers are already included above).
#undef emit

// std-only / btclibs-side headers ONLY (G3 boundary — no dashscript here).
#include "family/bitcoin/signer/SignSession.hpp"        // classify_spk, SpkType (std-only facade)
#include "family/bitcoin/artifact/TransferContainer.hpp"
#include "family/bitcoin/artifact/Digest.hpp"
#include "family/bitcoin/construct/Convert.hpp"
#include "family/bitcoin/construct/ConvertCoins.hpp"
#include "family/common/Amount.hpp"

namespace cv = c2w::convert;
namespace art = c2w::artifact;
namespace amt = c2w::amount;

namespace {

constexpr int kDecimals = 8;                 // Family-A: 8 decimals
constexpr int64_t kDustSats = 546;           // conservative dust floor (non-segwit)

using Bytes = std::vector<uint8_t>;

bool is_hex_str(const QString& s) {
    if (s.isEmpty() || s.size() % 2 != 0) return false;
    for (QChar c : s) {
        char ch = c.toLatin1();
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) return false;
    }
    return true;
}
bool from_hex(const QString& in, Bytes& out) {
    if (!is_hex_str(in)) return false;
    auto v = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return c - 'A' + 10;
    };
    out.clear();
    for (int i = 0; i < in.size(); i += 2) out.push_back(uint8_t((v(in.at(i).toLatin1()) << 4) | v(in.at(i + 1).toLatin1())));
    return true;
}
QString to_hex(const Bytes& v) {
    static const char* d = "0123456789abcdef";
    QString s; s.reserve(int(v.size()) * 2);
    for (uint8_t b : v) { s.append(QChar(d[b >> 4])); s.append(QChar(d[b & 0xf])); }
    return s;
}

void put_u32(Bytes& b, uint32_t v) { for (int i = 0; i < 4; ++i) b.push_back(uint8_t(v >> (8 * i))); }
void put_u64(Bytes& b, uint64_t v) { for (int i = 0; i < 8; ++i) b.push_back(uint8_t(v >> (8 * i))); }
void put_compact(Bytes& b, uint64_t n) {
    if (n < 0xfd) b.push_back(uint8_t(n));
    else if (n <= 0xffff) { b.push_back(0xfd); b.push_back(uint8_t(n)); b.push_back(uint8_t(n >> 8)); }
    else if (n <= 0xffffffffULL) { b.push_back(0xfe); put_u32(b, uint32_t(n)); }
    else { b.push_back(0xff); put_u64(b, n); }
}

// Amount rendered in BOTH units always (T-1).
QString both_units(int64_t sats, const QString& ticker) {
    return QString("%1 %2 (%3 sat)")
        .arg(QString::fromStdString(amt::format_amount(sats, kDecimals)), ticker, QString::number(qlonglong(sats)));
}

struct BuiltInput {
    Bytes txid_internal;   // 32 bytes, tx-serialization order
    uint32_t vout = 0;
    int64_t amount = 0;
    Bytes spk;
    std::string hint;
};
struct BuiltOutput {
    int64_t value = 0;
    Bytes spk;
    QString label;         // "OWN change (m/.../1/i)" or "EXTERNAL" or "OP_RETURN"
    bool is_change = false;
    bool is_opreturn = false;
};

} // namespace

PageBuildTx::PageBuildTx(QWidget* parent) : QWidget(parent)
{
    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 24, 24, 24);
    v->setSpacing(12);

    auto* heading = new QLabel(QStringLiteral("Build Transaction (Family A — key-free constructor)"), this);
    QFont hf = heading->font(); hf.setPointSize(hf.pointSize() + 6); hf.setBold(true);
    heading->setFont(hf);
    v->addWidget(heading);

    auto* note = new QLabel(
        QStringLiteral("Assembles an UNSIGNED transaction + PSBT-like artifact for the offline signer. "
                       "No keys are used here. Amounts are whole units (8 decimals)."), this);
    note->setWordWrap(true);
    v->addWidget(note);

    auto* form = new QFormLayout();
    coinCombo_ = new QComboBox(this);
    for (const auto& c : cv::convert_coins())
        coinCombo_->addItem(QString::fromStdString(c.ticker), QString::fromStdString(c.ticker));
    form->addRow(QStringLiteral("Coin:"), coinCombo_);
    v->addLayout(form);

    auto* inBox = new QGroupBox(QStringLiteral("Inputs — one per line:  txid:vout:amount:scriptPubKeyHexOrAddress[:hint]"), this);
    auto* inv = new QVBoxLayout(inBox);
    inputsEdit_ = new QPlainTextEdit(inBox);
    inputsEdit_->setPlaceholderText(QStringLiteral(
        "e.g.  9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff:0:6.25:76a914..88ac:m/44'/0'/0'/0/3"));
    inputsEdit_->setFont(QFont(QStringLiteral("monospace")));
    inputsEdit_->setMaximumHeight(120);
    inv->addWidget(inputsEdit_);
    v->addWidget(inBox);

    auto* outBox = new QGroupBox(QStringLiteral("Outputs — one per line:  address:amount[:change[:path]]   or   op_return:datahex"), this);
    auto* outv = new QVBoxLayout(outBox);
    outputsEdit_ = new QPlainTextEdit(outBox);
    outputsEdit_->setPlaceholderText(QStringLiteral(
        "e.g.  1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2:1.0\n"
        "      bc1q...:5.2499:change:m/84'/0'/0'/1/7"));
    outputsEdit_->setFont(QFont(QStringLiteral("monospace")));
    outputsEdit_->setMaximumHeight(120);
    outv->addWidget(outputsEdit_);
    v->addWidget(outBox);

    confirmHighFee_ = new QCheckBox(QStringLiteral("I confirm an unusually high fee (> 0.1 unit) is intended"), this);
    v->addWidget(confirmHighFee_);

    summaryLabel_ = new QLabel(this);
    summaryLabel_->setWordWrap(true);
    summaryLabel_->setTextFormat(Qt::RichText);
    v->addWidget(summaryLabel_);

    auto* btnRow = new QVBoxLayout();
    assembleBtn_ = new QPushButton(QStringLiteral("Assemble unsigned transaction + artifact"), this);
    assembleBtn_->setEnabled(false);
    btnRow->addWidget(assembleBtn_);
    saveBtn_ = new QPushButton(QStringLiteral("Save artifact to file…"), this);
    saveBtn_->setEnabled(false);
    btnRow->addWidget(saveBtn_);
    v->addLayout(btnRow);

    artifactEdit_ = new QPlainTextEdit(this);
    artifactEdit_->setReadOnly(true);
    artifactEdit_->setFont(QFont(QStringLiteral("monospace")));
    artifactEdit_->setMaximumHeight(120);
    artifactEdit_->setPlaceholderText(QStringLiteral("the assembled artifact hex appears here (carry it to the offline signer)"));
    v->addWidget(artifactEdit_);

    output_ = new QPlainTextEdit(this);
    output_->setReadOnly(true);
    output_->setFont(QFont(QStringLiteral("monospace")));
    output_->setMaximumHeight(160);
    v->addWidget(output_);

    connect(inputsEdit_, &QPlainTextEdit::textChanged, this, &PageBuildTx::onRecalc);
    connect(outputsEdit_, &QPlainTextEdit::textChanged, this, &PageBuildTx::onRecalc);
    connect(confirmHighFee_, &QCheckBox::toggled, this, &PageBuildTx::onRecalc);
    connect(coinCombo_, &QComboBox::currentTextChanged, this, &PageBuildTx::onRecalc);
    connect(assembleBtn_, &QPushButton::clicked, this, &PageBuildTx::onAssemble);
    connect(saveBtn_, &QPushButton::clicked, this, &PageBuildTx::onSaveArtifact);

    onRecalc();
}

// Parse the two edit boxes into structured inputs/outputs. Fills `err` on any
// invalid line. Money-correct: amounts via the integer-only parser only.
static bool parse_form(const QString& coin, const QString& inText, const QString& outText,
                       std::vector<BuiltInput>& ins, std::vector<BuiltOutput>& outs, QString& err)
{
    const cv::ConvertCoin* cc = cv::convert_coin(coin.toStdString());
    if (!cc) { err = "unknown coin"; return false; }

    auto decode_to_spk = [&](const QString& dest, Bytes& spk, QString& e) -> bool {
        // address (must be Own for this coin, #961 trichotomy) -> scriptPubKey.
        cv::ConvertResult r = cv::convert_address(dest.trimmed().toStdString(), coin.toStdString(), coin.toStdString());
        if (!r.ok()) { e = QString("address rejected: %1").arg(QString::fromStdString(r.reason)); return false; }
        spk.assign(r.script.begin(), r.script.end());
        return true;
    };

    const QStringList inLines = inText.split('\n', Qt::SkipEmptyParts);
    for (const QString& raw : inLines) {
        const QString ln = raw.trimmed();
        if (ln.isEmpty()) continue;
        const QStringList f = ln.split(':');
        if (f.size() < 4) { err = QString("input needs txid:vout:amount:spkOrAddr — got '%1'").arg(ln); return false; }
        BuiltInput bi;
        Bytes txid;
        if (!from_hex(f[0].trimmed(), txid) || txid.size() != 32) { err = "input txid must be 32-byte hex"; return false; }
        // display order -> internal (tx-serialization) order.
        bi.txid_internal.assign(txid.rbegin(), txid.rend());
        bool okv = false; bi.vout = f[1].trimmed().toUInt(&okv);
        if (!okv) { err = "input vout not a number"; return false; }
        amt::ParsedAmount pa = amt::parse_amount(f[2].trimmed().toStdString(), kDecimals);
        if (!pa.ok) { err = QString("input amount: %1").arg(QString::fromStdString(pa.error)); return false; }
        bi.amount = pa.sats;
        const QString spkField = f[3].trimmed();
        Bytes spk;
        if (is_hex_str(spkField)) { from_hex(spkField, spk); }
        else { QString e; if (!decode_to_spk(spkField, spk, e)) { err = QString("input spk/%1").arg(e); return false; } }
        bi.spk = spk;
        if (f.size() >= 5) bi.hint = f.mid(4).join(':').trimmed().toStdString();
        ins.push_back(std::move(bi));
    }
    if (ins.empty()) { err = "no inputs"; return false; }

    const QStringList outLines = outText.split('\n', Qt::SkipEmptyParts);
    for (const QString& raw : outLines) {
        const QString ln = raw.trimmed();
        if (ln.isEmpty()) continue;
        const QStringList f = ln.split(':');
        BuiltOutput bo;
        if (f.size() >= 1 && f[0].trimmed().compare("op_return", Qt::CaseInsensitive) == 0) {
            if (f.size() < 2) { err = "op_return needs datahex"; return false; }
            Bytes data;
            if (!from_hex(f[1].trimmed(), data) || data.size() > 80) { err = "op_return data must be <=80-byte hex"; return false; }
            Bytes spk = {0x6a};
            if (data.size() < 76) spk.push_back(uint8_t(data.size()));
            else { spk.push_back(0x4c); spk.push_back(uint8_t(data.size())); }
            spk.insert(spk.end(), data.begin(), data.end());
            bo.spk = spk; bo.value = 0; bo.is_opreturn = true; bo.label = "OP_RETURN (unspendable data)";
            outs.push_back(std::move(bo));
            continue;
        }
        if (f.size() < 2) { err = QString("output needs address:amount — got '%1'").arg(ln); return false; }
        Bytes spk; QString e;
        if (!decode_to_spk(f[0].trimmed(), spk, e)) { err = QString("output %1").arg(e); return false; }
        bo.spk = spk;
        amt::ParsedAmount pa = amt::parse_amount(f[1].trimmed().toStdString(), kDecimals);
        if (!pa.ok) { err = QString("output amount: %1").arg(QString::fromStdString(pa.error)); return false; }
        bo.value = pa.sats;
        if (f.size() >= 3 && f[2].trimmed().compare("change", Qt::CaseInsensitive) == 0) {
            bo.is_change = true;
            QString path = f.size() >= 4 ? f.mid(3).join(':').trimmed() : QString("(path not given)");
            bo.label = QString("OWN change (%1)").arg(path);
        } else {
            bo.label = QStringLiteral("EXTERNAL");
        }
        outs.push_back(std::move(bo));
    }
    if (outs.empty()) { err = "no outputs"; return false; }
    return true;
}

void PageBuildTx::onRecalc()
{
    assembleBtn_->setEnabled(false);
    saveBtn_->setEnabled(false);
    lastArtifact_.clear();
    const QString coin = coinCombo_->currentData().toString();

    std::vector<BuiltInput> ins;
    std::vector<BuiltOutput> outs;
    QString err;
    if (!parse_form(coin, inputsEdit_->toPlainText(), outputsEdit_->toPlainText(), ins, outs, err)) {
        summaryLabel_->setText(QString("<b>Not ready:</b> %1").arg(err.toHtmlEscaped()));
        return;
    }

    int64_t sum_in = 0, sum_out = 0;
    for (const auto& i : ins) sum_in += i.amount;
    for (const auto& o : outs) sum_out += o.value;
    const int64_t fee = sum_in - sum_out;

    bool has_change = false, has_dust = false;
    for (const auto& o : outs) {
        if (o.is_change) has_change = true;
        if (!o.is_opreturn && o.value < kDustSats) has_dust = true;
    }
    const bool absurd = fee > c2w::sign::kAbsurdFeeSats;

    QString html;
    html += QString("Inputs: %1 &nbsp; sum_in = %2<br>").arg(int(ins.size())).arg(both_units(sum_in, coin));
    html += QString("Outputs: %1 &nbsp; sum_out = %2<br>").arg(int(outs.size())).arg(both_units(sum_out, coin));
    for (const auto& o : outs)
        html += QString("&nbsp;&nbsp;• %1 — %2<br>").arg(both_units(o.value, coin), o.label.toHtmlEscaped());
    html += QString("Fee = %1<br>").arg(both_units(fee, coin));

    QStringList blockers;
    if (fee < 0) blockers << "fee is NEGATIVE (outputs exceed inputs)";
    if (has_dust) blockers << QString("an output is below the dust floor (%1 sat)").arg(qlonglong(kDustSats));
    if (absurd && !confirmHighFee_->isChecked()) blockers << "fee is absurdly high — tick the confirm box if intended";
    if (!has_change)
        html += QStringLiteral("<br><span style='color:#b00020;font-weight:bold'>⚠ NO CHANGE RETURNS TO YOU — "
                               "every output is EXTERNAL. Verify this is intended.</span><br>");

    if (blockers.isEmpty()) {
        summaryLabel_->setText(html + QStringLiteral("<br><b style='color:#0a6'>Ready to assemble.</b>"));
        assembleBtn_->setEnabled(true);
    } else {
        summaryLabel_->setText(html + QString("<br><b style='color:#b00020'>Blocked:</b> %1")
                                           .arg(blockers.join(QStringLiteral("; ")).toHtmlEscaped()));
    }
}

void PageBuildTx::onAssemble()
{
    output_->clear();
    const QString coin = coinCombo_->currentData().toString();

    std::vector<BuiltInput> ins;
    std::vector<BuiltOutput> outs;
    QString err;
    if (!parse_form(coin, inputsEdit_->toPlainText(), outputsEdit_->toPlainText(), ins, outs, err)) {
        output_->appendPlainText(QString("Refused: %1").arg(err));
        return;
    }

    // ── serialize the UNSIGNED tx (std-only byte writer) ────────────────────
    Bytes tx;
    put_u32(tx, 2);                       // version
    put_compact(tx, ins.size());
    for (const auto& i : ins) {
        tx.insert(tx.end(), i.txid_internal.begin(), i.txid_internal.end());
        put_u32(tx, i.vout);
        put_compact(tx, 0);               // empty scriptSig (unsigned)
        put_u32(tx, 0xffffffffu);         // sequence
    }
    put_compact(tx, outs.size());
    for (const auto& o : outs) {
        put_u64(tx, uint64_t(o.value));
        put_compact(tx, o.spk.size());
        tx.insert(tx.end(), o.spk.begin(), o.spk.end());
    }
    put_u32(tx, 0);                       // locktime

    // ── pick the sighash-algebra hint from the input SPK types ──────────────
    art::SighashAlgebra alg = art::SighashAlgebra::Legacy;
    for (const auto& i : ins) {
        switch (c2w::sign::classify_spk(i.spk)) {
            case c2w::sign::SpkType::P2TR: alg = art::SighashAlgebra::Bip341; break;
            case c2w::sign::SpkType::P2WPKH:
            case c2w::sign::SpkType::P2WSH:
                if (alg != art::SighashAlgebra::Bip341) alg = art::SighashAlgebra::Bip143;
                break;
            default: break;
        }
    }

    art::UnsignedContainer c;
    c.coin = coin.toStdString();
    c.network_version = 0;
    c.algebra = alg;
    c.unsigned_tx = tx;
    for (const auto& i : ins) {
        art::UnsignedInput ui;
        // container carries prevout txid in internal (tx-serialization) order.
        std::copy(i.txid_internal.begin(), i.txid_internal.end(), ui.prevout_txid.begin());
        ui.prevout_index = i.vout;
        ui.script_pubkey = i.spk;
        ui.amount = i.amount;
        ui.derivation_hint = i.hint;
        c.inputs.push_back(std::move(ui));
    }

    std::string aerr;
    std::string hexart = c.to_hex(aerr);
    if (hexart.empty()) {
        output_->appendPlainText(QString("Refused: %1").arg(QString::fromStdString(aerr)));
        return;
    }

    lastArtifact_ = QString::fromStdString(hexart);
    artifactEdit_->setPlainText(lastArtifact_);
    saveBtn_->setEnabled(true);

    // sha256 of the artifact string (cross-gap comparison of the artifact itself).
    Bytes artbytes(hexart.begin(), hexart.end());
    art::Hash32 sh = art::sha256(artbytes);

    output_->appendPlainText(QStringLiteral("Assembled OK."));
    output_->appendPlainText(QString("unsigned txid : %1").arg(QString::fromStdString(c.unsigned_txid_display())));
    output_->appendPlainText(QString("artifact bytes: %1").arg(int(hexart.size())));
    output_->appendPlainText(QString("artifact sha256: %1").arg(QString::fromStdString(art::to_hex(sh))));
    output_->appendPlainText(QString("sighash algebra hint: %1")
                                 .arg(alg == art::SighashAlgebra::Bip341 ? "BIP341" :
                                      alg == art::SighashAlgebra::Bip143 ? "BIP143" : "Legacy"));
    output_->appendPlainText(QStringLiteral("\nCarry the artifact above to the offline signer (Sign & Self-Verify)."));
}

void PageBuildTx::onSaveArtifact()
{
    if (lastArtifact_.isEmpty()) return;
    const QString path = QFileDialog::getSaveFileName(this, QStringLiteral("Save unsigned artifact"),
                                                      QStringLiteral("unsigned.c2wtx"),
                                                      QStringLiteral("c2wallet tx (*.c2wtx);;All files (*)"));
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        output_->appendPlainText(QString("Could not write %1").arg(path));
        return;
    }
    f.write(lastArtifact_.toUtf8());
    f.write("\n");
    f.close();
    output_->appendPlainText(QString("Saved artifact to %1").arg(path));
}
