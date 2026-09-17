// SPDX-License-Identifier: AGPL-3.0-or-later
#include "shell/PageSign.hpp"
#include "shell/ScopedSecret.hpp"

#include <QCheckBox>
#include <QFile>
#include <QFileDialog>
#include <QFont>
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

// The artifact library's SignedContainer::emit() collides with Qt's `emit`
// keyword-macro. This page emits no Qt signals, so drop the macro before the
// library headers (all Qt headers are already included above).
#undef emit

// std-only / btclibs-side headers ONLY (G3 boundary — no dashscript here).
#include "family/bitcoin/signer/SignSession.hpp"          // GAP-1 facade
#include "family/bitcoin/artifact/TransferContainer.hpp"
#include "family/bitcoin/artifact/ValidateSeam.hpp"        // crossgap_txid
#include "family/bitcoin/hdkeys/Address.hpp"               // address_candidates, spk_to_address
#include "family/bitcoin/hdkeys/CoinParams.hpp"
#include "family/bitcoin/hdkeys/KeyImport.hpp"             // decode_wif / decode_raw_hex
#include "family/bitcoin/hdkeys/Secp.hpp"
#include "family/bitcoin/construct/AddressConstruct.hpp"   // build_p2sh / build_p2wsh
#include "family/common/Amount.hpp"

namespace art = c2w::artifact;
namespace hk = c2w::hdkeys;
namespace ct = c2w::construct;
namespace amt = c2w::amount;

namespace {

constexpr int kDecimals = 8;
using Bytes = std::vector<uint8_t>;

QString hexq(const Bytes& v) {
    static const char* d = "0123456789abcdef";
    QString s; s.reserve(int(v.size()) * 2);
    for (uint8_t b : v) { s.append(QChar(d[b >> 4])); s.append(QChar(d[b & 0xf])); }
    return s;
}
bool is_hex64(const QString& s) {
    if (s.size() != 64) return false;
    for (QChar c : s) { char ch = c.toLatin1();
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) return false; }
    return true;
}
bool from_hex(const QString& in, Bytes& out) {
    if (in.isEmpty() || in.size() % 2 != 0) return false;
    auto v = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    for (int i = 0; i < in.size(); i += 2) {
        int hi = v(in.at(i).toLatin1()), lo = v(in.at(i + 1).toLatin1());
        if (hi < 0 || lo < 0) return false;
        out.push_back(uint8_t((hi << 4) | lo));
    }
    return true;
}
QString both_units(int64_t sats, const QString& ticker) {
    return QString("%1 %2 (%3 sat)")
        .arg(QString::fromStdString(amt::format_amount(sats, kDecimals)), ticker, QString::number(qlonglong(sats)));
}

const hk::CoinParams* coin_params(const QString& ticker) {
    if (auto* c = hk::coin_by_ticker(ticker.toStdString())) return c;
    return hk::coin_by_ticker(ticker.toUpper().toStdString());
}

} // namespace

PageSign::PageSign(QWidget* parent) : QWidget(parent)
{
    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 24, 24, 24);
    v->setSpacing(10);

    auto* heading = new QLabel(QStringLiteral("Sign & Self-Verify (Family A — offline, key-bearing)"), this);
    QFont hf = heading->font(); hf.setPointSize(hf.pointSize() + 6); hf.setBold(true);
    heading->setFont(hf);
    v->addWidget(heading);

    // ── 1. Load the unsigned artifact ───────────────────────────────────────
    artifactIn_ = new QPlainTextEdit(this);
    artifactIn_->setPlaceholderText(QStringLiteral("paste the unsigned artifact hex here, or load it from a file"));
    artifactIn_->setFont(QFont(QStringLiteral("monospace")));
    artifactIn_->setMaximumHeight(90);
    v->addWidget(artifactIn_);

    auto* row1 = new QVBoxLayout();
    loadFileBtn_ = new QPushButton(QStringLiteral("Load artifact from file…"), this);
    row1->addWidget(loadFileBtn_);
    parseBtn_ = new QPushButton(QStringLiteral("Parse + build confirm card"), this);
    row1->addWidget(parseBtn_);
    v->addLayout(row1);

    cardLabel_ = new QLabel(this);
    cardLabel_->setTextFormat(Qt::RichText);
    cardLabel_->setWordWrap(true);
    cardLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    cardLabel_->setStyleSheet(QStringLiteral("border:1px solid #bbb; border-radius:4px; padding:8px;"));
    v->addWidget(cardLabel_);

    // ── 2. Secret gate (fail-before-secret) ─────────────────────────────────
    reviewedCheck_ = new QCheckBox(QStringLiteral("I have reviewed every amount, address and the fee above."), this);
    v->addWidget(reviewedCheck_);

    auto* gateLbl = new QLabel(QStringLiteral("Type SPEND to arm signing:"), this);
    v->addWidget(gateLbl);
    spendGate_ = new QLineEdit(this);
    spendGate_->setPlaceholderText(QStringLiteral("SPEND"));
    v->addWidget(spendGate_);

    keysEdit_ = new QPlainTextEdit(this);
    keysEdit_->setPlaceholderText(QStringLiteral(
        "one private key per line: WIF or 64-hex.\n"
        "for a P2SH/P2WSH multisig input add the shared script:  <WIF-or-hex>#<redeemOrWitnessScriptHex>\n"
        "the widget is wiped the instant it is read."));
    keysEdit_->setFont(QFont(QStringLiteral("monospace")));
    keysEdit_->setMaximumHeight(90);
    v->addWidget(keysEdit_);

    signBtn_ = new QPushButton(QStringLiteral("Sign, self-verify, and emit signed artifact"), this);
    v->addWidget(signBtn_);

    // ── 3. Output ───────────────────────────────────────────────────────────
    output_ = new QPlainTextEdit(this);
    output_->setReadOnly(true);
    output_->setFont(QFont(QStringLiteral("monospace")));
    output_->setMaximumHeight(180);
    v->addWidget(output_);

    saveBtn_ = new QPushButton(QStringLiteral("Save signed artifact to file…"), this);
    saveBtn_->setEnabled(false);
    v->addWidget(saveBtn_);

    connect(loadFileBtn_, &QPushButton::clicked, this, &PageSign::onLoadFile);
    connect(parseBtn_, &QPushButton::clicked, this, &PageSign::onParse);
    connect(reviewedCheck_, &QCheckBox::toggled, this, &PageSign::onGateChanged);
    connect(spendGate_, &QLineEdit::textChanged, this, &PageSign::onGateChanged);
    connect(keysEdit_, &QPlainTextEdit::textChanged, this, &PageSign::onGateChanged);
    connect(signBtn_, &QPushButton::clicked, this, &PageSign::onSign);
    connect(saveBtn_, &QPushButton::clicked, this, &PageSign::onSaveSigned);

    resetSecretGate();
}

void PageSign::resetSecretGate()
{
    // Fail-before-secret: the key widgets are inert until parse + review.
    reviewedCheck_->setEnabled(parsedOk_);
    const bool armed = parsedOk_ && reviewedCheck_->isChecked();
    spendGate_->setEnabled(armed);
    keysEdit_->setEnabled(armed);
    const bool ok_to_sign = armed && spendGate_->text() == QStringLiteral("SPEND")
                            && !keysEdit_->toPlainText().trimmed().isEmpty();
    signBtn_->setEnabled(ok_to_sign);
}

void PageSign::onGateChanged() { resetSecretGate(); }

void PageSign::onLoadFile()
{
    const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("Load unsigned artifact"),
                                                      QString(), QStringLiteral("c2wallet tx (*.c2wtx);;All files (*)"));
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        cardLabel_->setText(QString("<b>Could not read</b> %1").arg(path.toHtmlEscaped()));
        return;
    }
    artifactIn_->setPlainText(QString::fromUtf8(f.readAll()).trimmed());
    f.close();
}

void PageSign::onParse()
{
    parsedOk_ = false;
    containerHex_.clear();
    coin_.clear();
    resetSecretGate();

    const QString hex = artifactIn_->toPlainText().trimmed();
    if (hex.isEmpty()) { cardLabel_->setText(QStringLiteral("Paste or load an artifact first.")); return; }

    std::string err;
    auto oc = art::UnsignedContainer::from_hex(hex.toStdString(), err);
    if (!oc) { cardLabel_->setText(QString("<b style='color:#b00020'>Not a valid artifact:</b> %1").arg(QString::fromStdString(err).toHtmlEscaped())); return; }

    c2w::sign::TxView view = c2w::sign::parse_unsigned(*oc);
    if (!view.ok) { cardLabel_->setText(QString("<b style='color:#b00020'>Artifact failed cross-check:</b> %1").arg(QString::fromStdString(view.error).toHtmlEscaped())); return; }

    coin_ = QString::fromStdString(oc->coin);
    const hk::CoinParams* cp = coin_params(coin_);

    QString html;
    html += QString("<b>Coin:</b> %1 &nbsp; <b>version:</b> %2 &nbsp; <b>locktime:</b> %3<br>")
                .arg(coin_.toHtmlEscaped()).arg(view.version).arg(view.locktime);
    html += QString("<br><b>INPUTS (%1) — TOTAL DEBIT %2</b><br>")
                .arg(int(view.inputs.size())).arg(both_units(view.sum_in, coin_));
    for (size_t i = 0; i < view.inputs.size(); ++i) {
        const auto& in = view.inputs[i];
        QString addr;
        if (cp) { hk::SpkAddress a = hk::spk_to_address(in.script_pubkey, *cp); addr = QString::fromStdString(a.address.empty() ? a.type : a.address); }
        html += QString("&nbsp;#%1 [%2] %3<br>&nbsp;&nbsp;&nbsp;from %4:%5  hint=%6<br>")
                    .arg(int(i))
                    .arg(QString::fromUtf8(c2w::sign::spk_type_str(in.type)))
                    .arg(both_units(in.amount, coin_))
                    .arg(QString::fromStdString(in.prevout_txid_display).left(20) + "…")
                    .arg(in.prevout_index)
                    .arg(addr.isEmpty() ? QStringLiteral("(n/a)") : addr.toHtmlEscaped());
    }
    html += QString("<br><b>OUTPUTS (%1) — total %2</b><br>")
                .arg(int(view.outputs.size())).arg(both_units(view.sum_out, coin_));
    for (const auto& o : view.outputs) {
        QString addr, type;
        if (cp) { hk::SpkAddress a = hk::spk_to_address(o.script_pubkey, *cp); addr = QString::fromStdString(a.address); type = QString::fromStdString(a.type); }
        html += QString("&nbsp;• %1 → %2 [%3] &nbsp;<i>EXTERNAL (unless a loaded key owns it)</i><br>")
                    .arg(both_units(o.value, coin_))
                    .arg(addr.isEmpty() ? QStringLiteral("(no address form)") : addr.toHtmlEscaped(), type.toHtmlEscaped());
    }
    const double rate = view.serialized_size ? double(view.fee) / double(view.serialized_size) : 0.0;
    html += QString("<br><b>FEE:</b> %1 &nbsp; (~%2 sat/byte over %3 unsigned bytes)<br>")
                .arg(both_units(view.fee, coin_)).arg(rate, 0, 'f', 2).arg(int(view.serialized_size));
    if (view.fee < 0)
        html += QStringLiteral("<span style='color:#b00020;font-weight:bold'>⚠ NEGATIVE FEE — unbalanced. Signing will refuse.</span><br>");
    else if (view.fee > c2w::sign::kAbsurdFeeSats)
        html += QStringLiteral("<span style='color:#b00020;font-weight:bold'>⚠ FEE IS ABSURDLY HIGH — verify before you type SPEND.</span><br>");

    cardLabel_->setText(html);
    parsedOk_ = true;
    containerHex_ = hex;
    resetSecretGate();
}

namespace {

// A decoded key line, kept in a zeroizing scalar until routed.
struct KeyLine {
    c2w::secure::SecureBytes sk;
    Bytes comp, uncomp;
    Bytes script;   // optional redeem/witnessScript
    bool ok = false;
    std::string error;
};

KeyLine decode_key_line(const QString& line)
{
    KeyLine kl;
    QString keypart = line;
    QString scriptpart;
    const int hashpos = line.indexOf('#');
    if (hashpos >= 0) { keypart = line.left(hashpos).trimmed(); scriptpart = line.mid(hashpos + 1).trimmed(); }
    keypart = keypart.trimmed();

    if (is_hex64(keypart)) {
        hk::RawHexDecode d = hk::decode_raw_hex(keypart.toStdString(), true);
        if (!d.ok) { kl.error = d.error; return kl; }
        kl.sk = std::move(d.scalar);
    } else {
        hk::WifDecode d = hk::decode_wif(keypart.toStdString());
        if (!d.ok) { kl.error = d.error; return kl; }
        kl.sk = std::move(d.scalar);
    }
    kl.comp = hk::Secp::instance().pubkey_create(kl.sk.data(), true);
    kl.uncomp = hk::Secp::instance().pubkey_create(kl.sk.data(), false);
    if (kl.comp.size() != 33) { kl.error = "pubkey derivation failed"; return kl; }
    if (!scriptpart.isEmpty()) {
        if (!from_hex(scriptpart, kl.script)) { kl.error = "bad script hex after '#'"; return kl; }
    }
    kl.ok = true;
    return kl;
}

} // namespace

void PageSign::onSign()
{
    output_->clear();
    saveBtn_->setEnabled(false);
    lastSigned_.clear();

    if (!parsedOk_ || spendGate_->text() != QStringLiteral("SPEND")) {
        output_->appendPlainText(QStringLiteral("Not armed."));
        return;
    }

    // Read the secret ONCE and wipe the widget immediately (T-8).
    ScopedSecret keytext(keysEdit_->toPlainText().toStdString());
    keysEdit_->clear();
    spendGate_->clear();

    // Re-decode the container so we sign exactly what the card showed.
    std::string derr;
    auto oc = art::UnsignedContainer::from_hex(containerHex_.toStdString(), derr);
    if (!oc) { output_->appendPlainText(QString("Artifact re-decode failed: %1").arg(QString::fromStdString(derr))); return; }
    c2w::sign::TxView view = c2w::sign::parse_unsigned(*oc);
    if (!view.ok) { output_->appendPlainText(QString("Artifact cross-check failed: %1").arg(QString::fromStdString(view.error))); return; }

    const hk::CoinParams* cp = coin_params(coin_);
    if (!cp) { output_->appendPlainText(QStringLiteral("Unknown coin — cannot derive binding candidates.")); return; }

    // Decode every key line (scalars stay in zeroizing SecureBytes here).
    QStringList lines = QString::fromStdString(keytext.str()).split('\n', Qt::SkipEmptyParts);
    std::vector<KeyLine> keylines;
    for (const QString& raw : lines) {
        const QString ln = raw.trimmed();
        if (ln.isEmpty()) continue;
        KeyLine kl = decode_key_line(ln);
        if (!kl.ok) { output_->appendPlainText(QString("Refused: key line invalid: %1").arg(QString::fromStdString(kl.error))); return; }
        keylines.push_back(std::move(kl));
    }
    if (keylines.empty()) { output_->appendPlainText(QStringLiteral("Refused: no keys provided.")); return; }

    // ── key↔input binding (T-6): route keys to inputs BEFORE any sighash ────
    std::vector<c2w::sign::KeyForInput> keys;
    QStringList bindingLog;
    std::vector<bool> input_keyed(view.inputs.size(), false);
    std::vector<QString> own_outputs;

    for (KeyLine& kl : keylines) {
        // single-key candidate scriptPubKeys for this key on this coin.
        std::vector<hk::AddressCandidate> cands = hk::address_candidates(kl.comp, *cp);

        // OWN-output detection (T-3): does any output pay back to this key?
        for (const auto& o : view.outputs)
            for (const auto& c : cands)
                if (!c.script_hex.empty() && QString::fromStdString(c.script_hex) == QString::fromStdString(o.spk_hex))
                    own_outputs.push_back(QString::fromStdString(c.label));

        for (size_t i = 0; i < view.inputs.size(); ++i) {
            const auto& in = view.inputs[i];
            const QString spkhex = QString::fromStdString(in.spk_hex);

            if (kl.script.empty()) {
                // single-key types: match a candidate exactly.
                for (const auto& c : cands) {
                    if (c.script_hex.empty()) continue;
                    if (QString::fromStdString(c.script_hex) != spkhex) continue;
                    Bytes pub = (c.encoding == "uncompressed") ? kl.uncomp : kl.comp;
                    keys.push_back({i, kl.sk.copy(), pub, {}});
                    input_keyed[i] = true;
                    bindingLog << QString("input #%1 ← key (%2)").arg(int(i)).arg(QString::fromStdString(c.label));
                    break;
                }
            } else {
                // multisig / wrapped: match the P2SH / P2WSH scriptPubKey derived
                // from the supplied inner script.
                bool matched = false;
                if (in.type == c2w::sign::SpkType::P2SH) {
                    ct::BuiltAddress ba = ct::build_p2sh(cp->p2sh_version, kl.script);
                    if (ba.ok() && hexq(Bytes(ba.script.begin(), ba.script.end())) == spkhex) matched = true;
                } else if (in.type == c2w::sign::SpkType::P2WSH) {
                    const std::string hrp = cp->bech32_hrp ? cp->bech32_hrp : "";
                    if (!hrp.empty()) {
                        ct::BuiltAddress ba = ct::build_p2wsh(hrp, kl.script);
                        if (ba.ok() && hexq(Bytes(ba.script.begin(), ba.script.end())) == spkhex) matched = true;
                    }
                }
                if (matched) {
                    keys.push_back({i, kl.sk.copy(), kl.comp, kl.script});
                    input_keyed[i] = true;
                    bindingLog << QString("input #%1 ← multisig cosigner").arg(int(i));
                }
            }
        }
    }

    if (keys.empty()) {
        output_->appendPlainText(QStringLiteral("Refused: no provided key funds any input (binding failed, T-6)."));
        return;
    }
    for (size_t i = 0; i < input_keyed.size(); ++i)
        if (!input_keyed[i])
            bindingLog << QString("input #%1 ← (no key — signing will refuse)").arg(int(i));

    output_->appendPlainText(QStringLiteral("Binding:"));
    for (const QString& l : bindingLog) output_->appendPlainText("  " + l);
    if (own_outputs.empty())
        output_->appendPlainText(QStringLiteral("  NOTE: no output returns to a loaded key (all EXTERNAL / no change)."));
    else
        for (const QString& o : own_outputs) output_->appendPlainText("  OWN change output: " + o);

    // ── sign + mandatory finalize self-verify (T-5) ─────────────────────────
    c2w::sign::SignOptions opt;
    opt.sighash = 0x01;                       // SIGHASH_ALL
    opt.absurd_fee_confirmed = true;          // the SPEND-after-card is the T-4 second confirm
    c2w::sign::SignOutcome o = c2w::sign::sign_and_verify(*oc, std::move(keys), opt);
    if (!o.ok) {
        output_->appendPlainText(QString("\nREFUSED: %1").arg(QString::fromStdString(o.error)));
        return;
    }

    // ── re-assert the txid against the cross-gap digest ─────────────────────
    const std::string cg = art::crossgap_txid(o.signed_tx);
    const bool xok = (cg == o.wtxid_display);

    art::SignedContainer sc; sc.tx_hexes.push_back(o.signed_tx);
    lastSigned_ = QString::fromStdString(sc.emit());

    output_->appendPlainText(QStringLiteral("\nSIGNED + SELF-VERIFIED."));
    output_->appendPlainText(QString("txid : %1").arg(QString::fromStdString(o.txid_display)));
    output_->appendPlainText(QString("wtxid: %1  (cross-gap re-assert: %2)")
                                 .arg(QString::fromStdString(o.wtxid_display), xok ? "OK" : "MISMATCH"));
    for (const auto& w : o.warnings) output_->appendPlainText(QString("warning: %1").arg(QString::fromStdString(w)));
    output_->appendPlainText(QStringLiteral("\nsigned artifact (one raw tx hex per line — the c2pool loader format):"));
    output_->appendPlainText(lastSigned_);
    saveBtn_->setEnabled(true);

    // Secrets: keytext wiped on scope exit; every SecureBytes copy wiped when
    // the facade consumed & destroyed the moved-in key vector.
}

void PageSign::onSaveSigned()
{
    if (lastSigned_.isEmpty()) return;
    const QString path = QFileDialog::getSaveFileName(this, QStringLiteral("Save signed artifact"),
                                                      QStringLiteral("signed.c2wtx"),
                                                      QStringLiteral("c2wallet tx (*.c2wtx);;All files (*)"));
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        output_->appendPlainText(QString("Could not write %1").arg(path));
        return;
    }
    f.write(lastSigned_.toUtf8());
    f.close();
    output_->appendPlainText(QString("Saved signed artifact to %1").arg(path));
}
