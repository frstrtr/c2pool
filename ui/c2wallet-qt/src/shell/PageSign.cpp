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
namespace sg = c2w::sign;

// Opaque holder (declared in the header) for the decoded private keys.
struct PageSign::Bound {
    std::vector<sg::KeyForInput> keys;
};

namespace {

constexpr int kDecimals = 8;
using Bytes = std::vector<uint8_t>;

QString hexq(const Bytes& v) {
    static const char* d = "0123456789abcdef";
    QString s; s.reserve(int(v.size()) * 2);
    for (uint8_t b : v) { s.append(QChar(d[b >> 4])); s.append(QChar(d[b & 0xf])); }
    return s;
}
bool is_hex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
    return true;
}
bool from_hex_str(const std::string& in, Bytes& out) {
    if (in.empty() || in.size() % 2 != 0) return false;
    auto v = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    for (size_t i = 0; i < in.size(); i += 2) {
        int hi = v(in[i]), lo = v(in[i + 1]);
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

// std-only trim + wipe helper: securely erase a std::string's storage.
void wipe(std::string& s) { if (!s.empty()) c2w::secure::secure_wipe(&s[0], s.size()); s.clear(); }

int derived_algebra(const c2w::sign::TxView& v) {
    int a = 0; // Legacy
    for (const auto& in : v.inputs) {
        if (in.type == sg::SpkType::P2TR) return 2;             // Bip341
        if (in.type == sg::SpkType::P2WPKH || in.type == sg::SpkType::P2WSH) a = 1; // Bip143
    }
    return a;
}
const char* algebra_name(int a) { return a == 2 ? "BIP341" : a == 1 ? "BIP143" : "Legacy"; }

// Build the confirm card. ownFlags empty => stage-1 (pre-bind) render; otherwise
// one entry per output (true = owned by a loaded key). `bound` gates the LOUD
// no-change warning (only meaningful once binding ran).
QString render_card(const c2w::sign::TxView& v, const QString& coin, const hk::CoinParams* cp,
                    const std::vector<char>& ownFlags, bool bound, int container_algebra)
{
    QString html;
    html += QString("<b>Coin:</b> %1 &nbsp; <b>version:</b> %2 &nbsp; <b>locktime:</b> %3<br>")
                .arg(coin.toHtmlEscaped()).arg(v.version).arg(v.locktime);

    // legacy-amount trust banner (item 4): legacy sighash does not commit to the
    // input amount, so a lying online host can inflate the displayed fee.
    bool any_legacy = false;
    for (const auto& in : v.inputs)
        if (in.type == sg::SpkType::P2PK || in.type == sg::SpkType::P2PKH || in.type == sg::SpkType::P2SH)
            any_legacy = true;
    if (any_legacy)
        html += QStringLiteral("<div style='color:#b00020;font-weight:bold'>⚠ input amounts UNVERIFIED "
                               "(legacy sighash) — the fee display cannot be trusted.</div>");

    // algebra sanity (nit): SPK is the selector; warn if the container disagrees.
    const int da = derived_algebra(v);
    if (da != container_algebra)
        html += QString("<div style='color:#8a5a00'>note: container algebra hint (%1) disagrees with the "
                        "SPK-derived algebra (%2); the SPK is authoritative.</div>")
                    .arg(algebra_name(container_algebra), algebra_name(da));

    html += QString("<br><b>INPUTS (%1) — TOTAL DEBIT %2</b><br>")
                .arg(int(v.inputs.size())).arg(both_units(v.sum_in, coin));
    for (size_t i = 0; i < v.inputs.size(); ++i) {
        const auto& in = v.inputs[i];
        QString addr;
        if (cp) { hk::SpkAddress a = hk::spk_to_address(in.script_pubkey, *cp); addr = QString::fromStdString(a.address.empty() ? a.type : a.address); }
        html += QString("&nbsp;#%1 [%2] %3<br>&nbsp;&nbsp;&nbsp;from %4:%5  hint=%6<br>")
                    .arg(int(i))
                    .arg(QString::fromUtf8(sg::spk_type_str(in.type)))
                    .arg(both_units(in.amount, coin))
                    .arg(QString::fromStdString(in.prevout_txid_display).left(20) + "…")
                    .arg(in.prevout_index)
                    .arg(in.derivation_hint.empty() ? QStringLiteral("-") : QString::fromStdString(in.derivation_hint).toHtmlEscaped());
    }

    html += QString("<br><b>OUTPUTS (%1) — total %2</b><br>")
                .arg(int(v.outputs.size())).arg(both_units(v.sum_out, coin));
    int owned_count = 0;
    for (size_t i = 0; i < v.outputs.size(); ++i) {
        const auto& o = v.outputs[i];
        QString addr, type;
        if (cp) { hk::SpkAddress a = hk::spk_to_address(o.script_pubkey, *cp); addr = QString::fromStdString(a.address); type = QString::fromStdString(a.type); }
        QString label, colour;
        if (ownFlags.empty()) { label = QStringLiteral("EXTERNAL — pending key binding"); colour = "#8a5a00"; }
        else if (i < ownFlags.size() && ownFlags[i]) { label = QStringLiteral("OWN — change returns to you"); colour = "#0a6"; owned_count++; }
        else { label = QStringLiteral("EXTERNAL — leaves your wallet"); colour = "#b00020"; }
        const bool unknown = (type == "Unknown");
        html += QString("&nbsp;• %1 → %2 [%3] &nbsp;<span style='color:%4;font-weight:bold'>%5</span>%6<br>")
                    .arg(both_units(o.value, coin))
                    .arg(addr.isEmpty() ? QStringLiteral("(no address form)") : addr.toHtmlEscaped(),
                         type.toHtmlEscaped(), colour, label,
                         unknown ? QStringLiteral(" <span style='color:#b00020;font-weight:bold'>[UNKNOWN SCRIPT]</span>") : QString());
    }

    if (bound && owned_count == 0)
        html += QString("<div style='color:#fff;background:#b00020;font-weight:bold;padding:4px;margin-top:6px'>"
                        "NO CHANGE RETURNS TO YOU — every output leaves your wallet. "
                        "TOTAL DEBIT = %1. Verify this is intended before you sign.</div>")
                    .arg(both_units(v.sum_in, coin));

    const double rate = v.serialized_size ? double(v.fee) / double(v.serialized_size) : 0.0;
    html += QString("<br><b>FEE:</b> %1 &nbsp; (~%2 sat/byte over %3 unsigned bytes)<br>")
                .arg(both_units(v.fee, coin)).arg(rate, 0, 'f', 2).arg(int(v.serialized_size));
    if (v.fee < 0)
        html += QStringLiteral("<span style='color:#b00020;font-weight:bold'>⚠ NEGATIVE FEE — unbalanced; signing will refuse.</span><br>");
    else if (v.fee > sg::default_absurd_fee_sats(coin.toStdString()))
        html += QStringLiteral("<span style='color:#b00020;font-weight:bold'>⚠ FEE IS ABSURDLY HIGH — confirm the high-fee box below only if intended.</span><br>");
    return html;
}

// A decoded key line; the private scalar stays zeroizing until routed/consumed.
struct KeyLine {
    c2w::secure::SecureBytes sk;
    Bytes comp, uncomp, script;
    bool ok = false;
    std::string error;
};

KeyLine decode_key_line(const std::string& line_in) {
    KeyLine kl;
    // split on '#' into key part and optional script part (secret-minimising:
    // std::string only, no QString copies of the secret).
    std::string keypart = line_in, scriptpart;
    const size_t hp = line_in.find('#');
    if (hp != std::string::npos) { keypart = line_in.substr(0, hp); scriptpart = line_in.substr(hp + 1); }
    auto trim = [](std::string s) {
        size_t a = s.find_first_not_of(" \t\r\n");
        size_t b = s.find_last_not_of(" \t\r\n");
        return a == std::string::npos ? std::string() : s.substr(a, b - a + 1);
    };
    keypart = trim(keypart);
    scriptpart = trim(scriptpart);

    if (is_hex64(keypart)) {
        hk::RawHexDecode d = hk::decode_raw_hex(keypart, true);
        if (!d.ok) { kl.error = d.error; wipe(keypart); return kl; }
        kl.sk = std::move(d.scalar);
    } else {
        hk::WifDecode d = hk::decode_wif(keypart);
        if (!d.ok) { kl.error = d.error; wipe(keypart); return kl; }
        kl.sk = std::move(d.scalar);
    }
    wipe(keypart);
    kl.comp = hk::Secp::instance().pubkey_create(kl.sk.data(), true);
    kl.uncomp = hk::Secp::instance().pubkey_create(kl.sk.data(), false);
    if (kl.comp.size() != 33) { kl.error = "pubkey derivation failed"; return kl; }
    if (!scriptpart.empty()) {
        Bytes s;
        if (!from_hex_str(scriptpart, s)) { kl.error = "bad script hex after '#'"; return kl; }
        kl.script = s;
    }
    kl.ok = true;
    return kl;
}

} // namespace

PageSign::PageSign(QWidget* parent) : QWidget(parent), bound_(std::make_unique<Bound>())
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
    artifactIn_->setMaximumHeight(80);
    v->addWidget(artifactIn_);

    loadFileBtn_ = new QPushButton(QStringLiteral("Load artifact from file…"), this);
    v->addWidget(loadFileBtn_);
    parseBtn_ = new QPushButton(QStringLiteral("1) Parse + build confirm card"), this);
    v->addWidget(parseBtn_);

    cardLabel_ = new QLabel(this);
    cardLabel_->setTextFormat(Qt::RichText);
    cardLabel_->setWordWrap(true);
    cardLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    cardLabel_->setStyleSheet(QStringLiteral("border:1px solid #bbb; border-radius:4px; padding:8px;"));
    v->addWidget(cardLabel_);

    // ── 2. Bind keys + preview (must run BEFORE the commit gate) ─────────────
    keysEdit_ = new QPlainTextEdit(this);
    keysEdit_->setPlaceholderText(QStringLiteral(
        "one private key per line: WIF or 64-hex.\n"
        "for a P2SH/P2WSH multisig input add the shared script:  <WIF-or-hex>#<redeemOrWitnessScriptHex>\n"
        "the widget is wiped the instant it is read at Bind."));
    keysEdit_->setFont(QFont(QStringLiteral("monospace")));
    keysEdit_->setMaximumHeight(80);
    v->addWidget(keysEdit_);
    bindBtn_ = new QPushButton(QStringLiteral("2) Bind keys + preview OWN/EXTERNAL"), this);
    v->addWidget(bindBtn_);

    // ── 3. Commit gate ──────────────────────────────────────────────────────
    reviewedCheck_ = new QCheckBox(QStringLiteral("I have reviewed every amount, address, the OWN/EXTERNAL labels and the fee above."), this);
    v->addWidget(reviewedCheck_);
    confirmHighFee_ = new QCheckBox(QStringLiteral("I confirm the ABSURDLY HIGH fee shown above is intended."), this);
    v->addWidget(confirmHighFee_);

    spendGate_ = new QLineEdit(this);
    spendGate_->setPlaceholderText(QStringLiteral("type SPEND to arm signing"));
    v->addWidget(spendGate_);

    signBtn_ = new QPushButton(QStringLiteral("3) Sign, self-verify, and emit signed artifact"), this);
    v->addWidget(signBtn_);

    // ── Output ──────────────────────────────────────────────────────────────
    output_ = new QPlainTextEdit(this);
    output_->setReadOnly(true);
    output_->setFont(QFont(QStringLiteral("monospace")));
    output_->setMaximumHeight(170);
    v->addWidget(output_);
    saveBtn_ = new QPushButton(QStringLiteral("Save signed artifact to file…"), this);
    v->addWidget(saveBtn_);

    connect(loadFileBtn_, &QPushButton::clicked, this, &PageSign::onLoadFile);
    connect(parseBtn_, &QPushButton::clicked, this, &PageSign::onParse);
    connect(artifactIn_, &QPlainTextEdit::textChanged, this, &PageSign::onArtifactChanged);
    connect(bindBtn_, &QPushButton::clicked, this, &PageSign::onBindPreview);
    connect(keysEdit_, &QPlainTextEdit::textChanged, this, &PageSign::invalidateBinding);
    connect(reviewedCheck_, &QCheckBox::toggled, this, &PageSign::onGateChanged);
    connect(confirmHighFee_, &QCheckBox::toggled, this, &PageSign::onGateChanged);
    connect(spendGate_, &QLineEdit::textChanged, this, &PageSign::onGateChanged);
    connect(signBtn_, &QPushButton::clicked, this, &PageSign::onSign);
    connect(saveBtn_, &QPushButton::clicked, this, &PageSign::onSaveSigned);

    invalidateParse();
}

PageSign::~PageSign() = default;

void PageSign::invalidateParse()
{
    parsedOk_ = false;
    containerHex_.clear();
    coin_.clear();
    invalidateBinding();
    keysEdit_->setEnabled(false);
    bindBtn_->setEnabled(false);
}

void PageSign::invalidateBinding()
{
    boundOk_ = false;
    if (bound_) bound_->keys.clear();     // zeroizes the SecureBytes it held
    lastSigned_.clear();
    reviewedCheck_->setChecked(false);
    reviewedCheck_->setEnabled(false);
    confirmHighFee_->setChecked(false);
    confirmHighFee_->setVisible(false);
    spendGate_->clear();
    spendGate_->setEnabled(false);
    signBtn_->setEnabled(false);
    if (saveBtn_) saveBtn_->setEnabled(false);
    // keys widget stays enabled while parsed (operator may re-enter keys).
    if (keysEdit_) keysEdit_->setEnabled(parsedOk_);
    if (bindBtn_) bindBtn_->setEnabled(parsedOk_);
}

void PageSign::onArtifactChanged()
{
    // Attestation is bound to a specific artifact (item 2): any edit resets it.
    invalidateParse();
    cardLabel_->clear();
    output_->clear();
}

void PageSign::onGateChanged() { updateSignEnabled(); }

void PageSign::updateSignEnabled()
{
    const bool feeConfirmOk = !confirmHighFee_->isVisible() || confirmHighFee_->isChecked();
    const bool ok = boundOk_ && reviewedCheck_->isChecked()
                    && spendGate_->text() == QStringLiteral("SPEND")
                    && feeConfirmOk;
    signBtn_->setEnabled(ok);
}

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
    invalidateParse();
    output_->clear();

    const QString hex = artifactIn_->toPlainText().trimmed();
    if (hex.isEmpty()) { cardLabel_->setText(QStringLiteral("Paste or load an artifact first.")); return; }

    std::string err;
    auto oc = art::UnsignedContainer::from_hex(hex.toStdString(), err);
    if (!oc) { cardLabel_->setText(QString("<b style='color:#b00020'>Not a valid artifact:</b> %1").arg(QString::fromStdString(err).toHtmlEscaped())); return; }

    c2w::sign::TxView view = c2w::sign::parse_unsigned(*oc);
    if (!view.ok) { cardLabel_->setText(QString("<b style='color:#b00020'>Artifact failed cross-check:</b> %1").arg(QString::fromStdString(view.error).toHtmlEscaped())); return; }

    coin_ = QString::fromStdString(oc->coin);
    const hk::CoinParams* cp = coin_params(coin_);

    QString head;
    if (sg::coin_is_bch(oc->coin))
        head = QStringLiteral("<div style='color:#fff;background:#b00020;font-weight:bold;padding:4px'>"
                              "BCH artifact — signing needs SIGHASH_FORKID, not in slice-2a. This tx cannot be signed here.</div>");
    cardLabel_->setText(head + render_card(view, coin_, cp, /*ownFlags*/{}, /*bound*/false, int(oc->algebra)));

    parsedOk_ = true;
    containerHex_ = hex;
    invalidateBinding();   // arms stage 2 (keys + bind) but not stage 3
}

void PageSign::onBindPreview()
{
    if (!parsedOk_) return;
    invalidateBinding();
    output_->clear();

    // Read the secret ONCE and clear the widget the instant it is read (T-8).
    ScopedSecret keytext(keysEdit_->toPlainText().toStdString());
    keysEdit_->clear();

    std::string derr;
    auto oc = art::UnsignedContainer::from_hex(containerHex_.toStdString(), derr);
    if (!oc) { output_->appendPlainText(QString("Artifact re-decode failed: %1").arg(QString::fromStdString(derr))); return; }
    if (sg::coin_is_bch(oc->coin)) { output_->appendPlainText(QStringLiteral("Refused: BCH signing needs SIGHASH_FORKID — not in slice-2a.")); return; }
    c2w::sign::TxView view = c2w::sign::parse_unsigned(*oc);
    if (!view.ok) { output_->appendPlainText(QString("Artifact cross-check failed: %1").arg(QString::fromStdString(view.error))); return; }

    const hk::CoinParams* cp = coin_params(coin_);
    if (!cp) { output_->appendPlainText(QStringLiteral("Unknown coin — cannot derive binding candidates.")); return; }

    // Decode key lines (std::string splitting; each line wiped after decode).
    std::vector<KeyLine> keylines;
    {
        const std::string& all = keytext.str();
        size_t pos = 0;
        while (pos <= all.size()) {
            size_t nl = all.find('\n', pos);
            std::string line = all.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
            pos = (nl == std::string::npos) ? all.size() + 1 : nl + 1;
            // trim for emptiness test
            std::string t = line; size_t a = t.find_first_not_of(" \t\r");
            if (a == std::string::npos) { wipe(line); continue; }
            KeyLine kl = decode_key_line(line);
            wipe(line);
            if (!kl.ok) { output_->appendPlainText(QString("Refused: key line invalid: %1").arg(QString::fromStdString(kl.error))); return; }
            keylines.push_back(std::move(kl));
        }
    }
    if (keylines.empty()) { output_->appendPlainText(QStringLiteral("Refused: no keys provided.")); return; }

    // Route keys to inputs (binding, T-6) and detect owned outputs (T-3).
    std::vector<sg::KeyForInput> keys;
    std::vector<char> ownFlags(view.outputs.size(), 0);
    QStringList bindingLog;
    std::vector<bool> input_keyed(view.inputs.size(), false);

    for (KeyLine& kl : keylines) {
        std::vector<hk::AddressCandidate> cands = hk::address_candidates(kl.comp, *cp);

        for (size_t oi = 0; oi < view.outputs.size(); ++oi)
            for (const auto& c : cands)
                if (!c.script_hex.empty() && QString::fromStdString(c.script_hex) == QString::fromStdString(view.outputs[oi].spk_hex))
                    ownFlags[oi] = 1;

        for (size_t i = 0; i < view.inputs.size(); ++i) {
            const auto& in = view.inputs[i];
            const QString spkhex = QString::fromStdString(in.spk_hex);
            // GAP-4 (slice-2c): when the key line carries no explicit '#script',
            // fall back to a redeem/witness script the UNSIGNED CONTAINER carries
            // in-band (R_INPUT_SCRIPT), so a P2SH/P2WSH input can be signed
            // without the operator re-pasting the shared script.
            Bytes eff = kl.script;
            bool eff_from_container = false;
            if (eff.empty()) {
                if (in.type == sg::SpkType::P2SH) {
                    if (auto sc = oc->script_for_input(i, art::InputScriptKind::Redeem)) { eff = *sc; eff_from_container = true; }
                } else if (in.type == sg::SpkType::P2WSH) {
                    if (auto sc = oc->script_for_input(i, art::InputScriptKind::Witness)) { eff = *sc; eff_from_container = true; }
                }
            }
            if (eff.empty()) {
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
                bool matched = false;
                if (in.type == sg::SpkType::P2SH) {
                    ct::BuiltAddress ba = ct::build_p2sh(cp->p2sh_version, eff);
                    if (ba.ok() && hexq(Bytes(ba.script.begin(), ba.script.end())) == spkhex) matched = true;
                } else if (in.type == sg::SpkType::P2WSH) {
                    const std::string hrp = cp->bech32_hrp ? cp->bech32_hrp : "";
                    if (!hrp.empty()) {
                        ct::BuiltAddress ba = ct::build_p2wsh(hrp, eff);
                        if (ba.ok() && hexq(Bytes(ba.script.begin(), ba.script.end())) == spkhex) matched = true;
                    }
                }
                if (matched) {
                    keys.push_back({i, kl.sk.copy(), kl.comp, eff});
                    input_keyed[i] = true;
                    bindingLog << QString("input #%1 ← multisig cosigner%2").arg(int(i))
                                  .arg(eff_from_container ? QStringLiteral(" (script from container GAP-4)") : QString());
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

    // Re-render the card with the OWN/EXTERNAL verdict (item 1 BLOCKER: shown
    // BEFORE the SPEND commit).
    QString head;
    cardLabel_->setText(head + render_card(view, coin_, cp, ownFlags, /*bound*/true, int(oc->algebra)));

    output_->appendPlainText(QStringLiteral("Binding preview (review the card above, then arm signing):"));
    for (const QString& l : bindingLog) output_->appendPlainText("  " + l);
    int owned = 0; for (char f : ownFlags) if (f) ++owned;
    if (owned == 0) output_->appendPlainText(QStringLiteral("  WARNING: no output returns to a loaded key (all EXTERNAL)."));

    // High-fee confirmation is required ONLY when the fee actually trips the
    // per-coin absurd ceiling (item 3).
    const bool absurd = view.fee > sg::default_absurd_fee_sats(coin_.toStdString());
    confirmHighFee_->setVisible(absurd);

    bound_->keys = std::move(keys);
    boundOk_ = true;
    reviewedCheck_->setEnabled(true);
    spendGate_->setEnabled(true);
    updateSignEnabled();
}

void PageSign::onSign()
{
    if (!boundOk_ || !reviewedCheck_->isChecked() || spendGate_->text() != QStringLiteral("SPEND")) {
        output_->appendPlainText(QStringLiteral("Not armed."));
        return;
    }
    output_->clear();
    saveBtn_->setEnabled(false);
    lastSigned_.clear();

    std::string derr;
    auto oc = art::UnsignedContainer::from_hex(containerHex_.toStdString(), derr);
    if (!oc) { output_->appendPlainText(QString("Artifact re-decode failed: %1").arg(QString::fromStdString(derr))); invalidateBinding(); return; }

    c2w::sign::SignOptions opt;
    opt.sighash = 0x01;                                              // SIGHASH_ALL
    opt.absurd_fee_sats = sg::default_absurd_fee_sats(coin_.toStdString());
    opt.absurd_fee_confirmed = confirmHighFee_->isVisible() && confirmHighFee_->isChecked();

    c2w::sign::SignOutcome o = c2w::sign::sign_and_verify(*oc, std::move(bound_->keys), opt);
    // keys consumed by the facade (and wiped there); re-arm binding either way.
    boundOk_ = false;

    if (!o.ok) {
        output_->appendPlainText(QString("REFUSED: %1").arg(QString::fromStdString(o.error)));
        invalidateBinding();
        return;
    }

    const std::string cg = art::crossgap_txid(o.signed_tx);
    const bool xok = (cg == o.wtxid_display);

    art::SignedContainer sc; sc.tx_hexes.push_back(o.signed_tx);
    lastSigned_ = QString::fromStdString(sc.emit());

    output_->appendPlainText(QStringLiteral("SIGNED + SELF-VERIFIED."));
    output_->appendPlainText(QString("txid : %1").arg(QString::fromStdString(o.txid_display)));
    output_->appendPlainText(QString("wtxid: %1  (cross-gap re-assert: %2)")
                                 .arg(QString::fromStdString(o.wtxid_display), xok ? "OK" : "MISMATCH"));
    for (const auto& w : o.warnings) output_->appendPlainText(QString("warning: %1").arg(QString::fromStdString(w)));
    output_->appendPlainText(QStringLiteral("\nsigned artifact (one raw tx hex per line — the c2pool loader format):"));
    output_->appendPlainText(lastSigned_);
    saveBtn_->setEnabled(true);

    // Force a fresh bind before any further signing (attestation not reusable).
    reviewedCheck_->setChecked(false);
    reviewedCheck_->setEnabled(false);
    confirmHighFee_->setChecked(false);
    confirmHighFee_->setVisible(false);
    spendGate_->clear();
    spendGate_->setEnabled(false);
    signBtn_->setEnabled(false);
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
