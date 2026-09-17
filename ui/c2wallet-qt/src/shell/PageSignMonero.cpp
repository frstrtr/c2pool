// SPDX-License-Identifier: AGPL-3.0-or-later
#include "shell/PageSignMonero.hpp"
#include "shell/ScopedSecret.hpp"

#include <QCheckBox>
#include <QComboBox>
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

#undef emit

#include "family/monero/MoneroCrypto.hpp"                 // mcrypto::keccak256, Bytes32
#include "family/monero/MoneroKey.hpp"                     // MoneroKeys, keys_from_*
#include "family/monero/addr/MoneroAddress.hpp"            // Network, MoneroAddress, address_encode
#include "family/monero/scan/MoneroScanner.hpp"            // SubaddressTable
#include "family/monero/prover/MoneroRingctBuilder.hpp"    // assemble/self_verify
#include "family/monero/artifact/MoneroArtifact.hpp"       // UnsignedTxSet, SignedTxSet
#include "family/monero/compose/MoneroSpendGate.hpp"       // the Qt-free money gate

namespace xm  = c2wallet::monero;
namespace art = c2wallet::monero::artifact;
namespace pv  = c2wallet::monero::prover;
namespace cg  = c2wallet::monero::compose;

// Opaque holder (declared in the header): the parsed txset (public) + the
// derived secrets. MoneroKeys' and SpendInput's own destructors wipe their
// secret scalars; invalidateBinding resets them so a re-bind starts clean.
struct PageSignMonero::State {
    art::UnsignedTxSet          u;
    xm::MoneroKeys              keys;
    std::vector<pv::SpendInput> inputs;
};

namespace {

using Bytes = std::vector<unsigned char>;

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
    for (int i = 0; i < in.size(); i += 2)
        out.push_back((unsigned char)((v(in.at(i).toLatin1()) << 4) | v(in.at(i + 1).toLatin1())));
    return true;
}
QString to_hex32(const xm::Bytes32& v) {
    static const char* d = "0123456789abcdef";
    QString s; s.reserve(64);
    for (unsigned char b : v) { s.append(QChar(d[b >> 4])); s.append(QChar(d[b & 0xf])); }
    return s;
}
xm::Network net_of(const QString& s) {
    if (s.compare("testnet", Qt::CaseInsensitive) == 0)  return xm::Network::Testnet;
    if (s.compare("stagenet", Qt::CaseInsensitive) == 0) return xm::Network::Stagenet;
    return xm::Network::Mainnet;
}

// Encode a destination's pubkeys back to an address string for the card.
QString dest_address(const pv::TxDestination& d, xm::Network net) {
    xm::MoneroAddress a;
    a.net = net;
    a.type = d.is_subaddress ? xm::AddressType::Subaddress : xm::AddressType::Standard;
    a.spend_pub = d.spend_pub;
    a.view_pub  = d.view_pub;
    std::string s = xm::address_encode(a);
    return QString::fromStdString(s);
}

// Build the confirm card. ownFlags empty => stage-1 (pre-bind) render; otherwise
// one entry per dest (true = OWN/change). `bound` gates the LOUD no-change line.
QString render_card(const art::UnsignedTxSet& u, xm::Network net,
                    const std::vector<char>& ownFlags, bool bound, const QString& digestHex)
{
    std::uint64_t sum_in = 0, sum_out = 0;
    for (const auto& s : u.sources) sum_in += s.amount;
    for (const auto& d : u.dests)   sum_out += d.amount;
    const bool balanced = (sum_in == sum_out + u.fee);

    QString html;
    html += QString("<b>Monero unsigned_txset</b> &nbsp; keccak256 = %1<br>").arg(digestHex.left(24) + "…");

    html += QString("<br><b>SOURCES (%1) — TOTAL DEBIT %2</b><br>")
                .arg(int(u.sources.size())).arg(QString::fromStdString(cg::both_units(sum_in)));
    for (std::size_t i = 0; i < u.sources.size(); ++i) {
        const auto& s = u.sources[i];
        html += QString("&nbsp;#%1 ring %2, real_index %3 — %4<br>")
                    .arg(int(i)).arg(int(s.ring.size())).arg(int(s.real_index))
                    .arg(QString::fromStdString(cg::both_units(s.amount)));
    }

    html += QString("<br><b>DESTINATIONS (%1) — total %2</b><br>")
                .arg(int(u.dests.size())).arg(QString::fromStdString(cg::both_units(sum_out)));
    int owned_count = 0;
    for (std::size_t i = 0; i < u.dests.size(); ++i) {
        const auto& d = u.dests[i];
        const QString addr = dest_address(d, net);
        QString label, colour;
        if (ownFlags.empty()) { label = QStringLiteral("pending key binding"); colour = "#8a5a00"; }
        else if (i < ownFlags.size() && ownFlags[i]) { label = QStringLiteral("OWN — change returns to you"); colour = "#0a6"; owned_count++; }
        else { label = QStringLiteral("EXTERNAL — leaves your wallet"); colour = "#b00020"; }
        html += QString("&nbsp;• %1 → %2 %3&nbsp;<span style='color:%4;font-weight:bold'>%5</span><br>")
                    .arg(QString::fromStdString(cg::both_units(d.amount)),
                         addr.isEmpty() ? QStringLiteral("(no address form)") : addr.toHtmlEscaped(),
                         d.is_subaddress ? QStringLiteral("[subaddress] ") : QString(),
                         colour, label);
    }

    if (bound && owned_count == 0)
        html += QString("<div style='color:#fff;background:#b00020;font-weight:bold;padding:4px;margin-top:6px'>"
                        "NO CHANGE RETURNS TO YOU — every destination leaves your wallet. "
                        "TOTAL DEBIT = %1. Verify this is intended before you sign.</div>")
                    .arg(QString::fromStdString(cg::both_units(sum_in)));

    html += QString("<br><b>FEE:</b> %1<br>").arg(QString::fromStdString(cg::both_units(u.fee)));
    html += QString("<b>Balance:</b> Σin (%1) %2 Σout+fee (%3)<br>")
                .arg(QString::number(qulonglong(sum_in)),
                     balanced ? QStringLiteral("==") : QStringLiteral("≠"),
                     QString::number(qulonglong(sum_out + u.fee)));
    if (!balanced)
        html += QStringLiteral("<span style='color:#b00020;font-weight:bold'>⚠ UNBALANCED — signing will refuse.</span><br>");
    return html;
}

} // namespace

PageSignMonero::PageSignMonero(QWidget* parent) : QWidget(parent), st_(std::make_unique<State>())
{
    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 24, 24, 24);
    v->setSpacing(10);

    auto* heading = new QLabel(QStringLiteral("Sign & Self-Verify (Family B — Monero / RingCT, offline, key-bearing)"), this);
    QFont hf = heading->font(); hf.setPointSize(hf.pointSize() + 6); hf.setBold(true);
    heading->setFont(hf);
    v->addWidget(heading);

    auto* netRow = new QVBoxLayout();
    netCombo_ = new QComboBox(this);
    netCombo_->addItem(QStringLiteral("mainnet"));
    netCombo_->addItem(QStringLiteral("testnet"));
    netCombo_->addItem(QStringLiteral("stagenet"));
    netRow->addWidget(new QLabel(QStringLiteral("Network (for address display):"), this));
    netRow->addWidget(netCombo_);
    v->addLayout(netRow);

    // ── 1. Load the unsigned_txset ──────────────────────────────────────────
    artifactIn_ = new QPlainTextEdit(this);
    artifactIn_->setPlaceholderText(QStringLiteral("paste the unsigned_txset hex here, or load it from a file"));
    artifactIn_->setFont(QFont(QStringLiteral("monospace")));
    artifactIn_->setMaximumHeight(72);
    v->addWidget(artifactIn_);

    loadFileBtn_ = new QPushButton(QStringLiteral("Load unsigned_txset from file…"), this);
    v->addWidget(loadFileBtn_);
    parseBtn_ = new QPushButton(QStringLiteral("1) Parse + build confirm card"), this);
    v->addWidget(parseBtn_);

    cardLabel_ = new QLabel(this);
    cardLabel_->setTextFormat(Qt::RichText);
    cardLabel_->setWordWrap(true);
    cardLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    cardLabel_->setStyleSheet(QStringLiteral("border:1px solid #bbb; border-radius:4px; padding:8px;"));
    v->addWidget(cardLabel_);

    // ── 2. Bind keys + preview ──────────────────────────────────────────────
    secretType_ = new QComboBox(this);
    secretType_->addItem(QStringLiteral("25-word mnemonic"));
    secretType_->addItem(QStringLiteral("dual hex (spend view)"));
    v->addWidget(secretType_);
    keysEdit_ = new QPlainTextEdit(this);
    keysEdit_->setPlaceholderText(QStringLiteral(
        "25-word Monero mnemonic, OR the two 64-hex private scalars 'spend view' (space/colon/newline separated).\n"
        "A view-only key set is REFUSED. The widget is wiped the instant it is read at Bind."));
    keysEdit_->setFont(QFont(QStringLiteral("monospace")));
    keysEdit_->setMaximumHeight(72);
    v->addWidget(keysEdit_);
    bindBtn_ = new QPushButton(QStringLiteral("2) Bind keys + preview OWN/EXTERNAL"), this);
    v->addWidget(bindBtn_);

    // ── 3. Commit gate ──────────────────────────────────────────────────────
    reviewedCheck_ = new QCheckBox(QStringLiteral("I have reviewed every amount, destination address, the OWN/EXTERNAL labels and the fee above."), this);
    v->addWidget(reviewedCheck_);
    spendGate_ = new QLineEdit(this);
    spendGate_->setPlaceholderText(QStringLiteral("type SPEND to arm signing"));
    v->addWidget(spendGate_);
    signBtn_ = new QPushButton(QStringLiteral("3) Sign, self-verify, and emit signed_txset"), this);
    v->addWidget(signBtn_);

    // ── Output ──────────────────────────────────────────────────────────────
    output_ = new QPlainTextEdit(this);
    output_->setReadOnly(true);
    output_->setFont(QFont(QStringLiteral("monospace")));
    output_->setMaximumHeight(170);
    v->addWidget(output_);
    saveBtn_ = new QPushButton(QStringLiteral("Save signed_txset to file…"), this);
    v->addWidget(saveBtn_);

    connect(loadFileBtn_, &QPushButton::clicked, this, &PageSignMonero::onLoadFile);
    connect(parseBtn_, &QPushButton::clicked, this, &PageSignMonero::onParse);
    connect(artifactIn_, &QPlainTextEdit::textChanged, this, &PageSignMonero::onArtifactChanged);
    connect(netCombo_, &QComboBox::currentTextChanged, this, &PageSignMonero::onArtifactChanged);
    connect(bindBtn_, &QPushButton::clicked, this, &PageSignMonero::onBindPreview);
    connect(secretType_, &QComboBox::currentTextChanged, this, &PageSignMonero::invalidateBinding);
    connect(keysEdit_, &QPlainTextEdit::textChanged, this, &PageSignMonero::invalidateBinding);
    connect(reviewedCheck_, &QCheckBox::toggled, this, &PageSignMonero::onGateChanged);
    connect(spendGate_, &QLineEdit::textChanged, this, &PageSignMonero::onGateChanged);
    connect(signBtn_, &QPushButton::clicked, this, &PageSignMonero::onSign);
    connect(saveBtn_, &QPushButton::clicked, this, &PageSignMonero::onSaveSigned);

    invalidateParse();
}

PageSignMonero::~PageSignMonero() = default;

void PageSignMonero::invalidateParse()
{
    parsedOk_ = false;
    containerHex_.clear();
    st_->u = art::UnsignedTxSet{};
    invalidateBinding();
    secretType_->setEnabled(false);
    keysEdit_->setEnabled(false);
    bindBtn_->setEnabled(false);
}

void PageSignMonero::invalidateBinding()
{
    boundOk_ = false;
    if (st_) {
        cg::wipe_spend_inputs(st_->inputs);   // GAP-6 explicit scrub before release
        st_->inputs.clear();                  // SpendInput dtor scrubs any residue
        st_->keys = xm::MoneroKeys{};         // old keys' dtor wipes its scalars
    }
    lastSigned_.clear();
    reviewedCheck_->setChecked(false);
    reviewedCheck_->setEnabled(false);
    spendGate_->clear();
    spendGate_->setEnabled(false);
    signBtn_->setEnabled(false);
    if (saveBtn_) saveBtn_->setEnabled(false);
    if (secretType_) secretType_->setEnabled(parsedOk_);
    if (keysEdit_) keysEdit_->setEnabled(parsedOk_);
    if (bindBtn_) bindBtn_->setEnabled(parsedOk_);
}

void PageSignMonero::onArtifactChanged()
{
    invalidateParse();
    cardLabel_->clear();
    output_->clear();
}

void PageSignMonero::onGateChanged() { updateSignEnabled(); }

void PageSignMonero::updateSignEnabled()
{
    const bool ok = boundOk_ && reviewedCheck_->isChecked()
                    && spendGate_->text() == QStringLiteral("SPEND");
    signBtn_->setEnabled(ok);
}

void PageSignMonero::onLoadFile()
{
    const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("Load unsigned_txset"),
                                                      QString(), QStringLiteral("c2wallet tx (*.c2wtx);;All files (*)"));
    if (path.isEmpty()) return;
    QFile fl(path);
    if (!fl.open(QIODevice::ReadOnly | QIODevice::Text)) {
        cardLabel_->setText(QString("<b>Could not read</b> %1").arg(path.toHtmlEscaped()));
        return;
    }
    artifactIn_->setPlainText(QString::fromUtf8(fl.readAll()).trimmed());
    fl.close();
}

void PageSignMonero::onParse()
{
    invalidateParse();
    output_->clear();

    const QString hex = artifactIn_->toPlainText().trimmed();
    if (hex.isEmpty()) { cardLabel_->setText(QStringLiteral("Paste or load an unsigned_txset first.")); return; }
    Bytes blob;
    if (!from_hex(hex, blob)) { cardLabel_->setText(QStringLiteral("<b style='color:#b00020'>Not valid hex.</b>")); return; }

    art::UnsignedTxSet u; std::string err;
    if (!art::parse_unsigned_txset(blob, u, err)) {
        cardLabel_->setText(QString("<b style='color:#b00020'>Not a valid unsigned_txset:</b> %1")
                                .arg(QString::fromStdString(err).toHtmlEscaped()));
        return;
    }
    if (u.sources.empty() || u.dests.empty()) {
        cardLabel_->setText(QStringLiteral("<b style='color:#b00020'>Refused:</b> unsigned_txset has no sources or no destinations."));
        return;
    }

    const xm::Bytes32 dg = xm::mcrypto::keccak256(blob.data(), blob.size());
    st_->u = u;
    cardLabel_->setText(render_card(u, net_of(netCombo_->currentText()), /*ownFlags*/{}, /*bound*/false, to_hex32(dg)));

    parsedOk_ = true;
    containerHex_ = hex;
    invalidateBinding();   // arms stage 2, not stage 3
}

void PageSignMonero::onBindPreview()
{
    if (!parsedOk_) return;
    invalidateBinding();
    output_->clear();

    // Read the secret ONCE and clear the widget the instant it is read (T-8).
    ScopedSecret keytext(keysEdit_->toPlainText().toStdString());
    keysEdit_->clear();

    // Re-decode the container so binding is bound to the exact parsed bytes.
    Bytes blob;
    if (!from_hex(containerHex_, blob)) { output_->appendPlainText(QStringLiteral("Artifact re-decode failed.")); return; }
    art::UnsignedTxSet u; std::string derr;
    if (!art::parse_unsigned_txset(blob, u, derr)) { output_->appendPlainText(QString("Artifact re-parse failed: %1").arg(QString::fromStdString(derr))); return; }
    st_->u = u;

    // Derive the key set from the chosen secret form.
    xm::KeyImportResult kr;
    if (secretType_->currentIndex() == 0) {
        kr = xm::keys_from_mnemonic(keytext.str());
    } else {
        // dual hex: two 64-hex tokens, separated by space / colon / newline.
        std::string spend, view;
        {
            std::string t = keytext.str();
            for (char& c : t) if (c == ':' || c == '\n' || c == '\r' || c == '\t') c = ' ';
            std::size_t p = 0;
            auto next = [&](std::string& out) {
                while (p < t.size() && t[p] == ' ') ++p;
                std::size_t s = p;
                while (p < t.size() && t[p] != ' ') ++p;
                out = t.substr(s, p - s);
            };
            next(spend); next(view);
        }
        kr = xm::keys_from_dual_hex(spend, view);
    }
    if (!kr.ok) { output_->appendPlainText(QString("Refused: key import failed: %1").arg(QString::fromStdString(kr.error))); return; }
    if (!kr.keys.can_sign()) { output_->appendPlainText(QStringLiteral("Refused: this is a VIEW-ONLY key set — it cannot sign (T-6).")); return; }
    st_->keys = std::move(kr.keys);

    // Subaddress table for OWN/change detection (a modest change grid).
    xm::SubaddressTable subs;
    subs.build(st_->keys.view_priv, st_->keys.spend_pub, /*major*/2, /*minor*/200);

    // Re-derive each real ring member's one-time secret x_i (also the wrong-
    // wallet + view-only refusal, T-6): "re-derived one-time secret does not
    // match the real ring member".
    std::vector<pv::SpendInput> inputs; std::string serr;
    if (!art::sources_to_spend_inputs(st_->u, st_->keys, inputs, serr)) {
        output_->appendPlainText(QString("Refused: %1").arg(QString::fromStdString(serr)));
        st_->keys = xm::MoneroKeys{};
        return;
    }

    // Per-destination OWN/EXTERNAL verdict (T-3), shown BEFORE the SPEND commit.
    std::vector<char> ownFlags(st_->u.dests.size(), 0);
    int owned = 0;
    for (std::size_t i = 0; i < st_->u.dests.size(); ++i) {
        if (cg::classify_dest(st_->u.dests[i], st_->keys, subs) == cg::Ownership::Own) { ownFlags[i] = 1; ++owned; }
    }

    const xm::Bytes32 dg = xm::mcrypto::keccak256(blob.data(), blob.size());
    cardLabel_->setText(render_card(st_->u, net_of(netCombo_->currentText()), ownFlags, /*bound*/true, to_hex32(dg)));

    output_->appendPlainText(QStringLiteral("Binding preview (review the card above, then arm signing):"));
    output_->appendPlainText(QString("  re-derived %1 spend input(s) from the wallet keys").arg(int(inputs.size())));
    output_->appendPlainText(QString("  %1 of %2 destination(s) return to you (OWN/change)").arg(owned).arg(int(st_->u.dests.size())));
    if (owned == 0) output_->appendPlainText(QStringLiteral("  WARNING: no destination returns to a loaded key (all EXTERNAL)."));

    st_->inputs = std::move(inputs);
    boundOk_ = true;
    reviewedCheck_->setEnabled(true);
    spendGate_->setEnabled(true);
    updateSignEnabled();
}

void PageSignMonero::onSign()
{
    if (!boundOk_ || !reviewedCheck_->isChecked() || spendGate_->text() != QStringLiteral("SPEND")) {
        output_->appendPlainText(QStringLiteral("Not armed."));
        return;
    }
    output_->clear();
    saveBtn_->setEnabled(false);
    lastSigned_.clear();

    // ── assemble with the library self-verify ON (T-5) ──────────────────────
    pv::AssembleResult r = pv::assemble_ringct_tx(st_->inputs, st_->u.dests, st_->u.fee,
                                                  st_->u.tx_extra, /*self_verify*/true);
    if (!r.ok) {
        output_->appendPlainText(QString("REFUSED (assemble): %1").arg(QString::fromStdString(r.error)));
        cg::wipe_spend_inputs(st_->inputs);
        invalidateBinding();
        return;
    }

    // ── explicit belt-and-braces self-verify (public + key-image) ───────────
    std::string why;
    if (!pv::self_verify_tx_public(r.tx, why)) {
        output_->appendPlainText(QString("REFUSED (self_verify_tx_public): %1").arg(QString::fromStdString(why)));
        cg::wipe_spend_inputs(st_->inputs);
        invalidateBinding();
        return;
    }
    if (!pv::self_verify_key_images(st_->inputs, r.tx, why)) {
        output_->appendPlainText(QString("REFUSED (self_verify_key_images): %1").arg(QString::fromStdString(why)));
        cg::wipe_spend_inputs(st_->inputs);
        invalidateBinding();
        return;
    }

    // The spend secrets are no longer needed — scrub them now (GAP-6, T-8).
    cg::wipe_spend_inputs(st_->inputs);

    // ── emit + round-trip equality before showing anything ──────────────────
    Bytes sb = art::produce_signed_txset(r.tx);
    art::SignedTxSet s2; std::string perr;
    if (!art::parse_signed_txset(sb, s2, perr)) {
        output_->appendPlainText(QString("REFUSED (signed_txset round-trip parse): %1").arg(QString::fromStdString(perr)));
        invalidateBinding();
        return;
    }
    if (!(s2.tx_blob == r.tx.blob && s2.tx_hash == r.tx.tx_hash && s2.key_images == r.tx.key_images)) {
        output_->appendPlainText(QStringLiteral("REFUSED: signed_txset round-trip mismatch (blob/hash/key-images)."));
        invalidateBinding();
        return;
    }

    QString hex; hex.reserve(int(sb.size()) * 2);
    static const char* d = "0123456789abcdef";
    for (unsigned char b : sb) { hex.append(QChar(d[b >> 4])); hex.append(QChar(d[b & 0xf])); }
    lastSigned_ = hex;

    output_->appendPlainText(QStringLiteral("SIGNED + SELF-VERIFIED (BP+/CLSAG/balance + key images) + round-trip OK."));
    output_->appendPlainText(QString("tx_hash    : %1").arg(to_hex32(r.tx.tx_hash)));
    output_->appendPlainText(QString("key images : %1").arg(int(r.tx.key_images.size())));
    for (std::size_t i = 0; i < r.tx.key_images.size(); ++i)
        output_->appendPlainText(QString("   I[%1] = %2").arg(int(i)).arg(to_hex32(r.tx.key_images[i])));
    output_->appendPlainText(QString("signed_txset bytes: %1").arg(int(sb.size())));
    output_->appendPlainText(QStringLiteral("\nsigned_txset hex (carry it back to the online view-only wallet):"));
    output_->appendPlainText(lastSigned_);
    saveBtn_->setEnabled(true);

    // Force a fresh bind before any further signing (attestation not reusable).
    boundOk_ = false;
    reviewedCheck_->setChecked(false);
    reviewedCheck_->setEnabled(false);
    spendGate_->clear();
    spendGate_->setEnabled(false);
    signBtn_->setEnabled(false);
    st_->inputs.clear();
    st_->keys = xm::MoneroKeys{};
}

void PageSignMonero::onSaveSigned()
{
    if (lastSigned_.isEmpty()) return;
    const QString path = QFileDialog::getSaveFileName(this, QStringLiteral("Save signed_txset"),
                                                      QStringLiteral("signed.xmr.c2wtx"),
                                                      QStringLiteral("c2wallet tx (*.c2wtx);;All files (*)"));
    if (path.isEmpty()) return;
    QFile fl(path);
    if (!fl.open(QIODevice::WriteOnly | QIODevice::Text)) {
        output_->appendPlainText(QString("Could not write %1").arg(path));
        return;
    }
    fl.write(lastSigned_.toUtf8());
    fl.write("\n");
    fl.close();
    output_->appendPlainText(QString("Saved signed_txset to %1").arg(path));
}
