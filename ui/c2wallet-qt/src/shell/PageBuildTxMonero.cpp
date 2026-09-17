// SPDX-License-Identifier: AGPL-3.0-or-later
#include "shell/PageBuildTxMonero.hpp"

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

// The Monero artifact library defines no `emit`, but keep the Family-A habit of
// dropping the Qt keyword-macro before the library headers (this page emits no
// Qt signals of its own beyond the auto-connected slots).
#undef emit

#include "family/monero/MoneroCrypto.hpp"                 // mcrypto::keccak256
#include "family/monero/addr/MoneroAddress.hpp"           // Network
#include "family/monero/prover/MoneroRingctBuilder.hpp"   // TxDestination
#include "family/monero/artifact/MoneroArtifact.hpp"      // UnsignedTxSet, parse/produce
#include "family/monero/scan/MoneroScanner.hpp"           // ExportedOutput
#include "family/monero/compose/MoneroSpendGate.hpp"      // the Qt-free money gate

namespace xm  = c2wallet::monero;
namespace art = c2wallet::monero::artifact;
namespace pv  = c2wallet::monero::prover;
namespace cg  = c2wallet::monero::compose;

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
QString to_hex(const Bytes& v) {
    static const char* d = "0123456789abcdef";
    QString s; s.reserve(int(v.size()) * 2);
    for (unsigned char b : v) { s.append(QChar(d[b >> 4])); s.append(QChar(d[b & 0xf])); }
    return s;
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

} // namespace

PageBuildTxMonero::PageBuildTxMonero(QWidget* parent) : QWidget(parent)
{
    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 24, 24, 24);
    v->setSpacing(12);

    auto* heading = new QLabel(QStringLiteral("Build Transaction (Family B — Monero / RingCT, key-free composer)"), this);
    QFont hf = heading->font(); hf.setPointSize(hf.pointSize() + 6); hf.setBold(true);
    heading->setFont(hf);
    v->addWidget(heading);

    auto* note = new QLabel(
        QStringLiteral("Assembles a Monero <b>unsigned_txset</b> for the offline signer. Ring/decoy "
                       "selection is the ONLINE side's job, so the frozen sources (rings + commitments) "
                       "are loaded from an unsigned_txset the online wallet produced; this page recomposes "
                       "destinations + fee over them. View-only keys suffice. Amounts are XMR (12 decimals)."),
        this);
    note->setTextFormat(Qt::RichText);
    note->setWordWrap(true);
    v->addWidget(note);

    auto* form = new QFormLayout();
    netCombo_ = new QComboBox(this);
    netCombo_->addItem(QStringLiteral("mainnet"));
    netCombo_->addItem(QStringLiteral("testnet"));
    netCombo_->addItem(QStringLiteral("stagenet"));
    form->addRow(QStringLiteral("Network:"), netCombo_);
    v->addLayout(form);

    auto* srcBox = new QGroupBox(QStringLiteral("Frozen sources — paste the unsigned_txset hex the ONLINE wallet produced (rings/decoys frozen)"), this);
    auto* srcv = new QVBoxLayout(srcBox);
    sourcesEdit_ = new QPlainTextEdit(srcBox);
    sourcesEdit_->setPlaceholderText(QStringLiteral(
        "paste an unsigned_txset (hex). Its `sources` (frozen rings) are taken verbatim; its dests/fee are recomposed below."));
    sourcesEdit_->setFont(QFont(QStringLiteral("monospace")));
    sourcesEdit_->setMaximumHeight(80);
    srcv->addWidget(sourcesEdit_);
    v->addWidget(srcBox);

    auto* oeBox = new QGroupBox(QStringLiteral("Owned outputs export (optional, informational) — outputs-export hex"), this);
    auto* oev = new QVBoxLayout(oeBox);
    outputsExportEdit_ = new QPlainTextEdit(oeBox);
    outputsExportEdit_->setPlaceholderText(QStringLiteral("optional: paste an outputs-export to display the owned outputs it carries."));
    outputsExportEdit_->setFont(QFont(QStringLiteral("monospace")));
    outputsExportEdit_->setMaximumHeight(56);
    oev->addWidget(outputsExportEdit_);
    v->addWidget(oeBox);

    auto* dstBox = new QGroupBox(QStringLiteral("Destinations — one per line:  address:amountXMR[:change]"), this);
    auto* dstv = new QVBoxLayout(dstBox);
    destsEdit_ = new QPlainTextEdit(dstBox);
    destsEdit_->setPlaceholderText(QStringLiteral(
        "e.g.  4Abc...:1.5\n"
        "      8Sub...:0.25:change   (your own address to receive change)"));
    destsEdit_->setFont(QFont(QStringLiteral("monospace")));
    destsEdit_->setMaximumHeight(90);
    dstv->addWidget(destsEdit_);
    v->addWidget(dstBox);

    auto* feeForm = new QFormLayout();
    feeEdit_ = new QPlainTextEdit(this);
    feeEdit_->setPlaceholderText(QStringLiteral("fee in XMR, e.g. 0.000030000000"));
    feeEdit_->setFont(QFont(QStringLiteral("monospace")));
    feeEdit_->setMaximumHeight(30);
    feeForm->addRow(QStringLiteral("Fee (XMR):"), feeEdit_);
    v->addLayout(feeForm);

    summaryLabel_ = new QLabel(this);
    summaryLabel_->setWordWrap(true);
    summaryLabel_->setTextFormat(Qt::RichText);
    v->addWidget(summaryLabel_);

    assembleBtn_ = new QPushButton(QStringLiteral("Assemble unsigned_txset"), this);
    assembleBtn_->setEnabled(false);
    v->addWidget(assembleBtn_);
    saveBtn_ = new QPushButton(QStringLiteral("Save unsigned_txset to file…"), this);
    saveBtn_->setEnabled(false);
    v->addWidget(saveBtn_);

    artifactEdit_ = new QPlainTextEdit(this);
    artifactEdit_->setReadOnly(true);
    artifactEdit_->setFont(QFont(QStringLiteral("monospace")));
    artifactEdit_->setMaximumHeight(90);
    artifactEdit_->setPlaceholderText(QStringLiteral("the assembled unsigned_txset hex appears here (carry it to the offline signer)"));
    v->addWidget(artifactEdit_);

    output_ = new QPlainTextEdit(this);
    output_->setReadOnly(true);
    output_->setFont(QFont(QStringLiteral("monospace")));
    output_->setMaximumHeight(140);
    v->addWidget(output_);

    connect(sourcesEdit_, &QPlainTextEdit::textChanged, this, &PageBuildTxMonero::onRecalc);
    connect(outputsExportEdit_, &QPlainTextEdit::textChanged, this, &PageBuildTxMonero::onRecalc);
    connect(destsEdit_, &QPlainTextEdit::textChanged, this, &PageBuildTxMonero::onRecalc);
    connect(feeEdit_, &QPlainTextEdit::textChanged, this, &PageBuildTxMonero::onRecalc);
    connect(netCombo_, &QComboBox::currentTextChanged, this, &PageBuildTxMonero::onRecalc);
    connect(assembleBtn_, &QPushButton::clicked, this, &PageBuildTxMonero::onAssemble);
    connect(saveBtn_, &QPushButton::clicked, this, &PageBuildTxMonero::onSaveArtifact);

    onRecalc();
}

// Parse the form into an UnsignedTxSet. Frozen sources come from a loaded
// unsigned_txset; destinations + fee are recomposed here. `warns` collects
// non-blocking notes (integrated payment id, no-change).
static bool parse_form(xm::Network net, const QString& srcHex, const QString& destText,
                       const QString& feeText, art::UnsignedTxSet& u,
                       QStringList& warns, QString& err)
{
    u = art::UnsignedTxSet{};

    // ── frozen sources (rings) from the online unsigned_txset ───────────────
    const QString sh = srcHex.trimmed();
    if (sh.isEmpty()) { err = "paste the frozen sources (an unsigned_txset the online wallet produced)"; return false; }
    Bytes sb;
    if (!from_hex(sh, sb)) { err = "sources: not valid hex"; return false; }
    art::UnsignedTxSet loaded; std::string lerr;
    if (!art::parse_unsigned_txset(sb, loaded, lerr)) { err = QString("sources: %1").arg(QString::fromStdString(lerr)); return false; }
    if (loaded.sources.empty()) { err = "sources: the unsigned_txset carries no sources"; return false; }
    u.sources = loaded.sources;                 // take the frozen rings verbatim
    u.tx_extra = loaded.tx_extra;               // carry frozen extra verbatim

    // ── fee ─────────────────────────────────────────────────────────────────
    std::uint64_t fee = 0; std::string ferr;
    if (!cg::parse_xmr(feeText.trimmed().toStdString(), fee, ferr)) { err = QString("fee: %1").arg(QString::fromStdString(ferr)); return false; }
    u.fee = fee;

    // ── destinations ────────────────────────────────────────────────────────
    const QStringList lines = destText.split('\n', Qt::SkipEmptyParts);
    for (const QString& raw : lines) {
        const QString ln = raw.trimmed();
        if (ln.isEmpty()) continue;
        const QStringList f = ln.split(':');
        if (f.size() < 2) { err = QString("destination needs address:amount — got '%1'").arg(ln); return false; }
        cg::DecodedDest dd; std::string derr;
        if (!cg::decode_dest(f[0].trimmed().toStdString(), net, dd, derr)) { err = QString("destination %1").arg(QString::fromStdString(derr)); return false; }
        std::uint64_t amt = 0; std::string aerr;
        if (!cg::parse_xmr(f[1].trimmed().toStdString(), amt, aerr)) { err = QString("destination amount: %1").arg(QString::fromStdString(aerr)); return false; }
        if (amt == 0) { err = "destination amount is zero"; return false; }
        dd.dest.amount = amt;
        if (dd.has_payment_id)
            warns << "an INTEGRATED destination carries a payment id (read + carried in tx_extra by the online side; not generated here)";
        u.dests.push_back(dd.dest);
    }
    if (u.dests.empty()) { err = "no destinations"; return false; }
    return true;
}

void PageBuildTxMonero::onRecalc()
{
    assembleBtn_->setEnabled(false);
    saveBtn_->setEnabled(false);
    lastArtifact_.clear();
    const xm::Network net = net_of(netCombo_->currentText());

    // informational: owned-outputs export.
    QString oeInfo;
    const QString oeHex = outputsExportEdit_->toPlainText().trimmed();
    if (!oeHex.isEmpty()) {
        Bytes ob;
        if (from_hex(oeHex, ob)) {
            std::vector<xm::ExportedOutput> outs; std::uint64_t off = 0; std::string oerr;
            if (art::parse_outputs_export(ob, outs, off, oerr)) {
                std::uint64_t total = 0; for (const auto& o : outs) total += o.amount;
                oeInfo = QString("<br><span style='color:#0a6'>owned outputs export: %1 output(s), total %2</span>")
                             .arg(int(outs.size())).arg(QString::fromStdString(cg::both_units(total)));
            } else {
                oeInfo = QString("<br><span style='color:#8a5a00'>owned outputs export: not parseable (%1)</span>")
                             .arg(QString::fromStdString(oerr).toHtmlEscaped());
            }
        }
    }

    art::UnsignedTxSet u; QStringList warns; QString err;
    if (!parse_form(net, sourcesEdit_->toPlainText(), destsEdit_->toPlainText(),
                    feeEdit_->toPlainText(), u, warns, err)) {
        summaryLabel_->setText(QString("<b>Not ready:</b> %1%2").arg(err.toHtmlEscaped(), oeInfo));
        return;
    }

    std::uint64_t sum_in = 0, sum_out = 0;
    const bool balanced = cg::balance_ok(u.sources, u.dests, u.fee, sum_in, sum_out);

    QString html;
    html += QString("Sources (frozen rings): %1 &nbsp; Σin = %2<br>")
                .arg(int(u.sources.size())).arg(QString::fromStdString(cg::both_units(sum_in)));
    for (const auto& s : u.sources)
        html += QString("&nbsp;&nbsp;• ring %1, real_index %2 — %3<br>")
                    .arg(int(s.ring.size())).arg(int(s.real_index)).arg(QString::fromStdString(cg::both_units(s.amount)));
    html += QString("Destinations: %1 &nbsp; Σout = %2<br>")
                .arg(int(u.dests.size())).arg(QString::fromStdString(cg::both_units(sum_out)));
    for (const auto& d : u.dests)
        html += QString("&nbsp;&nbsp;• %1 %2<br>")
                    .arg(QString::fromStdString(cg::both_units(d.amount)), d.is_subaddress ? QStringLiteral("[subaddress]") : QString());
    html += QString("Fee = %1<br>").arg(QString::fromStdString(cg::both_units(u.fee)));
    html += QString("<b>Balance gate:</b> Σin (%1) %2 Σout+fee (%3)<br>")
                .arg(QString::number(qulonglong(sum_in)),
                     balanced ? QStringLiteral("==") : QStringLiteral("≠"),
                     QString::number(qulonglong(sum_out + u.fee)));
    for (const QString& w : warns)
        html += QString("<span style='color:#8a5a00'>note: %1</span><br>").arg(w.toHtmlEscaped());
    html += oeInfo;

    if (!balanced) {
        summaryLabel_->setText(html + QStringLiteral("<br><b style='color:#b00020'>Blocked:</b> "
                                                     "not balanced — Σsources must equal Σdestinations + fee."));
        return;
    }
    summaryLabel_->setText(html + QStringLiteral("<br><b style='color:#0a6'>Balanced — ready to assemble.</b>"));
    assembleBtn_->setEnabled(true);
}

void PageBuildTxMonero::onAssemble()
{
    output_->clear();
    const xm::Network net = net_of(netCombo_->currentText());

    art::UnsignedTxSet u; QStringList warns; QString err;
    if (!parse_form(net, sourcesEdit_->toPlainText(), destsEdit_->toPlainText(),
                    feeEdit_->toPlainText(), u, warns, err)) {
        output_->appendPlainText(QString("Refused: %1").arg(err));
        return;
    }
    std::uint64_t sum_in = 0, sum_out = 0;
    if (!cg::balance_ok(u.sources, u.dests, u.fee, sum_in, sum_out)) {
        output_->appendPlainText(QStringLiteral("Refused: unbalanced (Σsources != Σdests + fee)."));
        return;
    }

    Bytes blob = art::produce_unsigned_txset(u);
    if (blob.empty()) { output_->appendPlainText(QStringLiteral("Refused: produce_unsigned_txset returned no bytes.")); return; }

    lastArtifact_ = to_hex(blob);
    artifactEdit_->setPlainText(lastArtifact_);
    saveBtn_->setEnabled(true);

    const xm::Bytes32 dg = xm::mcrypto::keccak256(blob.data(), blob.size());

    output_->appendPlainText(QStringLiteral("Assembled unsigned_txset OK."));
    output_->appendPlainText(QString("blob bytes    : %1").arg(int(blob.size())));
    output_->appendPlainText(QString("keccak256(blob): %1").arg(to_hex32(dg)));
    output_->appendPlainText(QStringLiteral("\nCarry the unsigned_txset above to the offline signer (Sign & Self-Verify — Monero)."));
}

void PageBuildTxMonero::onSaveArtifact()
{
    if (lastArtifact_.isEmpty()) return;
    const QString path = QFileDialog::getSaveFileName(this, QStringLiteral("Save unsigned_txset"),
                                                      QStringLiteral("unsigned.xmr.c2wtx"),
                                                      QStringLiteral("c2wallet tx (*.c2wtx);;All files (*)"));
    if (path.isEmpty()) return;
    QFile fl(path);
    if (!fl.open(QIODevice::WriteOnly | QIODevice::Text)) {
        output_->appendPlainText(QString("Could not write %1").arg(path));
        return;
    }
    fl.write(lastArtifact_.toUtf8());
    fl.write("\n");
    fl.close();
    output_->appendPlainText(QString("Saved unsigned_txset to %1").arg(path));
}
