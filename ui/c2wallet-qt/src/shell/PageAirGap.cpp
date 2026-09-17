// SPDX-License-Identifier: AGPL-3.0-or-later
#include "shell/PageAirGap.hpp"

#include <QComboBox>
#include <QFile>
#include <QFileDialog>
#include <QFont>
#include <QFormLayout>
#include <QGroupBox>
#include <QGuiApplication>
#include <QClipboard>
#include <QHBoxLayout>
#include <QImage>
#include <QLabel>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

// c2w::artifact::SignedContainer::emit() collides with Qt's `emit` keyword
// macro. This page raises no Qt signals of its own, so drop the macro before
// the artifact headers (every Qt header is already included above).
#undef emit

#include <array>
#include <cstdint>
#include <string>
#include <vector>

// std-only artifact headers (no Qt, no btclibs uint256/hash headers pulled).
#include "family/bitcoin/artifact/Digest.hpp"
#include "family/bitcoin/artifact/TransferContainer.hpp"
#include "family/bitcoin/artifact/QrTransport.hpp"
#include "family/bitcoin/artifact/QrRender.hpp"
#include "family/bitcoin/artifact/TxIntrospect.hpp"

// Family B (Monero) transport artifacts + the keccak digest primitive.
#include "family/monero/artifact/MoneroArtifact.hpp"
#include "family/monero/MoneroCrypto.hpp"

namespace art = c2w::artifact;
namespace mart = c2wallet::monero::artifact;
namespace mcrypto = c2wallet::monero::mcrypto;

namespace {

using Bytes = std::vector<uint8_t>;

// The per-frame QR chunk (payload bytes). A 256-byte chunk yields a ~600-char
// text frame that fits comfortably inside a mid-version QR symbol, and the
// 100 kB oversize ceiling bounds the resulting frame count.
constexpr size_t kQrChunk = 256;

QString hexq(const Bytes& v) {
    static const char* d = "0123456789abcdef";
    QString s; s.reserve(int(v.size()) * 2);
    for (uint8_t b : v) { s.append(QChar(d[b >> 4])); s.append(QChar(d[b & 0xf])); }
    return s;
}
QString hexq(const std::array<uint8_t, 32>& h) {
    return hexq(Bytes(h.begin(), h.end()));
}
bool from_hex_q(const QString& in, Bytes& out) {
    std::string s = in.toStdString();
    // strip all whitespace (a pasted hex blob may be wrapped)
    std::string c;
    c.reserve(s.size());
    for (char ch : s) if (!std::isspace(static_cast<unsigned char>(ch))) c.push_back(ch);
    auto v = art::from_hex(c);
    if (!v) return false;
    out = *v;
    return true;
}
bool is_pure_hex(const QString& in) {
    std::string s = in.toStdString();
    size_t n = 0;
    for (char ch : s) {
        if (std::isspace(static_cast<unsigned char>(ch))) continue;
        const bool ok = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
        if (!ok) return false;
        ++n;
    }
    return n > 0 && (n % 2 == 0);
}

// A QR frame line starts with the c2wqr/1| prefix.
bool looks_like_frames(const QString& text) {
    const QStringList lines = text.split('\n');
    for (const QString& l : lines)
        if (l.trimmed().startsWith(QStringLiteral("c2wqr/1|"))) return true;
    return false;
}

// Render a QR module matrix into a crisp QImage with a 4-module quiet zone.
QImage qr_to_image(const art::QrModules& m) {
    if (!m.ok()) return QImage();
    const int quiet = 4;
    const int dim = m.size + quiet * 2;
    QImage img(dim, dim, QImage::Format_RGB32);
    img.fill(qRgb(255, 255, 255));
    for (int y = 0; y < m.size; ++y)
        for (int x = 0; x < m.size; ++x)
            if (m.at(x, y))
                img.setPixel(x + quiet, y + quiet, qRgb(0, 0, 0));
    return img;
}

} // namespace

PageAirGap::PageAirGap(QWidget* parent) : QWidget(parent)
{
    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 24, 24, 24);
    v->setSpacing(10);

    auto* heading = new QLabel(QStringLiteral("Air-Gap Transfer (marshals bytes across the diode — never signs)"), this);
    QFont hf = heading->font(); hf.setPointSize(hf.pointSize() + 6); hf.setBold(true);
    heading->setFont(hf);
    v->addWidget(heading);

    auto* note = new QLabel(
        QStringLiteral("File (QFile) or multi-frame animated QR (GAP-8). NO CAMERA — QR input is "
                       "paste / file / keyboard-wedge frame text only. The corruption ladder and the "
                       "unsigned&#8596;signed confusion guard run on every load."), this);
    note->setWordWrap(true);
    note->setTextFormat(Qt::RichText);
    v->addWidget(note);

    // ── Family + direction selectors ────────────────────────────────────────
    auto* form = new QFormLayout();
    familyCombo_ = new QComboBox(this);
    familyCombo_->addItem(QStringLiteral("Bitcoin-script (Family A)"));
    familyCombo_->addItem(QStringLiteral("Monero (Family B)"));
    form->addRow(QStringLiteral("Family:"), familyCombo_);

    dirCombo_ = new QComboBox(this);
    dirCombo_->addItem(QStringLiteral("Import unsigned  (online → offline)"));
    dirCombo_->addItem(QStringLiteral("Export signed  (offline → online)"));
    dirCombo_->addItem(QStringLiteral("Export unsigned  (offline-built → online dry-run)"));
    form->addRow(QStringLiteral("Direction:"), dirCombo_);
    v->addLayout(form);

    // ── Input slot (colour-coded by unsigned vs signed) ─────────────────────
    inputBox_ = new QGroupBox(QStringLiteral("Input"), this);
    auto* inv = new QVBoxLayout(inputBox_);
    slotBadge_ = new QLabel(inputBox_);
    slotBadge_->setTextFormat(Qt::RichText);
    inv->addWidget(slotBadge_);
    inputEdit_ = new QPlainTextEdit(inputBox_);
    inputEdit_->setFont(QFont(QStringLiteral("monospace")));
    inputEdit_->setMaximumHeight(120);
    inv->addWidget(inputEdit_);
    auto* inBtns = new QHBoxLayout();
    loadBtn_ = new QPushButton(QStringLiteral("Load from file…"), inputBox_);
    decodeBtn_ = new QPushButton(QStringLiteral("Decode + validate"), inputBox_);
    inBtns->addWidget(loadBtn_);
    inBtns->addWidget(decodeBtn_);
    inBtns->addStretch(1);
    inv->addLayout(inBtns);
    v->addWidget(inputBox_);

    // ── Corruption / confusion ladder card ──────────────────────────────────
    cardLabel_ = new QLabel(this);
    cardLabel_->setTextFormat(Qt::RichText);
    cardLabel_->setWordWrap(true);
    cardLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    cardLabel_->setStyleSheet(QStringLiteral("border:1px solid #bbb; border-radius:4px; padding:8px;"));
    v->addWidget(cardLabel_);

    // ── Export panel (file + animated QR) ───────────────────────────────────
    exportBox_ = new QGroupBox(QStringLiteral("Transport the validated payload"), this);
    auto* ev = new QVBoxLayout(exportBox_);
    auto* row = new QHBoxLayout();
    qrView_ = new QLabel(exportBox_);
    qrView_->setFixedSize(360, 360);
    qrView_->setAlignment(Qt::AlignCenter);
    qrView_->setStyleSheet(QStringLiteral("background:#fff; border:1px solid #ccc;"));
    qrView_->setText(QStringLiteral("(QR appears after a successful decode)"));
    row->addWidget(qrView_);
    auto* rcol = new QVBoxLayout();
    frameLabel_ = new QLabel(exportBox_);
    frameLabel_->setTextFormat(Qt::RichText);
    frameLabel_->setWordWrap(true);
    rcol->addWidget(frameLabel_);
    animBtn_ = new QPushButton(QStringLiteral("Play frames"), exportBox_);
    rcol->addWidget(animBtn_);
    copyFramesBtn_ = new QPushButton(QStringLiteral("Copy all frame lines"), exportBox_);
    rcol->addWidget(copyFramesBtn_);
    saveBtn_ = new QPushButton(QStringLiteral("Save payload to file…"), exportBox_);
    rcol->addWidget(saveBtn_);
    rcol->addStretch(1);
    row->addLayout(rcol, 1);
    ev->addLayout(row);
    v->addWidget(exportBox_);

    v->addStretch(1);

    qrTimer_ = new QTimer(this);
    qrTimer_->setInterval(600);

    connect(familyCombo_, &QComboBox::currentIndexChanged, this, &PageAirGap::onModeChanged);
    connect(dirCombo_, &QComboBox::currentIndexChanged, this, &PageAirGap::onModeChanged);
    connect(loadBtn_, &QPushButton::clicked, this, &PageAirGap::onLoadFile);
    connect(decodeBtn_, &QPushButton::clicked, this, &PageAirGap::onDecode);
    connect(saveBtn_, &QPushButton::clicked, this, &PageAirGap::onSaveExport);
    connect(copyFramesBtn_, &QPushButton::clicked, this, &PageAirGap::onCopyFrames);
    connect(animBtn_, &QPushButton::clicked, this, &PageAirGap::onToggleAnim);
    connect(qrTimer_, &QTimer::timeout, this, &PageAirGap::onTick);

    onModeChanged();
    resetValidated();
}

PageAirGap::~PageAirGap() = default;

int  PageAirGap::family() const { return familyCombo_ ? familyCombo_->currentIndex() : 0; }
int  PageAirGap::direction() const { return dirCombo_ ? dirCombo_->currentIndex() : 0; }
bool PageAirGap::isSignedSlot() const { return direction() == 1; }

void PageAirGap::resetValidated()
{
    validated_ = false;
    payload_.clear();
    frames_.clear();
    curFrame_ = 0;
    if (qrTimer_) qrTimer_->stop();
    if (animBtn_) animBtn_->setText(QStringLiteral("Play frames"));
    if (qrView_) { qrView_->setPixmap(QPixmap()); qrView_->setText(QStringLiteral("(QR appears after a successful decode)")); }
    if (frameLabel_) frameLabel_->clear();
    if (saveBtn_) saveBtn_->setEnabled(false);
    if (copyFramesBtn_) copyFramesBtn_->setEnabled(false);
    if (animBtn_) animBtn_->setEnabled(false);
}

void PageAirGap::onModeChanged()
{
    resetValidated();
    cardLabel_->clear();

    const bool signedSlot = isSignedSlot();
    // Two visually distinct slots (confusion guard, T-*): unsigned = blue,
    // signed = green.
    if (signedSlot) {
        slotBadge_->setText(QStringLiteral(
            "<span style='color:#fff;background:#0a6;font-weight:bold;padding:2px 6px;border-radius:3px'>"
            "SIGNED slot</span> &nbsp; a finished, fully-signed transaction for the online loader. "
            "Every input must carry a scriptSig / witness; a C2WU container is refused here."));
        inputBox_->setStyleSheet(QStringLiteral("QGroupBox{border:2px solid #0a6;border-radius:5px;margin-top:8px;padding-top:6px;} QGroupBox::title{subcontrol-origin:margin;left:8px;}"));
    } else {
        slotBadge_->setText(QStringLiteral(
            "<span style='color:#fff;background:#2266cc;font-weight:bold;padding:2px 6px;border-radius:3px'>"
            "UNSIGNED slot</span> &nbsp; a constructed, NOT-yet-signed artifact. "
            "The C2WU container magic (or the Monero unsigned-txset magic) is required here."));
        inputBox_->setStyleSheet(QStringLiteral("QGroupBox{border:2px solid #2266cc;border-radius:5px;margin-top:8px;padding-top:6px;} QGroupBox::title{subcontrol-origin:margin;left:8px;}"));
    }

    if (family() == 0) {
        inputEdit_->setPlaceholderText(signedSlot
            ? QStringLiteral("paste the signed artifact (one raw signed tx hex per line), or QR frame lines, or Load from file")
            : QStringLiteral("paste the unsigned container hex (.c2wu), or QR frame lines, or Load from file"));
    } else {
        inputEdit_->setPlaceholderText(QStringLiteral(
            "Monero blobs are binary: use Load from file (.unsigned_txset / .signed_txset), or paste QR frame lines / the blob as hex"));
    }
}

void PageAirGap::onLoadFile()
{
    QString filter;
    if (family() == 0)
        filter = isSignedSlot() ? QStringLiteral("signed tx (*.txs);;All files (*)")
                                : QStringLiteral("unsigned container (*.c2wu);;All files (*)");
    else
        filter = isSignedSlot() ? QStringLiteral("Monero signed txset (*.signed_txset);;All files (*)")
                                : QStringLiteral("Monero unsigned txset (*.unsigned_txset);;All files (*)");

    const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("Load transfer artifact"), QString(), filter);
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        cardLabel_->setText(QString("<b style='color:#b00020'>Could not read</b> %1").arg(path.toHtmlEscaped()));
        return;
    }
    const QByteArray all = f.readAll();
    f.close();

    if (family() == 0) {
        // Family A artifacts are text (hex / one-hex-per-line).
        inputEdit_->setPlainText(QString::fromUtf8(all).trimmed());
    } else {
        // Family B blobs are binary — show as hex so the single hex/QR input
        // path can consume them and they stay inspectable.
        Bytes raw(all.begin(), all.end());
        inputEdit_->setPlainText(hexq(raw));
    }
    onDecode();
}

void PageAirGap::onDecode()
{
    resetValidated();
    const QString text = inputEdit_->toPlainText().trimmed();
    if (text.isEmpty()) { cardLabel_->setText(QStringLiteral("Paste or load an artifact first.")); return; }

    QString ladder; // accumulate the corruption-ladder rungs we passed
    Bytes raw;      // the artifact payload bytes

    // ── Rung 1: QR per-frame sha256 (only if the input is frame text) ────────
    if (looks_like_frames(text)) {
        std::vector<std::string> frames;
        const QStringList lines = text.split('\n');
        for (const QString& l : lines) {
            const QString t = l.trimmed();
            if (t.startsWith(QStringLiteral("c2wqr/1|"))) frames.push_back(t.toStdString());
        }
        art::QrDecodeResult d = art::qr_decode(frames);
        if (!d.ok) {
            cardLabel_->setText(QString("<b style='color:#b00020'>QR reassembly REFUSED:</b> %1"
                                        "<br><span style='color:#555'>(per-frame sha256 / missing seq / "
                                        "inconsistent total / conflicting duplicate)</span>")
                                    .arg(QString::fromStdString(d.error).toHtmlEscaped()));
            return;
        }
        raw = d.payload;
        ladder += QString("&#10003; QR: %1 frame(s) reassembled, every per-frame sha256 verified<br>")
                      .arg(int(frames.size()));
    } else if (family() == 0) {
        raw = Bytes(text.toUtf8().begin(), text.toUtf8().end());
    } else {
        // Family B direct input: accept the blob as hex.
        if (!from_hex_q(text, raw)) {
            cardLabel_->setText(QStringLiteral(
                "<b style='color:#b00020'>Monero input not understood.</b> Load the raw "
                ".unsigned_txset / .signed_txset file, or paste QR frame lines, or paste the blob as hex."));
            return;
        }
    }

    // ── Rungs 2..5: container / footer / confusion guard + human digest ──────
    if (family() == 0) {
        if (!isSignedSlot()) {
            // UNSIGNED slot: require the C2WU container (magic/version/TLV +
            // GAP-3 R_DIGEST). from_hex refuses a signed tx (bad magic) — the
            // confusion guard for this direction.
            const QString hex = QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(raw.data()), int(raw.size()))).trimmed();
            std::string err;
            auto oc = art::UnsignedContainer::from_hex(hex.toStdString(), err);
            if (!oc) {
                cardLabel_->setText(ladder + QString("<b style='color:#b00020'>UNSIGNED container REFUSED:</b> %1")
                                                 .arg(QString::fromStdString(err).toHtmlEscaped()));
                return;
            }
            // GAP-3 presence probe: to_hex appends [0x06][0x20][32]; detect it.
            Bytes cb;
            const bool haveDigest = from_hex_q(hex, cb) && cb.size() >= 34 &&
                                    cb[cb.size() - 34] == 0x06 && cb[cb.size() - 33] == 0x20;
            payload_ = Bytes(hex.toUtf8().begin(), hex.toUtf8().end());

            ladder += QStringLiteral("&#10003; container magic C2WU + version + TLV bounds OK<br>");
            ladder += haveDigest
                ? QStringLiteral("&#10003; GAP-3 R_DIGEST present and verified (a single flipped byte would have refused here)<br>")
                : QStringLiteral("&#9888; GAP-3 R_DIGEST ABSENT (older 2a container) — integrity rests on the sha256d compare only<br>");

            int nscript = int(oc->input_scripts.size());
            cardLabel_->setText(ladder +
                QString("<hr><b>Unsigned artifact — coin %1, %2 input(s), %3 output-metadata, %4 GAP-4 input-script(s)</b><br>")
                    .arg(QString::fromStdString(oc->coin).toHtmlEscaped())
                    .arg(int(oc->inputs.size())).arg(int(oc->inputs.size())).arg(nscript) +
                QString("<b>human digest (sha256d of the unsigned tx):</b><br><tt>%1</tt><br>")
                    .arg(QString::fromStdString(oc->unsigned_txid_display())) +
                QStringLiteral("<div style='color:#8a5a00;margin-top:6px'>Residual limit: beyond the QR and GAP-3 "
                               "digests, the only guard on the tx <i>semantics</i> (amounts/addresses) is your eyes on the "
                               "Sign-tab confirm card and comparing this sha256d on BOTH machines. A valid-but-wrong tx "
                               "that still parses is not caught here.</div>"));
        } else {
            // SIGNED slot: the c2pool loader format; every line must be a
            // plausible signed tx (scriptSig/witness on every input, NOT a
            // C2WU container).
            const QString txt = QString::fromUtf8(QByteArray(reinterpret_cast<const char*>(raw.data()), int(raw.size())));
            std::string err;
            auto sc = art::SignedContainer::parse(txt.toStdString(), err);
            if (!sc) {
                cardLabel_->setText(ladder + QString("<b style='color:#b00020'>SIGNED container REFUSED:</b> %1")
                                                 .arg(QString::fromStdString(err).toHtmlEscaped()));
                return;
            }
            QString rows;
            for (size_t i = 0; i < sc->tx_hexes.size(); ++i) {
                Bytes tb;
                from_hex_q(QString::fromStdString(sc->tx_hexes[i]), tb);
                std::string why;
                if (!art::accept_as_signed(tb, why)) {
                    cardLabel_->setText(ladder + QString("<b style='color:#b00020'>CONFUSION GUARD REFUSED tx #%1:</b> %2")
                                                     .arg(int(i)).arg(QString::fromStdString(why).toHtmlEscaped()));
                    return;
                }
                rows += QString("&nbsp;#%1 &nbsp;<tt>%2</tt><br>")
                            .arg(int(i)).arg(QString::fromStdString(art::sha256d_display(tb)));
            }
            payload_ = Bytes(txt.toUtf8().begin(), txt.toUtf8().end());
            ladder += QString("&#10003; %1 signed tx line(s) parsed (loader rules) + confusion guard PASSED "
                              "(scriptSig/witness on every input; not a container)<br>").arg(int(sc->tx_hexes.size()));
            cardLabel_->setText(ladder +
                QStringLiteral("<hr><b>Signed artifact — cross-gap sha256d txid(s):</b><br>") + rows +
                QStringLiteral("<div style='color:#8a5a00;margin-top:6px'>Residual limit: a syntactically valid signed "
                               "tx can still be the wrong one. Compare these sha256d values against the offline machine.</div>"));
        }
    } else {
        // ── Family B (Monero): keccak-footer envelope + magic ───────────────
        std::string err;
        art::Hash32 keccak{};
        {
            auto h = mcrypto::keccak256(raw.data(), raw.size());
            std::copy(h.begin(), h.end(), keccak.begin());
        }
        if (!isSignedSlot()) {
            mart::UnsignedTxSet u;
            if (!mart::parse_unsigned_txset(raw, u, err)) {
                cardLabel_->setText(ladder + QString("<b style='color:#b00020'>Monero UNSIGNED txset REFUSED:</b> %1"
                                                     "<br><span style='color:#555'>(magic or 8-byte keccak integrity footer)</span>")
                                                 .arg(QString::fromStdString(err).toHtmlEscaped()));
                return;
            }
            payload_ = raw;
            ladder += QStringLiteral("&#10003; Monero unsigned-txset magic + keccak integrity footer verified<br>");
            cardLabel_->setText(ladder +
                QString("<hr><b>Monero unsigned txset — %1 source(s), %2 destination(s), fee %3</b><br>")
                    .arg(int(u.sources.size())).arg(int(u.dests.size())).arg(qulonglong(u.fee)) +
                QString("<b>human digest (keccak-256 of the blob):</b><br><tt>%1</tt><br>").arg(hexq(keccak)) +
                QStringLiteral("<div style='color:#8a5a00;margin-top:6px'>Residual limit: the keccak footer stands in for "
                               "monero's chacha20 view-key MAC (byte-parity gap, MoneroArtifact.hpp) — it detects "
                               "corruption/truncation, not a re-sealed tampered blob. Confirm amounts in the Monero Sign tab "
                               "and compare this keccak digest on both machines.</div>"));
        } else {
            mart::SignedTxSet s;
            if (!mart::parse_signed_txset(raw, s, err)) {
                cardLabel_->setText(ladder + QString("<b style='color:#b00020'>Monero SIGNED txset REFUSED:</b> %1"
                                                     "<br><span style='color:#555'>(magic or 8-byte keccak integrity footer)</span>")
                                                 .arg(QString::fromStdString(err).toHtmlEscaped()));
                return;
            }
            payload_ = raw;
            ladder += QStringLiteral("&#10003; Monero signed-txset magic + keccak integrity footer verified<br>");
            cardLabel_->setText(ladder +
                QString("<hr><b>Monero signed txset — %1-byte tx blob, %2 key image(s)</b><br>")
                    .arg(int(s.tx_blob.size())).arg(int(s.key_images.size())) +
                QString("<b>tx_hash:</b> <tt>%1</tt><br>").arg(hexq(s.tx_hash)) +
                QString("<b>human digest (keccak-256 of the blob):</b><br><tt>%1</tt><br>").arg(hexq(keccak)) +
                QStringLiteral("<div style='color:#8a5a00;margin-top:6px'>Residual limit: as above, the keccak footer is a "
                               "corruption check, not an authenticated MAC. Compare tx_hash / keccak on both machines.</div>"));
        }
    }

    // ── Build the QR frames of the validated payload ─────────────────────────
    validated_ = true;
    saveBtn_->setEnabled(true);
    art::QrEncodeResult enc = art::qr_encode(payload_, kQrChunk);
    if (!enc.ok) {
        frames_.clear();
        frameLabel_->setText(QString("<span style='color:#b00020'>QR unavailable: %1</span> — use file transport.")
                                 .arg(QString::fromStdString(enc.error).toHtmlEscaped()));
        return;
    }
    frames_ = enc.frames;
    curFrame_ = 0;
    copyFramesBtn_->setEnabled(true);
    animBtn_->setEnabled(frames_.size() > 1);
    showFrame(0);
}

void PageAirGap::showFrame(int i)
{
    if (frames_.empty()) return;
    if (i < 0) i = 0;
    if (i >= int(frames_.size())) i = int(frames_.size()) - 1;
    curFrame_ = i;

    const std::string& frameText = frames_[size_t(i)];
    art::QrModules m = art::qr_render_modules(frameText);
    QImage img = qr_to_image(m);
    if (!img.isNull()) {
        QPixmap pm = QPixmap::fromImage(img).scaled(qrView_->size(), Qt::KeepAspectRatio, Qt::FastTransformation);
        qrView_->setPixmap(pm);
    } else {
        qrView_->setText(QStringLiteral("(frame too large to render as one QR)"));
    }

    // Per-frame chunk digest (the value stamped into the frame text itself).
    std::string errf;
    auto fr = art::QrFrame::from_text(frameText, errf);
    QString digest = fr ? QString::fromStdString(art::to_hex(fr->chunk_digest)).left(16) + "…"
                        : QStringLiteral("(?)");
    frameLabel_->setText(QString("<b>frame %1 / %2</b><br>chunk sha256 = <tt>%3</tt><br>"
                                 "<span style='color:#555'>%4 total frame(s); each frame is public data.</span>")
                             .arg(i + 1).arg(int(frames_.size())).arg(digest).arg(int(frames_.size())));
}

void PageAirGap::onToggleAnim()
{
    if (frames_.size() < 2) return;
    if (qrTimer_->isActive()) {
        qrTimer_->stop();
        animBtn_->setText(QStringLiteral("Play frames"));
    } else {
        qrTimer_->start();
        animBtn_->setText(QStringLiteral("Pause"));
    }
}

void PageAirGap::onTick()
{
    if (frames_.empty()) return;
    showFrame((curFrame_ + 1) % int(frames_.size()));
}

void PageAirGap::onCopyFrames()
{
    if (frames_.empty()) return;
    QString all;
    for (const auto& f : frames_) { all += QString::fromStdString(f); all += '\n'; }
    QGuiApplication::clipboard()->setText(all);
    frameLabel_->setText(frameLabel_->text() + QStringLiteral("<br><span style='color:#0a6'>copied all frame lines to the clipboard.</span>"));
}

void PageAirGap::onSaveExport()
{
    if (!validated_ || payload_.empty()) return;
    QString def, filter;
    if (family() == 0) {
        if (isSignedSlot()) { def = QStringLiteral("transfer.txs"); filter = QStringLiteral("signed tx (*.txs);;All files (*)"); }
        else                { def = QStringLiteral("transfer.c2wu"); filter = QStringLiteral("unsigned container (*.c2wu);;All files (*)"); }
    } else {
        if (isSignedSlot()) { def = QStringLiteral("transfer.signed_txset"); filter = QStringLiteral("Monero signed txset (*.signed_txset);;All files (*)"); }
        else                { def = QStringLiteral("transfer.unsigned_txset"); filter = QStringLiteral("Monero unsigned txset (*.unsigned_txset);;All files (*)"); }
    }
    const QString path = QFileDialog::getSaveFileName(this, QStringLiteral("Save payload"), def, filter);
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) {
        cardLabel_->setText(cardLabel_->text() + QString("<br><span style='color:#b00020'>Could not write %1</span>").arg(path.toHtmlEscaped()));
        return;
    }
    f.write(reinterpret_cast<const char*>(payload_.data()), qint64(payload_.size()));
    f.close();
    cardLabel_->setText(cardLabel_->text() + QString("<br><span style='color:#0a6'>saved %1 byte(s) to %2</span>")
                                                 .arg(qulonglong(payload_.size())).arg(path.toHtmlEscaped()));
}
