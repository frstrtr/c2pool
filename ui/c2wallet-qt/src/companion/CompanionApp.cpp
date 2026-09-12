// SPDX-License-Identifier: AGPL-3.0-or-later
//
// c2wallet-qt-companion — the ONLINE, KEY-FREE companion GUI (design §5.2).
//
// This is a SEPARATE binary from the network-incapable signer. Unlike the
// signer (which links Qt6::Core/Gui/Widgets ONLY so a socket is a link error),
// the companion is the ONLINE side and MAY link the network: it links
// Qt6::Network to host the loopback validate/submit seam. It still holds NO
// keys — all crypto lives in the offline signer. The GUI wires the key-free
// companion library:
//   * PRODUCE : funding JSON  -> M5-A UnsignedContainer hex + cross-gap digest;
//   * SUBMIT  : signed artifact -> write the --pin-local-tx-hex FILE the node
//               loads (primary proven seam) + validate_inject dry-run;
//   * QR      : reassemble the signed artifact from scanned animated-QR frames.

#include "FundingData.hpp"
#include "Produce.hpp"
#include "Submit.hpp"
#include "ValidateClient.hpp"
#include "QrReassembly.hpp"

#include "Digest.hpp"
#include "TransferContainer.hpp"

#include <QApplication>
#include <QFileDialog>
#include <QLabel>
#include <QMainWindow>
#include <QNetworkAccessManager> // online side: network-capable (contrast the signer)
#include <QPlainTextEdit>
#include <QPushButton>
#include <QString>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QWidget>

#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace {

// A Qt-network-backed transport home for the loopback validate_inject seam.
// DISARMED by default (money-path discipline §5.5); even armed, the online
// node's validate_inject endpoint is cross-lane and not on master, so the real
// POST is deliberately left unwired. Its mere presence makes the companion the
// network-capable online binary — the concrete contrast to the signer's
// network-incapable link-guard.
struct QtLoopbackTransport : c2w::companion::NodeTransport {
    QNetworkAccessManager nam;
    bool armed = false;
    bool send(const std::string& /*req*/, std::string& /*resp*/, std::string& err) override {
        if (!armed) { err = "loopback-http-disarmed"; return false; }
        err = "loopback-http-seam-unwired"; // cross-lane endpoint not on master
        return false;
    }
    const char* name() const override { return "qt-loopback-http"; }
};

QString qstr(const std::string& s) { return QString::fromStdString(s); }
std::string sstr(const QString& s) { return s.toStdString(); }

} // namespace

int main(int argc, char** argv) {
    QApplication app(argc, argv);

    QMainWindow win;
    win.setWindowTitle("c2wallet-qt companion (online, key-free)");
    auto* tabs = new QTabWidget(&win);
    win.setCentralWidget(tabs);

    // The online-side network transport. Instantiating it constructs a live
    // QNetworkAccessManager, so this binary genuinely LINKS Qt6::Network — the
    // deliberate contrast to the network-incapable signer. The validate/submit
    // POST is a loopback-only, armed-flag-gated seam (disarmed by default).
    auto loopback = std::make_shared<QtLoopbackTransport>();

    // ── PRODUCE tab ──────────────────────────────────────────────────────────
    {
        auto* page = new QWidget;
        auto* lay = new QVBoxLayout(page);
        lay->addWidget(new QLabel("Funding JSON (UTXOs + outputs + coin/network) — NO keys:"));
        auto* in = new QPlainTextEdit;
        in->setPlaceholderText("{ \"coin\":\"btc\", \"algebra\":\"bip143\", \"inputs\":[...], \"outputs\":[...] }");
        lay->addWidget(in);
        auto* btn = new QPushButton("Build unsigned artifact (online -> offline)");
        lay->addWidget(btn);
        auto* out = new QPlainTextEdit;
        out->setReadOnly(true);
        lay->addWidget(out);

        QObject::connect(btn, &QPushButton::clicked, [in, out]() {
            std::string err;
            auto fd = c2w::companion::FundingData::from_json(sstr(in->toPlainText()), err);
            if (!fd) { out->setPlainText(qstr("funding JSON error: " + err)); return; }
            auto c = c2w::companion::produce_unsigned(*fd, err);
            if (!c) { out->setPlainText(qstr("produce error: " + err)); return; }
            std::string hex = c->to_hex(err);
            if (hex.empty()) { out->setPlainText(qstr("to_hex error: " + err)); return; }
            std::string text =
                "UNSIGNED ARTIFACT (hex, hand to the offline signer):\n" + hex +
                "\n\nunsigned-tx cross-gap digest (compare on both sides):\n" +
                c->unsigned_txid_display();
            out->setPlainText(qstr(text));
        });
        tabs->addTab(page, "Produce");
    }

    // ── SUBMIT tab ───────────────────────────────────────────────────────────
    {
        auto* page = new QWidget;
        auto* lay = new QVBoxLayout(page);
        lay->addWidget(new QLabel("Signed artifact from the offline signer (one raw hex per line):"));
        auto* in = new QPlainTextEdit;
        lay->addWidget(in);
        auto* writeBtn = new QPushButton("Write --pin-local-tx-hex file (the node loads this)");
        lay->addWidget(writeBtn);
        auto* dryBtn = new QPushButton("validate_inject dry-run (read-only, tap-free)");
        lay->addWidget(dryBtn);
        lay->addWidget(new QLabel(QString("loopback node seam: ") + loopback->name() +
                                  (loopback->armed ? " (ARMED)" : " (disarmed — file seam is primary)")));
        auto* out = new QPlainTextEdit;
        out->setReadOnly(true);
        lay->addWidget(out);

        QObject::connect(writeBtn, &QPushButton::clicked, [in, out, &win]() {
            std::string err;
            auto sc = c2w::companion::parse_signed_artifact(sstr(in->toPlainText()), err);
            if (!sc) { out->setPlainText(qstr("parse error: " + err)); return; }
            QString path = QFileDialog::getSaveFileName(&win, "Write pin-local-tx-hex file");
            if (path.isEmpty()) return;
            if (!c2w::companion::write_pin_local_tx_file(sstr(path), *sc, err)) {
                out->setPlainText(qstr("write error: " + err)); return;
            }
            std::string text = "Wrote " + std::to_string(sc->tx_hexes.size()) +
                               " tx(es) to:\n" + sstr(path) + "\n\ntxids:\n";
            for (const auto& t : sc->txid_displays()) text += "  " + t + "\n";
            out->setPlainText(qstr(text));
        });

        QObject::connect(dryBtn, &QPushButton::clicked, [in, out]() {
            std::string err;
            auto sc = c2w::companion::parse_signed_artifact(sstr(in->toPlainText()), err);
            if (!sc) { out->setPlainText(qstr("parse error: " + err)); return; }
            c2w::companion::ValidateInjectClient client(
                std::make_shared<c2w::companion::UnwiredTransport>());
            std::string text;
            for (const auto& tx : sc->tx_hexes) {
                auto r = client.validate_dry_run("btc", tx);
                text += r.display + "\n";
            }
            out->setPlainText(qstr(text));
        });
        tabs->addTab(page, "Submit");
    }

    // ── QR tab ───────────────────────────────────────────────────────────────
    {
        auto* page = new QWidget;
        auto* lay = new QVBoxLayout(page);
        lay->addWidget(new QLabel("Scanned animated-QR frames of the signed artifact (one per line):"));
        auto* in = new QPlainTextEdit;
        lay->addWidget(in);
        auto* btn = new QPushButton("Reassemble signed artifact");
        lay->addWidget(btn);
        auto* out = new QPlainTextEdit;
        out->setReadOnly(true);
        lay->addWidget(out);

        QObject::connect(btn, &QPushButton::clicked, [in, out]() {
            std::vector<std::string> frames;
            std::istringstream is(sstr(in->toPlainText()));
            std::string line;
            while (std::getline(is, line)) {
                if (!line.empty()) frames.push_back(line);
            }
            std::string err;
            auto sc = c2w::companion::reassemble_signed_from_qr(frames, err);
            if (!sc) { out->setPlainText(qstr("reassembly error: " + err)); return; }
            std::string text = "Reassembled " + std::to_string(sc->tx_hexes.size()) + " tx(es):\n";
            for (const auto& t : sc->tx_hexes) text += t + "\n";
            out->setPlainText(qstr(text));
        });
        tabs->addTab(page, "QR reassembly");
    }

    win.resize(760, 560);
    win.show();
    return app.exec();
}
