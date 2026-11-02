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
//   * SCAN & PLAN (slice S-C): scan an address (dashd and/or the node), write
//               the files the offline signer imports, then preflight and
//               queue the signed pair the operator brings back. It runs the
//               headless scheduler's own command line (sched::cli::run) in a
//               worker thread; it never signs and never arms the node.

#include "FundingData.hpp"
#include "Produce.hpp"
#include "Submit.hpp"
#include "ValidateClient.hpp"
#include "QrReassembly.hpp"

#include "Digest.hpp"
#include "TransferContainer.hpp"

#include "scan/QtRpcApi.hpp"
#include "sched/Clock.hpp"
#include "sched/QtNodeApi.hpp"
#include "sched/SchedCli.hpp"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QSpinBox>
#include <QThread>
#include <QMainWindow>
#include <QNetworkAccessManager> // online side: network-capable (contrast the signer)
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QString>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QWidget>

#include <atomic>
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

// Run one c2wallet-qt-schedd command line (the daemon's own sched::cli::run)
// in a worker thread: the Qt transports are created there, the output is
// appended to `out` when it finishes, and `cancel` is the operator's Cancel
// (it aborts a running scantxoutset and drops a node scan request).
void run_cli(QPlainTextEdit* out, std::vector<QPushButton*> buttons, std::shared_ptr<std::atomic<bool>> cancel,
             std::vector<std::string> args)
{
    namespace sched = c2w::companion::sched;
    for (QPushButton* b : buttons) b->setEnabled(false);
    cancel->store(false);
    std::string shown = "c2wallet-qt-schedd";
    for (const std::string& a : args) shown += " " + a;
    out->setPlainText(qstr("running: " + shown + "\n"));
    QThread* t = QThread::create([out, buttons, cancel, args]() {
        std::ostringstream os;
        sched::SystemClock clock;
        sched::cli::Env env;
        env.out = &os;
        env.err = &os;
        env.clock = &clock;
        env.make_api = [](const std::string& url, std::string& why) -> std::unique_ptr<sched::NodeApi> {
            return sched::QtNodeApi::create(url, why);
        };
        env.make_scan_api = [cancel](const std::string& url, std::string& why) -> std::unique_ptr<sched::NodeApi> {
            auto api = sched::QtNodeApi::create(url, why, 130000);
            if (api) api->set_stop_check([cancel] { return cancel->load(); });
            return api;
        };
        env.make_rpc = [](const std::string& url, const std::string& auth,
                          std::string& why) -> std::unique_ptr<c2w::companion::scan::RpcApi> {
            return c2w::companion::scan::QtRpcApi::create(url, auth, why);
        };
        env.sleep_ms = [](int64_t) {};
        env.stop_requested = [cancel] { return cancel->load(); };
        const int rc = sched::cli::run(args, env);
        const QString text = qstr(os.str() + "\n(exit " + std::to_string(rc) + ")\n");
        QMetaObject::invokeMethod(
            out,
            [out, buttons, text] {
                out->appendPlainText(text);
                for (QPushButton* b : buttons) b->setEnabled(true);
            },
            Qt::QueuedConnection);
    });
    QObject::connect(t, &QThread::finished, t, &QObject::deleteLater);
    t->start();
}

std::vector<std::string> words(const QString& s)
{
    std::vector<std::string> v;
    for (const QString& w : s.split(QRegularExpression(QStringLiteral("[\\s,]+")), Qt::SkipEmptyParts))
        v.push_back(sstr(w));
    return v;
}

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

    // ── SCAN & PLAN tab (slice S-C) ─────────────────────────────────────────
    {
        auto* page = new QWidget;
        auto* lay = new QVBoxLayout(page);
        lay->addWidget(new QLabel(
            "Scan an address, write the files the OFFLINE signer imports, then bring back the signed pair.\n"
            "This tab never signs and never arms the node: it writes files and queues signed txs."));
        auto* form = new QFormLayout;
        auto* addresses = new QLineEdit;
        addresses->setPlaceholderText("XdgF55... (up to 16, space separated)");
        auto* source = new QComboBox;
        source->addItems({"both", "dashd", "c2pool"});
        auto* dashdUrl = new QLineEdit("http://127.0.0.1:9998");
        auto* authFile = new QLineEdit;
        authFile->setPlaceholderText("0600 file: dashd .cookie or user:password (never typed here)");
        auto* nodeUrl = new QLineEdit("http://127.0.0.1:8080");
        auto* single = new QCheckBox("allow a single source when the other cannot serve (not cross-checked)");
        auto* mode = new QComboBox;
        mode->addItems({"consolidate", "collateral"});
        auto* govHash = new QLineEdit;
        govHash->setPlaceholderText("collateral: the 64-hex hash `gobject check` prints");
        auto* feeMode = new QComboBox;
        feeMode->addItems({"inject", "relay"});
        auto* feeRate = new QSpinBox;
        feeRate->setRange(1, 100);
        auto* keyEnc = new QComboBox;
        keyEnc->addItems({"unknown", "compressed", "uncompressed"});
        auto* maxInputs = new QSpinBox;
        maxInputs->setRange(0, 1000);
        maxInputs->setSpecialValueText("node cap (1000)");
        auto* outName = new QLineEdit;
        outName->setPlaceholderText("path/name (writes name.utxos.json, name.scanplan.json, name.report.txt)");
        auto* c2wu = new QCheckBox("also write name.c2wu.hex (generic Air-Gap route)");
        form->addRow("addresses", addresses);
        form->addRow("source", source);
        form->addRow("dashd URL (loopback)", dashdUrl);
        form->addRow("dashd credentials file", authFile);
        form->addRow("node URL (loopback)", nodeUrl);
        form->addRow("", single);
        form->addRow("mode", mode);
        form->addRow("gov hash", govHash);
        form->addRow("fee mode", feeMode);
        form->addRow("relay fee rate (duffs/B)", feeRate);
        form->addRow("key encoding", keyEnc);
        form->addRow("max inputs per tx", maxInputs);
        form->addRow("output", outName);
        form->addRow("", c2wu);
        lay->addLayout(form);
        auto* row1 = new QHBoxLayout;
        auto* scanBtn = new QPushButton("Scan && write files for the signer");
        auto* cancelBtn = new QPushButton("Cancel");
        row1->addWidget(scanBtn);
        row1->addWidget(cancelBtn);
        lay->addLayout(row1);

        lay->addWidget(new QLabel("Signed pair from the offline signer:"));
        auto* form2 = new QFormLayout;
        auto* hexFile = new QLineEdit;
        hexFile->setPlaceholderText("name.hex (its name.manifest.json beside it)");
        auto* utxosFile = new QLineEdit;
        auto* scanplanFile = new QLineEdit;
        auto* queueFile = new QLineEdit(qstr(c2w::companion::sched::cli::default_queue_path()));
        auto* tokenFile = new QLineEdit;
        tokenFile->setPlaceholderText("the node's 0600 control-token file (for the dry run and the queue)");
        auto* parents = new QLineEdit;
        parents->setPlaceholderText("stage 2: the stage-1 txids (--after-parent)");
        auto* force = new QLineEdit;
        force->setPlaceholderText("empty, or the reason to queue despite a dry-run cause (journaled)");
        form2->addRow("signed hex", hexFile);
        form2->addRow("utxos file", utxosFile);
        form2->addRow("scan-plan sidecar", scanplanFile);
        form2->addRow("queue", queueFile);
        form2->addRow("token file", tokenFile);
        form2->addRow("after parents", parents);
        form2->addRow("force reason", force);
        lay->addLayout(form2);
        auto* row2 = new QHBoxLayout;
        auto* preBtn = new QPushButton("Preflight");
        auto* addBtn = new QPushButton("Preflight && queue (add)");
        row2->addWidget(preBtn);
        row2->addWidget(addBtn);
        lay->addLayout(row2);
        auto* out = new QPlainTextEdit;
        out->setReadOnly(true);
        lay->addWidget(out);

        auto cancel = std::make_shared<std::atomic<bool>>(false);
        const std::vector<QPushButton*> busy = {scanBtn, preBtn, addBtn};
        auto source_args = [=](std::vector<std::string>& a) {
            const std::string src = sstr(source->currentText());
            a.insert(a.end(), {"--source", src});
            if (src != "c2pool") a.insert(a.end(), {"--dashd-url", sstr(dashdUrl->text()), "--dashd-auth-file", sstr(authFile->text())});
        };
        QObject::connect(cancelBtn, &QPushButton::clicked, [cancel] { cancel->store(true); });
        QObject::connect(scanBtn, &QPushButton::clicked, [=] {
            std::vector<std::string> a = {"--node-url", sstr(nodeUrl->text()), "scan"};
            for (const std::string& w : words(addresses->text())) a.insert(a.end(), {"--address", w});
            source_args(a);
            if (single->isChecked()) a.push_back("--allow-single-source");
            a.insert(a.end(), {"--mode", sstr(mode->currentText())});
            if (mode->currentText() == "collateral") a.insert(a.end(), {"--gov-hash", sstr(govHash->text())});
            a.insert(a.end(), {"--fee-mode", sstr(feeMode->currentText())});
            if (feeMode->currentText() == "relay") a.insert(a.end(), {"--fee-rate", std::to_string(feeRate->value())});
            a.insert(a.end(), {"--key-encoding", sstr(keyEnc->currentText())});
            if (maxInputs->value() > 0) a.insert(a.end(), {"--max-inputs", std::to_string(maxInputs->value())});
            if (!outName->text().isEmpty()) {
                a.insert(a.end(), {"--out", sstr(outName->text())});
                if (utxosFile->text().isEmpty()) utxosFile->setText(outName->text() + ".utxos.json");
                if (scanplanFile->text().isEmpty()) scanplanFile->setText(outName->text() + ".scanplan.json");
            }
            if (c2wu->isChecked()) a.push_back("--emit-c2wu");
            run_cli(out, busy, cancel, a);
        });
        auto pair_args = [=](std::vector<std::string>& a) {
            a.insert(a.end(), {"--hex", sstr(hexFile->text())});
            if (!utxosFile->text().isEmpty()) a.insert(a.end(), {"--utxos", sstr(utxosFile->text())});
            if (!scanplanFile->text().isEmpty()) a.insert(a.end(), {"--scanplan", sstr(scanplanFile->text())});
            source_args(a);
            if (!force->text().isEmpty()) a.insert(a.end(), {"--force", sstr(force->text())});
        };
        auto globals = [=] {
            std::vector<std::string> a = {"--queue", sstr(queueFile->text()), "--node-url", sstr(nodeUrl->text())};
            if (!tokenFile->text().isEmpty()) a.insert(a.end(), {"--token-file", sstr(tokenFile->text())});
            return a;
        };
        QObject::connect(preBtn, &QPushButton::clicked, [=] {
            std::vector<std::string> a = globals();
            a.push_back("preflight");
            pair_args(a);
            run_cli(out, busy, cancel, a);
        });
        QObject::connect(addBtn, &QPushButton::clicked, [=] {
            std::vector<std::string> a = globals();
            a.push_back("add");
            for (const std::string& t : words(parents->text())) a.insert(a.end(), {"--after-parent", t});
            a.push_back("--preflight");
            pair_args(a);
            run_cli(out, busy, cancel, a);
        });
        tabs->addTab(page, "Scan & Plan");
    }

    win.resize(760, 560);
    win.show();
    return app.exec();
}
