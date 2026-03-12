#include "PageLaunch.hpp"

#include <QDir>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QScrollArea>
#include <QSettings>
#include <QSplitter>
#include <QStringList>
#include <QVBoxLayout>

namespace {

struct PortDefaults {
    int p2p;
    int stratum;
    int http;
    int rpc;
};

PortDefaults defaultsForNetwork(const QString& chain, bool testnet)
{
    if (chain == "bitcoin") {
        const int p2p = testnet ? 19333 : 9333;
        const int stratum = testnet ? 19332 : 9332;
        const int http = (stratum + 1 == p2p) ? stratum + 2 : stratum + 1;
        const int rpc = testnet ? 18332 : 8332;
        return {p2p, stratum, http, rpc};
    }

    if (chain == "dogecoin") {
        const int p2p = testnet ? 44556 : 22556;
        const int stratum = testnet ? 44555 : 22555;
        const int http = stratum + 2;
        const int rpc = testnet ? 44555 : 22555;
        return {p2p, stratum, http, rpc};
    }

    const int p2p = testnet ? 19338 : 9338;
    const int stratum = testnet ? 19327 : 9327;
    const int http = stratum + 1;
    const int rpc = testnet ? 19332 : 9332;
    return {p2p, stratum, http, rpc};
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Construction
// ─────────────────────────────────────────────────────────────────────────────

PageLaunch::PageLaunch(QWidget* parent)
    : QWidget(parent), process_(new QProcess(this))
{
    setupUi();

    connect(modeCombo_, &QComboBox::currentIndexChanged, this, &PageLaunch::updateNetworkDefaults);
    connect(chainCombo_, &QComboBox::currentIndexChanged, this, &PageLaunch::updateNetworkDefaults);
    connect(testnetCheck_, &QCheckBox::stateChanged, this, &PageLaunch::updateNetworkDefaults);
    connect(httpPortSpin_, &QSpinBox::valueChanged, this, &PageLaunch::emitApiBaseUrlChanged);

    // Process state signals → daemonStateChanged
    connect(process_, &QProcess::started, this, [this]() {
        launchBtn_->setEnabled(false);
        stopBtn_->setEnabled(true);
        restartBtn_->setEnabled(true);
        emit daemonStateChanged("Daemon: running", "color: #1d7f3b;");
    });

    connect(process_,
            static_cast<void (QProcess::*)(int, QProcess::ExitStatus)>(&QProcess::finished),
            this, [this](int code, QProcess::ExitStatus) {
                launchBtn_->setEnabled(true);
                stopBtn_->setEnabled(false);
                restartBtn_->setEnabled(false);
                emit daemonStateChanged(
                    QString("Daemon: stopped (exit %1)").arg(code),
                    "color: #b04020;");
            });

    connect(process_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        launchBtn_->setEnabled(true);
        stopBtn_->setEnabled(false);
        restartBtn_->setEnabled(false);
        emit daemonStateChanged(
            QString("Daemon: error — %1").arg(process_->errorString()),
            "color: #b04020;");
    });

    updateNetworkDefaults();
}

// ─────────────────────────────────────────────────────────────────────────────
// UI construction helpers
// ─────────────────────────────────────────────────────────────────────────────

QGroupBox* PageLaunch::makeGroup(const QString& title)
{
    auto* g = new QGroupBox(title, this);
    g->setStyleSheet("QGroupBox { font-weight: bold; margin-top: 6px; }"
                     "QGroupBox::title { subcontrol-origin: margin; left: 8px; }");
    return g;
}

void PageLaunch::setupUi()
{
    // ── Outer scroll area ────────────────────────────────────────────────────
    auto* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    auto* container = new QWidget;
    auto* outerLayout = new QVBoxLayout(this);
    outerLayout->setContentsMargins(0, 0, 0, 0);
    outerLayout->addWidget(scroll);

    auto* vbox = new QVBoxLayout(container);
    vbox->setSpacing(8);
    vbox->setContentsMargins(10, 10, 10, 10);
    scroll->setWidget(container);

    // ── 1. Mode / Network ────────────────────────────────────────────────────
    {
        auto* g = makeGroup("Operation Mode & Network");
        auto* form = new QFormLayout(g);

        modeCombo_ = new QComboBox;
        modeCombo_->addItems({"Integrated (full pool)", "Sharechain (P2P node)", "Solo (default)"});
        modeCombo_->setCurrentIndex(1);
        form->addRow("Mode:", modeCombo_);

        chainCombo_ = new QComboBox;
        chainCombo_->addItems({"litecoin", "bitcoin", "dogecoin"});
        form->addRow("Blockchain:", chainCombo_);

        testnetCheck_ = new QCheckBox("Use testnet");
        form->addRow("Network:", testnetCheck_);

        vbox->addWidget(g);
    }

    // ── 2. Executable ────────────────────────────────────────────────────────
    {
        auto* g = makeGroup("Daemon Executable");
        auto* form = new QFormLayout(g);

        binaryEdit_ = new QLineEdit("./build/bin/c2pool");
        binaryEdit_->setPlaceholderText("Path to c2pool binary");
        form->addRow("Binary:", binaryEdit_);

        vbox->addWidget(g);
    }

    // ── 3. Ports ─────────────────────────────────────────────────────────────
    {
        auto* g = makeGroup("Port Configuration");
        auto* form = new QFormLayout(g);

        p2pPortSpin_ = new QSpinBox;
        p2pPortSpin_->setRange(1, 65535);
        p2pPortSpin_->setValue(19338);
        p2pPortSpin_->setToolTip("--p2pool-port  (Python p2pool-compatible sharechain port)");
        form->addRow("P2P sharechain port:", p2pPortSpin_);

        stratumPortSpin_ = new QSpinBox;
        stratumPortSpin_->setRange(1, 65535);
        stratumPortSpin_->setValue(19327);
        stratumPortSpin_->setToolTip("-w / --worker-port  (Python p2pool worker/Stratum default for selected chain/network)");
        form->addRow("Stratum / worker port:", stratumPortSpin_);

        httpPortSpin_ = new QSpinBox;
        httpPortSpin_->setRange(1, 65535);
        httpPortSpin_->setValue(19328);
        httpPortSpin_->setToolTip("--web-port / --http-port  (dashboard/API; defaults next to worker port to avoid collisions)");
        form->addRow("HTTP API port:", httpPortSpin_);

        vbox->addWidget(g);
    }

    // ── 4. Parent Coin Daemon ─────────────────────────────────────────────────
    {
        auto* g = makeGroup("Parent Coin Daemon (litecoind / bitcoind)");
        auto* form = new QFormLayout(g);

        coindHostEdit_ = new QLineEdit("127.0.0.1");
        coindHostEdit_->setToolTip("--coind-address / --rpchost");
        form->addRow("RPC host:", coindHostEdit_);

        coindPortSpin_ = new QSpinBox;
        coindPortSpin_->setRange(0, 65535);
        coindPortSpin_->setValue(19332);
        coindPortSpin_->setSpecialValueText("auto-detect");
        coindPortSpin_->setToolTip("--coind-rpc-port  (0 = auto-detect from chain)");
        form->addRow("RPC port:", coindPortSpin_);

        rpcUserEdit_ = new QLineEdit;
        rpcUserEdit_->setPlaceholderText("litecoinrpc");
        rpcUserEdit_->setToolTip("--rpcuser");
        form->addRow("RPC user:", rpcUserEdit_);

        rpcPassEdit_ = new QLineEdit;
        rpcPassEdit_->setEchoMode(QLineEdit::Password);
        rpcPassEdit_->setPlaceholderText("password");
        rpcPassEdit_->setToolTip("--rpcpassword");
        form->addRow("RPC password:", rpcPassEdit_);

        vbox->addWidget(g);
    }

    // ── 5. Payout & Fees ─────────────────────────────────────────────────────
    {
        auto* g = makeGroup("Payout, Fees & Redistribution");
        auto* form = new QFormLayout(g);

        addressEdit_ = new QLineEdit;
        addressEdit_->setPlaceholderText("LTC/BTC/DOGE payout address");
        addressEdit_->setToolTip("--address / --solo-address");
        form->addRow("Payout address:", addressEdit_);

        feeSpinBox_ = new QDoubleSpinBox;
        feeSpinBox_->setRange(0.0, 100.0);
        feeSpinBox_->setDecimals(2);
        feeSpinBox_->setSuffix(" %");
        feeSpinBox_->setValue(0.0);
        feeSpinBox_->setToolTip("-f / --fee / --node-owner-fee  (fee kept by the pool operator)");
        form->addRow("Node owner fee (-f):", feeSpinBox_);

        nodeOwnerAddrEdit_ = new QLineEdit;
        nodeOwnerAddrEdit_->setPlaceholderText("Leave blank to use same as payout address");
        nodeOwnerAddrEdit_->setToolTip("--node-owner-address");
        form->addRow("Node owner address:", nodeOwnerAddrEdit_);

        giveAuthorSpinBox_ = new QDoubleSpinBox;
        giveAuthorSpinBox_->setRange(0.0, 100.0);
        giveAuthorSpinBox_->setDecimals(2);
        giveAuthorSpinBox_->setSuffix(" %");
        giveAuthorSpinBox_->setValue(0.0);
        giveAuthorSpinBox_->setToolTip("--give-author / --dev-donation");
        form->addRow("Dev donation (--give-author):", giveAuthorSpinBox_);

        redistributeCombo_ = new QComboBox;
        redistributeCombo_->addItems({"pplns", "fee", "boost", "donate"});
        redistributeCombo_->setToolTip(
            "--redistribute MODE\n"
            "  pplns  - distribute anonymised shares by PPLNS weight (default)\n"
            "  fee    - 100% of anonymous shares → node operator\n"
            "  boost  - give to active miners with zero PPLNS weight\n"
            "  donate - 100% to donation address");
        form->addRow("Redistribute mode:", redistributeCombo_);

        vbox->addWidget(g);
    }

    // ── 6. Merged Mining ─────────────────────────────────────────────────────
    {
        auto* g = makeGroup("Merged Mining (--merged SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS[:P2P_PORT])");
        auto* gLayout = new QVBoxLayout(g);

        auto* note = new QLabel(
            "Add one row per auxiliary chain. "
            "Example: DOGE : 98 : 192.168.86.29 : 22555 : dogerpc : pass");
        note->setWordWrap(true);
        gLayout->addWidget(note);

        mergedTable_ = new QTableWidget(0, 7);
        mergedTable_->setHorizontalHeaderLabels(
            {"Symbol", "Chain ID", "RPC Host", "RPC Port", "User", "Password", "P2P Port"});
        mergedTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        mergedTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
        mergedTable_->setMinimumHeight(120);
        gLayout->addWidget(mergedTable_);

        auto* btnRow = new QHBoxLayout;
        addMergedBtn_    = new QPushButton("+ Add chain");
        removeMergedBtn_ = new QPushButton("- Remove selected");
        btnRow->addWidget(addMergedBtn_);
        btnRow->addWidget(removeMergedBtn_);
        btnRow->addStretch();
        gLayout->addLayout(btnRow);

        connect(addMergedBtn_,    &QPushButton::clicked, this, &PageLaunch::addMergedRow);
        connect(removeMergedBtn_, &QPushButton::clicked, this, &PageLaunch::removeSelectedMergedRow);

        vbox->addWidget(g);
    }

    // ── 7. Network tuning ────────────────────────────────────────────────────
    {
        auto* g = makeGroup("Network Tuning");
        auto* form = new QFormLayout(g);

        maxConnsSpinBox_ = new QSpinBox;
        maxConnsSpinBox_->setRange(0, 2048);
        maxConnsSpinBox_->setValue(8);
        maxConnsSpinBox_->setSpecialValueText("default");
        maxConnsSpinBox_->setToolTip("--max-conns / --outgoing-conns  (0 = default)");
        form->addRow("Max outgoing P2P connections:", maxConnsSpinBox_);

        vbox->addWidget(g);
    }

    // ── 8. Command preview + controls ────────────────────────────────────────
    {
        auto* g = makeGroup("Generated Command");
        auto* gLayout = new QVBoxLayout(g);

        cmdPreview_ = new QTextEdit;
        cmdPreview_->setReadOnly(true);
        cmdPreview_->setMinimumHeight(80);
        cmdPreview_->setFont(QFont("Monospace", 9));
        gLayout->addWidget(cmdPreview_);

        auto* btnRow = new QHBoxLayout;
        buildPreviewBtn_ = new QPushButton("Refresh preview");
        launchBtn_       = new QPushButton("Launch Daemon");
        stopBtn_         = new QPushButton("Stop");
        restartBtn_      = new QPushButton("Restart");

        launchBtn_->setStyleSheet("font-weight: bold; color: #1d7f3b;");
        stopBtn_->setEnabled(false);
        restartBtn_->setEnabled(false);

        btnRow->addWidget(buildPreviewBtn_);
        btnRow->addStretch();
        btnRow->addWidget(launchBtn_);
        btnRow->addWidget(stopBtn_);
        btnRow->addWidget(restartBtn_);
        gLayout->addLayout(btnRow);

        connect(buildPreviewBtn_, &QPushButton::clicked, this, &PageLaunch::onBuildPreview);
        connect(launchBtn_,       &QPushButton::clicked, this, &PageLaunch::launch);
        connect(stopBtn_,         &QPushButton::clicked, this, &PageLaunch::stop);
        connect(restartBtn_,      &QPushButton::clicked, this, &PageLaunch::restart);

        vbox->addWidget(g);
    }

    vbox->addStretch();
    onBuildPreview();  // initial preview
    emitApiBaseUrlChanged();
}

// ─────────────────────────────────────────────────────────────────────────────
// Command builder
// ─────────────────────────────────────────────────────────────────────────────

QString PageLaunch::buildCommand() const
{
    QStringList parts;

    // Binary
    parts << binaryEdit_->text().trimmed();

    // Mode
    const int modeIdx = modeCombo_->currentIndex();
    if (modeIdx == 0)      parts << "--integrated";
    else if (modeIdx == 1) parts << "--sharechain";
    // solo = default, no flag

    // Network
    if (testnetCheck_->isChecked()) parts << "--testnet";
    const QString chain = chainCombo_->currentText();
    if (chain != "litecoin") parts << "--net" << chain;

    // Ports
    parts << "--p2pool-port" << QString::number(p2pPortSpin_->value());
    parts << "-w"            << QString::number(stratumPortSpin_->value());
    parts << "--web-port"    << QString::number(httpPortSpin_->value());

    // Coin daemon
    const QString coindHost = coindHostEdit_->text().trimmed();
    if (!coindHost.isEmpty()) parts << "--coind-address" << coindHost;
    if (coindPortSpin_->value() > 0)
        parts << "--coind-rpc-port" << QString::number(coindPortSpin_->value());
    const QString rpcUser = rpcUserEdit_->text().trimmed();
    const QString rpcPass = rpcPassEdit_->text().trimmed();
    if (!rpcUser.isEmpty()) parts << "--rpcuser" << rpcUser;
    if (!rpcPass.isEmpty()) parts << "--rpcpassword" << rpcPass;

    // Payout address
    const QString addr = addressEdit_->text().trimmed();
    if (!addr.isEmpty()) parts << "--address" << addr;

    // Fee / donation
    if (feeSpinBox_->value() > 0.0)
        parts << "-f" << QString::number(feeSpinBox_->value(), 'f', 2);
    if (giveAuthorSpinBox_->value() > 0.0)
        parts << "--give-author" << QString::number(giveAuthorSpinBox_->value(), 'f', 2);
    const QString nodeOwnerAddr = nodeOwnerAddrEdit_->text().trimmed();
    if (!nodeOwnerAddr.isEmpty())
        parts << "--node-owner-address" << nodeOwnerAddr;

    // Redistribute (only if non-default)
    const QString redistribute = redistributeCombo_->currentText();
    if (redistribute != "pplns")
        parts << "--redistribute" << redistribute;

    // Merged mining
    for (int row = 0; row < mergedTable_->rowCount(); ++row) {
        auto cell = [&](int col) -> QString {
            const QTableWidgetItem* item = mergedTable_->item(row, col);
            return item ? item->text().trimmed() : QString{};
        };
        const QString sym     = cell(0);
        const QString chainId = cell(1);
        const QString host    = cell(2);
        const QString port    = cell(3);
        const QString user    = cell(4);
        const QString pass    = cell(5);
        const QString p2pPort = cell(6);

        if (sym.isEmpty() || chainId.isEmpty() || host.isEmpty() || port.isEmpty())
            continue;

        QString spec = sym + ":" + chainId + ":" + host + ":" + port + ":" + user + ":" + pass;
        if (!p2pPort.isEmpty())
            spec += ":" + p2pPort;
        parts << "--merged" << spec;
    }

    // Network tuning
    if (maxConnsSpinBox_->value() > 0)
        parts << "--max-conns" << QString::number(maxConnsSpinBox_->value());

    return parts.join(" ");
}

QString PageLaunch::suggestedApiBaseUrl() const
{
    return QString("http://127.0.0.1:%1").arg(httpPortSpin_->value());
}

// ─────────────────────────────────────────────────────────────────────────────
// Slots
// ─────────────────────────────────────────────────────────────────────────────

void PageLaunch::onBuildPreview()
{
    cmdPreview_->setPlainText(buildCommand());
}

void PageLaunch::updateNetworkDefaults()
{
    const PortDefaults defaults = defaultsForNetwork(chainCombo_->currentText(), testnetCheck_->isChecked());
    p2pPortSpin_->setValue(defaults.p2p);
    stratumPortSpin_->setValue(defaults.stratum);
    httpPortSpin_->setValue(defaults.http);
    coindPortSpin_->setValue(defaults.rpc);

    onBuildPreview();
    emitApiBaseUrlChanged();
}

void PageLaunch::emitApiBaseUrlChanged()
{
    emit apiBaseUrlChanged(suggestedApiBaseUrl());
}

void PageLaunch::addMergedRow()
{
    const int row = mergedTable_->rowCount();
    mergedTable_->insertRow(row);
    const bool testnet = testnetCheck_->isChecked();
    const QString rpcPort = testnet ? "44555" : "22555";
    const QString p2pPort = testnet ? "44556" : "22556";
    mergedTable_->setItem(row, 0, new QTableWidgetItem("DOGE"));
    mergedTable_->setItem(row, 1, new QTableWidgetItem("98"));
    mergedTable_->setItem(row, 2, new QTableWidgetItem(testnet ? "192.168.86.27" : "127.0.0.1"));
    mergedTable_->setItem(row, 3, new QTableWidgetItem(rpcPort));
    mergedTable_->setItem(row, 4, new QTableWidgetItem(testnet ? "dogecoinrpc" : "dogerpc"));
    mergedTable_->setItem(row, 5, new QTableWidgetItem(""));
    mergedTable_->setItem(row, 6, new QTableWidgetItem(p2pPort));
}

void PageLaunch::removeSelectedMergedRow()
{
    const auto selected = mergedTable_->selectedItems();
    if (selected.isEmpty()) return;
    const int row = selected.first()->row();
    mergedTable_->removeRow(row);
}

void PageLaunch::launch()
{
    if (process_->state() != QProcess::NotRunning) {
        emit daemonStateChanged("Daemon: already running", "color: #b04020;");
        return;
    }
    onBuildPreview();
    const QString cmd = buildCommand();
    if (cmd.trimmed().isEmpty()) {
        emit daemonStateChanged("Daemon: empty command", "color: #b04020;");
        return;
    }
    process_->setWorkingDirectory(QDir::currentPath());
    process_->start("/bin/bash", {"-lc", cmd});
}

void PageLaunch::stop()
{
    if (process_->state() == QProcess::NotRunning) {
        emit daemonStateChanged("Daemon: not running", "color: #888888;");
        return;
    }
    process_->terminate();
    if (!process_->waitForFinished(2000))
        process_->kill();
}

void PageLaunch::restart()
{
    stop();
    launch();
}

bool PageLaunch::isDaemonRunning() const
{
    return process_->state() != QProcess::NotRunning;
}

// ─────────────────────────────────────────────────────────────────────────────
// QSettings persistence
// ─────────────────────────────────────────────────────────────────────────────

void PageLaunch::saveSettings() const
{
    QSettings s;
    s.beginGroup("launch");
    s.setValue("binary",        binaryEdit_->text());
    s.setValue("mode",          modeCombo_->currentIndex());
    s.setValue("chain",         chainCombo_->currentText());
    s.setValue("testnet",       testnetCheck_->isChecked());
    s.setValue("p2pPort",       p2pPortSpin_->value());
    s.setValue("stratumPort",   stratumPortSpin_->value());
    s.setValue("httpPort",      httpPortSpin_->value());
    s.setValue("coindHost",     coindHostEdit_->text());
    s.setValue("coindPort",     coindPortSpin_->value());
    s.setValue("rpcUser",       rpcUserEdit_->text());
    s.setValue("rpcPass",       rpcPassEdit_->text());
    s.setValue("address",       addressEdit_->text());
    s.setValue("fee",           feeSpinBox_->value());
    s.setValue("nodeOwnerAddr", nodeOwnerAddrEdit_->text());
    s.setValue("giveAuthor",    giveAuthorSpinBox_->value());
    s.setValue("redistribute",  redistributeCombo_->currentText());
    s.setValue("maxConns",      maxConnsSpinBox_->value());

    // Merged chains
    s.remove("merged");
    s.beginWriteArray("merged");
    for (int row = 0; row < mergedTable_->rowCount(); ++row) {
        s.setArrayIndex(row);
        for (int col = 0; col < mergedTable_->columnCount(); ++col) {
            const QTableWidgetItem* item = mergedTable_->item(row, col);
            s.setValue(QString("col%1").arg(col), item ? item->text() : QString{});
        }
    }
    s.endArray();
    s.endGroup();
}

void PageLaunch::loadSettings()
{
    QSettings s;
    s.beginGroup("launch");
    binaryEdit_->setText(s.value("binary", "./build/bin/c2pool").toString());
    modeCombo_->setCurrentIndex(s.value("mode", 1).toInt());
    {
        const int idx = chainCombo_->findText(s.value("chain", "litecoin").toString());
        chainCombo_->setCurrentIndex(idx >= 0 ? idx : 0);
    }
    testnetCheck_->setChecked(s.value("testnet", true).toBool());
    const PortDefaults defaults = defaultsForNetwork(chainCombo_->currentText(), testnetCheck_->isChecked());
    p2pPortSpin_->setValue(s.value("p2pPort", defaults.p2p).toInt());
    stratumPortSpin_->setValue(s.value("stratumPort", defaults.stratum).toInt());
    httpPortSpin_->setValue(s.value("httpPort", defaults.http).toInt());
    coindHostEdit_->setText(s.value("coindHost", "127.0.0.1").toString());
    coindPortSpin_->setValue(s.value("coindPort", defaults.rpc).toInt());
    rpcUserEdit_->setText(s.value("rpcUser").toString());
    rpcPassEdit_->setText(s.value("rpcPass").toString());
    addressEdit_->setText(s.value("address").toString());
    feeSpinBox_->setValue(s.value("fee", 0.0).toDouble());
    nodeOwnerAddrEdit_->setText(s.value("nodeOwnerAddr").toString());
    giveAuthorSpinBox_->setValue(s.value("giveAuthor", 0.0).toDouble());
    {
        const int idx = redistributeCombo_->findText(s.value("redistribute", "pplns").toString());
        redistributeCombo_->setCurrentIndex(idx >= 0 ? idx : 0);
    }
    maxConnsSpinBox_->setValue(s.value("maxConns", 0).toInt());

    // Merged chains
    mergedTable_->setRowCount(0);
    const int mergedCount = s.beginReadArray("merged");
    for (int row = 0; row < mergedCount; ++row) {
        s.setArrayIndex(row);
        mergedTable_->insertRow(row);
        for (int col = 0; col < mergedTable_->columnCount(); ++col) {
            mergedTable_->setItem(row, col,
                new QTableWidgetItem(s.value(QString("col%1").arg(col)).toString()));
        }
    }
    s.endArray();
    s.endGroup();

    onBuildPreview();
    emitApiBaseUrlChanged();
}
