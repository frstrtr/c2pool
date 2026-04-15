#include "PageLaunch.hpp"
#include "ConfigSerializer.hpp"
#include "ProcessLauncher.hpp"

#include <QDir>
#include <QFileDialog>
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
    : QWidget(parent), launcher_(new ProcessLauncher(this))
{
    setupUi();

    connect(modeCombo_, &QComboBox::currentIndexChanged, this, &PageLaunch::updateNetworkDefaults);
    connect(chainCombo_, &QComboBox::currentIndexChanged, this, &PageLaunch::updateNetworkDefaults);
    connect(testnetCheck_, &QCheckBox::stateChanged, this, &PageLaunch::updateNetworkDefaults);
    connect(httpPortSpin_, &QSpinBox::valueChanged, this, &PageLaunch::emitApiBaseUrlChanged);

    // ProcessLauncher signals → daemonStateChanged
    connect(launcher_, &ProcessLauncher::started, this, [this]() {
        launchBtn_->setEnabled(false);
        stopBtn_->setEnabled(true);
        restartBtn_->setEnabled(true);
        emit daemonStateChanged("Daemon: running", "color: #1d7f3b;");
    });

    connect(launcher_, &ProcessLauncher::finished,
            this, [this](int code, QProcess::ExitStatus) {
                launchBtn_->setEnabled(true);
                stopBtn_->setEnabled(false);
                restartBtn_->setEnabled(false);
                emit daemonStateChanged(
                    QString("Daemon: stopped (exit %1)").arg(code),
                    "color: #b04020;");
            });

    connect(launcher_, &ProcessLauncher::errorOccurred, this, [this](const QString& msg) {
        launchBtn_->setEnabled(true);
        stopBtn_->setEnabled(false);
        restartBtn_->setEnabled(false);
        emit daemonStateChanged(
            QString("Daemon: error — %1").arg(msg),
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

        custodialCheck_ = new QCheckBox("Custodial mode (all coinbase to operator)");
        custodialCheck_->setToolTip("--custodial");
        form->addRow("", custodialCheck_);

        vbox->addWidget(g);
    }

    // ── 1b. Embedded SPV ─────────────────────────────────────────────────────
    {
        auto* g = makeGroup("Embedded SPV Nodes");
        auto* form = new QFormLayout(g);

        embeddedLtcCheck_ = new QCheckBox("Embedded LTC SPV (no litecoind needed)");
        embeddedLtcCheck_->setChecked(true);
        embeddedLtcCheck_->setToolTip("--embedded-ltc / --no-embedded-ltc");
        form->addRow("", embeddedLtcCheck_);

        embeddedDogeCheck_ = new QCheckBox("Embedded DOGE SPV (no dogecoind needed)");
        embeddedDogeCheck_->setChecked(true);
        embeddedDogeCheck_->setToolTip("--embedded-doge / --no-embedded-doge");
        form->addRow("", embeddedDogeCheck_);

        dogeTestnet4Check_ = new QCheckBox("DOGE testnet4alpha (instead of testnet3)");
        dogeTestnet4Check_->setToolTip("--doge-testnet4alpha");
        form->addRow("", dogeTestnet4Check_);

        headerCheckpointEdit_ = new QLineEdit;
        headerCheckpointEdit_->setPlaceholderText("HEIGHT:HASH (leave blank for built-in)");
        headerCheckpointEdit_->setToolTip("--header-checkpoint  (LTC SPV bootstrap point)");
        form->addRow("LTC checkpoint:", headerCheckpointEdit_);

        dogeHeaderCheckpointEdit_ = new QLineEdit;
        dogeHeaderCheckpointEdit_->setPlaceholderText("HEIGHT:HASH (leave blank for built-in)");
        dogeHeaderCheckpointEdit_->setToolTip("--doge-header-checkpoint  (DOGE SPV bootstrap point)");
        form->addRow("DOGE checkpoint:", dogeHeaderCheckpointEdit_);

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

    // ── 3b. Stratum Tuning ───────────────────────────────────────────────────
    {
        auto* g = makeGroup("Stratum Tuning");
        auto* form = new QFormLayout(g);

        stratumMinDiffSpin_ = new QDoubleSpinBox;
        stratumMinDiffSpin_->setRange(0.0001, 65536.0);
        stratumMinDiffSpin_->setDecimals(4);
        stratumMinDiffSpin_->setValue(0.0005);
        stratumMinDiffSpin_->setToolTip("--stratum-min-diff  (per-connection vardiff floor)");
        form->addRow("Min difficulty:", stratumMinDiffSpin_);

        stratumMaxDiffSpin_ = new QDoubleSpinBox;
        stratumMaxDiffSpin_->setRange(0.001, 1000000.0);
        stratumMaxDiffSpin_->setDecimals(3);
        stratumMaxDiffSpin_->setValue(65536.0);
        stratumMaxDiffSpin_->setToolTip("--stratum-max-diff  (per-connection vardiff ceiling)");
        form->addRow("Max difficulty:", stratumMaxDiffSpin_);

        stratumTargetTimeSpin_ = new QDoubleSpinBox;
        stratumTargetTimeSpin_->setRange(0.1, 120.0);
        stratumTargetTimeSpin_->setDecimals(1);
        stratumTargetTimeSpin_->setValue(3.0);
        stratumTargetTimeSpin_->setSuffix(" sec");
        stratumTargetTimeSpin_->setToolTip("--stratum-target-time  (target seconds per pseudoshare)");
        form->addRow("Target time:", stratumTargetTimeSpin_);

        vardiffCheck_ = new QCheckBox("Enable automatic difficulty adjustment");
        vardiffCheck_->setChecked(true);
        vardiffCheck_->setToolTip("--no-vardiff  (uncheck to disable vardiff)");
        form->addRow("", vardiffCheck_);

        maxCoinbaseOutputsSpin_ = new QSpinBox;
        maxCoinbaseOutputsSpin_->setRange(1, 100000);
        maxCoinbaseOutputsSpin_->setValue(4000);
        maxCoinbaseOutputsSpin_->setToolTip("--max-coinbase-outputs  (max payees per block)");
        form->addRow("Max coinbase outputs:", maxCoinbaseOutputsSpin_);

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

        coindP2pPortSpin_ = new QSpinBox;
        coindP2pPortSpin_->setRange(0, 65535);
        coindP2pPortSpin_->setValue(0);
        coindP2pPortSpin_->setSpecialValueText("auto-detect");
        coindP2pPortSpin_->setToolTip("--coind-p2p-port  (0 = auto-detect from chain)");
        form->addRow("P2P port:", coindP2pPortSpin_);

        coindP2pAddrEdit_ = new QLineEdit;
        coindP2pAddrEdit_->setPlaceholderText("same as RPC host");
        coindP2pAddrEdit_->setToolTip("--coind-p2p-address  (defaults to RPC host)");
        form->addRow("P2P address:", coindP2pAddrEdit_);

        dogeP2pAddrEdit_ = new QLineEdit;
        dogeP2pAddrEdit_->setPlaceholderText("auto-detect (override for DOGE SPV)");
        dogeP2pAddrEdit_->setToolTip("--doge-p2p-address  (direct peer for embedded DOGE)");
        form->addRow("DOGE P2P address:", dogeP2pAddrEdit_);

        dogeP2pPortSpin_ = new QSpinBox;
        dogeP2pPortSpin_->setRange(0, 65535);
        dogeP2pPortSpin_->setValue(0);
        dogeP2pPortSpin_->setSpecialValueText("auto-detect");
        dogeP2pPortSpin_->setToolTip("--doge-p2p-port  (0 = auto-detect)");
        form->addRow("DOGE P2P port:", dogeP2pPortSpin_);

        vbox->addWidget(g);
    }

    // ── 5. Payout & Fees ─────────────────────────────────────────────────────
    {
        auto* g = makeGroup("Payout, Fees & Redistribution");
        auto* form = new QFormLayout(g);

        addressEdit_ = new QLineEdit;
        addressEdit_->setPlaceholderText("LTC/BTC/DOGE payout address");
        addressEdit_->setToolTip("--address / --solo-address  (YOUR mining payout address)");
        form->addRow("Payout address:", addressEdit_);

        autoDetectWalletCheck_ = new QCheckBox("Auto-detect wallet address");
        autoDetectWalletCheck_->setChecked(true);
        autoDetectWalletCheck_->setToolTip("--auto-detect-wallet / --no-auto-detect-wallet");
        form->addRow("", autoDetectWalletCheck_);

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

        nodeOwnerScriptEdit_ = new QLineEdit;
        nodeOwnerScriptEdit_->setPlaceholderText("hex script (advanced, usually leave blank)");
        nodeOwnerScriptEdit_->setToolTip("--node-owner-script  (raw hex script for node-owner payout)");
        form->addRow("Node owner script:", nodeOwnerScriptEdit_);

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

        nodeOwnerMergedAddrEdit_ = new QLineEdit;
        nodeOwnerMergedAddrEdit_->setPlaceholderText("separate DOGE fee address (optional)");
        nodeOwnerMergedAddrEdit_->setToolTip("--node-owner-merged-address  (separate fee address for merged chains)");
        form->addRow("Merged fee address:", nodeOwnerMergedAddrEdit_);

        payoutWindowSpin_ = new QSpinBox;
        payoutWindowSpin_->setRange(3600, 604800);
        payoutWindowSpin_->setValue(86400);
        payoutWindowSpin_->setSuffix(" sec");
        payoutWindowSpin_->setToolTip("--payout-window  (PPLNS lookback period, default 86400 = 24h)");
        form->addRow("Payout window:", payoutWindowSpin_);

        storageSaveIntervalSpin_ = new QSpinBox;
        storageSaveIntervalSpin_->setRange(10, 3600);
        storageSaveIntervalSpin_->setValue(300);
        storageSaveIntervalSpin_->setSuffix(" sec");
        storageSaveIntervalSpin_->setToolTip("--storage-save-interval  (periodic database save interval)");
        form->addRow("Storage save interval:", storageSaveIntervalSpin_);

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

        seedNodesEdit_ = new QPlainTextEdit;
        seedNodesEdit_->setMaximumHeight(80);
        seedNodesEdit_->setPlaceholderText("One HOST:PORT per line, e.g. 192.168.86.29:19338");
        seedNodesEdit_->setToolTip("-n HOST:PORT  (seed/bootstrap node addresses)");
        form->addRow("Seed nodes (-n):", seedNodesEdit_);

        httpHostEdit_ = new QLineEdit("0.0.0.0");
        httpHostEdit_->setToolTip("--http-host  (bind address for HTTP API server)");
        form->addRow("HTTP bind address:", httpHostEdit_);

        vbox->addWidget(g);
    }

    // ── 7b. Logging ──────────────────────────────────────────────────────────
    {
        auto* g = makeGroup("Logging");
        auto* form = new QFormLayout(g);

        logLevelCombo_ = new QComboBox;
        logLevelCombo_->addItems({"trace", "debug", "info", "warning", "error"});
        logLevelCombo_->setCurrentIndex(2);  // info
        logLevelCombo_->setToolTip("--log-level");
        form->addRow("Log level:", logLevelCombo_);

        logFileEdit_ = new QLineEdit;
        logFileEdit_->setPlaceholderText("debug.log (default, in data dir)");
        logFileEdit_->setToolTip("--log-file  (custom log file path)");
        form->addRow("Log file:", logFileEdit_);

        logRotationMbSpin_ = new QSpinBox;
        logRotationMbSpin_->setRange(1, 10000);
        logRotationMbSpin_->setValue(100);
        logRotationMbSpin_->setSuffix(" MB");
        logRotationMbSpin_->setToolTip("--log-rotation-mb  (rotate log at this size)");
        form->addRow("Rotation size:", logRotationMbSpin_);

        logMaxMbSpin_ = new QSpinBox;
        logMaxMbSpin_->setRange(1, 10000);
        logMaxMbSpin_->setValue(50);
        logMaxMbSpin_->setSuffix(" MB");
        logMaxMbSpin_->setToolTip("--log-max-mb  (max total log size)");
        form->addRow("Max log size:", logMaxMbSpin_);

        vbox->addWidget(g);
    }

    // ── 7c. Performance & Limits ─────────────────────────────────────────────
    {
        auto* g = makeGroup("Performance & Limits");
        auto* form = new QFormLayout(g);

        p2pMaxPeersSpin_ = new QSpinBox;
        p2pMaxPeersSpin_->setRange(1, 500);
        p2pMaxPeersSpin_->setValue(30);
        p2pMaxPeersSpin_->setToolTip("--p2p-max-peers  (total P2P connections)");
        form->addRow("Max P2P peers:", p2pMaxPeersSpin_);

        banDurationSpin_ = new QSpinBox;
        banDurationSpin_->setRange(0, 86400);
        banDurationSpin_->setValue(300);
        banDurationSpin_->setSuffix(" sec");
        banDurationSpin_->setToolTip("--ban-duration  (peer ban timeout)");
        form->addRow("Ban duration:", banDurationSpin_);

        rssLimitMbSpin_ = new QSpinBox;
        rssLimitMbSpin_->setRange(256, 65536);
        rssLimitMbSpin_->setValue(4000);
        rssLimitMbSpin_->setSuffix(" MB");
        rssLimitMbSpin_->setToolTip("--rss-limit-mb  (abort if memory exceeds)");
        form->addRow("RSS limit:", rssLimitMbSpin_);

        cacheSharedHashesSpin_ = new QSpinBox;
        cacheSharedHashesSpin_->setRange(1000, 500000);
        cacheSharedHashesSpin_->setValue(50000);
        cacheSharedHashesSpin_->setToolTip("cache_max_shared_hashes  (de-dup set size)");
        form->addRow("Cache shared hashes:", cacheSharedHashesSpin_);

        cacheKnownTxsSpin_ = new QSpinBox;
        cacheKnownTxsSpin_->setRange(1000, 500000);
        cacheKnownTxsSpin_->setValue(10000);
        cacheKnownTxsSpin_->setToolTip("cache_max_known_txs  (TX cache size)");
        form->addRow("Cache known TXs:", cacheKnownTxsSpin_);

        cacheRawSharesSpin_ = new QSpinBox;
        cacheRawSharesSpin_->setRange(1000, 500000);
        cacheRawSharesSpin_->setValue(50000);
        cacheRawSharesSpin_->setToolTip("cache_max_raw_shares  (share cache size)");
        form->addRow("Cache raw shares:", cacheRawSharesSpin_);

        vbox->addWidget(g);
    }

    // ── 7d. Web & CORS ───────────────────────────────────────────────────────
    {
        auto* g = makeGroup("Web & CORS");
        auto* form = new QFormLayout(g);

        externalIpEdit_ = new QLineEdit;
        externalIpEdit_->setPlaceholderText("auto-detect");
        externalIpEdit_->setToolTip("--external-ip  (public IP for stratum URLs)");
        form->addRow("External IP:", externalIpEdit_);

        corsOriginEdit_ = new QLineEdit;
        corsOriginEdit_->setPlaceholderText("disabled (e.g. * or https://example.com)");
        corsOriginEdit_->setToolTip("--cors-origin  (CORS Access-Control-Allow-Origin header)");
        form->addRow("CORS origin:", corsOriginEdit_);

        dashboardDirEdit_ = new QLineEdit;
        dashboardDirEdit_->setPlaceholderText("web-static (default)");
        dashboardDirEdit_->setToolTip("--dashboard-dir  (path to web dashboard files)");
        form->addRow("Dashboard dir:", dashboardDirEdit_);

        vbox->addWidget(g);
    }

    // ── 7e. Block Explorer ───────────────────────────────────────────────────
    {
        auto* g = makeGroup("Block Explorer (embedded)");
        auto* form = new QFormLayout(g);

        explorerCheck_ = new QCheckBox("Enable embedded block explorer");
        explorerCheck_->setToolTip("explorer  (serve block/tx data from embedded SPV)");
        form->addRow("", explorerCheck_);

        explorerUrlEdit_ = new QLineEdit;
        explorerUrlEdit_->setPlaceholderText("auto (custom explorer base URL)");
        explorerUrlEdit_->setToolTip("explorer_url");
        form->addRow("Explorer URL:", explorerUrlEdit_);

        explorerDepthLtcSpin_ = new QSpinBox;
        explorerDepthLtcSpin_->setRange(1, 10000);
        explorerDepthLtcSpin_->setValue(288);
        explorerDepthLtcSpin_->setToolTip("explorer_depth_ltc  (blocks to retain)");
        form->addRow("LTC depth:", explorerDepthLtcSpin_);

        explorerDepthDogeSpin_ = new QSpinBox;
        explorerDepthDogeSpin_->setRange(1, 50000);
        explorerDepthDogeSpin_->setValue(1440);
        explorerDepthDogeSpin_->setToolTip("explorer_depth_doge  (blocks to retain)");
        form->addRow("DOGE depth:", explorerDepthDogeSpin_);

        addrExplorerPrefixEdit_ = new QLineEdit;
        addrExplorerPrefixEdit_->setPlaceholderText("https://blockchair.com/litecoin/address/");
        addrExplorerPrefixEdit_->setToolTip("address_explorer_prefix");
        form->addRow("Address explorer:", addrExplorerPrefixEdit_);

        blockExplorerPrefixEdit_ = new QLineEdit;
        blockExplorerPrefixEdit_->setPlaceholderText("https://blockchair.com/litecoin/block/");
        blockExplorerPrefixEdit_->setToolTip("block_explorer_prefix");
        form->addRow("Block explorer:", blockExplorerPrefixEdit_);

        txExplorerPrefixEdit_ = new QLineEdit;
        txExplorerPrefixEdit_->setPlaceholderText("https://blockchair.com/litecoin/transaction/");
        txExplorerPrefixEdit_->setToolTip("tx_explorer_prefix");
        form->addRow("TX explorer:", txExplorerPrefixEdit_);

        vbox->addWidget(g);
    }

    // ── 8. Private Sharechain ─────────────────────────────────────────────────
    {
        auto* g = makeGroup("Private Sharechain");
        auto* form = new QFormLayout(g);

        privateChainCheck_ = new QCheckBox("Enable private sharechain");
        privateChainCheck_->setToolTip(
            "Create an isolated mining network. Only nodes with the same\n"
            "Network ID can exchange shares. The ID is hashed into every\n"
            "share's verification hash (IDENTIFIER) — it acts as a shared\n"
            "secret that gates sharechain participation.");
        form->addRow(privateChainCheck_);

        auto* idRow = new QHBoxLayout;
        networkIdEdit_ = new QLineEdit;
        networkIdEdit_->setPlaceholderText("e.g. DEADBEEF12345678");
        networkIdEdit_->setMaxLength(16);
        networkIdEdit_->setToolTip(
            "--network-id  (8-byte hex identifier)\n\n"
            "This overrides the IDENTIFIER used in share consensus.\n"
            "A node without this ID cannot forge valid shares.\n"
            "Share it only with trusted miners.");
        networkIdEdit_->setEnabled(false);
        idRow->addWidget(networkIdEdit_);

        generateIdBtn_ = new QPushButton("Generate");
        generateIdBtn_->setToolTip("Generate a random 8-byte network identifier");
        generateIdBtn_->setEnabled(false);
        generateIdBtn_->setFixedWidth(80);
        connect(generateIdBtn_, &QPushButton::clicked, this, [this]() {
            // Generate 8 random bytes as hex
            static const char* HEX = "0123456789ABCDEF";
            QString id;
            std::srand(static_cast<unsigned>(std::time(nullptr)));
            for (int i = 0; i < 16; ++i)
                id += HEX[std::rand() % 16];
            networkIdEdit_->setText(id);
            onBuildPreview();
        });
        idRow->addWidget(generateIdBtn_);
        form->addRow("Network ID:", idRow);

        privateStatusLabel_ = new QLabel("Public p2pool network");
        privateStatusLabel_->setStyleSheet("color: green; font-weight: bold;");
        form->addRow("Status:", privateStatusLabel_);

        // Startup mode
        startupModeCombo_ = new QComboBox;
        startupModeCombo_->addItem("Auto (wait 60s, then genesis)", "auto");
        startupModeCombo_->addItem("Genesis (new chain immediately)", "genesis");
        startupModeCombo_->addItem("Wait for peers (never genesis)", "wait");
        startupModeCombo_->setToolTip(
            "--startup-mode\n\n"
            "auto: Wait for peers (60s timeout), create genesis if none found\n"
            "genesis: Create new chain immediately, don't wait for peers\n"
            "wait: Never create genesis, wait indefinitely for peers to sync");
        connect(startupModeCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged),
                this, [this](int) { onBuildPreview(); });
        form->addRow("Startup mode:", startupModeCombo_);

        connect(privateChainCheck_, &QCheckBox::stateChanged, this, [this](int state) {
            bool enabled = (state == Qt::Checked);
            networkIdEdit_->setEnabled(enabled);
            generateIdBtn_->setEnabled(enabled);
            if (enabled) {
                privateStatusLabel_->setText("Private chain (isolated network)");
                privateStatusLabel_->setStyleSheet("color: orange; font-weight: bold;");
                if (networkIdEdit_->text().isEmpty())
                    generateIdBtn_->click();  // auto-generate on first enable
            } else {
                networkIdEdit_->clear();
                privateStatusLabel_->setText("Public p2pool network");
                privateStatusLabel_->setStyleSheet("color: green; font-weight: bold;");
            }
            onBuildPreview();
        });

        vbox->addWidget(g);
    }

    // ── 9. Advanced ──────────────────────────────────────────────────────────
    {
        auto* g = makeGroup("Advanced");
        auto* form = new QFormLayout(g);

        configFileEdit_ = new QLineEdit;
        configFileEdit_->setPlaceholderText("path/to/config.yaml (optional)");
        configFileEdit_->setToolTip("--config  (load settings from YAML config file)");
        form->addRow("Config file:", configFileEdit_);

        auto* configBtnRow = new QHBoxLayout;
        importConfigBtn_ = new QPushButton("Import Config...");
        importConfigBtn_->setToolTip("Load a YAML config file and populate all form fields");
        exportConfigBtn_ = new QPushButton("Export Config...");
        exportConfigBtn_->setToolTip("Save current form state as a YAML config file");
        configBtnRow->addWidget(importConfigBtn_);
        configBtnRow->addWidget(exportConfigBtn_);
        configBtnRow->addStretch();
        form->addRow("", configBtnRow);

        connect(importConfigBtn_, &QPushButton::clicked, this, [this]() {
            const QString path = QFileDialog::getOpenFileName(
                this, "Import c2pool Config", QString(), "YAML files (*.yaml *.yml);;All files (*)");
            if (path.isEmpty()) return;
            const auto config = ConfigSerializer::loadYaml(path);
            ConfigSerializer::toPageLaunch(config, this);
            onBuildPreview();
        });

        connect(exportConfigBtn_, &QPushButton::clicked, this, [this]() {
            const QString path = QFileDialog::getSaveFileName(
                this, "Export c2pool Config", "c2pool.yaml", "YAML files (*.yaml *.yml);;All files (*)");
            if (path.isEmpty()) return;
            saveSettings();  // ensure QSettings is up-to-date
            const auto config = ConfigSerializer::fromPageLaunch(this);
            ConfigSerializer::saveYaml(config, path);
        });

        messageBlobEdit_ = new QLineEdit;
        messageBlobEdit_->setPlaceholderText("hex string (optional, v36+)");
        messageBlobEdit_->setToolTip("--message-blob-hex  (embedded share message data)");
        form->addRow("Message blob hex:", messageBlobEdit_);

        coinbaseTextEdit_ = new QLineEdit;
        coinbaseTextEdit_->setPlaceholderText("/c2pool/ (default, max 20 chars with MM)");
        coinbaseTextEdit_->setMaxLength(20);
        coinbaseTextEdit_->setToolTip(
            "--coinbase-text  (custom text in coinbase scriptSig)\n"
            "Replaces /c2pool/ tag. Max 20 chars with merged mining, 64 without.\n"
            "c2pool is always identified by donation address in coinbase outputs.");
        form->addRow("Coinbase text:", coinbaseTextEdit_);

        vbox->addWidget(g);
    }

    // ── 10. Command preview + controls ────────────────────────────────────────
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

QString LaunchCommand::displayString() const
{
    QStringList parts;
    parts << program;
    parts << arguments;
    return parts.join(" ");
}

LaunchCommand PageLaunch::buildCommand() const
{
    LaunchCommand cmd;
    cmd.program = binaryEdit_->text().trimmed();
    QStringList& parts = cmd.arguments;

    // Mode
    const int modeIdx = modeCombo_->currentIndex();
    if (modeIdx == 0)      parts << "--integrated";
    else if (modeIdx == 1) parts << "--sharechain";
    // solo = default, no flag

    // Network
    if (testnetCheck_->isChecked()) parts << "--testnet";
    const QString chain = chainCombo_->currentText();
    if (chain != "litecoin") parts << "--net" << chain;

    // Custodial
    if (custodialCheck_->isChecked()) parts << "--custodial";

    // Embedded SPV
    if (!embeddedLtcCheck_->isChecked()) parts << "--no-embedded-ltc";
    if (!embeddedDogeCheck_->isChecked()) parts << "--no-embedded-doge";
    if (dogeTestnet4Check_->isChecked()) parts << "--doge-testnet4alpha";
    const QString hdrCp = headerCheckpointEdit_->text().trimmed();
    if (!hdrCp.isEmpty()) parts << "--header-checkpoint" << hdrCp;
    const QString dogeHdrCp = dogeHeaderCheckpointEdit_->text().trimmed();
    if (!dogeHdrCp.isEmpty()) parts << "--doge-header-checkpoint" << dogeHdrCp;

    // Ports
    parts << "--p2pool-port" << QString::number(p2pPortSpin_->value());
    parts << "-w"            << QString::number(stratumPortSpin_->value());
    parts << "--web-port"    << QString::number(httpPortSpin_->value());

    // Stratum tuning (only if non-default)
    if (stratumMinDiffSpin_->value() != 0.0005)
        parts << "--stratum-min-diff" << QString::number(stratumMinDiffSpin_->value(), 'f', 4);
    if (stratumMaxDiffSpin_->value() != 65536.0)
        parts << "--stratum-max-diff" << QString::number(stratumMaxDiffSpin_->value(), 'f', 3);
    if (stratumTargetTimeSpin_->value() != 3.0)
        parts << "--stratum-target-time" << QString::number(stratumTargetTimeSpin_->value(), 'f', 1);
    if (!vardiffCheck_->isChecked())
        parts << "--no-vardiff";
    if (maxCoinbaseOutputsSpin_->value() != 4000)
        parts << "--max-coinbase-outputs" << QString::number(maxCoinbaseOutputsSpin_->value());

    // Config file (must come early so CLI flags override it)
    const QString configFile = configFileEdit_->text().trimmed();
    if (!configFile.isEmpty()) parts << "--config" << configFile;

    // Coin daemon
    const QString coindHost = coindHostEdit_->text().trimmed();
    if (!coindHost.isEmpty()) parts << "--coind-address" << coindHost;
    if (coindPortSpin_->value() > 0)
        parts << "--coind-rpc-port" << QString::number(coindPortSpin_->value());
    const QString rpcUser = rpcUserEdit_->text().trimmed();
    const QString rpcPass = rpcPassEdit_->text().trimmed();
    if (!rpcUser.isEmpty()) parts << "--rpcuser" << rpcUser;
    if (!rpcPass.isEmpty()) parts << "--rpcpassword" << rpcPass;
    if (coindP2pPortSpin_->value() > 0)
        parts << "--coind-p2p-port" << QString::number(coindP2pPortSpin_->value());
    const QString coindP2pAddr = coindP2pAddrEdit_->text().trimmed();
    if (!coindP2pAddr.isEmpty()) parts << "--coind-p2p-address" << coindP2pAddr;
    const QString dogeP2pAddr = dogeP2pAddrEdit_->text().trimmed();
    if (!dogeP2pAddr.isEmpty()) parts << "--doge-p2p-address" << dogeP2pAddr;
    if (dogeP2pPortSpin_->value() > 0)
        parts << "--doge-p2p-port" << QString::number(dogeP2pPortSpin_->value());

    // Payout address
    const QString addr = addressEdit_->text().trimmed();
    if (!addr.isEmpty()) parts << "--address" << addr;
    if (!autoDetectWalletCheck_->isChecked())
        parts << "--no-auto-detect-wallet";

    // Fee / donation
    if (feeSpinBox_->value() > 0.0)
        parts << "-f" << QString::number(feeSpinBox_->value(), 'f', 2);
    if (giveAuthorSpinBox_->value() > 0.0)
        parts << "--give-author" << QString::number(giveAuthorSpinBox_->value(), 'f', 2);
    const QString nodeOwnerAddr = nodeOwnerAddrEdit_->text().trimmed();
    if (!nodeOwnerAddr.isEmpty())
        parts << "--node-owner-address" << nodeOwnerAddr;
    const QString nodeOwnerScript = nodeOwnerScriptEdit_->text().trimmed();
    if (!nodeOwnerScript.isEmpty())
        parts << "--node-owner-script" << nodeOwnerScript;

    const QString nodeOwnerMergedAddr = nodeOwnerMergedAddrEdit_->text().trimmed();
    if (!nodeOwnerMergedAddr.isEmpty())
        parts << "--node-owner-merged-address" << nodeOwnerMergedAddr;

    // Redistribute (only if non-default)
    const QString redistribute = redistributeCombo_->currentText();
    if (redistribute != "pplns")
        parts << "--redistribute" << redistribute;

    // Payout window / storage
    if (payoutWindowSpin_->value() != 86400)
        parts << "--payout-window" << QString::number(payoutWindowSpin_->value());
    if (storageSaveIntervalSpin_->value() != 300)
        parts << "--storage-save-interval" << QString::number(storageSaveIntervalSpin_->value());

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

    // HTTP host
    const QString httpHost = httpHostEdit_->text().trimmed();
    if (!httpHost.isEmpty() && httpHost != "0.0.0.0")
        parts << "--http-host" << httpHost;

    // Seed nodes
    const QStringList seedLines = seedNodesEdit_->toPlainText().split('\n', Qt::SkipEmptyParts);
    for (const QString& line : seedLines) {
        const QString trimmed = line.trimmed();
        if (!trimmed.isEmpty())
            parts << "-n" << trimmed;
    }

    // Logging
    const QString logLevel = logLevelCombo_->currentText();
    if (logLevel != "info")
        parts << "--log-level" << logLevel;
    const QString logFile = logFileEdit_->text().trimmed();
    if (!logFile.isEmpty())
        parts << "--log-file" << logFile;
    if (logRotationMbSpin_->value() != 100)
        parts << "--log-rotation-mb" << QString::number(logRotationMbSpin_->value());
    if (logMaxMbSpin_->value() != 50)
        parts << "--log-max-mb" << QString::number(logMaxMbSpin_->value());

    // Performance & Limits
    if (p2pMaxPeersSpin_->value() != 30)
        parts << "--p2p-max-peers" << QString::number(p2pMaxPeersSpin_->value());
    if (banDurationSpin_->value() != 300)
        parts << "--ban-duration" << QString::number(banDurationSpin_->value());
    if (rssLimitMbSpin_->value() != 4000)
        parts << "--rss-limit-mb" << QString::number(rssLimitMbSpin_->value());

    // Web & CORS
    const QString extIp = externalIpEdit_->text().trimmed();
    if (!extIp.isEmpty())
        parts << "--external-ip" << extIp;
    const QString corsOrigin = corsOriginEdit_->text().trimmed();
    if (!corsOrigin.isEmpty())
        parts << "--cors-origin" << corsOrigin;
    const QString dashDir = dashboardDirEdit_->text().trimmed();
    if (!dashDir.isEmpty() && dashDir != "web-static")
        parts << "--dashboard-dir" << dashDir;

    // Message blob
    const QString msgBlob = messageBlobEdit_->text().trimmed();
    if (!msgBlob.isEmpty())
        parts << "--message-blob-hex" << msgBlob;

    // Coinbase text
    const QString cbText = coinbaseTextEdit_->text().trimmed();
    if (!cbText.isEmpty())
        parts << "--coinbase-text" << cbText;

    // Private sharechain
    if (privateChainCheck_->isChecked()) {
        const QString nid = networkIdEdit_->text().trimmed();
        if (!nid.isEmpty())
            parts << "--network-id" << nid;
    }

    // Startup mode
    const QString smode = startupModeCombo_->currentData().toString();
    if (smode == "genesis")
        parts << "--genesis";
    else if (smode == "wait")
        parts << "--wait-for-peers";

    return cmd;
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
    cmdPreview_->setPlainText(buildCommand().displayString());
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
    if (launcher_->isRunning()) {
        emit daemonStateChanged("Daemon: already running", "color: #b04020;");
        return;
    }
    onBuildPreview();
    const auto cmd = buildCommand();
    if (cmd.program.isEmpty()) {
        emit daemonStateChanged("Daemon: empty command", "color: #b04020;");
        return;
    }
    launcher_->start(cmd.program, cmd.arguments, QDir::currentPath());
}

void PageLaunch::stop()
{
    if (!launcher_->isRunning()) {
        emit daemonStateChanged("Daemon: not running", "color: #888888;");
        return;
    }
    launcher_->stop();
}

void PageLaunch::restart()
{
    stop();
    launch();
}

bool PageLaunch::isDaemonRunning() const
{
    return launcher_->isRunning();
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
    s.setValue("coindP2pPort",  coindP2pPortSpin_->value());
    s.setValue("coindP2pAddr",  coindP2pAddrEdit_->text());
    s.setValue("autoDetectWallet", autoDetectWalletCheck_->isChecked());
    s.setValue("nodeOwnerScript", nodeOwnerScriptEdit_->text());
    s.setValue("httpHost",      httpHostEdit_->text());
    s.setValue("seedNodes",     seedNodesEdit_->toPlainText());
    s.setValue("configFile",    configFileEdit_->text());
    s.setValue("messageBlob",   messageBlobEdit_->text());
    s.setValue("coinbaseText",  coinbaseTextEdit_->text());

    // New Phase 1 settings
    s.setValue("custodial",     custodialCheck_->isChecked());
    s.setValue("embeddedLtc",   embeddedLtcCheck_->isChecked());
    s.setValue("embeddedDoge",  embeddedDogeCheck_->isChecked());
    s.setValue("dogeTestnet4",  dogeTestnet4Check_->isChecked());
    s.setValue("headerCheckpoint",     headerCheckpointEdit_->text());
    s.setValue("dogeHeaderCheckpoint",  dogeHeaderCheckpointEdit_->text());
    s.setValue("dogeP2pAddr",   dogeP2pAddrEdit_->text());
    s.setValue("dogeP2pPort",   dogeP2pPortSpin_->value());
    s.setValue("stratumMinDiff",  stratumMinDiffSpin_->value());
    s.setValue("stratumMaxDiff",  stratumMaxDiffSpin_->value());
    s.setValue("stratumTargetTime", stratumTargetTimeSpin_->value());
    s.setValue("vardiff",       vardiffCheck_->isChecked());
    s.setValue("maxCoinbaseOutputs", maxCoinbaseOutputsSpin_->value());
    s.setValue("nodeOwnerMergedAddr", nodeOwnerMergedAddrEdit_->text());
    s.setValue("payoutWindow",  payoutWindowSpin_->value());
    s.setValue("storageSaveInterval", storageSaveIntervalSpin_->value());
    s.setValue("logLevel",      logLevelCombo_->currentText());
    s.setValue("logFile",       logFileEdit_->text());
    s.setValue("logRotationMb", logRotationMbSpin_->value());
    s.setValue("logMaxMb",      logMaxMbSpin_->value());
    s.setValue("p2pMaxPeers",   p2pMaxPeersSpin_->value());
    s.setValue("banDuration",   banDurationSpin_->value());
    s.setValue("rssLimitMb",    rssLimitMbSpin_->value());
    s.setValue("cacheSharedHashes", cacheSharedHashesSpin_->value());
    s.setValue("cacheKnownTxs", cacheKnownTxsSpin_->value());
    s.setValue("cacheRawShares", cacheRawSharesSpin_->value());
    s.setValue("externalIp",    externalIpEdit_->text());
    s.setValue("corsOrigin",    corsOriginEdit_->text());
    s.setValue("dashboardDir",  dashboardDirEdit_->text());
    s.setValue("explorer",      explorerCheck_->isChecked());
    s.setValue("explorerUrl",   explorerUrlEdit_->text());
    s.setValue("explorerDepthLtc",  explorerDepthLtcSpin_->value());
    s.setValue("explorerDepthDoge", explorerDepthDogeSpin_->value());
    s.setValue("addrExplorerPrefix",  addrExplorerPrefixEdit_->text());
    s.setValue("blockExplorerPrefix", blockExplorerPrefixEdit_->text());
    s.setValue("txExplorerPrefix",    txExplorerPrefixEdit_->text());
    s.setValue("privateChain",  privateChainCheck_->isChecked());
    s.setValue("networkId",     networkIdEdit_->text());
    s.setValue("startupMode",   startupModeCombo_->currentData().toString());

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
    coindP2pPortSpin_->setValue(s.value("coindP2pPort", 0).toInt());
    coindP2pAddrEdit_->setText(s.value("coindP2pAddr").toString());
    autoDetectWalletCheck_->setChecked(s.value("autoDetectWallet", true).toBool());
    nodeOwnerScriptEdit_->setText(s.value("nodeOwnerScript").toString());
    httpHostEdit_->setText(s.value("httpHost", "0.0.0.0").toString());
    seedNodesEdit_->setPlainText(s.value("seedNodes").toString());
    configFileEdit_->setText(s.value("configFile").toString());
    messageBlobEdit_->setText(s.value("messageBlob").toString());
    coinbaseTextEdit_->setText(s.value("coinbaseText").toString());

    // New Phase 1 settings
    custodialCheck_->setChecked(s.value("custodial", false).toBool());
    embeddedLtcCheck_->setChecked(s.value("embeddedLtc", true).toBool());
    embeddedDogeCheck_->setChecked(s.value("embeddedDoge", true).toBool());
    dogeTestnet4Check_->setChecked(s.value("dogeTestnet4", false).toBool());
    headerCheckpointEdit_->setText(s.value("headerCheckpoint").toString());
    dogeHeaderCheckpointEdit_->setText(s.value("dogeHeaderCheckpoint").toString());
    dogeP2pAddrEdit_->setText(s.value("dogeP2pAddr").toString());
    dogeP2pPortSpin_->setValue(s.value("dogeP2pPort", 0).toInt());
    stratumMinDiffSpin_->setValue(s.value("stratumMinDiff", 0.0005).toDouble());
    stratumMaxDiffSpin_->setValue(s.value("stratumMaxDiff", 65536.0).toDouble());
    stratumTargetTimeSpin_->setValue(s.value("stratumTargetTime", 3.0).toDouble());
    vardiffCheck_->setChecked(s.value("vardiff", true).toBool());
    maxCoinbaseOutputsSpin_->setValue(s.value("maxCoinbaseOutputs", 4000).toInt());
    nodeOwnerMergedAddrEdit_->setText(s.value("nodeOwnerMergedAddr").toString());
    payoutWindowSpin_->setValue(s.value("payoutWindow", 86400).toInt());
    storageSaveIntervalSpin_->setValue(s.value("storageSaveInterval", 300).toInt());
    {
        const int idx = logLevelCombo_->findText(s.value("logLevel", "info").toString());
        logLevelCombo_->setCurrentIndex(idx >= 0 ? idx : 2);
    }
    logFileEdit_->setText(s.value("logFile").toString());
    logRotationMbSpin_->setValue(s.value("logRotationMb", 100).toInt());
    logMaxMbSpin_->setValue(s.value("logMaxMb", 50).toInt());
    p2pMaxPeersSpin_->setValue(s.value("p2pMaxPeers", 30).toInt());
    banDurationSpin_->setValue(s.value("banDuration", 300).toInt());
    rssLimitMbSpin_->setValue(s.value("rssLimitMb", 4000).toInt());
    cacheSharedHashesSpin_->setValue(s.value("cacheSharedHashes", 50000).toInt());
    cacheKnownTxsSpin_->setValue(s.value("cacheKnownTxs", 10000).toInt());
    cacheRawSharesSpin_->setValue(s.value("cacheRawShares", 50000).toInt());
    externalIpEdit_->setText(s.value("externalIp").toString());
    corsOriginEdit_->setText(s.value("corsOrigin").toString());
    dashboardDirEdit_->setText(s.value("dashboardDir").toString());
    explorerCheck_->setChecked(s.value("explorer", false).toBool());
    explorerUrlEdit_->setText(s.value("explorerUrl").toString());
    explorerDepthLtcSpin_->setValue(s.value("explorerDepthLtc", 288).toInt());
    explorerDepthDogeSpin_->setValue(s.value("explorerDepthDoge", 1440).toInt());
    addrExplorerPrefixEdit_->setText(s.value("addrExplorerPrefix").toString());
    blockExplorerPrefixEdit_->setText(s.value("blockExplorerPrefix").toString());
    txExplorerPrefixEdit_->setText(s.value("txExplorerPrefix").toString());
    privateChainCheck_->setChecked(s.value("privateChain", false).toBool());
    networkIdEdit_->setText(s.value("networkId").toString());
    {
        const QString smode = s.value("startupMode", "auto").toString();
        const int idx = startupModeCombo_->findData(smode);
        startupModeCombo_->setCurrentIndex(idx >= 0 ? idx : 0);
    }

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
