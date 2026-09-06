// SPDX-License-Identifier: AGPL-3.0-or-later
#include "PageLaunch.hpp"

#include "AddressValidator.hpp"
#include "CoinProfiles.hpp"
#include "LaunchCommand.hpp"
#include "SettingsStore.hpp"

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

using c2pool_qt::CliFamily;
using c2pool_qt::CoinProfile;
using c2pool_qt::coinProfile;

struct PortDefaults {
    int p2p;
    int stratum;
    int http;
    int rpc;
};

PortDefaults defaultsForNetwork(const QString& chain, bool testnet)
{
    const CoinProfile& p = coinProfile(chain);
    const int rpc = testnet ? p.rpcPortTestnet : p.rpcPortMainnet;

    // PerCoinRun coins (c2pool-dash / -dgb / -bch) use the profile's
    // miner-facing / dashboard port suggestions; the "p2p sharechain"
    // spin doubles as the sharechain listen port.
    if (p.cli == CliFamily::PerCoinRun) {
        const int stratum = p.stratumPortDefault;
        const int http = p.supportsWebPort ? p.webPortDefault : 0;
        const int listen = testnet ? 19339 : 9339;  // sharechain listen suggestion
        return {listen, stratum, http, rpc};
    }

    // LegacyUnified coins keep the Python-p2pool-compatible port layout.
    if (chain == "bitcoin") {
        const int p2p = testnet ? 19333 : 9333;
        const int stratum = testnet ? 19332 : 9332;
        const int http = (stratum + 1 == p2p) ? stratum + 2 : stratum + 1;
        return {p2p, stratum, http, rpc};
    }

    if (chain == "dogecoin") {
        const int p2p = testnet ? 44556 : 22556;
        const int stratum = testnet ? 44555 : 22555;
        const int http = stratum + 2;
        return {p2p, stratum, http, rpc};
    }

    const int p2p = testnet ? 19338 : 9338;
    const int stratum = testnet ? 19327 : 9327;
    const int http = stratum + 1;
    return {p2p, stratum, http, rpc};
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Construction
// ─────────────────────────────────────────────────────────────────────────────

PageLaunch::PageLaunch(SettingsStore* settings, QWidget* parent)
    : QWidget(parent), settings_(settings), process_(new QProcess(this))
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
        // Order matches c2pool_qt::LegacyMode. Each item maps to a catalog mode
        // alias; a legacy "solo" MUST emit --solo (emitting nothing silently ran
        // an integrated PPLNS node). Appending custodial/standalone at 3/4 keeps
        // older persisted `mode` indices (0/1/2) valid.
        modeCombo_->addItems({"Integrated (full pool, binary default)",
                              "Sharechain (P2P node)",
                              "Solo (no sharechain, --solo)",
                              "Custodial (--custodial, coinbase to --address)",
                              "Standalone legacy (--standalone, no embedded SPV)"});
        modeCombo_->setCurrentIndex(1);
        form->addRow("Mode:", modeCombo_);

        chainCombo_ = new QComboBox;
        {
            int n = 0;
            const c2pool_qt::CoinProfile* profs = c2pool_qt::coinProfiles(n);
            for (int i = 0; i < n; ++i)
                chainCombo_->addItem(profs[i].displayLabel, profs[i].symbol);
        }
        chainCombo_->setToolTip(
            "Coin-generic (profile-driven). LTC/BTC/DOGE use the unified\n"
            "`c2pool --net …` binary; DASH/DGB/BCH use the dedicated per-coin\n"
            "binary. DASH runs daemonless by default (bare --run); attaching an\n"
            "external dashd (--coin-rpc) is an explicit opt-in.");
        form->addRow("Blockchain:", chainCombo_);

        testnetCheck_ = new QCheckBox("Use testnet");
        form->addRow("Network:", testnetCheck_);

        coinNoteLabel_ = new QLabel;
        coinNoteLabel_->setWordWrap(true);
        coinNoteLabel_->setStyleSheet("color: #555; font-size: 11px;");
        form->addRow("", coinNoteLabel_);

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
        auto* g = makeGroup("Parent Coin Daemon");
        coindGroup_ = g;
        auto* form = new QFormLayout(g);

        // DASH runs daemonless by default (bare --run). Attaching an external
        // dashd (--coin-rpc HOST:PORT [+ --coin-rpc-auth]) is an explicit opt-in;
        // default OFF. Shown only for DASH (applyProfileUi()).
        dashdAttachCheck_ = new QCheckBox(
            "Attach external dashd (--coin-rpc HOST:PORT [+ --coin-rpc-auth]) "
            "— optional; default is daemonless");
        dashdAttachCheck_->setChecked(false);
        dashdAttachCheck_->setToolTip(
            "DASH only. Left unticked (default), the node launches with a bare\n"
            "`--run` — DAEMONLESS cut mode, with the node's good-citizen serving\n"
            "levers ON. Tick this to attach an external dashd via --coin-rpc\n"
            "(and --coin-rpc-auth); the RPC host/port below are then used.");
        connect(dashdAttachCheck_, &QCheckBox::stateChanged, this, [this](int) {
            applyProfileUi();
            onBuildPreview();
        });
        form->addRow("", dashdAttachCheck_);

        coindHostEdit_ = new QLineEdit("127.0.0.1");
        coindHostEdit_->setToolTip(
            "Legacy (LTC/BTC/DOGE): --coind-address / --rpchost\n"
            "Per-coin (DGB): host of --coin-rpc HOST:PORT\n"
            "Per-coin (DASH): only with 'Attach external dashd' ticked");
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

        // Per-coin binaries (DASH/DGB/BCH) read rpcuser/rpcpassword from the
        // coin's .conf so the password NEVER lands on argv. Blank ⇒ default
        // conf path for that coin.
        rpcConfPathEdit_ = new QLineEdit;
        rpcConfPathEdit_->setToolTip(
            "--coin-rpc-auth / --rpc-conf PATH\n"
            "bitcoin.conf-style file carrying rpcuser/rpcpassword. The\n"
            "password is read from here, never placed on the command line.\n"
            "Blank ⇒ the binary's default conf path.");
        form->addRow("RPC conf file:", rpcConfPathEdit_);

        dataDirEdit_ = new QLineEdit;
        dataDirEdit_->setPlaceholderText("~/.c2pool (default)");
        dataDirEdit_->setToolTip("--data-dir PATH  (per-instance state root; isolates co-located instances)");
        form->addRow("Data dir:", dataDirEdit_);

        vbox->addWidget(g);
    }

    // ── 5. Payout & Fees ─────────────────────────────────────────────────────
    {
        auto* g = makeGroup("Payout, Fees & Redistribution");
        auto* form = new QFormLayout(g);

        addressEdit_ = new QLineEdit;
        addressEdit_->setPlaceholderText("payout address for the selected coin");
        addressEdit_->setToolTip("--address / --solo-address  (YOUR mining payout address)");
        form->addRow("Payout address:", addressEdit_);

        // Inline address-flavor status (QP-B). Hidden until it has something
        // to say; turns red for a positively-identified wrong-coin address
        // (which launch() then refuses to start).
        addressStatusLabel_ = new QLabel;
        addressStatusLabel_->setWordWrap(true);
        addressStatusLabel_->setVisible(false);
        form->addRow("", addressStatusLabel_);

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
        // ★ Tri-state / reward-safety: at 0.00 the flag is OMITTED so the
        // binary default applies (0.1% for DASH/LTC/BIP110, 0.5% for BTC). The
        // special-value text says so; an explicit 0 requires the ack below.
        giveAuthorSpinBox_->setSpecialValueText("binary default (0.1% / BTC 0.5%)");
        giveAuthorSpinBox_->setToolTip(
            "--give-author / --dev-donation\n"
            "0.00 ⇒ OMITTED (binary default author donation applies).\n"
            "Set a value to override, or tick the box below to donate 0% "
            "explicitly (opt-in — never a silent default for a public node).");
        form->addRow("Dev donation (--give-author):", giveAuthorSpinBox_);

        giveAuthorZeroAckCheck_ = new QCheckBox(
            "Donate 0% to the author explicitly (opt-in; emits --give-author 0)");
        giveAuthorZeroAckCheck_->setChecked(false);
        giveAuthorZeroAckCheck_->setToolTip(
            "Reward-safety guard. Only with this ticked does the panel emit "
            "--give-author 0. Left unticked, a 0.00 spin value means \"use the "
            "binary default\", never a forced zero.");
        form->addRow("", giveAuthorZeroAckCheck_);
        connect(giveAuthorZeroAckCheck_, &QCheckBox::stateChanged, this,
                [this](int) { onBuildPreview(); });

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

    // ── 9b. PerCoinRun run-loop controls (DASH/DGB/BCH) ──────────────────────
    // Deeper, reward-NEUTRAL run-loop knobs for the dedicated per-coin binaries.
    // Every flag is catalog-gated on the active binary, so a control that the
    // selected coin's binary does not accept is simply not emitted (and the row
    // is greyed out by applyProfileUi()). Shown only for PerCoinRun coins.
    {
        auto* g = makeGroup("Run-loop controls (per-coin binary)");
        runLoopGroup_ = g;
        auto* form = new QFormLayout(g);

        coinP2pDiscoverCheck_ = new QCheckBox(
            "Scored coin-P2P peer discovery (--coin-p2p-discover)");
        coinP2pDiscoverCheck_->setToolTip(
            "--coin-p2p-discover — diverse/scored coin-network peer discovery. "
            "Transport only; reward-neutral (never moves the block-producing arm). "
            "DASH/DGB.");
        form->addRow("Peer discovery:", coinP2pDiscoverCheck_);

        noP2pRelayCheck_ = new QCheckBox(
            "Suppress embedded won-block relay (--no-p2p-relay)");
        noP2pRelayCheck_->setToolTip(
            "--no-p2p-relay — do not relay a won block over the embedded coin "
            "P2P arm (RPC submit still happens). DASH/DGB.");
        form->addRow("Won-block relay:", noP2pRelayCheck_);

        bchAnchorEdit_ = new QLineEdit;
        bchAnchorEdit_->setPlaceholderText("HEIGHT:HASH (BCH cold-start ABLA floor, optional)");
        bchAnchorEdit_->setToolTip(
            "--anchor HEIGHT:HASH — BCH cold-start ABLA (adaptive blocksize) "
            "anchor. Reward-neutral bootstrap hint; BCH only.");
        form->addRow("BCH anchor:", bchAnchorEdit_);

        connect(coinP2pDiscoverCheck_, &QCheckBox::stateChanged, this,
                [this](int) { onBuildPreview(); });
        connect(noP2pRelayCheck_, &QCheckBox::stateChanged, this,
                [this](int) { onBuildPreview(); });
        connect(bchAnchorEdit_, &QLineEdit::textChanged, this,
                [this]() { onBuildPreview(); });

        vbox->addWidget(g);
    }

    // ── 10. ★ Advanced / embedded coin-network (transport + gate-lift) ───────
    // Opt-in, default OFF. This is the ONLY place --coin-p2p-connect /
    // --embedded-mainnet may be emitted. DASH runs the embedded arm by default
    // when daemonless (bare --run): these controls only pin peers or force the
    // flag explicitly (needed when an external dashd is attached, where it is OFF).
    {
        auto* g = makeGroup("Advanced / embedded coin-network (transport + gate-lift)");
        embeddedGroup_ = g;
        auto* gLayout = new QVBoxLayout(g);

        embeddedWarnLabel_ = new QLabel(
            "These options pin the coin-P2P peers the embedded arm dials "
            "(--coin-p2p-connect) and/or force the embedded-mainnet gate open "
            "explicitly (--embedded-mainnet). For DASH the daemonless default "
            "(bare --run) already runs the embedded arm with --embedded-mainnet "
            "ON — you only need these to pin specific peers, or to force the flag "
            "when you have attached an external dashd (where it defaults OFF).");
        embeddedWarnLabel_->setWordWrap(true);
        embeddedWarnLabel_->setStyleSheet("color: #555;");
        gLayout->addWidget(embeddedWarnLabel_);

        embeddedP2pCheck_ = new QCheckBox(
            "Pin embedded coin-network P2P peers (--coin-p2p-connect)");
        embeddedP2pCheck_->setChecked(false);   // ★ default OFF
        embeddedP2pCheck_->setToolTip(
            "--coin-p2p-connect HOST:PORT (repeatable)\n"
            "Pins the coin-network peers the embedded arm dials. Optional —\n"
            "left off, the node discovers peers on its own. Default OFF.");
        gLayout->addWidget(embeddedP2pCheck_);

        embeddedP2pPeersEdit_ = new QPlainTextEdit;
        embeddedP2pPeersEdit_->setMaximumHeight(60);
        embeddedP2pPeersEdit_->setEnabled(false);
        embeddedP2pPeersEdit_->setPlaceholderText(
            "One coin-P2P HOST:PORT per line (e.g. 127.0.0.1:9999)");
        gLayout->addWidget(embeddedP2pPeersEdit_);

        embeddedMainnetCheck_ = new QCheckBox(
            "Force embedded MAINNET block production explicitly (--embedded-mainnet)");
        embeddedMainnetCheck_->setChecked(false);   // ★ default OFF
        embeddedMainnetCheck_->setToolTip(
            "--embedded-mainnet (DASH)\n"
            "Forces the embedded mainnet gate open explicitly. The daemonless\n"
            "default (bare --run) already has it ON — this is only needed when an\n"
            "external dashd is attached (where it defaults OFF). Default OFF.");
        gLayout->addWidget(embeddedMainnetCheck_);

        // DGB embedded coin-network producer target (--coin-daemon + --coin-magic
        // + --coin-genesis). Emitted ONLY when the embedded-P2P opt-in is on and
        // only where the catalog carries the alias for the active binary.
        auto* embForm = new QFormLayout;
        embeddedCoinDaemonEdit_ = new QLineEdit;
        embeddedCoinDaemonEdit_->setEnabled(false);
        embeddedCoinDaemonEdit_->setPlaceholderText("HOST:PORT (DGB --coin-daemon producer target)");
        embeddedCoinDaemonEdit_->setToolTip(
            "--coin-daemon HOST:PORT — DGB embedded-P2P producer target. "
            "Reward-unsafe embedded arm; emitted only with the opt-in above.");
        embForm->addRow("Coin daemon (DGB):", embeddedCoinDaemonEdit_);

        embeddedCoinMagicEdit_ = new QLineEdit;
        embeddedCoinMagicEdit_->setEnabled(false);
        embeddedCoinMagicEdit_->setPlaceholderText("HEX wire magic (regtest/embedded override)");
        embeddedCoinMagicEdit_->setToolTip(
            "--coin-magic / --coin-p2p-magic HEX — wire magic override for the "
            "embedded coin P2P (MONEY_RESTART). Emitted only with the opt-in above.");
        embForm->addRow("Coin magic:", embeddedCoinMagicEdit_);

        embeddedCoinGenesisEdit_ = new QLineEdit;
        embeddedCoinGenesisEdit_->setEnabled(false);
        embeddedCoinGenesisEdit_->setPlaceholderText("HASH (DGB --coin-genesis override)");
        embeddedCoinGenesisEdit_->setToolTip(
            "--coin-genesis HASH — DGB genesis override for the embedded arm. "
            "Emitted only with the opt-in above.");
        embForm->addRow("Coin genesis (DGB):", embeddedCoinGenesisEdit_);
        gLayout->addLayout(embForm);

        connect(embeddedP2pCheck_, &QCheckBox::stateChanged, this, [this](int st) {
            const bool on = (st == Qt::Checked);
            embeddedP2pPeersEdit_->setEnabled(on);
            embeddedCoinDaemonEdit_->setEnabled(on);
            embeddedCoinMagicEdit_->setEnabled(on);
            embeddedCoinGenesisEdit_->setEnabled(on);
            onBuildPreview();
        });
        connect(embeddedCoinDaemonEdit_,  &QLineEdit::textChanged, this, [this]() { onBuildPreview(); });
        connect(embeddedCoinMagicEdit_,   &QLineEdit::textChanged, this, [this]() { onBuildPreview(); });
        connect(embeddedCoinGenesisEdit_, &QLineEdit::textChanged, this, [this]() { onBuildPreview(); });
        connect(embeddedMainnetCheck_, &QCheckBox::stateChanged, this,
                [this](int) { onBuildPreview(); });
        connect(embeddedP2pPeersEdit_, &QPlainTextEdit::textChanged, this,
                [this]() { onBuildPreview(); });

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

    // Live address-flavor validation (QP-B). Re-check whenever the address,
    // the node-owner address, the coin, or the testnet flag changes.
    connect(addressEdit_,        &QLineEdit::textChanged, this, &PageLaunch::validateAddressField);
    connect(nodeOwnerAddrEdit_,  &QLineEdit::textChanged, this, &PageLaunch::validateAddressField);
    connect(testnetCheck_,       &QCheckBox::toggled,     this, &PageLaunch::validateAddressField);

    vbox->addStretch();
    onBuildPreview();  // initial preview
    emitApiBaseUrlChanged();
    validateAddressField();
}

// ─────────────────────────────────────────────────────────────────────────────
// Command builder
// ─────────────────────────────────────────────────────────────────────────────

QString PageLaunch::currentChain() const
{
    const QString data = chainCombo_->currentData().toString();
    return data.isEmpty() ? chainCombo_->currentText() : data;
}

QString PageLaunch::buildCommand() const
{
    // Dispatch on the coin's CLI family. LTC/BTC/DOGE use the unified
    // `c2pool --net …` binary; DASH/DGB/BCH use the dedicated per-coin
    // binary with the reward-SAFE --coin-rpc arm.
    const QString chain = currentChain();
    const c2pool_qt::CoinProfile& prof = c2pool_qt::coinProfile(chain);
    return prof.cli == c2pool_qt::CliFamily::PerCoinRun
               ? buildPerCoinCommand()
               : buildLegacyCommand();
}

QString PageLaunch::buildLegacyCommand() const
{
    QStringList parts;

    // Binary
    parts << binaryEdit_->text().trimmed();

    // Mode — resolved via the catalog (Qt-free seam, unit-tested). A legacy
    // "solo" MUST emit --solo: emitting nothing silently ran an integrated
    // PPLNS node. Integrated emits --integrated explicitly (harmless).
    const std::string mf = c2pool_qt::legacy_mode_flag(
        static_cast<c2pool_qt::LegacyMode>(modeCombo_->currentIndex()));
    if (!mf.empty()) parts << QString::fromStdString(mf);

    // Network
    if (testnetCheck_->isChecked()) parts << "--testnet";
    const QString chain = currentChain();
    if (chain != "litecoin") parts << "--net" << chain;

    // Ports
    parts << "--p2pool-port" << QString::number(p2pPortSpin_->value());
    parts << "-w"            << QString::number(stratumPortSpin_->value());
    parts << "--web-port"    << QString::number(httpPortSpin_->value());

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

    return parts.join(" ");
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-coin run-loop command (c2pool-dash / -dgb / -bch)
//
// DASH default is DAEMONLESS — a bare `--run` (plus stratum/web/listen/etc.):
//   `<binary> --run [--testnet] [--stratum PORT] [--web-port PORT]
//    [--data-dir PATH] …`. With no dashd arm the node keeps its good-citizen
//   serving levers ON (embedded-mainnet included), so the panel does NOT emit
//   --embedded-mainnet for that default. The dashd/coin-RPC arm (--coin-rpc +
//   --coin-rpc-auth) is appended ONLY behind the explicit "Attach external
//   dashd" opt-in; the embedded --coin-p2p-connect / --embedded-mainnet knobs
//   only when the "Advanced / embedded" controls are checked. All of this is
//   assembled in the Qt-free core (build_percoin_argv) and unit-tested there.
// ─────────────────────────────────────────────────────────────────────────────
QString PageLaunch::buildPerCoinCommand() const
{
    const QString chain = currentChain();
    const c2pool_qt::CoinProfile& prof = c2pool_qt::coinProfile(chain);

    // Marshal form + profile state into the Qt-free command core. The
    // reward-safety invariant (embedded flags gated behind default-OFF
    // opt-ins) lives in build_percoin_argv() and is unit-tested there.
    c2pool_qt::PerCoinParams pp = marshalPerCoinParams();
    return QString::fromStdString(
        c2pool_qt::join_argv(c2pool_qt::build_percoin_argv(pp)));
}

// Marshal the form + active profile into the Qt-free command core. Every flag
// SPELLING is chosen by build_percoin_argv() from the parameter catalog keyed on
// prof.bin, so the panel emits only flags the target binary accepts. Shared by
// buildPerCoinCommand() and launch()'s validate_percoin() precheck.
c2pool_qt::PerCoinParams PageLaunch::marshalPerCoinParams() const
{
    const QString chain = currentChain();
    const c2pool_qt::CoinProfile& prof = c2pool_qt::coinProfile(chain);

    c2pool_qt::PerCoinParams pp;
    pp.bin        = prof.bin;
    pp.binary     = binaryEdit_->text().trimmed().toStdString();
    pp.subcommand = prof.subcommand.toStdString();
    if (dataDirEdit_) pp.dataDir = dataDirEdit_->text().trimmed().toStdString();

    pp.testnet = testnetCheck_->isChecked();

    pp.rpcHost = coindHostEdit_->text().trimmed().toStdString();
    pp.rpcPort = coindPortSpin_->value();
    if (rpcConfPathEdit_) pp.confPath = rpcConfPathEdit_->text().trimmed().toStdString();

    // External dashd attach is an explicit opt-in on DASH only (default OFF =
    // daemonless cut mode). For every other binary the RPC/auth arm emits as
    // before, so force the flag true there.
    pp.externalDaemonRpc =
        (prof.bin != c2pool::catalog::Bin::BIN_DASH)
        || (dashdAttachCheck_ && dashdAttachCheck_->isChecked());

    pp.stratumPort = stratumPortSpin_->value();

    pp.webPort = httpPortSpin_->value();
    pp.webHost = httpHostEdit_->text().trimmed().toStdString();

    pp.sharechainPort = p2pPortSpin_->value();
    for (const QString& line : seedNodesEdit_->toPlainText().split('\n', Qt::SkipEmptyParts))
        pp.addnodes.push_back(line.trimmed().toStdString());

    pp.payoutAddress = addressEdit_->text().trimmed().toStdString();
    pp.fee           = feeSpinBox_->value();
    // ★ give-author tri-state: default OMIT (binary default). An explicit value
    // is emitted only when the operator overrode it, and an explicit ZERO only
    // behind the ack checkbox — never a silent --give-author 0 (reward-safety).
    pp.giveAuthor    = giveAuthorSpinBox_->value();
    pp.giveAuthorExplicitZeroAck =
        giveAuthorZeroAckCheck_ && giveAuthorZeroAckCheck_->isChecked();
    pp.giveAuthorSet = pp.giveAuthor > 0.0 || pp.giveAuthorExplicitZeroAck;
    pp.redistribute  = redistributeCombo_->currentText().toStdString();
    pp.messageBlob   = messageBlobEdit_->text().trimmed().toStdString();

    // ── DGB/BCH deeper run-loop controls (emitted only where the catalog has
    //    the alias for this binary — a no-op on coins that lack the flag). ──
    pp.coinP2pDiscover = coinP2pDiscoverCheck_ && coinP2pDiscoverCheck_->isChecked();
    pp.noP2pRelay      = noP2pRelayCheck_ && noP2pRelayCheck_->isChecked();
    if (bchAnchorEdit_) pp.bchAnchor = bchAnchorEdit_->text().trimmed().toStdString();

    // ── ★ Embedded coin-network transport / gate-lift — explicit controls ──
    pp.embeddedP2p = embeddedP2pCheck_ && embeddedP2pCheck_->isChecked();
    if (pp.embeddedP2p && embeddedP2pPeersEdit_) {
        for (const QString& line :
             embeddedP2pPeersEdit_->toPlainText().split('\n', Qt::SkipEmptyParts))
            pp.embeddedP2pPeers.push_back(line.trimmed().toStdString());
    }
    if (pp.embeddedP2p) {
        if (embeddedCoinDaemonEdit_)
            pp.coinDaemon = embeddedCoinDaemonEdit_->text().trimmed().toStdString();
        if (embeddedCoinMagicEdit_)
            pp.coinMagic = embeddedCoinMagicEdit_->text().trimmed().toStdString();
        if (embeddedCoinGenesisEdit_)
            pp.coinGenesis = embeddedCoinGenesisEdit_->text().trimmed().toStdString();
    }
    pp.embeddedMainnet = embeddedMainnetCheck_ && embeddedMainnetCheck_->isChecked();

    return pp;
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
    const QString chain = currentChain();
    const c2pool_qt::CoinProfile& prof = c2pool_qt::coinProfile(chain);
    const bool testnet = testnetCheck_->isChecked();

    const PortDefaults defaults = defaultsForNetwork(chain, testnet);
    p2pPortSpin_->setValue(defaults.p2p);
    stratumPortSpin_->setValue(defaults.stratum);
    if (defaults.http > 0)
        httpPortSpin_->setValue(defaults.http);
    coindPortSpin_->setValue(defaults.rpc);

    // Snap the binary path to the profile default on an explicit chain change.
    binaryEdit_->setText("./build/bin/" + prof.binary);

    applyProfileUi();
    onBuildPreview();
    emitApiBaseUrlChanged();
    validateAddressField();
}

void PageLaunch::applyProfileUi()
{
    const QString chain = currentChain();
    const c2pool_qt::CoinProfile& prof = c2pool_qt::coinProfile(chain);
    const bool perCoin = (prof.cli == c2pool_qt::CliFamily::PerCoinRun);

    using c2pool_qt::catview::spelling_for;
    const auto bin = prof.bin;
    auto has = [&](const char* canon) {
        return spelling_for(bin, canon).has_value();
    };

    // DASH runs daemonless by default (bare --run); the dashd/coin-RPC arm is an
    // explicit opt-in. Every other per-coin binary keeps its arm always on.
    const bool isDash = (prof.bin == c2pool::catalog::Bin::BIN_DASH);
    const bool attach = !isDash || (dashdAttachCheck_ && dashdAttachCheck_->isChecked());
    if (dashdAttachCheck_)
        dashdAttachCheck_->setVisible(isDash);

    // Relabel the parent-daemon group with the coin's daemon name.
    if (coindGroup_)
        coindGroup_->setTitle(
            QStringLiteral("Parent Coin Daemon (%1)").arg(prof.daemonLabel));

    // Daemon RPC fields: enabled only where the binary carries the alias AND (for
    // DASH) the external-dashd attach is ticked. BCH has no endpoint alias at all
    // (creds only via --rpc-conf), so its host/port stay disabled.
    const bool hasRpcEndpoint =
        has("daemon_rpc.endpoint") || has("daemon_rpc.submit_endpoint");
    if (coindHostEdit_) coindHostEdit_->setEnabled(perCoin ? (hasRpcEndpoint && attach) : true);
    if (coindPortSpin_) coindPortSpin_->setEnabled(perCoin ? (hasRpcEndpoint && attach) : true);

    // Suggest the coin's default RPC conf path (PerCoinRun only).
    if (rpcConfPathEdit_) {
        rpcConfPathEdit_->setPlaceholderText(
            perCoin && !prof.confHint.isEmpty()
                ? QStringLiteral("%1 (default)").arg(prof.confHint)
                : QStringLiteral("(legacy coin uses RPC user/password below)"));
        rpcConfPathEdit_->setEnabled(perCoin ? (has("daemon_rpc.auth_file") && attach)
                                             : false);
    }
    if (dataDirEdit_)
        dataDirEdit_->setEnabled(perCoin);

    // Show the embedded reward-unsafe opt-in only for PerCoinRun coins;
    // --embedded-mainnet is DASH-only. It always stays default-OFF.
    if (embeddedGroup_)
        embeddedGroup_->setVisible(perCoin);
    if (embeddedMainnetCheck_)
        embeddedMainnetCheck_->setVisible(chain == QStringLiteral("dash"));
    // Embedded DGB producer-target fields are DGB-only.
    {
        const bool isDgb = (chain == QStringLiteral("digibyte"));
        if (embeddedCoinDaemonEdit_)  embeddedCoinDaemonEdit_->setVisible(isDgb);
        if (embeddedCoinGenesisEdit_) embeddedCoinGenesisEdit_->setVisible(isDgb);
        // --coin-magic exists for DASH and DGB.
        if (embeddedCoinMagicEdit_)
            embeddedCoinMagicEdit_->setVisible(
                isDgb || chain == QStringLiteral("dash"));
    }

    // ── Catalog-driven per-coin control gating ────────────────────────────────
    // For a PerCoinRun coin, grey out any flag its binary does not accept per the
    // parameter catalog (keyed on prof.bin), so the form can never invite the
    // operator to set a value that would be silently dropped. LegacyUnified coins
    // keep every money widget enabled (they build the Python-p2pool argv).
    if (perCoin) {
        const bool hasFee        = has("money.node_owner_fee_pct");
        const bool hasGiveAuthor = has("money.give_author_pct");
        const bool hasOwnerAddr  = has("money.node_owner_address");
        const bool hasRedist     = has("money.redistribute");
        if (feeSpinBox_)             feeSpinBox_->setEnabled(hasFee);
        if (giveAuthorSpinBox_)      giveAuthorSpinBox_->setEnabled(hasGiveAuthor);
        if (giveAuthorZeroAckCheck_) giveAuthorZeroAckCheck_->setEnabled(hasGiveAuthor);
        if (nodeOwnerAddrEdit_)      nodeOwnerAddrEdit_->setEnabled(hasOwnerAddr);
        if (redistributeCombo_)      redistributeCombo_->setEnabled(hasRedist);

        // The "Payout address" field marshals to money.node_owner_address on the
        // per-coin path (marshalPerCoinParams). BCH has no such alias → the value
        // would be silently dropped, so disable the field there.
        if (addressEdit_)     addressEdit_->setEnabled(hasOwnerAddr);
        if (messageBlobEdit_) messageBlobEdit_->setEnabled(has("global.message_blob_hex"));

        // Run-loop rows: enable only where the catalog carries the alias.
        if (coinP2pDiscoverCheck_) coinP2pDiscoverCheck_->setEnabled(has("coin_p2p.discover"));
        if (noP2pRelayCheck_)      noP2pRelayCheck_->setEnabled(has("sharechain.no_p2p_relay"));
        if (bchAnchorEdit_)        bchAnchorEdit_->setEnabled(has("embedded.anchor"));

        // Legacy-only widgets are never read by marshalPerCoinParams(); disable
        // them on the per-coin path so the form cannot invite a silently-dropped
        // value. (Re-enabled in the else branch below.)
        if (rpcUserEdit_)          rpcUserEdit_->setEnabled(false);
        if (rpcPassEdit_)          rpcPassEdit_->setEnabled(false);
        if (coindP2pPortSpin_)     coindP2pPortSpin_->setEnabled(false);
        if (coindP2pAddrEdit_)     coindP2pAddrEdit_->setEnabled(false);
        if (nodeOwnerScriptEdit_)  nodeOwnerScriptEdit_->setEnabled(false);
        if (autoDetectWalletCheck_) autoDetectWalletCheck_->setEnabled(false);
        if (maxConnsSpinBox_)      maxConnsSpinBox_->setEnabled(false);
        if (configFileEdit_)       configFileEdit_->setEnabled(false);
        if (coinbaseTextEdit_)     coinbaseTextEdit_->setEnabled(false);
        if (privateChainCheck_)    privateChainCheck_->setEnabled(false);
        if (networkIdEdit_)        networkIdEdit_->setEnabled(false);
        if (generateIdBtn_)        generateIdBtn_->setEnabled(false);
        if (startupModeCombo_)     startupModeCombo_->setEnabled(false);
    } else {
        // Legacy coins: money + Python-p2pool widgets always available.
        if (feeSpinBox_)             feeSpinBox_->setEnabled(true);
        if (giveAuthorSpinBox_)      giveAuthorSpinBox_->setEnabled(true);
        if (giveAuthorZeroAckCheck_) giveAuthorZeroAckCheck_->setEnabled(true);
        if (nodeOwnerAddrEdit_)      nodeOwnerAddrEdit_->setEnabled(true);
        if (redistributeCombo_)      redistributeCombo_->setEnabled(true);
        if (addressEdit_)            addressEdit_->setEnabled(true);
        if (messageBlobEdit_)        messageBlobEdit_->setEnabled(true);
        if (rpcUserEdit_)            rpcUserEdit_->setEnabled(true);
        if (rpcPassEdit_)            rpcPassEdit_->setEnabled(true);
        if (coindP2pPortSpin_)       coindP2pPortSpin_->setEnabled(true);
        if (coindP2pAddrEdit_)       coindP2pAddrEdit_->setEnabled(true);
        if (nodeOwnerScriptEdit_)    nodeOwnerScriptEdit_->setEnabled(true);
        if (autoDetectWalletCheck_)  autoDetectWalletCheck_->setEnabled(true);
        if (maxConnsSpinBox_)        maxConnsSpinBox_->setEnabled(true);
        if (configFileEdit_)         configFileEdit_->setEnabled(true);
        if (coinbaseTextEdit_)       coinbaseTextEdit_->setEnabled(true);
        if (privateChainCheck_)      privateChainCheck_->setEnabled(true);
        if (startupModeCombo_)       startupModeCombo_->setEnabled(true);
        // network-id field follows the private-chain checkbox (its own logic).
        const bool priv = privateChainCheck_ && privateChainCheck_->isChecked();
        if (networkIdEdit_) networkIdEdit_->setEnabled(priv);
        if (generateIdBtn_) generateIdBtn_->setEnabled(priv);
    }

    // Run-loop group is only meaningful for PerCoinRun binaries.
    if (runLoopGroup_)
        runLoopGroup_->setVisible(perCoin);

    // Per-coin note: CLI arm, masternode-payee, experimental status.
    if (coinNoteLabel_) {
        QString note;
        if (perCoin) {
            if (isDash)
                note = QStringLiteral(
                           "%1 · %2 · binary %3 · daemonless by default (bare "
                           "--run); tick 'Attach external dashd' to use --coin-rpc "
                           "(creds from %4).")
                           .arg(prof.displayLabel, prof.algoLabel, prof.binary,
                                prof.confHint);
            else
                note = QStringLiteral(
                           "%1 · %2 · binary %3 · %4 arm (creds from %5).")
                           .arg(prof.displayLabel, prof.algoLabel, prof.binary,
                                prof.rpcAuthFlag.isEmpty() ? QStringLiteral("RPC")
                                                           : prof.rpcAuthFlag,
                                prof.confHint);
            if (chain == QStringLiteral("bitcoincash"))
                note += QStringLiteral("  c2pool-bch has no operator fee surface "
                                       "(param catalog) — fee/donation/redistribute "
                                       "are disabled; no RPC endpoint flag either "
                                       "(creds only via --rpc-conf), so RPC host/port "
                                       "and the payout-address field are disabled.");
            else if (chain == QStringLiteral("digibyte"))
                note += QStringLiteral("  c2pool-dgb: node-owner address + "
                                       "redistribute live; no author-fee surface.");
        } else {
            note = QStringLiteral("%1 · %2 · unified c2pool binary (--net %3).")
                       .arg(prof.displayLabel, prof.algoLabel, prof.symbol);
        }
        if (prof.masternodePayee)
            note += QStringLiteral("  Masternode-payee coin (block reward is split "
                                   "with the masternode network).");
        if (prof.experimental)
            note += QStringLiteral("  ⚠ per-coin binary still stabilising.");
        coinNoteLabel_->setText(note);
    }
}

void PageLaunch::emitApiBaseUrlChanged()
{
    emit apiBaseUrlChanged(suggestedApiBaseUrl());
}

void PageLaunch::validateAddressField()
{
    if (addressStatusLabel_ == nullptr) return;

    const QString chain   = currentChain();
    const bool    testnet = testnetCheck_ && testnetCheck_->isChecked();

    // The payout address is the money-critical field; the node-owner address
    // (fee payout) is checked too. Surface the payout verdict first.
    const c2pool_qt::AddressCheck payout =
        c2pool_qt::validatePayoutAddress(addressEdit_->text(), chain, testnet);
    const c2pool_qt::AddressCheck owner =
        c2pool_qt::validatePayoutAddress(
            nodeOwnerAddrEdit_ ? nodeOwnerAddrEdit_->text() : QString(),
            chain, testnet);

    // Choose the message to show: a hard wrong-coin block wins; then an
    // advisory (unknown version); otherwise clear.
    auto pick = [](const c2pool_qt::AddressCheck& c) {
        return c.verdict == c2pool_qt::AddressVerdict::WrongCoin
            || c.verdict == c2pool_qt::AddressVerdict::UnknownVersion;
    };

    QString text;
    bool blocking = false;
    if (payout.blocksLaunch()) {
        text = QStringLiteral("Payout address: %1").arg(payout.message);
        blocking = true;
    } else if (owner.blocksLaunch()) {
        text = QStringLiteral("Node owner address: %1").arg(owner.message);
        blocking = true;
    } else if (pick(payout)) {
        text = QStringLiteral("Payout address: %1").arg(payout.message);
    } else if (pick(owner)) {
        text = QStringLiteral("Node owner address: %1").arg(owner.message);
    }

    if (text.isEmpty()) {
        addressStatusLabel_->clear();
        addressStatusLabel_->setVisible(false);
        return;
    }
    addressStatusLabel_->setText((blocking ? QStringLiteral("⛔ ")   // ⛔
                                           : QStringLiteral("⚠ "))  // ⚠
                                 + text);
    addressStatusLabel_->setStyleSheet(blocking ? "color: #b04020;"
                                                : "color: #a06000;");
    addressStatusLabel_->setVisible(true);
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
    // ── QP-B: refuse to launch with a wrong-coin payout/node-owner address ──
    // Only a positively-identified other-coin base58 address blocks; bech32/
    // cashaddr/unknown-version addresses pass through (advisory only) so a
    // valid launch is never stopped by a flavor we do not model.
    const QString chain = currentChain();
    const bool testnet = testnetCheck_ && testnetCheck_->isChecked();
    const c2pool_qt::AddressCheck payoutCheck =
        c2pool_qt::validatePayoutAddress(addressEdit_->text(), chain, testnet);
    const c2pool_qt::AddressCheck ownerCheck =
        c2pool_qt::validatePayoutAddress(
            nodeOwnerAddrEdit_ ? nodeOwnerAddrEdit_->text() : QString(),
            chain, testnet);
    if (payoutCheck.blocksLaunch() || ownerCheck.blocksLaunch()) {
        validateAddressField();
        const c2pool_qt::AddressCheck& bad =
            payoutCheck.blocksLaunch() ? payoutCheck : ownerCheck;
        emit daemonStateChanged(
            QStringLiteral("Daemon: refused — %1").arg(bad.message),
            "color: #b04020;");
        return;
    }

    // ── Launchability precheck (PerCoinRun) ───────────────────────────────────
    // Only refuses when an explicitly-requested external-dashd attach carries no
    // RPC HOST:PORT to attach to. A daemonless DASH launch (bare --run, the
    // default) is always allowed. Runs BEFORE build_percoin_argv().
    if (c2pool_qt::coinProfile(chain).cli == c2pool_qt::CliFamily::PerCoinRun) {
        const std::string reason =
            c2pool_qt::validate_percoin(marshalPerCoinParams());
        if (!reason.empty()) {
            emit daemonStateChanged(
                QStringLiteral("Daemon: refused — %1")
                    .arg(QString::fromStdString(reason)),
                "color: #b04020;");
            return;
        }
    } else {
        // Legacy custodial mode pays the coinbase to --address (main_ltc.cpp
        // requires it). Refuse a blank payout address in that mode.
        if (static_cast<c2pool_qt::LegacyMode>(modeCombo_->currentIndex())
                == c2pool_qt::LegacyMode::Custodial
            && addressEdit_->text().trimmed().isEmpty()) {
            emit daemonStateChanged(
                "Daemon: refused — custodial mode (--custodial) needs a payout "
                "--address to send the coinbase to.",
                "color: #b04020;");
            return;
        }
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

QString PageLaunch::launchGroupPath() const
{
    if (settings_) {
        return QStringLiteral("profiles/%1/launch")
            .arg(settings_->activeProfile());
    }
    return QStringLiteral("launch");
}

void PageLaunch::saveSettings() const
{
    QSettings s;
    s.beginGroup(launchGroupPath());
    s.setValue("binary",        binaryEdit_->text());
    s.setValue("mode",          modeCombo_->currentIndex());
    s.setValue("chain",         currentChain());
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
    // Per-coin run-loop fields
    if (rpcConfPathEdit_) s.setValue("rpcConfPath", rpcConfPathEdit_->text());
    if (dataDirEdit_)     s.setValue("dataDir",     dataDirEdit_->text());
    // DASH external-dashd attach opt-in (default OFF = daemonless).
    if (dashdAttachCheck_) s.setValue("dashdAttach", dashdAttachCheck_->isChecked());
    // Embedded reward-UNSAFE opt-in state (persisted so it is never silently
    // re-enabled; defaults stay OFF on load).
    if (embeddedP2pCheck_)     s.setValue("embeddedP2p",      embeddedP2pCheck_->isChecked());
    if (embeddedP2pPeersEdit_) s.setValue("embeddedP2pPeers", embeddedP2pPeersEdit_->toPlainText());
    if (embeddedMainnetCheck_) s.setValue("embeddedMainnet",  embeddedMainnetCheck_->isChecked());
    if (embeddedCoinDaemonEdit_)  s.setValue("embeddedCoinDaemon",  embeddedCoinDaemonEdit_->text());
    if (embeddedCoinMagicEdit_)   s.setValue("embeddedCoinMagic",   embeddedCoinMagicEdit_->text());
    if (embeddedCoinGenesisEdit_) s.setValue("embeddedCoinGenesis", embeddedCoinGenesisEdit_->text());
    // give-author explicit-zero ack + run-loop controls
    if (giveAuthorZeroAckCheck_) s.setValue("giveAuthorZeroAck", giveAuthorZeroAckCheck_->isChecked());
    if (coinP2pDiscoverCheck_)   s.setValue("coinP2pDiscover",  coinP2pDiscoverCheck_->isChecked());
    if (noP2pRelayCheck_)        s.setValue("noP2pRelay",       noP2pRelayCheck_->isChecked());
    if (bchAnchorEdit_)          s.setValue("bchAnchor",        bchAnchorEdit_->text());

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
    s.beginGroup(launchGroupPath());
    binaryEdit_->setText(s.value("binary", "./build/bin/c2pool").toString());
    modeCombo_->setCurrentIndex(s.value("mode", 1).toInt());
    {
        // Chain persisted by symbol (combo userData). Fall back to legacy
        // display-text match for older settings written before profiles.
        const QString saved = s.value("chain", "litecoin").toString();
        int idx = chainCombo_->findData(saved);
        if (idx < 0) idx = chainCombo_->findText(saved);
        chainCombo_->setCurrentIndex(idx >= 0 ? idx : 0);
    }
    testnetCheck_->setChecked(s.value("testnet", true).toBool());
    const PortDefaults defaults = defaultsForNetwork(currentChain(), testnetCheck_->isChecked());
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
    // Per-coin run-loop fields
    if (rpcConfPathEdit_) rpcConfPathEdit_->setText(s.value("rpcConfPath").toString());
    if (dataDirEdit_)     dataDirEdit_->setText(s.value("dataDir").toString());
    // DASH external-dashd attach opt-in — default false, so a profile that used
    // to force --coin-rpc 127.0.0.1:9998 now launches daemonless (intended).
    if (dashdAttachCheck_)
        dashdAttachCheck_->setChecked(s.value("dashdAttach", false).toBool());
    // Embedded reward-UNSAFE opt-in — restore prior state (still defaults OFF
    // for a fresh profile).
    if (embeddedP2pCheck_)
        embeddedP2pCheck_->setChecked(s.value("embeddedP2p", false).toBool());
    if (embeddedP2pPeersEdit_) {
        embeddedP2pPeersEdit_->setPlainText(s.value("embeddedP2pPeers").toString());
        if (embeddedP2pCheck_)
            embeddedP2pPeersEdit_->setEnabled(embeddedP2pCheck_->isChecked());
    }
    if (embeddedMainnetCheck_)
        embeddedMainnetCheck_->setChecked(s.value("embeddedMainnet", false).toBool());
    if (embeddedCoinDaemonEdit_)  embeddedCoinDaemonEdit_->setText(s.value("embeddedCoinDaemon").toString());
    if (embeddedCoinMagicEdit_)   embeddedCoinMagicEdit_->setText(s.value("embeddedCoinMagic").toString());
    if (embeddedCoinGenesisEdit_) embeddedCoinGenesisEdit_->setText(s.value("embeddedCoinGenesis").toString());
    if (embeddedCoinDaemonEdit_ && embeddedP2pCheck_)
        embeddedCoinDaemonEdit_->setEnabled(embeddedP2pCheck_->isChecked());
    if (embeddedCoinMagicEdit_ && embeddedP2pCheck_)
        embeddedCoinMagicEdit_->setEnabled(embeddedP2pCheck_->isChecked());
    if (embeddedCoinGenesisEdit_ && embeddedP2pCheck_)
        embeddedCoinGenesisEdit_->setEnabled(embeddedP2pCheck_->isChecked());
    // give-author explicit-zero ack + run-loop controls (default OFF / empty).
    if (giveAuthorZeroAckCheck_)
        giveAuthorZeroAckCheck_->setChecked(s.value("giveAuthorZeroAck", false).toBool());
    if (coinP2pDiscoverCheck_)
        coinP2pDiscoverCheck_->setChecked(s.value("coinP2pDiscover", false).toBool());
    if (noP2pRelayCheck_)
        noP2pRelayCheck_->setChecked(s.value("noP2pRelay", false).toBool());
    if (bchAnchorEdit_)
        bchAnchorEdit_->setText(s.value("bchAnchor").toString());

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

    applyProfileUi();  // refresh labels/visibility for the loaded chain (keeps ports)
    onBuildPreview();
    emitApiBaseUrlChanged();
}