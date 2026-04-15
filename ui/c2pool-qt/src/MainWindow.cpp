#include "MainWindow.hpp"

#include <QCloseEvent>
#include <QElapsedTimer>
#include <QHBoxLayout>
#include <QSettings>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWidget>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle("c2pool-qt");
    resize(1200, 760);

    // ── Top toolbar: Node selector + Refresh ─────────────────────────────
    auto* topBar = addToolBar("Connection");
    topBar->setMovable(false);

    topBar->addWidget(new QLabel("Node:", this));
    nodeSelectorCombo_ = new QComboBox(this);
    nodeSelectorCombo_->setMinimumWidth(250);
    topBar->addWidget(nodeSelectorCombo_);

    auto* connectButton = new QPushButton("Connect", this);
    auto* refreshButton = new QPushButton("Refresh", this);
    topBar->addWidget(connectButton);
    topBar->addWidget(refreshButton);

    // ── Bottom status bar (Bitcoin-Qt style) ──────────────────────────────
    auto* sb = statusBar();
    daemonStateLabel_ = new QLabel("Daemon: detecting...", this);
    connectionStateLabel_ = new QLabel("API: unknown", this);
    statusLabel_ = new QLabel("Idle", this);

    sb->addWidget(daemonStateLabel_);
    sb->addWidget(connectionStateLabel_);
    sb->addPermanentWidget(statusLabel_);

    // ── Central area: nav list + stacked pages ────────────────────────────
    auto* central = new QWidget(this);
    auto* layout = new QHBoxLayout(central);

    navList_ = new QListWidget(central);
    navList_->addItems({"Launch", "Overview", "Mining", "Sharechain", "Logs", "Peers", "Settings"});
    navList_->setFixedWidth(180);
    layout->addWidget(navList_);

    stack_ = new QStackedWidget(central);
    launchPage_     = new PageLaunch(stack_);
    overviewPage_   = new PageOverview(stack_);
    miningPage_     = new PageMining(stack_);
    sharechainPage_ = new PageSharechain(stack_);
    logsPage_       = new PageLogs(stack_);
    peersPage_      = new PagePeers(stack_);
    settingsPage_   = new PageSettings(&nodeManager_, stack_);

    stack_->addWidget(launchPage_);     // index 0
    stack_->addWidget(overviewPage_);   // index 1
    stack_->addWidget(miningPage_);     // index 2
    stack_->addWidget(sharechainPage_); // index 3
    stack_->addWidget(logsPage_);       // index 4
    stack_->addWidget(peersPage_);      // index 5
    stack_->addWidget(settingsPage_);   // index 6

    layout->addWidget(stack_, 1);
    setCentralWidget(central);

    navList_->setCurrentRow(0);

    connect(navList_, &QListWidget::currentRowChanged, this, [this](int row) {
        stack_->setCurrentIndex(row);
        if (row == 6)
            settingsPage_->refresh();
        else
            refreshCurrentPage();
    });

    connect(connectButton, &QPushButton::clicked, this, [this]() {
        const int idx = nodeSelectorCombo_->currentIndex();
        if (idx < 0) return;
        const QString id = nodeSelectorCombo_->currentData().toString();
        nodeManager_.setActiveNode(id);
        nodeManager_.connectToNode(id);
        statusLabel_->setText("Connecting to " + nodeSelectorCombo_->currentText());
    });

    connect(refreshButton, &QPushButton::clicked, this, [this]() {
        refreshCurrentPage();
    });

    // ── PageLaunch signals ───────────────────────────────────────────────
    connect(launchPage_, &PageLaunch::daemonStateChanged, this,
            [this](const QString& text, const QString& style) {
                daemonStateLabel_->setText(text);
                daemonStateLabel_->setStyleSheet(style);
            });

    // ── NodeManager signals ──────────────────────────────────────────────
    connect(&nodeManager_, &NodeManager::activeNodeChanged,
            this, &MainWindow::onActiveNodeChanged);

    connect(&nodeManager_, &NodeManager::nodeConnected, this, [this](const QString& id) {
        if (id == nodeManager_.activeNodeId()) {
            connectionStateLabel_->setText("API: online");
            connectionStateLabel_->setStyleSheet("color: #1d7f3b;");
            updateDaemonState(true);
            refreshCurrentPage();
        }
    });

    connect(&nodeManager_, &NodeManager::nodeDisconnected, this, [this](const QString& id) {
        if (id == nodeManager_.activeNodeId()) {
            connectionStateLabel_->setText("API: offline");
            connectionStateLabel_->setStyleSheet("color: #b04020;");
            updateDaemonState(false);
        }
    });

    connect(&nodeManager_, &NodeManager::nodeConfigReceived,
            this, [this](const QString& id, const QJsonObject& config) {
                if (id == nodeManager_.activeNodeId()) {
                    statusLabel_->setText("Config received from " +
                        nodeManager_.activeProfile().label);
                }
            });

    // ── Settings page signals ────────────────────────────────────────────
    connect(settingsPage_, &PageSettings::profilesChanged, this, [this]() {
        rebuildNodeSelector();
    });

    // ── Initialize ───────────────────────────────────────────────────────
    nodeManager_.loadProfiles();
    launchPage_->loadSettings();
    rebuildNodeSelector();

    // Auto-connect to active node
    if (!nodeManager_.activeNodeId().isEmpty()) {
        nodeManager_.connectToNode(nodeManager_.activeNodeId());
    }

    refreshTimer_.setInterval(5000);
    connect(&refreshTimer_, &QTimer::timeout, this, [this]() {
        refreshCurrentPage();
    });
    refreshTimer_.start();

    refreshCurrentPage();
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    nodeManager_.saveProfiles();
    launchPage_->saveSettings();
    if (launchPage_->isDaemonRunning())
        launchPage_->stop();
    QMainWindow::closeEvent(event);
}

void MainWindow::onActiveNodeChanged(const QString& profileId)
{
    const auto prof = nodeManager_.profile(profileId);
    setWindowTitle(QString("c2pool-qt — %1").arg(prof.label));

    // Update combo box selection
    for (int i = 0; i < nodeSelectorCombo_->count(); ++i) {
        if (nodeSelectorCombo_->itemData(i).toString() == profileId) {
            nodeSelectorCombo_->setCurrentIndex(i);
            break;
        }
    }

    daemonStateLabel_->setText("Daemon: detecting...");
    connectionStateLabel_->setText("API: connecting...");
}

void MainWindow::rebuildNodeSelector()
{
    nodeSelectorCombo_->clear();
    const auto profs = nodeManager_.profiles();
    for (const auto& p : profs) {
        const QString display = p.isLocal
            ? QString("%1 (local)").arg(p.label)
            : QString("%1 (%2)").arg(p.label, p.address);
        nodeSelectorCombo_->addItem(display, p.id);
    }

    // Select active node
    const QString activeId = nodeManager_.activeNodeId();
    for (int i = 0; i < nodeSelectorCombo_->count(); ++i) {
        if (nodeSelectorCombo_->itemData(i).toString() == activeId) {
            nodeSelectorCombo_->setCurrentIndex(i);
            break;
        }
    }
}

void MainWindow::updateDaemonState(bool api_online)
{
    lastApiOnline_ = api_online;
    if (launchPage_->isDaemonRunning()) {
        return;  // Managed by PageLaunch signals
    }
    if (api_online) {
        daemonStateLabel_->setText("Daemon: running (external)");
        daemonStateLabel_->setStyleSheet("color: #1d7f3b;");
    } else {
        daemonStateLabel_->setText("Daemon: stopped");
        daemonStateLabel_->setStyleSheet("color: #b04020;");
    }
}

void MainWindow::refreshCurrentPage()
{
    auto* api = nodeManager_.activeClient();
    const int idx = stack_->currentIndex();

    switch (idx) {
    case 0: {
        // Ping the API even on Launch page so daemon state updates
        if (api) {
            api->getText("/uptime",
                [this](const QString&) { updateDaemonState(true); },
                [this](const QString&) { updateDaemonState(false); });
        }
        break;
    }
    case 1:
        if (api) overviewPage_->refresh(api);
        statusLabel_->setText("Overview refreshed");
        break;
    case 2:
        if (api) miningPage_->refresh(api);
        statusLabel_->setText("Mining refreshed");
        break;
    case 3: {
        // Sharechain window is 11MB+ -- throttle to every 30s for auto-refresh
        static QElapsedTimer lastSharechainRefresh;
        if (!lastSharechainRefresh.isValid() || lastSharechainRefresh.elapsed() > 25000) {
            if (api) sharechainPage_->refresh(api);
            lastSharechainRefresh.start();
            statusLabel_->setText("Sharechain refreshed");
        }
        break;
    }
    case 4:
        if (api) logsPage_->refresh(api);
        statusLabel_->setText("Logs refreshed");
        break;
    case 5:
        if (api) peersPage_->refresh(api);
        statusLabel_->setText("Peers refreshed");
        break;
    case 6:
        // Settings page manages itself
        break;
    default:
        break;
    }
}
