#include "MainWindow.hpp"

#include <QCloseEvent>
#include <QHBoxLayout>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWidget>

MainWindow::MainWindow(SettingsStore* settings, QWidget* parent)
    : QMainWindow(parent), settings_(settings)
{
    setWindowTitle("c2pool-qt");
    resize(1200, 760);

    // ── Top toolbar: Base URL + Apply / Refresh ───────────────────────────
    auto* topBar = addToolBar("Connection");
    topBar->setMovable(false);

    baseUrlEdit_ = new QLineEdit("http://127.0.0.1:8080", this);
    baseUrlEdit_->setMinimumWidth(320);
    topBar->addWidget(new QLabel("Base URL:", this));
    topBar->addWidget(baseUrlEdit_);

    auto* applyButton = new QPushButton("Apply", this);
    auto* refreshButton = new QPushButton("Refresh", this);
    topBar->addWidget(applyButton);
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
    navList_->addItems({"Launch", "Overview", "Mining", "Sharechain", "PPLNS", "Logs"});
    navList_->setFixedWidth(180);
    layout->addWidget(navList_);

    stack_ = new QStackedWidget(central);
    launchPage_     = new PageLaunch(stack_);
    overviewPage_   = new PageOverview(stack_);
    miningPage_     = new PageMining(stack_);

    // Sharechain page — hybrid: the Explorer JS bundle running inside
    // a QWebEngineView, talking to native c2pool via SharechainBridge
    // over QtWebChannel. Bundle lives at
    // qrc:///sharechain-explorer/dashboard-embed.html.
    // Per frstrtr/the/docs/c2pool-qt-hybrid-architecture.md §8 step 7.
    sharechainBridge_ = new SharechainBridge(&api_, this);
    PageEmbedded::Config sharechainCfg;
    sharechainCfg.qrcUrl = QStringLiteral(
        "qrc:///sharechain-explorer/dashboard-embed.html");
    sharechainCfg.bridges = { sharechainBridge_ };
    sharechainCfg.bridgeObjectName = QStringLiteral("qtBridge");
#ifdef C2POOL_QT_DEV_BUNDLE
    sharechainCfg.devReloadEnabled = true;
#endif
    sharechainPage_ = new PageEmbedded(sharechainCfg, stack_);

    // PPLNS View page — second hybrid surface. Same PageEmbedded
    // pattern, different bundle. Reuses the sharechain tip stream
    // (PPLNS View spec §5.4 — single SSE socket serves both views).
    // Per hybrid-architecture.md §8 step 12.
    pplnsBridge_ = new PplnsBridge(&api_, this);
    PageEmbedded::Config pplnsCfg;
    pplnsCfg.qrcUrl = QStringLiteral(
        "qrc:///sharechain-explorer/pplns-embed.html");
    pplnsCfg.bridges = { pplnsBridge_, sharechainBridge_ };
    pplnsCfg.bridgeObjectName = QStringLiteral("qtBridge");
#ifdef C2POOL_QT_DEV_BUNDLE
    pplnsCfg.devReloadEnabled = true;
#endif
    pplnsPage_ = new PageEmbedded(pplnsCfg, stack_);

    logsPage_       = new PageLogs(stack_);

    stack_->addWidget(launchPage_);     // index 0
    stack_->addWidget(overviewPage_);   // index 1
    stack_->addWidget(miningPage_);     // index 2
    stack_->addWidget(sharechainPage_); // index 3
    stack_->addWidget(pplnsPage_);      // index 4
    stack_->addWidget(logsPage_);       // index 5

    layout->addWidget(stack_, 1);
    setCentralWidget(central);

    navList_->setCurrentRow(0);

    connect(navList_, &QListWidget::currentRowChanged, this, [this](int row) {
        stack_->setCurrentIndex(row);
        refreshCurrentPage();
    });

    connect(applyButton, &QPushButton::clicked, this, [this]() {
        api_.setBaseUrl(baseUrlEdit_->text());
        statusLabel_->setText("Base URL applied");
        refreshCurrentPage();
    });

    connect(refreshButton, &QPushButton::clicked, this, [this]() {
        refreshCurrentPage();
    });

    connect(launchPage_, &PageLaunch::daemonStateChanged, this,
            [this](const QString& text, const QString& style) {
                daemonStateLabel_->setText(text);
                daemonStateLabel_->setStyleSheet(style);
            });

    connect(launchPage_, &PageLaunch::apiBaseUrlChanged, this,
            [this](const QString& url) {
                if (baseUrlEdit_->text().trimmed() == url)
                    return;
                baseUrlEdit_->setText(url);
                api_.setBaseUrl(url);
            });

    // ── API connection state → daemon auto-detect ─────────────────────────
    connect(&api_, &ApiClient::connectionStateChanged, this, [this](const QString& state) {
        const bool online = (state == "online");
        connectionStateLabel_->setText(QString("API: %1").arg(state));
        connectionStateLabel_->setStyleSheet(
            online ? "color: #1d7f3b;" : "color: #b04020;");
        updateDaemonState(online);
    });

    connect(&api_, &ApiClient::requestFailed, this, [this](const QString& message) {
        statusLabel_->setText(message);
    });

    loadSettings();
    launchPage_->loadSettings();
    api_.setBaseUrl(baseUrlEdit_->text());

    refreshTimer_.setInterval(5000);
    connect(&refreshTimer_, &QTimer::timeout, this, [this]() {
        refreshCurrentPage();
    });
    refreshTimer_.start();

    refreshCurrentPage();
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    saveSettings();
    launchPage_->saveSettings();
    if (launchPage_->isDaemonRunning())
        launchPage_->stop();
    QMainWindow::closeEvent(event);
}

void MainWindow::loadSettings()
{
    baseUrlEdit_->setText(settings_->uiBaseUrl());
    const int refreshMs = settings_->uiRefreshMs();
    refreshTimer_.setInterval(refreshMs > 0 ? refreshMs : 5000);
}

void MainWindow::saveSettings() const
{
    settings_->setUiBaseUrl(baseUrlEdit_->text().trimmed());
    settings_->setUiRefreshMs(refreshTimer_.interval());
}

void MainWindow::updateDaemonState(bool api_online)
{
    lastApiOnline_ = api_online;
    if (launchPage_->isDaemonRunning()) {
        // Managed by us — PageLaunch signals handle the label
        return;
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
    const int idx = stack_->currentIndex();
    switch (idx) {
    case 0: {
        // Ping the API even on Launch page so daemon state updates
        api_.getText("/uptime",
            [](const QString&) { /* connectionStateChanged handles it */ },
            [](const QString&) { });
        break;
    }
    case 1:
        overviewPage_->refresh(&api_);
        statusLabel_->setText("Overview refreshed");
        break;
    case 2:
        miningPage_->refresh(&api_);
        statusLabel_->setText("Mining refreshed");
        break;
    case 3:
        // Sharechain is driven by the embedded JS bundle via
        // SharechainBridge; it self-refreshes through QtTransport +
        // the tip SSE stream. No native poke needed.
        statusLabel_->setText("Sharechain (embedded)");
        break;
    case 4:
        // PPLNS View is also driven by its embedded JS bundle
        // (pplns-view.js) via PplnsBridge; it reuses the sharechain
        // tip stream for refresh triggers. No native poke needed.
        statusLabel_->setText("PPLNS (embedded)");
        break;
    case 5:
        logsPage_->refresh(&api_);
        statusLabel_->setText("Logs refreshed");
        break;
    default:
        break;
    }
}
