#include "MainWindow.hpp"

#include <QCloseEvent>
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

    // ── Top toolbar: Base URL + Apply / Refresh ───────────────────────────
    auto* topBar = addToolBar("Connection");
    topBar->setMovable(false);

    baseUrlEdit_ = new QLineEdit("http://127.0.0.1:8080", this);
    baseUrlEdit_->setMinimumWidth(320);
    topBar->addWidget(new QLabel("Base URL:", this));
    topBar->addWidget(baseUrlEdit_);

    authTokenEdit_ = new QLineEdit(this);
    authTokenEdit_->setEchoMode(QLineEdit::Password);
    authTokenEdit_->setPlaceholderText("auth token (optional)");
    authTokenEdit_->setMaximumWidth(180);
    topBar->addWidget(new QLabel("Token:", this));
    topBar->addWidget(authTokenEdit_);

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
    navList_->addItems({"Launch", "Overview", "Mining", "Sharechain", "Logs"});
    navList_->setFixedWidth(180);
    layout->addWidget(navList_);

    stack_ = new QStackedWidget(central);
    launchPage_     = new PageLaunch(stack_);
    overviewPage_   = new PageOverview(stack_);
    miningPage_     = new PageMining(stack_);
    sharechainPage_ = new PageSharechain(stack_);
    logsPage_       = new PageLogs(stack_);

    stack_->addWidget(launchPage_);     // index 0
    stack_->addWidget(overviewPage_);   // index 1
    stack_->addWidget(miningPage_);     // index 2
    stack_->addWidget(sharechainPage_); // index 3
    stack_->addWidget(logsPage_);       // index 4

    layout->addWidget(stack_, 1);
    setCentralWidget(central);

    navList_->setCurrentRow(0);

    connect(navList_, &QListWidget::currentRowChanged, this, [this](int row) {
        stack_->setCurrentIndex(row);
        refreshCurrentPage();
    });

    connect(applyButton, &QPushButton::clicked, this, [this]() {
        api_.setBaseUrl(baseUrlEdit_->text());
        api_.setAuthToken(authTokenEdit_->text());
        statusLabel_->setText("Connection settings applied");
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
    api_.setAuthToken(authTokenEdit_->text());

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
    QSettings s;
    baseUrlEdit_->setText(s.value("ui/baseUrl", "http://127.0.0.1:8080").toString());
    authTokenEdit_->setText(s.value("ui/authToken").toString());
    const int refreshMs = s.value("ui/refreshMs", 5000).toInt();
    refreshTimer_.setInterval(refreshMs > 0 ? refreshMs : 5000);
}

void MainWindow::saveSettings() const
{
    QSettings s;
    s.setValue("ui/baseUrl", baseUrlEdit_->text().trimmed());
    s.setValue("ui/authToken", authTokenEdit_->text().trimmed());
    s.setValue("ui/refreshMs", refreshTimer_.interval());
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
        sharechainPage_->refresh(&api_);
        statusLabel_->setText("Sharechain refreshed");
        break;
    case 4:
        logsPage_->refresh(&api_);
        statusLabel_->setText("Logs refreshed");
        break;
    default:
        break;
    }
}
