#include "MainWindow.hpp"

#include <QCloseEvent>
#include <QDir>
#include <QHBoxLayout>
#include <QSettings>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWidget>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), daemonProcess_(new QProcess(this))
{
    setWindowTitle("c2pool Qt Control Panel (MVP)");
    resize(1200, 760);

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

    topBar->addSeparator();
    topBar->addWidget(new QLabel("Daemon cmd:", this));
    daemonCmdEdit_ = new QLineEdit("./build-debug.sh", this);
    daemonCmdEdit_->setMinimumWidth(240);
    topBar->addWidget(daemonCmdEdit_);
    auto* daemonStartButton = new QPushButton("Start", this);
    auto* daemonStopButton = new QPushButton("Stop", this);
    auto* daemonRestartButton = new QPushButton("Restart", this);
    topBar->addWidget(daemonStartButton);
    topBar->addWidget(daemonStopButton);
    topBar->addWidget(daemonRestartButton);

    daemonStateLabel_ = new QLabel("Daemon: stopped", this);
    topBar->addWidget(daemonStateLabel_);

    topBar->addSeparator();
    connectionStateLabel_ = new QLabel("API: unknown", this);
    topBar->addWidget(connectionStateLabel_);

    statusLabel_ = new QLabel("Idle", this);
    topBar->addSeparator();
    topBar->addWidget(statusLabel_);

    auto* central = new QWidget(this);
    auto* layout = new QHBoxLayout(central);

    navList_ = new QListWidget(central);
    navList_->addItems({"Overview", "Mining", "Sharechain", "Logs"});
    navList_->setFixedWidth(180);
    layout->addWidget(navList_);

    stack_ = new QStackedWidget(central);
    overviewPage_ = new PageOverview(stack_);
    miningPage_ = new PageMining(stack_);
    sharechainPage_ = new PageSharechain(std::make_shared<ApiClient>(&api_), stack_);
    logsPage_ = new PageLogs(stack_);

    stack_->addWidget(overviewPage_);
    stack_->addWidget(miningPage_);
    stack_->addWidget(sharechainPage_);
    stack_->addWidget(logsPage_);

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

    connect(daemonStartButton, &QPushButton::clicked, this, &MainWindow::startDaemon);
    connect(daemonStopButton, &QPushButton::clicked, this, &MainWindow::stopDaemon);
    connect(daemonRestartButton, &QPushButton::clicked, this, &MainWindow::restartDaemon);

    connect(daemonProcess_, &QProcess::started, this, [this]() {
        daemonStateLabel_->setText("Daemon: running");
        daemonStateLabel_->setStyleSheet("color: #1d7f3b;");
        statusLabel_->setText("Daemon started");
    });

    connect(daemonProcess_, &QProcess::finished, this, [this](int code, QProcess::ExitStatus) {
        daemonStateLabel_->setText(QString("Daemon: stopped (%1)").arg(code));
        daemonStateLabel_->setStyleSheet("color: #b04020;");
    });

    connect(daemonProcess_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError err) {
        Q_UNUSED(err);
        daemonStateLabel_->setText("Daemon: error");
        daemonStateLabel_->setStyleSheet("color: #b04020;");
        statusLabel_->setText(daemonProcess_->errorString());
    });

    connect(&api_, &ApiClient::connectionStateChanged, this, [this](const QString& state) {
        connectionStateLabel_->setText(QString("API: %1").arg(state));
        if (state == "online") {
            connectionStateLabel_->setStyleSheet("color: #1d7f3b;");
        } else {
            connectionStateLabel_->setStyleSheet("color: #b04020;");
        }
    });

    connect(&api_, &ApiClient::requestFailed, this, [this](const QString& message) {
        statusLabel_->setText(message);
    });

    loadSettings();
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
    if (daemonProcess_->state() != QProcess::NotRunning) {
        daemonProcess_->terminate();
        daemonProcess_->waitForFinished(1500);
    }
    QMainWindow::closeEvent(event);
}

void MainWindow::loadSettings()
{
    QSettings s;
    baseUrlEdit_->setText(s.value("ui/baseUrl", "http://127.0.0.1:8080").toString());
    daemonCmdEdit_->setText(s.value("daemon/command", "./build-debug.sh").toString());
    const int refreshMs = s.value("ui/refreshMs", 5000).toInt();
    refreshTimer_.setInterval(refreshMs > 0 ? refreshMs : 5000);
}

void MainWindow::saveSettings() const
{
    QSettings s;
    s.setValue("ui/baseUrl", baseUrlEdit_->text().trimmed());
    s.setValue("daemon/command", daemonCmdEdit_->text().trimmed());
    s.setValue("ui/refreshMs", refreshTimer_.interval());
}

void MainWindow::startDaemon()
{
    if (daemonProcess_->state() != QProcess::NotRunning) {
        statusLabel_->setText("Daemon already running");
        return;
    }

    const QString command = daemonCmdEdit_->text().trimmed();
    if (command.isEmpty()) {
        statusLabel_->setText("Daemon command is empty");
        return;
    }

    daemonProcess_->setWorkingDirectory(QDir::currentPath());
    daemonProcess_->start("/bin/bash", {"-lc", command});
}

void MainWindow::stopDaemon()
{
    if (daemonProcess_->state() == QProcess::NotRunning) {
        statusLabel_->setText("Daemon not running");
        return;
    }
    daemonProcess_->terminate();
    if (!daemonProcess_->waitForFinished(2000)) {
        daemonProcess_->kill();
        daemonProcess_->waitForFinished(1000);
    }
    statusLabel_->setText("Daemon stopped");
}

void MainWindow::restartDaemon()
{
    stopDaemon();
    startDaemon();
}

void MainWindow::refreshCurrentPage()
{
    const int idx = stack_->currentIndex();
    switch (idx) {
    case 0:
        overviewPage_->refresh(&api_);
        statusLabel_->setText("Overview refreshed");
        break;
    case 1:
        miningPage_->refresh(&api_);
        statusLabel_->setText("Mining refreshed");
        break;
    case 2:
        sharechainPage_->refresh();
        statusLabel_->setText("Sharechain refreshed");
        break;
    case 3:
        logsPage_->refresh(&api_);
        statusLabel_->setText("Logs refreshed");
        break;
    default:
        break;
    }
}
