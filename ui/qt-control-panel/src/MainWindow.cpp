#include "MainWindow.hpp"

#include <QHBoxLayout>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWidget>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
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

    statusLabel_ = new QLabel("Idle", this);
    topBar->addSeparator();
    topBar->addWidget(statusLabel_);

    auto* central = new QWidget(this);
    auto* layout = new QHBoxLayout(central);

    navList_ = new QListWidget(central);
    navList_->addItems({"Overview", "Mining", "Logs"});
    navList_->setFixedWidth(180);
    layout->addWidget(navList_);

    stack_ = new QStackedWidget(central);
    overviewPage_ = new PageOverview(stack_);
    miningPage_ = new PageMining(stack_);
    logsPage_ = new PageLogs(stack_);

    stack_->addWidget(overviewPage_);
    stack_->addWidget(miningPage_);
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

    refreshTimer_.setInterval(5000);
    connect(&refreshTimer_, &QTimer::timeout, this, [this]() {
        refreshCurrentPage();
    });
    refreshTimer_.start();

    refreshCurrentPage();
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
        logsPage_->refresh(&api_);
        statusLabel_->setText("Logs refreshed");
        break;
    default:
        break;
    }
}
