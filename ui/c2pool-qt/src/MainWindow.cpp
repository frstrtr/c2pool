#include "MainWindow.hpp"

#include <QAction>
#include <QCloseEvent>
#include <QComboBox>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QMenu>
#include <QMessageBox>
#include <QSignalBlocker>
#include <QToolBar>
#include <QToolButton>
#include <QVBoxLayout>
#include <QWidget>

MainWindow::MainWindow(SettingsStore* settings, QWidget* parent)
    : QMainWindow(parent), settings_(settings)
{
    setWindowTitle("c2pool-qt");
    resize(1200, 760);

    // ── Top toolbar: Profile + Base URL + Apply / Refresh ─────────────────
    auto* topBar = addToolBar("Connection");
    topBar->setMovable(false);

    // Connection-profile switcher (§7 step 10). Selecting an entry
    // flips SettingsStore::activeProfile, which cascades to
    // PageLaunch.loadSettings() + CoinBridge::coinChanged so the
    // launch form and the embedded dashboards re-bind to the new
    // coin without a window reload.
    topBar->addWidget(new QLabel("Profile:", this));
    profileCombo_ = new QComboBox(this);
    profileCombo_->setMinimumWidth(180);
    topBar->addWidget(profileCombo_);

    auto* manageButton = new QToolButton(this);
    manageButton->setText("\u2026");  // ellipsis
    manageButton->setToolTip("Manage connection profiles");
    manageButton->setPopupMode(QToolButton::InstantPopup);
    auto* manageMenu = new QMenu(manageButton);
    manageMenu->addAction("New profile\u2026", this, [this]() {
        bool ok = false;
        const QString name = QInputDialog::getText(this, tr("New profile"),
            tr("Profile name:"), QLineEdit::Normal, QString(), &ok).trimmed();
        if (!ok || name.isEmpty()) return;
        if (settings_->profileNames().contains(name)) {
            QMessageBox::warning(this, tr("New profile"),
                tr("A profile named \"%1\" already exists.").arg(name));
            return;
        }
        settings_->createProfile(name);
        settings_->setActiveProfile(name);
    });
    manageMenu->addAction("Rename current\u2026", this, [this]() {
        const QString cur = settings_->activeProfile();
        bool ok = false;
        const QString name = QInputDialog::getText(this, tr("Rename profile"),
            tr("New name for \"%1\":").arg(cur),
            QLineEdit::Normal, cur, &ok).trimmed();
        if (!ok || name.isEmpty() || name == cur) return;
        if (settings_->profileNames().contains(name)) {
            QMessageBox::warning(this, tr("Rename profile"),
                tr("A profile named \"%1\" already exists.").arg(name));
            return;
        }
        settings_->renameProfile(cur, name);
    });
    manageMenu->addAction("Delete current", this, [this]() {
        const QString cur = settings_->activeProfile();
        if (settings_->profileNames().size() <= 1) {
            QMessageBox::information(this, tr("Delete profile"),
                tr("Cannot delete the last remaining profile."));
            return;
        }
        const auto r = QMessageBox::question(this, tr("Delete profile"),
            tr("Delete profile \"%1\"? Its launch config and secrets "
               "will be removed.").arg(cur));
        if (r != QMessageBox::Yes) return;
        settings_->deleteProfile(cur);
    });
    manageButton->setMenu(manageMenu);
    topBar->addWidget(manageButton);

    topBar->addSeparator();

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
    navList_->addItems({"Launch", "Overview", "Mining", "Sharechain", "PPLNS", "Logs", "Settings"});
    navList_->setFixedWidth(180);
    layout->addWidget(navList_);

    stack_ = new QStackedWidget(central);
    launchPage_     = new PageLaunch(settings_, stack_);
    overviewPage_   = new PageOverview(stack_);

    // Bridges. SharechainBridge + PplnsBridge carry data; SettingsBridge
    // routes JS view-state writes to SettingsStore per
    // frstrtr/the/docs/c2pool-qt-hybrid-architecture.md §4.3.
    // SettingsBridge is a single instance shared across every embed —
    // JS plugins see the same allow-list everywhere.
    sharechainBridge_ = new SharechainBridge(&api_, this);
    settingsBridge_   = new SettingsBridge(settings_, this);
    coinBridge_       = new CoinBridge(settings_, this);
    pplnsBridge_      = new PplnsBridge(&api_, this);

    // PageMining hybrid split (§7 step 11) — native controls on top,
    // embedded PPLNS View bundle on the bottom for the miner list.
    // Uses the same bridge tri as the standalone PPLNS tab so the two
    // surfaces see identical bridge state.
    miningPage_ = new PageMining(
        { pplnsBridge_, sharechainBridge_, settingsBridge_, coinBridge_ },
        stack_);

    // Sharechain page — hybrid: the Explorer JS bundle running inside
    // a QWebEngineView, talking to native c2pool via SharechainBridge
    // over QtWebChannel. Bundle lives at
    // qrc:///sharechain-explorer/dashboard-embed.html.
    // Per §8 step 7.
    PageEmbedded::Config sharechainCfg;
    sharechainCfg.qrcUrl = QStringLiteral(
        "qrc:///sharechain-explorer/dashboard-embed.html");
    sharechainCfg.bridges = { sharechainBridge_, settingsBridge_, coinBridge_ };
    sharechainCfg.bridgeObjectName = QStringLiteral("qtBridge");
#ifdef C2POOL_QT_DEV_BUNDLE
    sharechainCfg.devReloadEnabled = true;
#endif
    sharechainPage_ = new PageEmbedded(sharechainCfg, stack_);

    // PPLNS View page — second hybrid surface. Same PageEmbedded
    // pattern, different bundle. Reuses the sharechain tip stream
    // (PPLNS View spec §5.4 — single SSE socket serves both views).
    // Per hybrid-architecture.md §8 step 12.
    PageEmbedded::Config pplnsCfg;
    pplnsCfg.qrcUrl = QStringLiteral(
        "qrc:///sharechain-explorer/pplns-embed.html");
    pplnsCfg.bridges = { pplnsBridge_, sharechainBridge_, settingsBridge_, coinBridge_ };
    pplnsCfg.bridgeObjectName = QStringLiteral("qtBridge");
#ifdef C2POOL_QT_DEV_BUNDLE
    pplnsCfg.devReloadEnabled = true;
#endif
    pplnsPage_ = new PageEmbedded(pplnsCfg, stack_);

    logsPage_       = new PageLogs(stack_);
    settingsPage_   = new PageSettings(settings_, stack_);

    stack_->addWidget(launchPage_);     // index 0
    stack_->addWidget(overviewPage_);   // index 1
    stack_->addWidget(miningPage_);     // index 2
    stack_->addWidget(sharechainPage_); // index 3
    stack_->addWidget(pplnsPage_);      // index 4
    stack_->addWidget(logsPage_);       // index 5
    stack_->addWidget(settingsPage_);   // index 6

    // Settings page Import can touch any key — rebuild every UI
    // surface that mirrors SettingsStore so nothing drifts.
    connect(settingsPage_, &PageSettings::settingsImported, this,
            [this]() {
                reloadProfileCombo();
                launchPage_->loadSettings();
                baseUrlEdit_->setText(settings_->uiBaseUrl());
                api_.setBaseUrl(baseUrlEdit_->text());
                refreshTimer_.setInterval(settings_->uiRefreshMs());
                statusLabel_->setText(tr("Settings imported"));
            });

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

    // ── Profile combo wiring ──────────────────────────────────────────────
    reloadProfileCombo();
    connect(profileCombo_, &QComboBox::activated, this, [this](int idx) {
        const QString name = profileCombo_->itemText(idx);
        if (name.isEmpty() || name == settings_->activeProfile()) return;
        // Persist the current launch form to the outgoing profile first
        // so edits aren't lost by the profile flip.
        launchPage_->saveSettings();
        settings_->setActiveProfile(name);
    });
    // Listen for profile/name changes (including rename/delete/set).
    // profileChanged fires on activeProfile flip; changed(profiles/names)
    // fires on create/rename/delete (the combo needs to repopulate).
    connect(settings_, &SettingsStore::profileChanged, this,
            [this](const QString& newActive) {
                launchPage_->loadSettings();
                // Sync the base URL too — per-profile in future, for now
                // the form's suggested URL reflects the new launch values.
                const QString url = launchPage_->suggestedApiBaseUrl();
                if (!url.isEmpty()) {
                    baseUrlEdit_->setText(url);
                    api_.setBaseUrl(url);
                }
                reloadProfileCombo();
                statusLabel_->setText(tr("Profile: %1").arg(newActive));
                refreshCurrentPage();
            });
    connect(settings_, &SettingsStore::changed, this,
            [this](const QString& key) {
                if (key == QStringLiteral("profiles/names")) {
                    reloadProfileCombo();
                }
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

void MainWindow::reloadProfileCombo()
{
    // Signal-block so repopulating doesn't fire activated and recurse
    // through setActiveProfile.
    const QSignalBlocker blocker(profileCombo_);
    profileCombo_->clear();
    profileCombo_->addItems(settings_->profileNames());
    const int idx = profileCombo_->findText(settings_->activeProfile());
    if (idx >= 0) profileCombo_->setCurrentIndex(idx);
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
    case 6:
        // PageSettings is self-refreshing via SettingsStore signals;
        // reload on tab entry to pick up any external writes (toolbar
        // combo, keychain daemon prompts).
        settingsPage_->reload();
        statusLabel_->setText("Settings");
        break;
    default:
        break;
    }
}
