#include "PageSettings.hpp"

#include <QDir>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QSplitter>
#include <QVBoxLayout>

PageSettings::PageSettings(NodeManager* manager, QWidget* parent)
    : QWidget(parent), manager_(manager)
{
    auto* root = new QHBoxLayout(this);

    // ── Left: profile list ───────────────────────────────────────────────
    auto* leftPanel = new QVBoxLayout;

    profileList_ = new QListWidget(this);
    profileList_->setFixedWidth(220);
    leftPanel->addWidget(new QLabel("Node Profiles:", this));
    leftPanel->addWidget(profileList_);

    auto* btnRow = new QHBoxLayout;
    addBtn_ = new QPushButton("+ Add", this);
    removeBtn_ = new QPushButton("- Remove", this);
    btnRow->addWidget(addBtn_);
    btnRow->addWidget(removeBtn_);
    leftPanel->addLayout(btnRow);

    root->addLayout(leftPanel);

    // ── Right: profile editor ────────────────────────────────────────────
    auto* rightPanel = new QVBoxLayout;

    auto* formGroup = new QGroupBox("Profile Settings", this);
    auto* form = new QFormLayout(formGroup);

    labelEdit_ = new QLineEdit(this);
    labelEdit_->setPlaceholderText("My Testnet Node");
    form->addRow("Label:", labelEdit_);

    addressEdit_ = new QLineEdit(this);
    addressEdit_->setPlaceholderText("127.0.0.1:8080");
    form->addRow("Address (host:port):", addressEdit_);

    isLocalCheck_ = new QCheckBox("Local node (same machine)", this);
    isLocalCheck_->setChecked(true);
    form->addRow("", isLocalCheck_);

    dataDirEdit_ = new QLineEdit(this);
    dataDirEdit_->setPlaceholderText("~/.c2pool");
    dataDirEdit_->setToolTip("Data directory for local nodes (config files + .cookie)");
    form->addRow("Data directory:", dataDirEdit_);

    auto* tokenRow = new QHBoxLayout;
    authTokenEdit_ = new QLineEdit(this);
    authTokenEdit_->setEchoMode(QLineEdit::Password);
    authTokenEdit_->setPlaceholderText("auto-read from .cookie (local) or paste token (remote)");
    tokenRow->addWidget(authTokenEdit_);
    readCookieBtn_ = new QPushButton("Read Cookie", this);
    readCookieBtn_->setToolTip("Read auth token from data directory/.cookie");
    tokenRow->addWidget(readCookieBtn_);
    form->addRow("Auth token:", tokenRow);

    autoConnectCheck_ = new QCheckBox("Connect on app startup", this);
    form->addRow("", autoConnectCheck_);

    autoLaunchCheck_ = new QCheckBox("Launch daemon on app startup (local only)", this);
    form->addRow("", autoLaunchCheck_);

    rightPanel->addWidget(formGroup);

    auto* actionRow = new QHBoxLayout;
    testBtn_ = new QPushButton("Test Connection", this);
    saveBtn_ = new QPushButton("Save Profile", this);
    saveBtn_->setStyleSheet("font-weight: bold;");
    actionRow->addWidget(testBtn_);
    actionRow->addStretch();
    actionRow->addWidget(saveBtn_);
    rightPanel->addLayout(actionRow);

    statusLabel_ = new QLabel("Select or add a profile", this);
    rightPanel->addWidget(statusLabel_);
    rightPanel->addStretch();

    root->addLayout(rightPanel, 1);

    // ── Connections ──────────────────────────────────────────────────────
    connect(profileList_, &QListWidget::currentRowChanged, this, &PageSettings::onProfileSelected);
    connect(addBtn_, &QPushButton::clicked, this, &PageSettings::addProfile);
    connect(removeBtn_, &QPushButton::clicked, this, &PageSettings::removeProfile);
    connect(saveBtn_, &QPushButton::clicked, this, &PageSettings::saveCurrentProfile);
    connect(testBtn_, &QPushButton::clicked, this, &PageSettings::testConnection);

    connect(readCookieBtn_, &QPushButton::clicked, this, [this]() {
        const QString dir = dataDirEdit_->text().trimmed();
        if (dir.isEmpty()) {
            statusLabel_->setText("Enter data directory first");
            return;
        }
        const QString cookie = NodeManager::readCookie(dir);
        if (cookie.isEmpty()) {
            statusLabel_->setText("No .cookie file found in " + dir);
        } else {
            authTokenEdit_->setText(cookie);
            statusLabel_->setText("Cookie read successfully");
        }
    });

    connect(isLocalCheck_, &QCheckBox::toggled, this, [this](bool local) {
        dataDirEdit_->setEnabled(local);
        readCookieBtn_->setEnabled(local);
        autoLaunchCheck_->setEnabled(local);
    });
}

void PageSettings::refresh()
{
    profileList_->clear();
    const auto profs = manager_->profiles();
    for (const auto& p : profs) {
        auto* item = new QListWidgetItem(p.label);
        item->setData(Qt::UserRole, p.id);
        if (p.id == manager_->activeNodeId())
            item->setIcon(QIcon::fromTheme("network-connect"));
        profileList_->addItem(item);
    }

    if (profileList_->count() > 0)
        profileList_->setCurrentRow(0);
}

void PageSettings::onProfileSelected(int row)
{
    if (row < 0) {
        clearForm();
        return;
    }
    const QString id = profileList_->item(row)->data(Qt::UserRole).toString();
    currentProfileId_ = id;
    populateForm(manager_->profile(id));
}

void PageSettings::populateForm(const NodeProfile& p)
{
    labelEdit_->setText(p.label);
    addressEdit_->setText(p.address);
    authTokenEdit_->setText(p.authToken);
    dataDirEdit_->setText(p.dataDir);
    isLocalCheck_->setChecked(p.isLocal);
    autoConnectCheck_->setChecked(p.autoConnect);
    autoLaunchCheck_->setChecked(p.autoLaunch);
    dataDirEdit_->setEnabled(p.isLocal);
    readCookieBtn_->setEnabled(p.isLocal);
    autoLaunchCheck_->setEnabled(p.isLocal);
    statusLabel_->setText("Profile loaded: " + p.label);
}

void PageSettings::clearForm()
{
    labelEdit_->clear();
    addressEdit_->clear();
    authTokenEdit_->clear();
    dataDirEdit_->clear();
    isLocalCheck_->setChecked(true);
    autoConnectCheck_->setChecked(false);
    autoLaunchCheck_->setChecked(false);
    currentProfileId_.clear();
}

void PageSettings::addProfile()
{
#ifdef _WIN32
    const QString defaultDataDir = QString::fromLocal8Bit(qgetenv("APPDATA")) + "/c2pool";
#else
    const QString defaultDataDir = QDir::homePath() + "/.c2pool";
#endif
    auto p = NodeProfile::create("New Node", "127.0.0.1:8080", true, defaultDataDir);
    manager_->addProfile(p);
    refresh();
    // Select the new profile
    for (int i = 0; i < profileList_->count(); ++i) {
        if (profileList_->item(i)->data(Qt::UserRole).toString() == p.id) {
            profileList_->setCurrentRow(i);
            break;
        }
    }
    emit profilesChanged();
}

void PageSettings::removeProfile()
{
    if (currentProfileId_.isEmpty()) return;
    if (manager_->profiles().size() <= 1) {
        statusLabel_->setText("Cannot remove the last profile");
        return;
    }
    manager_->removeProfile(currentProfileId_);
    currentProfileId_.clear();
    refresh();
    emit profilesChanged();
}

void PageSettings::saveCurrentProfile()
{
    if (currentProfileId_.isEmpty()) return;

    NodeProfile p;
    p.id = currentProfileId_;
    p.label = labelEdit_->text().trimmed();
    p.address = addressEdit_->text().trimmed();
    p.authToken = authTokenEdit_->text().trimmed();
    p.dataDir = dataDirEdit_->text().trimmed();
    p.isLocal = isLocalCheck_->isChecked();
    p.autoConnect = autoConnectCheck_->isChecked();
    p.autoLaunch = autoLaunchCheck_->isChecked();

    if (p.label.isEmpty()) p.label = "Unnamed Node";
    if (p.address.isEmpty()) p.address = "127.0.0.1:8080";

    manager_->updateProfile(p);
    manager_->saveProfiles();
    statusLabel_->setText("Profile saved: " + p.label);

    // Refresh list labels
    for (int i = 0; i < profileList_->count(); ++i) {
        if (profileList_->item(i)->data(Qt::UserRole).toString() == p.id) {
            profileList_->item(i)->setText(p.label);
            break;
        }
    }
    emit profilesChanged();
}

void PageSettings::testConnection()
{
    const QString address = addressEdit_->text().trimmed();
    if (address.isEmpty()) {
        statusLabel_->setText("Enter an address first");
        return;
    }

    statusLabel_->setText("Testing connection...");

    // Create a temporary client to test
    auto* testClient = new ApiClient(this);
    const QString baseUrl = address.startsWith("http") ? address : "http://" + address;
    testClient->setBaseUrl(baseUrl);
    testClient->setAuthToken(authTokenEdit_->text().trimmed());

    testClient->getText("/uptime",
        [this, testClient](const QString& text) {
            statusLabel_->setText("Connected! Uptime: " + text.trimmed() + "s");
            statusLabel_->setStyleSheet("color: green;");
            testClient->deleteLater();
        },
        [this, testClient](const QString& err) {
            statusLabel_->setText("Connection failed: " + err);
            statusLabel_->setStyleSheet("color: red;");
            testClient->deleteLater();
        }
    );
}
