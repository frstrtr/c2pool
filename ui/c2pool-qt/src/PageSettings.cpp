#include "PageSettings.hpp"

#include "SettingsStore.hpp"

#include <QCoreApplication>
#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QScrollArea>
#include <QSettings>
#include <QSignalBlocker>
#include <QVBoxLayout>

namespace {

QGroupBox* makeGroup(const QString& title, QWidget* parent)
{
    auto* g = new QGroupBox(title, parent);
    g->setStyleSheet(
        "QGroupBox { font-weight: bold; border: 1px solid palette(mid); "
        "border-radius: 6px; margin-top: 10px; padding-top: 12px; }"
        "QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; }");
    return g;
}

} // namespace

PageSettings::PageSettings(SettingsStore* settings, QWidget* parent)
    : QWidget(parent), settings_(settings)
{
    // Outer scroll so the page renders correctly on small displays.
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    auto* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    outer->addWidget(scroll);

    auto* content = new QWidget(scroll);
    scroll->setWidget(content);
    auto* layout = new QVBoxLayout(content);
    layout->setContentsMargins(16, 16, 16, 16);

    // ── General ─────────────────────────────────────────────────────
    {
        auto* g = makeGroup(tr("General"), content);
        auto* form = new QFormLayout(g);

        themeCombo_ = new QComboBox(g);
        themeCombo_->addItem(tr("Follow system"), "system");
        themeCombo_->addItem(tr("Light"),         "light");
        themeCombo_->addItem(tr("Dark"),          "dark");
        form->addRow(tr("Theme:"), themeCombo_);
        connect(themeCombo_, &QComboBox::currentIndexChanged, this,
            [this](int) {
                settings_->setUiTheme(themeCombo_->currentData().toString());
            });

        refreshSpin_ = new QSpinBox(g);
        refreshSpin_->setRange(500, 60000);
        refreshSpin_->setSingleStep(500);
        refreshSpin_->setSuffix(tr(" ms"));
        form->addRow(tr("Refresh interval:"), refreshSpin_);
        connect(refreshSpin_, &QSpinBox::valueChanged, this,
            [this](int v) { settings_->setUiRefreshMs(v); });

        layout->addWidget(g);
    }

    // ── Connection ──────────────────────────────────────────────────
    {
        auto* g = makeGroup(tr("Connection"), content);
        auto* form = new QFormLayout(g);

        // Profile CRUD mirrors the toolbar's Manage\u2026 menu; we
        // intentionally don't duplicate a combo here — the toolbar
        // combo is always visible. This section owns the raw
        // per-profile baseUrl override.
        auto* hint = new QLabel(
            tr("Manage profiles from the toolbar combo. The active "
               "profile is edited below."), g);
        hint->setWordWrap(true);
        form->addRow(hint);

        baseUrlEdit_ = new QLineEdit(g);
        form->addRow(tr("Base URL override:"), baseUrlEdit_);
        connect(baseUrlEdit_, &QLineEdit::editingFinished, this,
            [this]() {
                settings_->setUiBaseUrl(baseUrlEdit_->text().trimmed());
            });

        layout->addWidget(g);
    }

    // ── Credentials ─────────────────────────────────────────────────
    {
        auto* g = makeGroup(tr("Credentials"), content);
        auto* form = new QFormLayout(g);

        keychainBadge_ = new QLabel(keychainBackendLabel(), g);
        keychainBadge_->setStyleSheet("color: palette(mid); font-size: 10pt;");
        form->addRow(keychainBadge_);

        rpcUserEdit_ = new QLineEdit(g);
        form->addRow(tr("RPC user:"), rpcUserEdit_);

        rpcPassEdit_ = new QLineEdit(g);
        rpcPassEdit_->setEchoMode(QLineEdit::Password);
        form->addRow(tr("RPC password:"), rpcPassEdit_);

        showPassCheck_ = new QCheckBox(tr("Show password"), g);
        form->addRow(showPassCheck_);
        connect(showPassCheck_, &QCheckBox::toggled, this,
                &PageSettings::onShowPasswordToggled);

        auto* btnRow = new QHBoxLayout();
        credSaveBtn_ = new QPushButton(tr("Save to keychain"), g);
        credStatus_  = new QLabel("", g);
        btnRow->addWidget(credSaveBtn_);
        btnRow->addWidget(credStatus_, 1);
        form->addRow(btnRow);
        connect(credSaveBtn_, &QPushButton::clicked, this,
                &PageSettings::saveCredentials);

        layout->addWidget(g);
    }

    // ── View ────────────────────────────────────────────────────────
    {
        auto* g = makeGroup(tr("View"), content);
        auto* form = new QFormLayout(g);

        sharechainCellSpin_ = new QSpinBox(g);
        sharechainCellSpin_->setRange(4, 160);
        sharechainCellSpin_->setSuffix(tr(" px"));
        form->addRow(tr("Sharechain cell size:"), sharechainCellSpin_);
        connect(sharechainCellSpin_, &QSpinBox::valueChanged, this,
            [this](int v) { settings_->setSharechainCellSize(v); });

        logsAutoScrollCheck_ = new QCheckBox(tr("Auto-scroll logs"), g);
        form->addRow(logsAutoScrollCheck_);
        connect(logsAutoScrollCheck_, &QCheckBox::toggled, this,
            [this](bool on) { settings_->setLogsAutoScroll(on); });

        resetViewBtn_ = new QPushButton(tr("Reset view state"), g);
        resetViewBtn_->setToolTip(tr(
            "Clears sharechain / PPLNS / plugin view state. Launch "
            "config, profiles, and credentials are unaffected."));
        form->addRow(resetViewBtn_);
        connect(resetViewBtn_, &QPushButton::clicked, this,
                &PageSettings::onResetViewState);

        layout->addWidget(g);
    }

    // ── Backup ──────────────────────────────────────────────────────
    {
        auto* g = makeGroup(tr("Backup"), content);
        auto* form = new QFormLayout(g);

        auto* note = new QLabel(
            tr("Export writes a JSON file containing every QSettings "
               "key except secrets (those stay in the keychain). "
               "Import replaces matching keys; it does not clear "
               "unlisted ones."), g);
        note->setWordWrap(true);
        form->addRow(note);

        auto* btnRow = new QHBoxLayout();
        exportBtn_ = new QPushButton(tr("Export\u2026"), g);
        importBtn_ = new QPushButton(tr("Import\u2026"), g);
        btnRow->addWidget(exportBtn_);
        btnRow->addWidget(importBtn_);
        btnRow->addStretch();
        form->addRow(btnRow);

        backupStatus_ = new QLabel("", g);
        backupStatus_->setStyleSheet("color: palette(mid);");
        form->addRow(backupStatus_);

        connect(exportBtn_, &QPushButton::clicked, this, &PageSettings::onExport);
        connect(importBtn_, &QPushButton::clicked, this, &PageSettings::onImport);

        layout->addWidget(g);
    }

    // ── About ───────────────────────────────────────────────────────
    {
        auto* g = makeGroup(tr("About"), content);
        auto* form = new QFormLayout(g);

        aboutVersion_ = new QLabel(
            QCoreApplication::applicationVersion().isEmpty()
                ? QStringLiteral("dev")
                : QCoreApplication::applicationVersion(), g);
        form->addRow(tr("c2pool-qt version:"), aboutVersion_);

        aboutConfigPath_ = new QLabel(QSettings{}.fileName(), g);
        aboutConfigPath_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        aboutConfigPath_->setWordWrap(true);
        form->addRow(tr("Config file:"), aboutConfigPath_);

        aboutKeychain_ = new QLabel(keychainBackendLabel(), g);
        form->addRow(tr("Secrets backend:"), aboutKeychain_);

        layout->addWidget(g);
    }

    layout->addStretch(1);

    reload();

    // React to external writes (profile switch, schema migration).
    connect(settings_, &SettingsStore::profileChanged, this,
            [this](const QString&) { reload(); });
}

void PageSettings::reload()
{
    // Block signals during repopulation so setter slots don't re-fire
    // into SettingsStore.
    QSignalBlocker b0(themeCombo_);
    QSignalBlocker b1(refreshSpin_);
    QSignalBlocker b2(baseUrlEdit_);
    QSignalBlocker b3(sharechainCellSpin_);
    QSignalBlocker b4(logsAutoScrollCheck_);

    const int themeIdx = themeCombo_->findData(settings_->uiTheme());
    themeCombo_->setCurrentIndex(themeIdx >= 0 ? themeIdx : 0);
    refreshSpin_->setValue(settings_->uiRefreshMs());
    baseUrlEdit_->setText(settings_->uiBaseUrl());
    sharechainCellSpin_->setValue(settings_->sharechainCellSize());
    logsAutoScrollCheck_->setChecked(settings_->logsAutoScroll());

    loadCredentials();
}

void PageSettings::loadCredentials()
{
    credStatus_->setText(tr("Loading\u2026"));
    settings_->loadRpcCredentials(
        [this](const QString& user, const QString& pass, bool ok) {
            rpcUserEdit_->setText(user);
            rpcPassEdit_->setText(pass);
            credStatus_->setText(ok ? tr("Loaded from %1")
                                        .arg(keychainBackendLabel())
                                    : tr("Not found"));
        });
}

void PageSettings::saveCredentials()
{
    credStatus_->setText(tr("Saving\u2026"));
    settings_->storeRpcCredentials(
        rpcUserEdit_->text(), rpcPassEdit_->text(),
        [this](bool ok) {
            credStatus_->setText(ok ? tr("Saved") : tr("Failed"));
        });
}

void PageSettings::onShowPasswordToggled(bool checked)
{
    rpcPassEdit_->setEchoMode(checked ? QLineEdit::Normal
                                      : QLineEdit::Password);
}

void PageSettings::onExport()
{
    const QString path = QFileDialog::getSaveFileName(this,
        tr("Export settings"), QString(),
        tr("JSON files (*.json);;All files (*)"));
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        backupStatus_->setText(tr("Export failed: %1").arg(f.errorString()));
        return;
    }
    f.write(settings_->exportAsJson());
    backupStatus_->setText(tr("Exported to %1").arg(path));
}

void PageSettings::onImport()
{
    const QString path = QFileDialog::getOpenFileName(this,
        tr("Import settings"), QString(),
        tr("JSON files (*.json);;All files (*)"));
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        backupStatus_->setText(tr("Import failed: %1").arg(f.errorString()));
        return;
    }
    const QByteArray raw = f.readAll();
    QString err;
    if (!settings_->importFromJson(raw, &err)) {
        backupStatus_->setText(tr("Import failed: %1").arg(err));
        return;
    }
    backupStatus_->setText(tr("Imported %1").arg(path));
    reload();
    emit settingsImported();
}

void PageSettings::onResetViewState()
{
    const auto r = QMessageBox::question(this, tr("Reset view state"),
        tr("Clear all sharechain / PPLNS / plugin view state? "
           "Launch config, profiles, and credentials are unaffected."));
    if (r != QMessageBox::Yes) return;
    QSettings s;
    for (const auto& group : { QStringLiteral("sharechain/view"),
                                QStringLiteral("pplns/view"),
                                QStringLiteral("explorer/plugins") }) {
        s.remove(group);
    }
    reload();
    backupStatus_->setText(tr("View state cleared"));
}

QString PageSettings::keychainBackendLabel()
{
#ifdef C2POOL_QT_USE_KEYCHAIN
    return QObject::tr("system keychain (QtKeychain)");
#else
    return QObject::tr("QSettings fallback (no keychain)");
#endif
}
