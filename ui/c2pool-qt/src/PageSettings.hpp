// PageSettings — dedicated settings tab per §9 of
// c2pool-qt-desktop-settings-module.md.
//
// Six sections: General, Connection, Credentials, View, Backup,
// About. Every control proxies to SettingsStore; there is no
// PageSettings-owned persistence. The Connection section
// overlaps the MainWindow toolbar combo intentionally — the
// toolbar is quick-switch, this is the formal CRUD surface.

#pragma once

#include <QCheckBox>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QWidget>

class SettingsStore;

class PageSettings : public QWidget
{
    Q_OBJECT
public:
    /** SettingsStore ownership stays in main(); PageSettings
     *  borrows the pointer and reads/writes through it. */
    explicit PageSettings(SettingsStore* settings, QWidget* parent = nullptr);

public slots:
    /** Re-read every field from SettingsStore. Called on show +
     *  after any external change (profile switch, import). */
    void reload();

signals:
    /** Fired after a successful import so MainWindow can refresh
     *  the rest of the UI (toolbar combo, PageLaunch form). */
    void settingsImported();

private slots:
    void onExport();
    void onImport();
    void onResetViewState();
    void onShowPasswordToggled(bool checked);

private:
    void loadCredentials();
    void saveCredentials();
    static QString keychainBackendLabel();

    SettingsStore* settings_;

    // General
    QComboBox* themeCombo_;
    QSpinBox*  refreshSpin_;

    // Connection
    QLineEdit* baseUrlEdit_;

    // Credentials
    QLineEdit*   rpcUserEdit_;
    QLineEdit*   rpcPassEdit_;
    QCheckBox*   showPassCheck_;
    QLabel*      keychainBadge_;
    QPushButton* credSaveBtn_;
    QLabel*      credStatus_;

    // View
    QSpinBox*    sharechainCellSpin_;
    QCheckBox*   logsAutoScrollCheck_;
    QPushButton* resetViewBtn_;

    // Backup
    QPushButton* exportBtn_;
    QPushButton* importBtn_;
    QLabel*      backupStatus_;

    // About
    QLabel* aboutVersion_;
    QLabel* aboutConfigPath_;
    QLabel* aboutKeychain_;
};
