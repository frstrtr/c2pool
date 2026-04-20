#pragma once

#include "ApiClient.hpp"
#include "PageEmbedded.hpp"
#include "PageLaunch.hpp"
#include "PageLogs.hpp"
#include "PageMining.hpp"
#include "PageOverview.hpp"
#include "PageSettings.hpp"
#include "SettingsStore.hpp"
#include "bridges/CoinBridge.hpp"
#include "bridges/PplnsBridge.hpp"
#include "bridges/SettingsBridge.hpp"
#include "bridges/SharechainBridge.hpp"

#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMainWindow>
#include <QPushButton>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTimer>

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    /** SettingsStore is constructed in main() before MainWindow so
     *  schema migrations run first. MainWindow borrows the reference;
     *  ownership stays in main(). */
    explicit MainWindow(SettingsStore* settings, QWidget* parent = nullptr);

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    void refreshCurrentPage();
    void updateDaemonState(bool api_online);
    void loadSettings();
    void saveSettings() const;
    /** Rebuild the profile combo contents from SettingsStore and
     *  select the currently active profile; signals are blocked so
     *  this is safe to call from change handlers. */
    void reloadProfileCombo();

    SettingsStore* settings_;
    ApiClient api_;

    QComboBox* profileCombo_;
    QLineEdit* baseUrlEdit_;
    QListWidget* navList_;
    QStackedWidget* stack_;

    // Status bar widgets (bottom, Bitcoin-Qt style)
    QLabel* daemonStateLabel_;
    QLabel* connectionStateLabel_;
    QLabel* statusLabel_;

    PageLaunch*       launchPage_;
    PageOverview*     overviewPage_;
    PageMining*       miningPage_;
    PageLogs*         logsPage_;
    PageSettings*     settingsPage_;
    PageEmbedded*     sharechainPage_;
    PageEmbedded*     pplnsPage_;
    SharechainBridge* sharechainBridge_;
    PplnsBridge*      pplnsBridge_;
    SettingsBridge*   settingsBridge_;
    CoinBridge*       coinBridge_;

    QTimer refreshTimer_;
    bool lastApiOnline_{false};
};
