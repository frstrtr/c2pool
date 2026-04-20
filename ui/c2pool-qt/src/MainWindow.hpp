#pragma once

#include "ApiClient.hpp"
#include "PageEmbedded.hpp"
#include "PageLaunch.hpp"
#include "PageLogs.hpp"
#include "PageMining.hpp"
#include "PageOverview.hpp"
#include "SettingsStore.hpp"
#include "bridges/PplnsBridge.hpp"
#include "bridges/SharechainBridge.hpp"

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

    SettingsStore* settings_;
    ApiClient api_;

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
    PageEmbedded*     sharechainPage_;
    PageEmbedded*     pplnsPage_;
    SharechainBridge* sharechainBridge_;
    PplnsBridge*      pplnsBridge_;

    QTimer refreshTimer_;
    bool lastApiOnline_{false};
};
