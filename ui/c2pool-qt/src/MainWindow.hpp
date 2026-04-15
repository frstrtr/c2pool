#pragma once

#include "NodeManager.hpp"
#include "PageLaunch.hpp"
#include "PageLogs.hpp"
#include "PageMining.hpp"
#include "PageOverview.hpp"
#include "PagePeers.hpp"
#include "PageSettings.hpp"
#include "PageSharechain.hpp"
#include "SseClient.hpp"

#include <QComboBox>
#include <QLabel>
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
    explicit MainWindow(QWidget* parent = nullptr);

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    void refreshCurrentPage();
    void updateDaemonState(bool api_online);
    void onActiveNodeChanged(const QString& profileId);
    void rebuildNodeSelector();

    NodeManager nodeManager_;

    QComboBox* nodeSelectorCombo_;
    QListWidget* navList_;
    QStackedWidget* stack_;

    // Status bar widgets (bottom, Bitcoin-Qt style)
    QLabel* daemonStateLabel_;
    QLabel* connectionStateLabel_;
    QLabel* statusLabel_;

    PageLaunch*    launchPage_;
    PageOverview*  overviewPage_;
    PageMining*    miningPage_;
    PageLogs*      logsPage_;
    PageSharechain* sharechainPage_;
    PagePeers*     peersPage_;
    PageSettings*  settingsPage_;

    SseClient sseClient_;
    QTimer refreshTimer_;
    bool lastApiOnline_{false};
};
