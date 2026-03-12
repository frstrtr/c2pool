#pragma once

#include "ApiClient.hpp"
#include "PageLaunch.hpp"
#include "PageLogs.hpp"
#include "PageMining.hpp"
#include "PageOverview.hpp"
#include "PageSharechain.hpp"

#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMainWindow>
#include <QPushButton>
#include <QStackedWidget>
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
    void loadSettings();
    void saveSettings() const;

    ApiClient api_;

    QLineEdit* baseUrlEdit_;
    QLabel* daemonStateLabel_;
    QLabel* connectionStateLabel_;
    QLabel* statusLabel_;
    QListWidget* navList_;
    QStackedWidget* stack_;

    PageLaunch*    launchPage_;
    PageOverview*  overviewPage_;
    PageMining*    miningPage_;
    PageLogs*      logsPage_;
    PageSharechain* sharechainPage_;

    QTimer refreshTimer_;
};
