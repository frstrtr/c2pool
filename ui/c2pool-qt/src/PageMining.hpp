#pragma once

#include "ApiClient.hpp"

#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QWidget>

class PageMining : public QWidget
{
    Q_OBJECT
public:
    explicit PageMining(QWidget* parent = nullptr);

    void refresh(ApiClient* api);

private slots:
    void onStartMining();
    void onStopMining();
    void onRestartMining();
    void onBanMiner();
    void onUnbanMiner();

private:
    void invokeControl(ApiClient* api, const QString& path, const QString& successLabel);

    ApiClient* api_{nullptr};
    QLabel* statusValue_;
    QLabel* connectedMinersValue_;
    QLabel* miningStateValue_;
    QTableWidget* workersTable_;

    QPushButton* startButton_;
    QPushButton* stopButton_;
    QPushButton* restartButton_;

    QLineEdit* minerInput_;
    QPushButton* banButton_;
    QPushButton* unbanButton_;
};
