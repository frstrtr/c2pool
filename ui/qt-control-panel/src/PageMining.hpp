#pragma once

#include "ApiClient.hpp"

#include <QLabel>
#include <QTableWidget>
#include <QWidget>

class PageMining : public QWidget
{
    Q_OBJECT
public:
    explicit PageMining(QWidget* parent = nullptr);

    void refresh(ApiClient* api);

private:
    QLabel* statusValue_;
    QLabel* connectedMinersValue_;
    QTableWidget* workersTable_;
};
