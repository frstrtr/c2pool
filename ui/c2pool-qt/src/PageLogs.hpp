#pragma once

#include "ApiClient.hpp"

#include <QComboBox>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTimer>
#include <QWidget>

class PageLogs : public QWidget
{
    Q_OBJECT
public:
    explicit PageLogs(QWidget* parent = nullptr);

    void refresh(ApiClient* api);

private:
    QString buildExportPath() const;
    void fetchLiveLogs();

    QComboBox* scopeBox_;
    QComboBox* formatBox_;
    QComboBox* rangeBox_;
    QPushButton* exportButton_;

    // Live tail mode
    QPushButton* liveTailBtn_;
    QComboBox* liveLevelFilter_;
    QPlainTextEdit* logView_;
    QTimer liveTailTimer_;
    bool liveTailActive_{false};

    ApiClient* api_{nullptr};
};
