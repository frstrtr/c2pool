#pragma once

#include "ApiClient.hpp"

#include <QComboBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QWidget>

class PageLogs : public QWidget
{
    Q_OBJECT
public:
    explicit PageLogs(QWidget* parent = nullptr);

    void refresh(ApiClient* api);

private:
    QString buildExportPath() const;

    QComboBox* scopeBox_;
    QComboBox* formatBox_;
    QComboBox* rangeBox_;
    QPushButton* exportButton_;
    QPlainTextEdit* logView_;
    ApiClient* api_{nullptr};
};
