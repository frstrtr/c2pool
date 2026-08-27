// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QObject>
#include <QString>

#include <functional>

class ApiClient : public QObject
{
    Q_OBJECT
public:
    using JsonSuccess = std::function<void(const QJsonDocument&)>;
    using TextSuccess = std::function<void(const QString&)>;
    using Failure = std::function<void(const QString&)>;

    explicit ApiClient(QObject* parent = nullptr);

    void setBaseUrl(const QString& baseUrl);
    QString baseUrl() const;

    void getJson(const QString& path, JsonSuccess onSuccess, Failure onFailure);
    void getText(const QString& path, TextSuccess onSuccess, Failure onFailure);
    void download(const QString& path, const QString& outputPath, TextSuccess onSuccess, Failure onFailure);

signals:
    void connectionStateChanged(const QString& state);
    void requestFailed(const QString& message);
    /** Emitted when setBaseUrl() actually changes the target daemon
     *  (e.g. an active-coin/profile switch). Consumers that hold a
     *  long-lived connection keyed on the base URL — notably the
     *  SharechainBridge SSE tip stream — reconnect against the new
     *  daemon so a coin switch does not keep streaming the old coin's
     *  tips. Request/response ops re-read baseUrl() per call and need
     *  no signal. */
    void baseUrlChanged(const QString& baseUrl);

private:
    QString makeUrl(const QString& path) const;

    QNetworkAccessManager manager_;
    QString baseUrl_;
};