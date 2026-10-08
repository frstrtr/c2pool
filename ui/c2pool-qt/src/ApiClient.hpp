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
    /** Delivered once an HTTP response is received (ANY status), carrying
     *  the numeric status and the parsed JSON body (an empty document if
     *  the body was not JSON). The control-plane apply endpoint conveys its
     *  meaning through non-2xx statuses with a JSON body (400 "no changes",
     *  403 wrong token, 409 nonce mismatch, 503 not armed, 200 need_confirm/
     *  applied), so a money POST MUST inspect the status here — not treat a
     *  non-2xx as an opaque failure. */
    using JsonStatusSuccess = std::function<void(int httpStatus, const QJsonDocument&)>;

    explicit ApiClient(QObject* parent = nullptr);

    void setBaseUrl(const QString& baseUrl);
    QString baseUrl() const;

    void getJson(const QString& path, JsonSuccess onSuccess, Failure onFailure);
    void getText(const QString& path, TextSuccess onSuccess, Failure onFailure);
    void download(const QString& path, const QString& outputPath, TextSuccess onSuccess, Failure onFailure);

    /** POST a JSON body (application/json), ~4s timeout, and — unlike
     *  getJson — with NO automatic retry: a retried money POST is a replay,
     *  so the arm/submit control path must never silently resend. onSuccess
     *  fires for any received HTTP response (with its status + parsed body);
     *  onFailure fires only for a transport/timeout error (no response). */
    void postJson(const QString& path, const QJsonObject& body,
                  JsonStatusSuccess onSuccess, Failure onFailure);

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