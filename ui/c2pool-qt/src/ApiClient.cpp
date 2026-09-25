// SPDX-License-Identifier: AGPL-3.0-or-later
#include "ApiClient.hpp"

#include <QFile>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>
#include <QUrl>

#include <memory>

ApiClient::ApiClient(QObject* parent)
    : QObject(parent), baseUrl_("http://127.0.0.1:8080")
{
}

void ApiClient::setBaseUrl(const QString& baseUrl)
{
    QString normalized = baseUrl.trimmed();
    if (normalized.endsWith('/')) {
        normalized.chop(1);
    }
    if (normalized == baseUrl_) {
        return;
    }
    baseUrl_ = normalized;
    emit baseUrlChanged(baseUrl_);
}

QString ApiClient::baseUrl() const
{
    return baseUrl_;
}

QString ApiClient::makeUrl(const QString& path) const
{
    QString p = path;
    if (!p.startsWith('/')) {
        p.prepend('/');
    }
    return baseUrl_ + p;
}

void ApiClient::getJson(const QString& path, JsonSuccess onSuccess, Failure onFailure)
{
    auto attempts = std::make_shared<int>(0);
    auto doRequest = std::make_shared<std::function<void()>>();

    *doRequest = [this, path, onSuccess, onFailure, attempts, doRequest]() {
        QNetworkRequest req(QUrl(makeUrl(path)));
        req.setTransferTimeout(4000);
        auto* reply = manager_.get(req);

        connect(reply, &QNetworkReply::finished, this, [this, reply, onSuccess, onFailure, attempts, doRequest]() {
            const auto err = reply->error();
            const QByteArray payload = reply->readAll();
            reply->deleteLater();

            if (err != QNetworkReply::NoError) {
                if (*attempts == 0) {
                    *attempts = 1;
                    QTimer::singleShot(300, this, [doRequest]() { (*doRequest)(); });
                    return;
                }
                const QString message = QString("HTTP error: %1").arg(reply->errorString());
                emit connectionStateChanged("offline");
                emit requestFailed(message);
                onFailure(message);
                return;
            }

            QJsonParseError parseErr;
            const auto doc = QJsonDocument::fromJson(payload, &parseErr);
            if (parseErr.error != QJsonParseError::NoError) {
                const QString message = QString("JSON parse error: %1").arg(parseErr.errorString());
                emit requestFailed(message);
                onFailure(message);
                return;
            }

            emit connectionStateChanged("online");
            onSuccess(doc);
        });
    };

    (*doRequest)();
}

void ApiClient::getText(const QString& path, TextSuccess onSuccess, Failure onFailure)
{
    auto attempts = std::make_shared<int>(0);
    auto doRequest = std::make_shared<std::function<void()>>();

    *doRequest = [this, path, onSuccess, onFailure, attempts, doRequest]() {
        QNetworkRequest req(QUrl(makeUrl(path)));
        req.setTransferTimeout(4000);
        auto* reply = manager_.get(req);

        connect(reply, &QNetworkReply::finished, this, [this, reply, onSuccess, onFailure, attempts, doRequest]() {
            const auto err = reply->error();
            const QByteArray payload = reply->readAll();
            reply->deleteLater();

            if (err != QNetworkReply::NoError) {
                if (*attempts == 0) {
                    *attempts = 1;
                    QTimer::singleShot(300, this, [doRequest]() { (*doRequest)(); });
                    return;
                }
                const QString message = QString("HTTP error: %1").arg(reply->errorString());
                emit connectionStateChanged("offline");
                emit requestFailed(message);
                onFailure(message);
                return;
            }

            emit connectionStateChanged("online");
            onSuccess(QString::fromUtf8(payload));
        });
    };

    (*doRequest)();
}

void ApiClient::postJson(const QString& path, const QJsonObject& body,
                         JsonStatusSuccess onSuccess, Failure onFailure)
{
    QNetworkRequest req(QUrl(makeUrl(path)));
    req.setHeader(QNetworkRequest::ContentTypeHeader,
                  QStringLiteral("application/json"));
    req.setTransferTimeout(4000);
    const QByteArray bytes = QJsonDocument(body).toJson(QJsonDocument::Compact);

    // NO retry: unlike getJson there is no *attempts re-dispatch. A money
    // POST (arm confirm / submit) that is transparently resent is a replay,
    // which the server's single-use nonce would reject anyway — but the UI
    // must not initiate it in the first place.
    auto* reply = manager_.post(req, bytes);
    connect(reply, &QNetworkReply::finished, this,
            [this, reply, onSuccess, onFailure]() {
        const auto err = reply->error();
        const QVariant codeVar =
            reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
        const int httpStatus = codeVar.isValid() ? codeVar.toInt() : 0;
        const QByteArray payload = reply->readAll();
        reply->deleteLater();

        // A transport-level failure (no HTTP response reached us: timeout,
        // connection refused, DNS) has no status code.
        if (httpStatus == 0) {
            const QString message =
                QString("HTTP error: %1").arg(reply->errorString());
            emit connectionStateChanged("offline");
            emit requestFailed(message);
            onFailure(message);
            return;
        }
        (void)err;  // a non-2xx sets err too, but it IS a real response we surface

        // Parse the body if it is JSON; otherwise hand back an empty doc so
        // the caller still sees the status code.
        QJsonParseError parseErr;
        QJsonDocument doc = QJsonDocument::fromJson(payload, &parseErr);
        if (parseErr.error != QJsonParseError::NoError)
            doc = QJsonDocument();

        emit connectionStateChanged("online");
        onSuccess(httpStatus, doc);
    });
}

void ApiClient::download(const QString& path, const QString& outputPath, TextSuccess onSuccess, Failure onFailure)
{
    QNetworkRequest req(QUrl(makeUrl(path)));
    auto* reply = manager_.get(req);

    connect(reply, &QNetworkReply::finished, this, [reply, outputPath, onSuccess, onFailure]() {
        const auto err = reply->error();
        const QByteArray payload = reply->readAll();
        reply->deleteLater();

        if (err != QNetworkReply::NoError) {
            onFailure(QString("HTTP error: %1").arg(reply->errorString()));
            return;
        }

        QFile out(outputPath);
        if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            onFailure(QString("Cannot write file: %1").arg(outputPath));
            return;
        }
        out.write(payload);
        out.close();

        onSuccess(QString("Saved %1 bytes to %2").arg(payload.size()).arg(outputPath));
    });
}