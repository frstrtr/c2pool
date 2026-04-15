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
    baseUrl_ = baseUrl.trimmed();
    if (baseUrl_.endsWith('/')) {
        baseUrl_.chop(1);
    }
}

QString ApiClient::baseUrl() const
{
    return baseUrl_;
}

void ApiClient::setAuthToken(const QString& token)
{
    authToken_ = token.trimmed();
}

QString ApiClient::authToken() const
{
    return authToken_;
}

QString ApiClient::makeUrl(const QString& path) const
{
    QString p = path;
    if (!p.startsWith('/')) {
        p.prepend('/');
    }
    QString url = baseUrl_ + p;

    // Inject auth token for protected endpoints
    if (!authToken_.isEmpty() &&
        (p.startsWith("/control/") || p.startsWith("/web/log") || p.startsWith("/logs/export")))
    {
        url += (url.contains('?') ? "&" : "?");
        url += "token=" + authToken_;
    }

    return url;
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
                         JsonSuccess onSuccess, Failure onFailure)
{
    QNetworkRequest req(QUrl(makeUrl(path)));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    req.setTransferTimeout(4000);

    const QByteArray data = QJsonDocument(body).toJson(QJsonDocument::Compact);
    auto* reply = manager_.post(req, data);

    connect(reply, &QNetworkReply::finished, this, [this, reply, onSuccess, onFailure]() {
        const auto err = reply->error();
        const QByteArray payload = reply->readAll();
        reply->deleteLater();

        if (err != QNetworkReply::NoError) {
            const QString message = QString("HTTP error: %1").arg(reply->errorString());
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

        onSuccess(doc);
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
