#include "ApiClient.hpp"

#include <QFile>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>

ApiClient::ApiClient(QObject* parent)
    : QObject(parent), baseUrl_("http://127.0.0.1:9332")
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
    QNetworkRequest req(QUrl(makeUrl(path)));
    auto* reply = manager_.get(req);

    connect(reply, &QNetworkReply::finished, this, [reply, onSuccess, onFailure]() {
        const auto err = reply->error();
        const QByteArray payload = reply->readAll();
        reply->deleteLater();

        if (err != QNetworkReply::NoError) {
            onFailure(QString("HTTP error: %1").arg(reply->errorString()));
            return;
        }

        QJsonParseError parseErr;
        const auto doc = QJsonDocument::fromJson(payload, &parseErr);
        if (parseErr.error != QJsonParseError::NoError) {
            onFailure(QString("JSON parse error: %1").arg(parseErr.errorString()));
            return;
        }
        onSuccess(doc);
    });
}

void ApiClient::getText(const QString& path, TextSuccess onSuccess, Failure onFailure)
{
    QNetworkRequest req(QUrl(makeUrl(path)));
    auto* reply = manager_.get(req);

    connect(reply, &QNetworkReply::finished, this, [reply, onSuccess, onFailure]() {
        const auto err = reply->error();
        const QByteArray payload = reply->readAll();
        reply->deleteLater();

        if (err != QNetworkReply::NoError) {
            onFailure(QString("HTTP error: %1").arg(reply->errorString()));
            return;
        }
        onSuccess(QString::fromUtf8(payload));
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
