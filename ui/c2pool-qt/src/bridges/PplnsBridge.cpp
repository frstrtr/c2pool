#include "PplnsBridge.hpp"

#include "ApiClient.hpp"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>

PplnsBridge::PplnsBridge(ApiClient* api, QObject* parent)
    : QObject(parent), api_(api), nam_(new QNetworkAccessManager(this))
{
    setObjectName(QStringLiteral("pplns"));
}

PplnsBridge::~PplnsBridge()
{
    for (auto* reply : std::as_const(pending_)) {
        if (reply != nullptr) reply->abort();
    }
    pending_.clear();
}

// ── Operations ───────────────────────────────────────────────────────

void PplnsBridge::getCurrentPayouts(int requestId)
{
    dispatch(requestId, QStringLiteral("/pplns/current"));
}

void PplnsBridge::getMinerDetail(int requestId, const QString& address)
{
    // URL-encode the address — server path is /pplns/miner/<addr>.
    const QString encoded = QString::fromUtf8(QUrl::toPercentEncoding(address));
    dispatch(requestId, QStringLiteral("/pplns/miner/") + encoded);
}

void PplnsBridge::cancelRequest(int requestId)
{
    auto it = pending_.find(requestId);
    if (it == pending_.end()) return;
    QNetworkReply* reply = it.value();
    pending_.erase(it);
    if (reply != nullptr) {
        reply->abort();
        reply->deleteLater();
    }
}

// ── Internals ────────────────────────────────────────────────────────

void PplnsBridge::dispatch(int requestId, const QString& path)
{
    QNetworkRequest req{QUrl(makeUrl(path))};
    req.setRawHeader("Accept", "application/json");
    QNetworkReply* reply = nam_->get(req);
    pending_.insert(requestId, reply);
    reply->setProperty("c2pool_requestId", requestId);
    connect(reply, &QNetworkReply::finished, this, &PplnsBridge::onReplyFinished);
}

QString PplnsBridge::makeUrl(const QString& path) const
{
    if (api_ == nullptr) return path;
    QString base = api_->baseUrl();
    if (base.endsWith('/')) base.chop(1);
    return base + path;
}

void PplnsBridge::onReplyFinished()
{
    auto* reply = qobject_cast<QNetworkReply*>(sender());
    if (reply == nullptr) return;
    const int requestId = reply->property("c2pool_requestId").toInt();
    const QString url = reply->url().toString();
    const int httpStatus =
        reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    pending_.remove(requestId);

    if (reply->error() != QNetworkReply::NoError) {
        emit responseFailed(requestId, buildTransportError(
            reply->errorString(), httpStatus, url));
        reply->deleteLater();
        return;
    }

    const QByteArray body = reply->readAll();
    reply->deleteLater();

    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(body, &pe);
    if (pe.error != QJsonParseError::NoError) {
        QJsonObject err;
        err.insert(QStringLiteral("type"), QStringLiteral("schema"));
        err.insert(QStringLiteral("message"),
                   QStringLiteral("JSON parse error: ") + pe.errorString());
        err.insert(QStringLiteral("path"), url);
        emit responseFailed(requestId, err);
        return;
    }

    if (doc.isObject()) {
        emit responseReady(requestId, doc.object());
        return;
    }
    if (doc.isArray()) {
        QJsonObject wrap;
        wrap.insert(QStringLiteral("data"), doc.array());
        emit responseReady(requestId, wrap);
        return;
    }
    QJsonObject err;
    err.insert(QStringLiteral("type"), QStringLiteral("schema"));
    err.insert(QStringLiteral("message"),
               QStringLiteral("response was neither object nor array"));
    err.insert(QStringLiteral("path"), url);
    emit responseFailed(requestId, err);
}

QJsonObject PplnsBridge::buildTransportError(const QString& message,
                                              int httpStatus,
                                              const QString& url)
{
    QJsonObject err;
    if (httpStatus == 429) {
        err.insert(QStringLiteral("type"), QStringLiteral("rate_limited"));
    } else {
        err.insert(QStringLiteral("type"), QStringLiteral("transport"));
    }
    err.insert(QStringLiteral("message"), message);
    if (httpStatus > 0) err.insert(QStringLiteral("status"), httpStatus);
    if (!url.isEmpty())  err.insert(QStringLiteral("url"), url);
    return err;
}
