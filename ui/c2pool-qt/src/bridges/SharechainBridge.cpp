#include "SharechainBridge.hpp"

#include "ApiClient.hpp"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRandomGenerator>
#include <QTimer>
#include <QUrl>
#include <QUrlQuery>

namespace {

/** Delta v1 §D.7 reconnect: 1s base / 30s cap / ×2 exp / ±30% jitter. */
int reconnectDelayMs(int attempt)
{
    constexpr int base = 1000;
    constexpr int cap  = 30000;
    const int pure = qMin(cap, base * (1 << qMin(attempt, 5)));
    // ±30% jitter
    const int jitter = static_cast<int>(pure * 0.3);
    const int noise = QRandomGenerator::global()->bounded(-jitter, jitter + 1);
    return qMax(base, pure + noise);
}

} // namespace

SharechainBridge::SharechainBridge(ApiClient* api, QObject* parent)
    : QObject(parent), api_(api), nam_(new QNetworkAccessManager(this))
{
    setObjectName(QStringLiteral("sharechain"));
    reconnectTimer_ = new QTimer(this);
    reconnectTimer_->setSingleShot(true);
    connect(reconnectTimer_, &QTimer::timeout, this, &SharechainBridge::onReconnectTimer);
}

SharechainBridge::~SharechainBridge()
{
    stopStream();
    for (auto* reply : std::as_const(pending_)) {
        if (reply != nullptr) reply->abort();
    }
    pending_.clear();
}

// ── Transport operations ─────────────────────────────────────────────

void SharechainBridge::getWindow(int requestId)
{
    dispatch(requestId, QStringLiteral("/sharechain/window"));
}

void SharechainBridge::getTip(int requestId)
{
    dispatch(requestId, QStringLiteral("/sharechain/tip"));
}

void SharechainBridge::getDelta(int requestId, const QString& since)
{
    QUrlQuery q;
    if (!since.isEmpty()) q.addQueryItem(QStringLiteral("since"), since);
    const QString path = QStringLiteral("/sharechain/delta") +
                         (q.isEmpty() ? QString() : QStringLiteral("?") + q.toString());
    dispatch(requestId, path);
}

void SharechainBridge::getStats(int requestId)
{
    dispatch(requestId, QStringLiteral("/sharechain/stats"));
}

void SharechainBridge::getShareDetail(int requestId, const QString& fullHash)
{
    // The /sharechain/share endpoint is a planned addition; c2pool
    // doesn't serve it yet. Until it lands, return a structured
    // error so the JS side's error taxonomy handling kicks in
    // consistently.
    QJsonObject err;
    err.insert(QStringLiteral("type"), QStringLiteral("transport"));
    err.insert(QStringLiteral("message"),
               QStringLiteral("share-detail endpoint not yet implemented"));
    err.insert(QStringLiteral("url"), makeUrl(
        QStringLiteral("/sharechain/share?hash=") + fullHash));
    emit responseFailed(requestId, err);
}

void SharechainBridge::negotiate(int requestId)
{
    // Same disposition as getShareDetail — negotiation endpoint is
    // planned. The JS side already falls back to assumed-v1 contract
    // when negotiate fails with a transport error.
    QJsonObject err;
    err.insert(QStringLiteral("type"), QStringLiteral("transport"));
    err.insert(QStringLiteral("message"),
               QStringLiteral("negotiate endpoint not yet implemented"));
    err.insert(QStringLiteral("url"), makeUrl(QStringLiteral("/sharechain/negotiate")));
    emit responseFailed(requestId, err);
}

void SharechainBridge::cancelRequest(int requestId)
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

// ── Stream control ───────────────────────────────────────────────────

void SharechainBridge::startStream()
{
    streamRequested_ = true;
    if (stream_ != nullptr) return;
    reconnectAttempts_ = 0;
    openStream();
}

void SharechainBridge::stopStream()
{
    streamRequested_ = false;
    if (reconnectTimer_ != nullptr) reconnectTimer_->stop();
    if (stream_ != nullptr) {
        stream_->abort();
        stream_->deleteLater();
        stream_ = nullptr;
    }
    streamBuffer_.clear();
}

// ── Internals ────────────────────────────────────────────────────────

void SharechainBridge::dispatch(int requestId, const QString& path)
{
    QNetworkRequest req{QUrl(makeUrl(path))};
    req.setRawHeader("Accept", "application/json");
    QNetworkReply* reply = nam_->get(req);
    pending_.insert(requestId, reply);
    reply->setProperty("c2pool_requestId", requestId);
    connect(reply, &QNetworkReply::finished, this, &SharechainBridge::onReplyFinished);
}

QString SharechainBridge::makeUrl(const QString& path) const
{
    if (api_ == nullptr) return path;
    QString base = api_->baseUrl();
    if (base.endsWith('/')) base.chop(1);
    return base + path;
}

void SharechainBridge::onReplyFinished()
{
    auto* reply = qobject_cast<QNetworkReply*>(sender());
    if (reply == nullptr) return;
    const int requestId = reply->property("c2pool_requestId").toInt();
    const QString url = reply->url().toString();
    const int httpStatus =
        reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    pending_.remove(requestId);

    if (reply->error() != QNetworkReply::NoError) {
        // Operation cancellation arrives as OperationCanceledError; the
        // JS side already treats that as "we asked for it" — still emit
        // a structured error so pending Promise resolves.
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
    // Some endpoints return arrays (e.g., current_merged_payouts).
    // Wrap under a `.data` key so the channel carries a QJsonObject.
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

QJsonObject SharechainBridge::buildTransportError(const QString& message,
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

void SharechainBridge::openStream()
{
    QNetworkRequest req{QUrl(makeUrl(QStringLiteral("/sharechain/stream")))};
    req.setRawHeader("Accept", "text/event-stream");
    req.setAttribute(QNetworkRequest::HttpPipeliningAllowedAttribute, false);
    stream_ = nam_->get(req);
    streamBuffer_.clear();
    connect(stream_, &QNetworkReply::readyRead, this, &SharechainBridge::onStreamReadyRead);
    connect(stream_, &QNetworkReply::finished,  this, &SharechainBridge::onStreamFinished);
}

void SharechainBridge::onStreamReadyRead()
{
    if (stream_ == nullptr) return;
    streamBuffer_.append(stream_->readAll());
    consumeStreamBuffer();
}

void SharechainBridge::consumeStreamBuffer()
{
    // SSE framing: events are separated by blank lines. Each event is
    // a sequence of `field: value` lines; we only care about `data: ...`.
    // Support both LF and CRLF line endings.
    int idx = 0;
    while (true) {
        const int sep = streamBuffer_.indexOf("\n\n", idx);
        const int sepCRLF = streamBuffer_.indexOf("\r\n\r\n", idx);
        int use, sepLen;
        if (sep < 0 && sepCRLF < 0) break;
        if (sep >= 0 && (sepCRLF < 0 || sep < sepCRLF)) { use = sep; sepLen = 2; }
        else                                             { use = sepCRLF; sepLen = 4; }

        const QByteArray event = streamBuffer_.mid(idx, use - idx);
        idx = use + sepLen;

        // Collect all data: lines.
        QByteArray dataJoined;
        for (const QByteArray& line : event.split('\n')) {
            QByteArray l = line;
            if (l.endsWith('\r')) l.chop(1);
            if (l.startsWith("data:")) {
                QByteArray v = l.mid(5);
                if (v.startsWith(' ')) v = v.mid(1);
                if (!dataJoined.isEmpty()) dataJoined.append('\n');
                dataJoined.append(v);
            }
        }
        if (dataJoined.isEmpty()) continue;

        QJsonParseError pe{};
        const QJsonDocument doc = QJsonDocument::fromJson(dataJoined, &pe);
        if (pe.error == QJsonParseError::NoError && doc.isObject()) {
            emit tipChanged(doc.object());
        }
    }
    if (idx > 0) streamBuffer_.remove(0, idx);
}

void SharechainBridge::onStreamFinished()
{
    if (stream_ != nullptr) {
        stream_->deleteLater();
        stream_ = nullptr;
    }
    streamBuffer_.clear();
    if (streamRequested_) scheduleReconnect();
}

void SharechainBridge::scheduleReconnect()
{
    if (!streamRequested_) return;
    const int delay = reconnectDelayMs(reconnectAttempts_++);
    if (reconnectTimer_ != nullptr) reconnectTimer_->start(delay);
}

void SharechainBridge::onReconnectTimer()
{
    if (!streamRequested_) return;
    openStream();
    emit tipReconnected();
}
