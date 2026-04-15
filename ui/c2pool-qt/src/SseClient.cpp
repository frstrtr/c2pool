#include "SseClient.hpp"

#include <QJsonDocument>
#include <QNetworkReply>
#include <QNetworkRequest>

SseClient::SseClient(QObject* parent)
    : QObject(parent)
{
    reconnectTimer_.setSingleShot(true);
    connect(&reconnectTimer_, &QTimer::timeout, this, &SseClient::tryReconnect);
}

SseClient::~SseClient()
{
    disconnect();
}

void SseClient::connectToStream(const QString& url)
{
    if (reply_)
        disconnect();

    url_ = url;
    reconnectDelayMs_ = 2000;

    QNetworkRequest req{QUrl(url_)};
    req.setRawHeader("Accept", "text/event-stream");
    req.setRawHeader("Cache-Control", "no-cache");
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                     QNetworkRequest::NoLessSafeRedirectPolicy);

    reply_ = manager_.get(req);

    connect(reply_, &QNetworkReply::readyRead, this, &SseClient::onReadyRead);
    connect(reply_, &QNetworkReply::finished, this, &SseClient::onFinished);
    connect(reply_, &QNetworkReply::errorOccurred, this, [this]() { onError(); });
}

void SseClient::disconnect()
{
    reconnectTimer_.stop();
    reset();
    emit disconnected();
}

bool SseClient::isConnected() const
{
    return reply_ != nullptr;
}

void SseClient::onReadyRead()
{
    if (!reply_) return;

    buffer_.append(reply_->readAll());

    // Parse SSE frames: "data: {...}\n\n"
    while (true) {
        const int end = buffer_.indexOf("\n\n");
        if (end < 0) break;

        const QByteArray frame = buffer_.left(end);
        buffer_.remove(0, end + 2);

        QString eventType = "message";
        QByteArray dataPayload;

        for (const auto& line : frame.split('\n')) {
            if (line.startsWith("event:")) {
                eventType = QString::fromUtf8(line.mid(6)).trimmed();
            } else if (line.startsWith("data:")) {
                dataPayload = line.mid(5).trimmed();
            }
        }

        if (dataPayload.isEmpty())
            continue;

        QJsonParseError err;
        const auto doc = QJsonDocument::fromJson(dataPayload, &err);
        if (err.error == QJsonParseError::NoError && doc.isObject()) {
            // Reset backoff on successful data
            reconnectDelayMs_ = 2000;

            if (!isConnected()) {
                // Shouldn't happen, but guard
            }

            // Emit connected on first successful data
            static bool firstData = true;
            if (firstData) {
                firstData = false;
                emit connected();
            }

            emit eventReceived(eventType, doc.object());
        }
    }
}

void SseClient::onFinished()
{
    reset();
    emit disconnected();

    if (!url_.isEmpty()) {
        // Auto-reconnect
        reconnectTimer_.start(reconnectDelayMs_);
    }
}

void SseClient::onError()
{
    const QString msg = reply_ ? reply_->errorString() : "Unknown error";
    emit error(msg);
}

void SseClient::tryReconnect()
{
    if (url_.isEmpty()) return;

    // Exponential backoff
    reconnectDelayMs_ = qMin(reconnectDelayMs_ * 2, kMaxReconnectMs);
    connectToStream(url_);
}

void SseClient::reset()
{
    if (reply_) {
        reply_->abort();
        reply_->deleteLater();
        reply_ = nullptr;
    }
    buffer_.clear();
}
