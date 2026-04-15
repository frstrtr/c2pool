#pragma once

#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QObject>
#include <QString>
#include <QTimer>

class QNetworkReply;

/// Server-Sent Events (SSE) consumer for real-time sharechain updates.
///
/// Connects to /sharechain/stream and emits eventReceived for each
/// SSE data frame. Auto-reconnects with exponential backoff on failure.
class SseClient : public QObject
{
    Q_OBJECT
public:
    explicit SseClient(QObject* parent = nullptr);
    ~SseClient();

    void connectToStream(const QString& url);
    void disconnect();
    bool isConnected() const;

signals:
    void eventReceived(const QString& eventType, const QJsonObject& data);
    void connected();
    void disconnected();
    void error(const QString& message);

private slots:
    void onReadyRead();
    void onFinished();
    void onError();
    void tryReconnect();

private:
    void reset();

    QNetworkAccessManager manager_;
    QNetworkReply* reply_{nullptr};
    QString url_;
    QByteArray buffer_;
    QTimer reconnectTimer_;
    int reconnectDelayMs_{2000};
    static constexpr int kMaxReconnectMs = 30000;
};
