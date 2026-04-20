// SharechainBridge — QtWebChannel transport for the embedded JS
// Explorer bundle. Mirrors the 9-operation Transport interface from
// web-static/sharechain-explorer/src/transport/types.ts so the JS
// side can swap HttpTransport ↔ QtTransport with no module-level
// changes (SharechainExplorer.init({ transport: QtTransport }) is
// the entire swap).
//
// Per frstrtr/the/docs/c2pool-qt-hybrid-architecture.md §4.2 + §8
// step 6. Bridge is self-contained: owns its own QNetworkAccessManager
// so per-request cancellation is cheap + doesn't conflict with
// ApiClient. ApiClient is used only for its baseUrl().
//
// Error taxonomy: response JSON objects on responseFailed follow the
// ExplorerError discriminated union (transport | schema | contract |
// version_mismatch | rate_limited | fork_switch | internal) from
// web-static/sharechain-explorer/src/errors.ts.

#pragma once

#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QObject>
#include <QString>

class ApiClient;
class QNetworkAccessManager;
class QNetworkReply;
class QTimer;

class SharechainBridge : public QObject {
    Q_OBJECT
public:
    explicit SharechainBridge(ApiClient* api, QObject* parent = nullptr);
    ~SharechainBridge() override;

    // ── Transport operations (delta v1 §A / Transport types.ts) ──────

    Q_INVOKABLE void getWindow(int requestId);
    Q_INVOKABLE void getTip(int requestId);
    Q_INVOKABLE void getDelta(int requestId, const QString& since);
    Q_INVOKABLE void getStats(int requestId);
    Q_INVOKABLE void getShareDetail(int requestId, const QString& fullHash);
    Q_INVOKABLE void negotiate(int requestId);

    // ── Cancellation (delta v1 §A.1) ─────────────────────────────────

    Q_INVOKABLE void cancelRequest(int requestId);

    // ── Tip-stream control (delta v1 §A.2 / §A.3) ────────────────────

    /** Open the SSE stream on /sharechain/stream. Subsequent tip events
     *  flow via tipChanged. If the stream drops, the bridge reconnects
     *  with exponential backoff (base 1s, cap 30s, ×2, ±30% jitter —
     *  matches delta v1 §D.7) and emits tipReconnected each time the
     *  connection is re-established. */
    Q_INVOKABLE void startStream();
    /** Close the stream + halt the reconnect loop. Safe to call
     *  repeatedly. */
    Q_INVOKABLE void stopStream();

signals:
    /** One per pending request, matched by requestId. Payload is the
     *  parsed JSON object. */
    void responseReady(int requestId, const QJsonObject& payload);
    /** Structured error per the ExplorerError taxonomy. Matched by
     *  requestId. */
    void responseFailed(int requestId, const QJsonObject& error);

    /** Tip event pushed by the server. Shape: {hash: string,
     *  seq?: number}. */
    void tipChanged(const QJsonObject& tipEvent);
    /** Fired each time the tip stream reconnects after a drop. */
    void tipReconnected();

private slots:
    void onReplyFinished();
    void onStreamReadyRead();
    void onStreamFinished();
    void onReconnectTimer();

private:
    void dispatch(int requestId, const QString& path);
    QString makeUrl(const QString& path) const;
    /** Build the stream request + connect signals. Called both by
     *  startStream() and onReconnectTimer(). */
    void openStream();
    /** Schedule the next reconnect attempt with exponential backoff. */
    void scheduleReconnect();
    /** Parse buffered SSE bytes; emit tipChanged for each complete
     *  `data: {...}\n\n` event. Incomplete trailing data stays in the
     *  buffer. */
    void consumeStreamBuffer();
    /** Build a structured error object compatible with the JS
     *  ExplorerError taxonomy. */
    static QJsonObject buildTransportError(const QString& message,
                                           int httpStatus,
                                           const QString& url);

    ApiClient* api_;
    QNetworkAccessManager* nam_;
    QHash<int, QNetworkReply*> pending_;

    // Tip stream
    QNetworkReply* stream_ = nullptr;
    QByteArray streamBuffer_;
    QTimer* reconnectTimer_ = nullptr;
    int reconnectAttempts_ = 0;
    bool streamRequested_ = false;
};
