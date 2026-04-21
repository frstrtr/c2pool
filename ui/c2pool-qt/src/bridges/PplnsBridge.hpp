// PplnsBridge — QtWebChannel transport for the embedded JS PPLNS View
// bundle. Mirrors SharechainBridge, but scoped to the two PPLNS-specific
// Transport operations (spec §4.2) + cancelRequest.
//
// Per frstrtr/the/docs/c2pool-qt-hybrid-architecture.md §8 step 12.
// The tip-push stream stays on SharechainBridge — per
// frstrtr/the/docs/c2pool-pplns-view-module-task.md §5.4, PPLNS View
// reuses the sharechain tip stream and refetches /pplns/current on
// each tip event. One SSE socket serves both surfaces.

#pragma once

#include <QHash>
#include <QJsonObject>
#include <QObject>
#include <QString>

class ApiClient;
class QNetworkAccessManager;
class QNetworkReply;

class PplnsBridge : public QObject {
    Q_OBJECT
public:
    explicit PplnsBridge(ApiClient* api, QObject* parent = nullptr);
    ~PplnsBridge() override;

    // ── Transport operations (spec §4.2) ────────────────────────────

    Q_INVOKABLE void getCurrentPayouts(int requestId);
    Q_INVOKABLE void getMinerDetail(int requestId, const QString& address);

    // ── Cancellation (delta v1 §A.1) ────────────────────────────────

    Q_INVOKABLE void cancelRequest(int requestId);

signals:
    /** Parsed JSON object from /pplns/current or /pplns/miner/<addr>.
     *  Matched to the pending promise by requestId. */
    void responseReady(int requestId, const QJsonObject& payload);
    /** Structured error per the ExplorerError taxonomy
     *  (types: transport | rate_limited | schema). */
    void responseFailed(int requestId, const QJsonObject& error);

private slots:
    void onReplyFinished();

private:
    void dispatch(int requestId, const QString& path);
    QString makeUrl(const QString& path) const;
    static QJsonObject buildTransportError(const QString& message,
                                           int httpStatus,
                                           const QString& url);

    ApiClient* api_;
    QNetworkAccessManager* nam_;
    QHash<int, QNetworkReply*> pending_;
};
