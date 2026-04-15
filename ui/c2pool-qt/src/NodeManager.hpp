#pragma once

#include "ApiClient.hpp"
#include "NodeProfile.hpp"

#include <QJsonObject>
#include <QMap>
#include <QObject>

#include <map>
#include <memory>

/// Manages multiple c2pool node connections.
///
/// Each node has a profile (local or remote) and its own ApiClient.
/// One node is "active" at a time -- all dashboard pages use its client.
/// For local nodes, auto-reads the .cookie file for authentication.
class NodeManager : public QObject
{
    Q_OBJECT
public:
    explicit NodeManager(QObject* parent = nullptr);

    // ── Profile management ───────────────────────────────────────────────
    void addProfile(const NodeProfile& profile);
    void removeProfile(const QString& id);
    void updateProfile(const NodeProfile& profile);
    QList<NodeProfile> profiles() const;
    NodeProfile profile(const QString& id) const;

    // ── Connection lifecycle ─────────────────────────────────────────────
    void connectToNode(const QString& profileId);
    void disconnectFromNode(const QString& profileId);

    // ── Active node ──────────────────────────────────────────────────────
    void setActiveNode(const QString& profileId);
    QString activeNodeId() const { return activeId_; }
    ApiClient* activeClient() const;
    NodeProfile activeProfile() const;

    // ── Cookie auto-detection ────────────────────────────────────────────
    /// Read auth cookie from dataDir/.cookie (for local nodes).
    static QString readCookie(const QString& dataDir);

    // ── Persistence ──────────────────────────────────────────────────────
    void saveProfiles() const;
    void loadProfiles();

signals:
    void activeNodeChanged(const QString& profileId);
    void nodeConnected(const QString& profileId);
    void nodeDisconnected(const QString& profileId);
    void nodeConfigReceived(const QString& profileId, const QJsonObject& config);

private:
    void fetchConfig(const QString& profileId);

    QMap<QString, NodeProfile> profiles_;
    std::map<QString, std::unique_ptr<ApiClient>> clients_;
    QString activeId_;
};
