#pragma once

#include <QString>
#include <QUuid>

/// Connection profile for a c2pool node (local or remote).
struct NodeProfile {
    QString id;              ///< Unique identifier (UUID)
    QString label;           ///< Display name ("My Testnet Node")
    QString address;         ///< host:port ("127.0.0.1:19328")
    QString authToken;       ///< Auth cookie/token (manual or auto-read)
    QString dataDir;         ///< Data directory for local nodes (~/.c2pool)
    bool isLocal = true;     ///< Can read local files, launch daemon
    bool autoConnect = false;///< Connect on app startup
    bool autoLaunch = false; ///< Start daemon on app startup (local only)

    /// Generate a new profile with a fresh UUID.
    static NodeProfile create(const QString& label, const QString& address,
                              bool isLocal = true, const QString& dataDir = {})
    {
        NodeProfile p;
        p.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
        p.label = label;
        p.address = address;
        p.isLocal = isLocal;
        p.dataDir = dataDir;
        return p;
    }

    /// Construct the base URL from address.
    QString baseUrl() const {
        if (address.startsWith("http"))
            return address;
        return QString("http://%1").arg(address);
    }
};
