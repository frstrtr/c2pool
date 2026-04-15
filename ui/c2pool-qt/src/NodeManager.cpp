#include "NodeManager.hpp"

#include <QDir>
#include <QFile>
#include <QSettings>
#include <QTextStream>

NodeManager::NodeManager(QObject* parent)
    : QObject(parent)
{
}

// ─────────────────────────────────────────────────────────────────────────────
// Profile management
// ─────────────────────────────────────────────────────────────────────────────

void NodeManager::addProfile(const NodeProfile& profile)
{
    profiles_[profile.id] = profile;
}

void NodeManager::removeProfile(const QString& id)
{
    disconnectFromNode(id);
    profiles_.remove(id);
    if (activeId_ == id) {
        activeId_.clear();
        emit activeNodeChanged({});
    }
}

void NodeManager::updateProfile(const NodeProfile& profile)
{
    profiles_[profile.id] = profile;

    // Update existing client if connected
    auto it = clients_.find(profile.id);
    if (it != clients_.end() && it->second) {
        it->second->setBaseUrl(profile.baseUrl());
        it->second->setAuthToken(profile.authToken);
    }
}

QList<NodeProfile> NodeManager::profiles() const
{
    return profiles_.values();
}

NodeProfile NodeManager::profile(const QString& id) const
{
    return profiles_.value(id);
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection lifecycle
// ─────────────────────────────────────────────────────────────────────────────

void NodeManager::connectToNode(const QString& profileId)
{
    if (!profiles_.contains(profileId))
        return;

    auto& prof = profiles_[profileId];

    // For local nodes, try to auto-read cookie
    if (prof.isLocal && prof.authToken.isEmpty() && !prof.dataDir.isEmpty()) {
        const QString cookie = readCookie(prof.dataDir);
        if (!cookie.isEmpty())
            prof.authToken = cookie;
    }

    // Create or reconfigure client
    auto& client = clients_[profileId];
    if (!client)
        client = std::make_unique<ApiClient>(this);

    client->setBaseUrl(prof.baseUrl());
    client->setAuthToken(prof.authToken);

    // Ping to verify connection
    client->getText("/uptime",
        [this, profileId](const QString&) {
            emit nodeConnected(profileId);
            fetchConfig(profileId);
        },
        [this, profileId](const QString&) {
            emit nodeDisconnected(profileId);
        }
    );
}

void NodeManager::disconnectFromNode(const QString& profileId)
{
    auto it = clients_.find(profileId);
    if (it != clients_.end())
        clients_.erase(it);
    emit nodeDisconnected(profileId);
}

// ─────────────────────────────────────────────────────────────────────────────
// Active node
// ─────────────────────────────────────────────────────────────────────────────

void NodeManager::setActiveNode(const QString& profileId)
{
    if (activeId_ == profileId)
        return;
    activeId_ = profileId;
    emit activeNodeChanged(profileId);
}

ApiClient* NodeManager::activeClient() const
{
    auto it = clients_.find(activeId_);
    return (it != clients_.end()) ? it->second.get() : nullptr;
}

NodeProfile NodeManager::activeProfile() const
{
    return profiles_.value(activeId_);
}

// ─────────────────────────────────────────────────────────────────────────────
// Cookie auto-detection
// ─────────────────────────────────────────────────────────────────────────────

QString NodeManager::readCookie(const QString& dataDir)
{
    const QString cookiePath = QDir(dataDir).filePath(".cookie");
    QFile file(cookiePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return {};

    QTextStream in(&file);
    return in.readLine().trimmed();
}

// ─────────────────────────────────────────────────────────────────────────────
// Fetch running config from connected node
// ─────────────────────────────────────────────────────────────────────────────

void NodeManager::fetchConfig(const QString& profileId)
{
    auto it = clients_.find(profileId);
    if (it == clients_.end())
        return;

    it->second->getJson("/config",
        [this, profileId](const QJsonDocument& doc) {
            if (doc.isObject())
                emit nodeConfigReceived(profileId, doc.object());
        },
        [](const QString&) {
            // Config endpoint may not exist on older daemons -- ignore
        }
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistence
// ─────────────────────────────────────────────────────────────────────────────

void NodeManager::saveProfiles() const
{
    QSettings s;
    s.remove("nodes");
    s.beginWriteArray("nodes");
    int idx = 0;
    for (const auto& prof : profiles_) {
        s.setArrayIndex(idx++);
        s.setValue("id", prof.id);
        s.setValue("label", prof.label);
        s.setValue("address", prof.address);
        s.setValue("authToken", prof.authToken);
        s.setValue("dataDir", prof.dataDir);
        s.setValue("isLocal", prof.isLocal);
        s.setValue("autoConnect", prof.autoConnect);
        s.setValue("autoLaunch", prof.autoLaunch);
    }
    s.endArray();
    s.setValue("nodes/activeId", activeId_);
}

void NodeManager::loadProfiles()
{
    QSettings s;
    const int count = s.beginReadArray("nodes");
    for (int i = 0; i < count; ++i) {
        s.setArrayIndex(i);
        NodeProfile prof;
        prof.id = s.value("id").toString();
        prof.label = s.value("label").toString();
        prof.address = s.value("address").toString();
        prof.authToken = s.value("authToken").toString();
        prof.dataDir = s.value("dataDir").toString();
        prof.isLocal = s.value("isLocal", true).toBool();
        prof.autoConnect = s.value("autoConnect", false).toBool();
        prof.autoLaunch = s.value("autoLaunch", false).toBool();
        profiles_[prof.id] = prof;
    }
    s.endArray();
    activeId_ = s.value("nodes/activeId").toString();

    // Create default local profile if none exist
    if (profiles_.isEmpty()) {
#ifdef _WIN32
        const QString defaultDataDir = QString::fromLocal8Bit(qgetenv("APPDATA")) + "/c2pool";
#else
        const QString defaultDataDir = QDir::homePath() + "/.c2pool";
#endif
        auto local = NodeProfile::create("Local Node", "127.0.0.1:8080", true, defaultDataDir);
        local.autoConnect = true;
        profiles_[local.id] = local;
        activeId_ = local.id;
    }
}
