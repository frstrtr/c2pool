#include "SettingsStore.hpp"

#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QSettings>
#include <QTimer>

namespace {

constexpr const char* DEFAULT_PROFILE   = "default";
constexpr const char* DEFAULT_BASE_URL  = "http://127.0.0.1:8080";
constexpr int         DEFAULT_REFRESH_MS = 5000;

} // namespace

SettingsStore::SettingsStore(QObject* parent) : QObject(parent) {}

// ── Schema versioning ───────────────────────────────────────────────

int SettingsStore::schemaVersion() const
{
    return QSettings{}.value(QStringLiteral("meta/schemaVersion"), 1).toInt();
}

void SettingsStore::runMigrationsIfNeeded()
{
    const int v = schemaVersion();
    if (v >= kSchemaVersion) return;
    if (v == 1) {
        migrateV1ToV2();
        emit schemaMigrated(1, 2);
    }
    QSettings{}.setValue(QStringLiteral("meta/schemaVersion"), kSchemaVersion);
}

void SettingsStore::migrateV1ToV2()
{
    // Move legacy [launch/*] under [profiles/default/launch/*]. Also
    // sets ui/activeProfile + profiles/names.
    //
    // rpcUser / rpcPass in the legacy [launch] group should move to
    // the secrets fallback (in v2 those live under [secrets/<profile>/*]
    // instead of cleartext QSettings). Copying before deletion so a
    // failure to write leaves the legacy values recoverable on next
    // launch.
    QSettings s;
    s.beginGroup(QStringLiteral("launch"));
    const QStringList keys = s.allKeys();
    s.endGroup();

    const QString profile = QString::fromLatin1(DEFAULT_PROFILE);
    for (const QString& k : keys) {
        const QVariant val = s.value(QStringLiteral("launch/") + k);
        if (k == QStringLiteral("rpcUser") || k == QStringLiteral("rpcPass")) {
            s.setValue(secretsKey(profile, k), val.toString());
        } else {
            s.setValue(profileLaunchPath(profile, k), val);
        }
    }
    s.remove(QStringLiteral("launch"));

    if (!s.contains(QStringLiteral("ui/activeProfile"))) {
        s.setValue(QStringLiteral("ui/activeProfile"), profile);
    }
    if (!s.contains(QStringLiteral("profiles/names"))) {
        s.setValue(QStringLiteral("profiles/names"), QStringList{profile});
    }
}

// ── UI ──────────────────────────────────────────────────────────────

QString SettingsStore::uiBaseUrl() const
{
    return QSettings{}.value(QStringLiteral("ui/baseUrl"),
        QString::fromLatin1(DEFAULT_BASE_URL)).toString();
}

void SettingsStore::setUiBaseUrl(const QString& v)
{
    QSettings{}.setValue(QStringLiteral("ui/baseUrl"), v);
    emit changed(QStringLiteral("ui/baseUrl"));
}

int SettingsStore::uiRefreshMs() const
{
    return QSettings{}.value(QStringLiteral("ui/refreshMs"),
        DEFAULT_REFRESH_MS).toInt();
}

void SettingsStore::setUiRefreshMs(int v)
{
    QSettings{}.setValue(QStringLiteral("ui/refreshMs"), v);
    emit changed(QStringLiteral("ui/refreshMs"));
}

QString SettingsStore::uiTheme() const
{
    return QSettings{}.value(QStringLiteral("ui/theme"),
        QStringLiteral("system")).toString();
}

void SettingsStore::setUiTheme(const QString& v)
{
    QSettings{}.setValue(QStringLiteral("ui/theme"), v);
    emit changed(QStringLiteral("ui/theme"));
}

// ── Window state ────────────────────────────────────────────────────

QByteArray SettingsStore::mainWindowGeometry() const
{
    return QSettings{}.value(QStringLiteral("window/mainGeometry")).toByteArray();
}

void SettingsStore::setMainWindowGeometry(const QByteArray& v)
{
    QSettings{}.setValue(QStringLiteral("window/mainGeometry"), v);
    emit changed(QStringLiteral("window/mainGeometry"));
}

QByteArray SettingsStore::mainWindowState() const
{
    return QSettings{}.value(QStringLiteral("window/mainState")).toByteArray();
}

void SettingsStore::setMainWindowState(const QByteArray& v)
{
    QSettings{}.setValue(QStringLiteral("window/mainState"), v);
    emit changed(QStringLiteral("window/mainState"));
}

// ── Profiles ────────────────────────────────────────────────────────

QStringList SettingsStore::profileNames() const
{
    QStringList names = QSettings{}.value(QStringLiteral("profiles/names")).toStringList();
    if (names.isEmpty()) names << QString::fromLatin1(DEFAULT_PROFILE);
    return names;
}

QString SettingsStore::activeProfile() const
{
    const QString a = QSettings{}.value(QStringLiteral("ui/activeProfile")).toString();
    if (!a.isEmpty()) return a;
    return QString::fromLatin1(DEFAULT_PROFILE);
}

void SettingsStore::setActiveProfile(const QString& name)
{
    if (name.isEmpty()) return;
    const QStringList all = profileNames();
    if (!all.contains(name)) return;     // silent no-op per doc §7
    QSettings{}.setValue(QStringLiteral("ui/activeProfile"), name);
    emit profileChanged(name);
    emit changed(QStringLiteral("ui/activeProfile"));
}

void SettingsStore::createProfile(const QString& name)
{
    if (name.isEmpty()) return;
    QStringList all = profileNames();
    if (all.contains(name)) return;
    all << name;
    QSettings{}.setValue(QStringLiteral("profiles/names"), all);
    emit changed(QStringLiteral("profiles/names"));
}

void SettingsStore::deleteProfile(const QString& name)
{
    if (name.isEmpty()) return;
    QStringList all = profileNames();
    if (!all.removeOne(name)) return;
    if (all.isEmpty()) all << QString::fromLatin1(DEFAULT_PROFILE);
    QSettings s;
    s.setValue(QStringLiteral("profiles/names"), all);
    s.remove(QStringLiteral("profiles/") + name);
    s.remove(QStringLiteral("secrets/") + name);
    // If we just deleted the active profile, reset to the first remaining.
    if (activeProfile() == name) {
        s.setValue(QStringLiteral("ui/activeProfile"), all.first());
        emit profileChanged(all.first());
    }
    emit changed(QStringLiteral("profiles/names"));
}

void SettingsStore::renameProfile(const QString& from, const QString& to)
{
    if (from.isEmpty() || to.isEmpty() || from == to) return;
    QStringList all = profileNames();
    const int idx = all.indexOf(from);
    if (idx < 0) return;
    if (all.contains(to)) return;    // don't clobber existing
    all[idx] = to;
    QSettings s;
    s.setValue(QStringLiteral("profiles/names"), all);
    // Move launch + secrets groups.
    for (const QString& topGroup : { QStringLiteral("profiles"),
                                      QStringLiteral("secrets") }) {
        const QString oldP = topGroup + QStringLiteral("/") + from;
        const QString newP = topGroup + QStringLiteral("/") + to;
        s.beginGroup(oldP);
        const QStringList keys = s.allKeys();
        s.endGroup();
        for (const QString& k : keys) {
            s.setValue(newP + QStringLiteral("/") + k, s.value(oldP + QStringLiteral("/") + k));
        }
        s.remove(oldP);
    }
    if (activeProfile() == from) {
        s.setValue(QStringLiteral("ui/activeProfile"), to);
        emit profileChanged(to);
    }
    emit changed(QStringLiteral("profiles/names"));
}

QString SettingsStore::profileLaunchPath(const QString& profile, const QString& key) const
{
    return QStringLiteral("profiles/%1/launch/%2").arg(profile, key);
}

QVariant SettingsStore::launchValue(const QString& key, const QVariant& def) const
{
    return QSettings{}.value(profileLaunchPath(activeProfile(), key), def);
}

void SettingsStore::setLaunchValue(const QString& key, const QVariant& v)
{
    const QString path = profileLaunchPath(activeProfile(), key);
    QSettings{}.setValue(path, v);
    emit changed(path);
}

// ── View state: sharechain ──────────────────────────────────────────

int SettingsStore::sharechainCellSize() const
{
    return QSettings{}.value(QStringLiteral("sharechain/view/cellSize"), 10).toInt();
}

void SettingsStore::setSharechainCellSize(int px)
{
    QSettings{}.setValue(QStringLiteral("sharechain/view/cellSize"), px);
    emit changed(QStringLiteral("sharechain/view/cellSize"));
}

QStringList SettingsStore::sharechainHiddenMiners() const
{
    return QSettings{}.value(QStringLiteral("sharechain/view/hiddenMiners")).toStringList();
}

void SettingsStore::setSharechainHiddenMiners(const QStringList& v)
{
    QSettings{}.setValue(QStringLiteral("sharechain/view/hiddenMiners"), v);
    emit changed(QStringLiteral("sharechain/view/hiddenMiners"));
}

// ── View state: logs ────────────────────────────────────────────────

QString SettingsStore::logsFilterScope() const
{
    return QSettings{}.value(QStringLiteral("logs/view/filterScope"),
        QStringLiteral("all")).toString();
}

void SettingsStore::setLogsFilterScope(const QString& v)
{
    QSettings{}.setValue(QStringLiteral("logs/view/filterScope"), v);
    emit changed(QStringLiteral("logs/view/filterScope"));
}

bool SettingsStore::logsAutoScroll() const
{
    return QSettings{}.value(QStringLiteral("logs/view/autoScroll"), true).toBool();
}

void SettingsStore::setLogsAutoScroll(bool v)
{
    QSettings{}.setValue(QStringLiteral("logs/view/autoScroll"), v);
    emit changed(QStringLiteral("logs/view/autoScroll"));
}

// ── View state: mining ──────────────────────────────────────────────

QByteArray SettingsStore::miningTableHeaderState() const
{
    return QSettings{}.value(QStringLiteral("mining/view/tableHeaderState")).toByteArray();
}

void SettingsStore::setMiningTableHeaderState(const QByteArray& v)
{
    QSettings{}.setValue(QStringLiteral("mining/view/tableHeaderState"), v);
    emit changed(QStringLiteral("mining/view/tableHeaderState"));
}

// ── Secrets ─────────────────────────────────────────────────────────
//
// Step 3 implementation uses a QSettings fallback under a
// [secrets/<profile>/<key>] group. Step 4 replaces the body of these
// methods with qtkeychain async jobs behind #ifdef
// C2POOL_QT_USE_KEYCHAIN, with this QSettings path as the keychain-
// unavailable fallback.

QString SettingsStore::secretsKey(const QString& profile, const QString& key) const
{
    return QStringLiteral("secrets/%1/%2").arg(profile, key);
}

void SettingsStore::readSecret(const QString& key,
                               std::function<void(QString, bool)> cb)
{
    const QString path = secretsKey(activeProfile(), key);
    const QVariant v = QSettings{}.value(path);
    const QString str = v.toString();
    // Defer via single-shot timer so callbacks are always async —
    // matches the keychain-backed implementation's contract.
    QTimer::singleShot(0, this, [cb, str]() {
        if (cb) cb(str, !str.isEmpty());
    });
}

void SettingsStore::writeSecret(const QString& key, const QString& value,
                                std::function<void(bool)> cb)
{
    const QString path = secretsKey(activeProfile(), key);
    QSettings{}.setValue(path, value);
    emit changed(path);
    QTimer::singleShot(0, this, [cb]() { if (cb) cb(true); });
}

void SettingsStore::deleteSecret(const QString& key, std::function<void(bool)> cb)
{
    const QString path = secretsKey(activeProfile(), key);
    QSettings{}.remove(path);
    emit changed(path);
    QTimer::singleShot(0, this, [cb]() { if (cb) cb(true); });
}

void SettingsStore::loadRpcCredentials(
    std::function<void(QString, QString, bool)> cb)
{
    // Chain two readSecret calls; `ok` is true iff both are non-empty.
    readSecret(QStringLiteral("rpcUser"), [this, cb](QString user, bool ok1) {
        readSecret(QStringLiteral("rpcPass"),
            [cb, user, ok1](QString pass, bool ok2) {
                if (cb) cb(user, pass, ok1 && ok2);
            });
    });
}

void SettingsStore::storeRpcCredentials(
    const QString& user, const QString& pass,
    std::function<void(bool)> cb)
{
    writeSecret(QStringLiteral("rpcUser"), user, [this, pass, cb](bool ok1) {
        writeSecret(QStringLiteral("rpcPass"), pass,
            [cb, ok1](bool ok2) { if (cb) cb(ok1 && ok2); });
    });
}

// ── Import / export ─────────────────────────────────────────────────

QByteArray SettingsStore::exportAsJson() const
{
    // Flat { "<fullKey>": <value> } — excludes [secrets/*].
    QJsonObject doc;
    QSettings s;
    for (const QString& key : s.allKeys()) {
        if (key.startsWith(QStringLiteral("secrets/"))) continue;
        const QVariant v = s.value(key);
        doc.insert(key, QJsonValue::fromVariant(v));
    }
    return QJsonDocument(doc).toJson(QJsonDocument::Indented);
}

bool SettingsStore::importFromJson(const QByteArray& doc, QString* errorOut)
{
    QJsonParseError pe{};
    const QJsonDocument j = QJsonDocument::fromJson(doc, &pe);
    if (pe.error != QJsonParseError::NoError || !j.isObject()) {
        if (errorOut != nullptr) *errorOut = pe.errorString();
        return false;
    }
    QSettings s;
    for (const QString& key : j.object().keys()) {
        if (key.startsWith(QStringLiteral("secrets/"))) continue;
        s.setValue(key, j.object().value(key).toVariant());
        emit changed(key);
    }
    return true;
}
