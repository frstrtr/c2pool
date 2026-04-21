// SettingsStore — typed façade over QSettings (+ QKeychain in step 4).
//
// Public interface per
// frstrtr/the/docs/c2pool-qt-desktop-settings-module.md §5.1. The
// keychain methods (readSecret / writeSecret / loadRpcCredentials /
// storeRpcCredentials) ship here with a QSettings fallback under a
// [secrets/<profile>/<key>] group; step 4 replaces that fallback
// with real qtkeychain calls behind the C2POOL_QT_USE_KEYCHAIN
// compile flag.
//
// Ownership: one process-wide instance, constructed in main.cpp,
// injected into pages via references — not a singleton.

#pragma once

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariant>

#include <functional>

class SettingsStore : public QObject {
    Q_OBJECT
public:
    /** Schema version — bumps on breaking layout changes. */
    static constexpr int kSchemaVersion = 2;

    explicit SettingsStore(QObject* parent = nullptr);

    // ── Schema versioning ───────────────────────────────────────────

    int  schemaVersion() const;
    /** Run any v(n-1)→v(n) migrations; safe to call more than once —
     *  subsequent calls are no-ops. Invoked from main() at startup. */
    void runMigrationsIfNeeded();

    // ── UI ──────────────────────────────────────────────────────────

    QString uiBaseUrl() const;
    void    setUiBaseUrl(const QString& v);
    int     uiRefreshMs() const;
    void    setUiRefreshMs(int v);
    QString uiTheme() const;          // "system" | "light" | "dark"
    void    setUiTheme(const QString& v);

    // ── Window state ────────────────────────────────────────────────

    QByteArray mainWindowGeometry() const;
    void       setMainWindowGeometry(const QByteArray& v);
    QByteArray mainWindowState() const;
    void       setMainWindowState(const QByteArray& v);

    // ── Connection profiles (doc §7) ────────────────────────────────

    QStringList profileNames() const;
    QString     activeProfile() const;
    void        setActiveProfile(const QString& name);
    void        createProfile(const QString& name);
    void        deleteProfile(const QString& name);
    void        renameProfile(const QString& from, const QString& to);

    /** Per-profile launch value read/write — key is the QSettings
     *  sub-key under [profiles/<active>/launch/...]. */
    QVariant launchValue(const QString& key, const QVariant& def = {}) const;
    void     setLaunchValue(const QString& key, const QVariant& v);

    // ── View state: sharechain page ─────────────────────────────────

    int         sharechainCellSize() const;
    void        setSharechainCellSize(int px);
    QStringList sharechainHiddenMiners() const;
    void        setSharechainHiddenMiners(const QStringList& v);

    // ── View state: logs page ───────────────────────────────────────

    QString logsFilterScope() const;
    void    setLogsFilterScope(const QString& v);
    bool    logsAutoScroll() const;
    void    setLogsAutoScroll(bool v);

    // ── View state: mining page ─────────────────────────────────────

    QByteArray miningTableHeaderState() const;
    void       setMiningTableHeaderState(const QByteArray& v);

    // ── Secrets (async — keychain may prompt on macOS) ──────────────

    /** Async. Callback gets (value, ok). In step 3 this reads from a
     *  QSettings fallback group; step 4 switches to qtkeychain when
     *  C2POOL_QT_USE_KEYCHAIN is ON. */
    void readSecret(const QString& key, std::function<void(QString, bool)> cb);
    void writeSecret(const QString& key, const QString& value, std::function<void(bool)> cb);
    void deleteSecret(const QString& key, std::function<void(bool)> cb);

    /** Convenience wrappers — resolve under active profile. */
    void loadRpcCredentials(std::function<void(QString user, QString pass, bool ok)> cb);
    void storeRpcCredentials(const QString& user, const QString& pass,
                             std::function<void(bool)> cb);

    // ── Import / export (secrets excluded) ──────────────────────────

    QByteArray exportAsJson() const;
    bool       importFromJson(const QByteArray& doc, QString* errorOut = nullptr);

signals:
    /** Fired after every setter. Key is the QSettings path
     *  (e.g. "ui/baseUrl", "profiles/default/launch/mode"). */
    void changed(const QString& key);
    /** Fired after setActiveProfile succeeds. */
    void profileChanged(const QString& newActive);
    /** Fired once per actual migration step during
     *  runMigrationsIfNeeded(). */
    void schemaMigrated(int fromVersion, int toVersion);

private:
    QString profileLaunchPath(const QString& profile, const QString& key) const;
    QString secretsKey(const QString& profile, const QString& key) const;
    void    migrateV1ToV2();
};
