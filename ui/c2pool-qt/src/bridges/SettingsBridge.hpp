// SettingsBridge — exposes a subset of SettingsStore to JS over
// QtWebChannel so the embedded Explorer / PPLNS View bundles (and
// their plugins) can persist view state into the same native
// SettingsStore that owns launch config.
//
// Per frstrtr/the/docs/c2pool-qt-hybrid-architecture.md §4.3 + §5
// (division of labour). Scope is restricted to view state and
// plugin config by a key allow-list — native-only state (launch
// config, window geometry, active profile) is read-only or
// forbidden to JS.

#pragma once

#include <QObject>
#include <QString>

class SettingsStore;

class SettingsBridge : public QObject {
    Q_OBJECT
public:
    /** Borrows SettingsStore; ownership stays in main(). */
    explicit SettingsBridge(SettingsStore* store, QObject* parent = nullptr);

    /** Return a JSON-encoded value for the key, or "" on miss /
     *  disallowed key. JS wrappers call JSON.parse on the result;
     *  an empty string signals "use your default". */
    Q_INVOKABLE QString getSetting(const QString& key) const;

    /** Set a value — `valueJson` must be valid JSON (strings double-
     *  quoted, etc.). Silently refuses keys outside the allow-list.
     *  Emits settingChanged on success. */
    Q_INVOKABLE void setSetting(const QString& key, const QString& valueJson);

    /** Read-only accessor for the native active profile. JS bundles
     *  use this to bind the coin descriptor — writing is reserved
     *  for the native connection-profile UI (step 10). */
    Q_INVOKABLE QString getActiveProfile() const;

signals:
    /** Mirrors SettingsStore::changed for keys within the allow-list.
     *  JS subscribers can react without polling. */
    void settingChanged(const QString& key, const QString& valueJson);
    /** Mirrors SettingsStore::profileChanged. */
    void profileChanged(const QString& newProfile);

private:
    /** Return true iff `key` matches one of the documented allow-list
     *  patterns: sharechain.view.*, pplns.view.*, explorer.plugins.*. */
    static bool isAllowedForWrite(const QString& key);

    /** JS uses dot-separated keys ("sharechain.view.cellSize");
     *  SettingsStore / QSettings uses slash-separated paths
     *  ("sharechain/view/cellSize"). */
    static QString toStorePath(const QString& jsKey);
    static QString toJsKey(const QString& storePath);

    SettingsStore* store_;
};
