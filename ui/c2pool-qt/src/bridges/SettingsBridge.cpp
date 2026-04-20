#include "SettingsBridge.hpp"

#include "../SettingsStore.hpp"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QSettings>

SettingsBridge::SettingsBridge(SettingsStore* store, QObject* parent)
    : QObject(parent), store_(store)
{
    setObjectName(QStringLiteral("settings"));

    // Forward native change signals to JS subscribers — but only
    // for allow-listed keys. Prevents JS from observing writes to
    // native-only state (launch/*, window/*, profiles/*/launch/*).
    connect(store_, &SettingsStore::changed, this, [this](const QString& storePath) {
        const QString jsKey = toJsKey(storePath);
        if (!isAllowedForWrite(jsKey)) return;
        emit settingChanged(jsKey, getSetting(jsKey));
    });
    connect(store_, &SettingsStore::profileChanged, this,
            &SettingsBridge::profileChanged);
}

QString SettingsBridge::getSetting(const QString& key) const
{
    if (!isAllowedForWrite(key)) return QString();  // disallowed → empty
    const QString storePath = toStorePath(key);
    const QVariant v = QSettings{}.value(storePath);
    if (!v.isValid()) return QString();
    // Serialise through QJsonValue → JSON so JS can JSON.parse()
    // regardless of underlying QSettings type (int, bool, string,
    // QStringList, QByteArray-as-string).
    const QJsonValue jv = QJsonValue::fromVariant(v);
    // QJsonDocument needs an object/array at root; wrap scalar in array
    // then strip the brackets to get the bare JSON value.
    const QJsonArray wrap{jv};
    const QByteArray full = QJsonDocument(wrap).toJson(QJsonDocument::Compact);
    // full is e.g. "[5]" or "[\"abc\"]" — strip [ and ].
    if (full.size() >= 2 && full.front() == '[' && full.back() == ']') {
        return QString::fromUtf8(full.mid(1, full.size() - 2));
    }
    return QString::fromUtf8(full);
}

void SettingsBridge::setSetting(const QString& key, const QString& valueJson)
{
    if (!isAllowedForWrite(key)) return;     // silent refusal per doc
    // Parse the incoming JSON. Wrap in array to reuse
    // QJsonDocument::fromJson's object/array root requirement.
    const QByteArray wrapped = '[' + valueJson.toUtf8() + ']';
    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(wrapped, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isArray()
        || doc.array().size() != 1) {
        return;                              // invalid JSON → ignore
    }
    const QVariant v = doc.array().at(0).toVariant();
    const QString storePath = toStorePath(key);
    QSettings{}.setValue(storePath, v);
    // Bridge-driven writes go straight to QSettings (no typed
    // SettingsStore accessor for arbitrary view-state keys), so we
    // fire settingChanged directly. Native writes that go through
    // SettingsStore reach JS via the constructor's forwarder from
    // SettingsStore::changed — so both paths emit this signal.
    emit settingChanged(key, valueJson);
}

QString SettingsBridge::getActiveProfile() const
{
    return store_->activeProfile();
}

// ── allow-list + path translation ────────────────────────────────────

bool SettingsBridge::isAllowedForWrite(const QString& key)
{
    // Documented patterns — dots separating segments.
    return key.startsWith(QStringLiteral("sharechain.view."))
        || key.startsWith(QStringLiteral("pplns.view."))
        || key.startsWith(QStringLiteral("explorer.plugins."));
}

QString SettingsBridge::toStorePath(const QString& jsKey)
{
    return QString(jsKey).replace(QLatin1Char('.'), QLatin1Char('/'));
}

QString SettingsBridge::toJsKey(const QString& storePath)
{
    return QString(storePath).replace(QLatin1Char('/'), QLatin1Char('.'));
}
