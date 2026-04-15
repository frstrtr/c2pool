#pragma once

#include <QMap>
#include <QString>
#include <QStringList>
#include <QVariant>

class PageLaunch;

/// Lightweight YAML serializer for the flat c2pool config schema.
///
/// Supports the subset of YAML used by c2pool config files:
///   - Flat key: value pairs (string, int, float, bool)
///   - Simple sequences (key:\n  - item1\n  - item2)
///   - Comments (# ...)
///
/// No yaml-cpp dependency -- keeps the Qt app fully decoupled from the daemon.
class ConfigSerializer
{
public:
    using ConfigMap = QMap<QString, QVariant>;

    /// Parse a flat YAML file into a key-value map.
    /// Lists are stored as QStringList values.
    static ConfigMap loadYaml(const QString& filePath);

    /// Write a key-value map as flat YAML.
    static bool saveYaml(const ConfigMap& config, const QString& filePath);

    /// Extract form state from PageLaunch into a config map.
    static ConfigMap fromPageLaunch(const PageLaunch* page);

    /// Populate PageLaunch form from a config map.
    static void toPageLaunch(const ConfigMap& config, PageLaunch* page);
};
