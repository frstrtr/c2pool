#pragma once

#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QObject>
#include <QString>

#include <functional>

class ApiClient : public QObject
{
    Q_OBJECT
public:
    using JsonSuccess = std::function<void(const QJsonDocument&)>;
    using TextSuccess = std::function<void(const QString&)>;
    using Failure = std::function<void(const QString&)>;

    explicit ApiClient(QObject* parent = nullptr);

    void setBaseUrl(const QString& baseUrl);
    QString baseUrl() const;

    void setAuthToken(const QString& token);
    QString authToken() const;

    void getJson(const QString& path, JsonSuccess onSuccess, Failure onFailure);
    void getText(const QString& path, TextSuccess onSuccess, Failure onFailure);
    void postJson(const QString& path, const QJsonObject& body,
                  JsonSuccess onSuccess, Failure onFailure);
    void download(const QString& path, const QString& outputPath, TextSuccess onSuccess, Failure onFailure);

signals:
    void connectionStateChanged(const QString& state);
    void requestFailed(const QString& message);

private:
    QString makeUrl(const QString& path) const;

    QNetworkAccessManager manager_;
    QString baseUrl_;
    QString authToken_;
};
