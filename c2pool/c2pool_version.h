#pragma once

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QDebug>

namespace c2pool
{
    inline std::tuple<int, int, int> version()
    {
        return std::make_tuple(C2POOL_MAJOR, C2POOL_MINOR, C2POOL_PATCH);
    }

    inline std::string version_str()
    {
        return std::to_string(C2POOL_MAJOR) + "." + std::to_string(C2POOL_MINOR) + "." + std::to_string(C2POOL_PATCH);
    }

    inline void check_version()
    {
        QNetworkAccessManager manager;
        QUrl url("https://raw.githubusercontent.com/frstrtr/c2pool/master/version.cfg");
//        QUrl url("https://pastebin.com/raw/v0q2uZRU");

        QNetworkRequest request(url);
        QNetworkReply *reply = manager.get(request);

        std::tuple<int, int, int> actual_version;

        QEventLoop loop;
        QObject::connect(reply, &QNetworkReply::finished, &loop, [&]()
        {
            if (reply->error() == QNetworkReply::NoError)
            {
                std::vector<int> v;
                for (int i = 0; i < 3; i++)
                {
                    auto kv = reply->readLine().split(' ');
                    if (kv.size() == 2)
                    {
                        v.push_back(kv.at(1).toInt());
                    } else
                    {
                        qWarning() << "Can't parse version file";
                        v = {0,0,0};
                        break;
                    }
                }
                actual_version = std::tie(v[0], v[1], v[2]);
            } else
            {
                qDebug() << "Failed to fetch file:" << reply->errorString();
            }

            // Освобождение ресурсов
            reply->deleteLater();
//        a.quit();
            loop.quit();
        });
        loop.exec();

        if (c2pool::version() < actual_version)
        {
            std::string actual_str = std::to_string(get<0>(actual_version)) + "." + std::to_string(get<1>(actual_version)) + "." + std::to_string(get<2>(actual_version));
            qInfo() << "The new version is already on GitHub. Now:" << c2pool::version_str().c_str() << "- actual:" << actual_str.c_str();
        }
    }
}