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
}