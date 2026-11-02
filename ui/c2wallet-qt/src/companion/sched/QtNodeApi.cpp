// SPDX-License-Identifier: AGPL-3.0-or-later
#include "QtNodeApi.hpp"

#include "Config.hpp"

#include "../../secure/SecureString.hpp"

#include <QByteArray>
#include <QEventLoop>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QObject>
#include <QString>
#include <QTimer>
#include <QUrl>
#include <QVariant>

namespace c2w::companion::sched {

std::unique_ptr<QtNodeApi> QtNodeApi::create(const std::string& base_url, std::string& why, int timeout_ms)
{
    if (!validate_node_url(base_url, why)) return nullptr;
    std::string base = base_url;
    while (!base.empty() && base.back() == '/') base.pop_back();
    if (timeout_ms < 1) timeout_ms = kDefaultTimeoutMs;
    return std::unique_ptr<QtNodeApi>(new QtNodeApi(std::move(base), timeout_ms));
}

QtNodeApi::QtNodeApi(std::string base, int timeout_ms)
    : base_(std::move(base)),
      name_("qt-network " + base_),
      timeout_ms_(timeout_ms),
      nam_(std::make_unique<QNetworkAccessManager>())
{
    // A per-manager proxy replaces any proxy factory: http_proxy / all_proxy
    // and the system configuration are never consulted.
    nam_->setProxy(QNetworkProxy(QNetworkProxy::NoProxy));
    nam_->setRedirectPolicy(QNetworkRequest::ManualRedirectPolicy);
    nam_->setStrictTransportSecurityEnabled(false);
}

QtNodeApi::~QtNodeApi() = default;

HttpReply QtNodeApi::get(const std::string& path)
{
    return request(false, path, nullptr);
}

HttpReply QtNodeApi::post_json(const std::string& path, const std::string& body)
{
    return request(true, path, &body);
}

HttpReply QtNodeApi::request(bool post, const std::string& path, const std::string* body)
{
    HttpReply out;
    if (path.empty() || path[0] != '/') {
        out.error = "request path must start with '/'";
        return out;
    }
    const QUrl url(QString::fromStdString(base_ + path), QUrl::StrictMode);
    if (!url.isValid() || url.scheme() != QLatin1String("http")) {
        out.error = "invalid request URL";
        return out;
    }

    QNetworkRequest req(url);
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    req.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    req.setAttribute(QNetworkRequest::CacheSaveControlAttribute, false);
    req.setAttribute(QNetworkRequest::CookieLoadControlAttribute, QNetworkRequest::Manual);
    req.setAttribute(QNetworkRequest::CookieSaveControlAttribute, QNetworkRequest::Manual);
    req.setAttribute(QNetworkRequest::AuthenticationReuseAttribute, QNetworkRequest::Manual);

    QByteArray payload;
    if (post) {
        req.setHeader(QNetworkRequest::ContentTypeHeader, QByteArrayLiteral("application/json"));
        payload = QByteArray(body->data(), static_cast<qsizetype>(body->size()));
    }

    QNetworkReply* reply = post ? nam_->post(req, payload) : nam_->get(req);
    QByteArray data;
    bool timed_out = false;
    bool too_large = false;
    QEventLoop loop;
    QTimer guard;
    guard.setSingleShot(true);
    QObject::connect(reply, &QNetworkReply::readyRead, &loop, [&] {
        data += reply->readAll();
        if (data.size() > kMaxReplyBytes) {
            too_large = true;
            reply->abort();
        }
    });
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&guard, &QTimer::timeout, &loop, [&] {
        timed_out = true;
        reply->abort();
    });
    guard.start(timeout_ms_);
    if (!reply->isFinished()) loop.exec(QEventLoop::ExcludeUserInputEvents);
    guard.stop();

    const bool aborted = timed_out || too_large;
    if (!aborted) data += reply->readAll();
    const QVariant status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
    if (!aborted && status.isValid()) {
        out.transport_ok = true;
        out.status = status.toInt();
        out.body.assign(data.constData(), static_cast<size_t>(data.size()));
    } else if (timed_out) {
        out.error = "no complete reply within " + std::to_string(timeout_ms_) + " ms (timeout)";
    } else if (too_large) {
        out.error = "reply larger than " + std::to_string(kMaxReplyBytes) + " bytes";
    } else {
        out.error = reply->errorString().toStdString();
    }
    QObject::disconnect(reply, nullptr, &loop, nullptr);
    delete reply; // drops Qt's reference to the upload buffer
    if (post && !aborted && !payload.isEmpty()) {
        // The request completed: nothing reads the upload buffer any more.
        // Wipe it in place (not through a detaching write).
        c2w::secure::secure_wipe(const_cast<char*>(payload.constData()), static_cast<size_t>(payload.size()));
    }
    return out;
}

} // namespace c2w::companion::sched
