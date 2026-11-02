// SPDX-License-Identifier: AGPL-3.0-or-later
#include "QtRpcApi.hpp"

#include "RpcAuth.hpp"

#include "../sched/Config.hpp" // validate_node_url

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

#include <algorithm>

namespace c2w::companion::scan {

std::unique_ptr<QtRpcApi> QtRpcApi::create(const std::string& url, const std::string& auth_file, std::string& why,
                                           int timeout_ms, int long_timeout_ms)
{
    if (!sched::validate_node_url(url, why)) {
        why = "dashd URL: " + why;
        return nullptr;
    }
    c2w::secure::SecureString probe;
    if (!read_rpc_auth_file(auth_file, probe, why)) return nullptr;
    probe.clear();
    std::string base = url;
    while (!base.empty() && base.back() == '/') base.pop_back();
    if (timeout_ms < 1) timeout_ms = kDefaultTimeoutMs;
    if (long_timeout_ms < timeout_ms) long_timeout_ms = kLongTimeoutMs;
    return std::unique_ptr<QtRpcApi>(new QtRpcApi(std::move(base), auth_file, timeout_ms, long_timeout_ms));
}

QtRpcApi::QtRpcApi(std::string base, std::string auth_file, int timeout_ms, int long_timeout_ms)
    : base_(std::move(base)),
      auth_file_(std::move(auth_file)),
      name_("qt-rpc " + base_),
      timeout_ms_(timeout_ms),
      long_timeout_ms_(long_timeout_ms),
      nam_(std::make_unique<QNetworkAccessManager>())
{
    nam_->setProxy(QNetworkProxy(QNetworkProxy::NoProxy));
    nam_->setRedirectPolicy(QNetworkRequest::ManualRedirectPolicy);
    nam_->setStrictTransportSecurityEnabled(false);
}

QtRpcApi::~QtRpcApi() = default;

RpcReply QtRpcApi::call(const std::string& method, const std::string& params_json)
{
    return request(method, params_json, nullptr, nullptr, timeout_ms_);
}

RpcReply QtRpcApi::call_long(const std::string& method, const std::string& params_json, const CancelCheck& cancelled,
                             const std::function<void()>& on_cancel)
{
    return request(method, params_json, cancelled ? &cancelled : nullptr, &on_cancel, long_timeout_ms_);
}

RpcReply QtRpcApi::request(const std::string& method, const std::string& params_json, const CancelCheck* cancelled,
                           const std::function<void()>* on_cancel, int timeout_ms)
{
    RpcReply out;
    const QUrl url(QString::fromStdString(base_ + "/"), QUrl::StrictMode);
    if (!url.isValid() || url.scheme() != QLatin1String("http")) {
        out.error = "invalid dashd URL";
        return out;
    }
    // The credentials: read now, used for this request, wiped after it.
    c2w::secure::SecureString cred;
    std::string why;
    if (!read_rpc_auth_file(auth_file_, cred, why)) {
        out.error = why;
        return out;
    }
    const c2w::secure::SecureString basic = basic_auth_value(cred);
    cred.clear();
    QByteArray auth("Basic ");
    auth.append(reinterpret_cast<const char*>(basic.bytes()), static_cast<qsizetype>(basic.size()));

    // The method name and the params are ours (built by SourceDashd); the
    // params are already JSON.
    const std::string body = "{\"jsonrpc\":\"1.0\",\"id\":" + std::to_string(next_id_++) + ",\"method\":\"" + method +
                             "\",\"params\":" + params_json + "}";
    QNetworkRequest req(url);
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    req.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    req.setAttribute(QNetworkRequest::CacheSaveControlAttribute, false);
    req.setAttribute(QNetworkRequest::CookieLoadControlAttribute, QNetworkRequest::Manual);
    req.setAttribute(QNetworkRequest::CookieSaveControlAttribute, QNetworkRequest::Manual);
    req.setAttribute(QNetworkRequest::AuthenticationReuseAttribute, QNetworkRequest::Manual);
    req.setHeader(QNetworkRequest::ContentTypeHeader, QByteArrayLiteral("application/json"));
    req.setRawHeader(QByteArrayLiteral("Authorization"), auth);

    QNetworkReply* reply = nam_->post(req, QByteArray(body.data(), static_cast<qsizetype>(body.size())));
    QByteArray data;
    bool timed_out = false, too_large = false, cancel_sent = false;
    QEventLoop loop;
    QTimer guard;
    guard.setSingleShot(true);
    QTimer poll;
    if (cancelled && on_cancel) {
        poll.setInterval(100);
        QObject::connect(&poll, &QTimer::timeout, &loop, [&] {
            if (cancel_sent || !(*cancelled)()) return;
            cancel_sent = true;
            poll.stop();
            // The method's own abort, on a second request; then wait for the
            // original answer (dashd returns it at once), at most 30 s more.
            (*on_cancel)();
            guard.start(std::min(timeout_ms, kDefaultTimeoutMs));
        });
        poll.start();
    }
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
    guard.start(timeout_ms);
    if (!reply->isFinished()) loop.exec(QEventLoop::ExcludeUserInputEvents);
    guard.stop();
    poll.stop();

    const bool aborted = timed_out || too_large;
    if (!aborted) data += reply->readAll();
    const QVariant status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
    if (!aborted && status.isValid()) {
        out.transport_ok = true;
        out.http_status = status.toInt();
        out.body.assign(data.constData(), static_cast<size_t>(data.size()));
    } else if (timed_out) {
        out.error = "no complete reply from dashd within the timeout";
    } else if (too_large) {
        out.error = "dashd reply larger than " + std::to_string(kMaxReplyBytes) + " bytes";
    } else {
        out.error = reply->errorString().toStdString();
    }
    QObject::disconnect(reply, nullptr, &loop, nullptr);
    delete reply;
    // The header bytes are shared with the request's copy: wipe them in place.
    c2w::secure::secure_wipe(const_cast<char*>(auth.constData()), static_cast<size_t>(auth.size()));
    return out;
}

} // namespace c2w::companion::scan
