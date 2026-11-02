// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KATs for slice S2 of the c2wallet-qt inject scheduler: the Qt Network
// transport (QtNodeApi) against a local QTcpServer fake node, the scheduler
// core driven over it, and an end-to-end run of the c2wallet-qt-schedd binary
// (QProcess) against the same fake node. Loopback only; no real node, no
// production host. The fake speaks the master node's reply shapes
// (tx-inject-status, getblockchaininfo incl. an optional bestchainlock,
// getrawmempool, getmempoolentry, getblock?height=, getblockhash as a bare
// JSON string, the token-gated submit and the two-phase config apply).

#include "../sched/ChainView.hpp"
#include "../sched/Clock.hpp"
#include "../sched/InjectQueue.hpp"
#include "../sched/NodeApi.hpp"
#include "../sched/QtNodeApi.hpp"
#include "../sched/Runner.hpp"
#include "../sched/Scheduler.hpp"

#include "Digest.hpp"
#include "ValidateSeam.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QProcessEnvironment>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QTimer>
#include <QUrlQuery>

#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <sys/stat.h>

using namespace c2w::companion::sched;
namespace art = c2w::artifact;

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                                                                   \
    do {                                                                                   \
        if (cond) { ++g_pass; }                                                            \
        else { ++g_fail; std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); }  \
    } while (0)

static const char* kToken = "SCHEDD-QT-KAT-TOKEN-0123456789abcdef0123456789";

static bool leaks_token(const QByteArray& s)
{
    const QByteArray tok(kToken);
    for (int i = 0; i + 20 <= tok.size(); ++i)
        if (s.contains(tok.mid(i, 20))) return true;
    return false;
}

static int count_of(const QByteArray& hay, const QByteArray& needle)
{
    int n = 0;
    for (qsizetype p = hay.indexOf(needle); p >= 0; p = hay.indexOf(needle, p + 1)) ++n;
    return n;
}

// ── a structurally valid signed legacy tx (the scheduler never runs scripts) ─

static void put_le(std::vector<uint8_t>& o, uint64_t v, int n)
{
    for (int i = 0; i < n; ++i) o.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xff));
}

static std::string make_tx(uint32_t seed)
{
    std::vector<uint8_t> t;
    put_le(t, 2, 4);
    t.push_back(1);
    const std::vector<uint8_t> pre = {static_cast<uint8_t>(seed), static_cast<uint8_t>(seed >> 8), 0x51};
    const art::Hash32 h = art::sha256(pre);
    t.insert(t.end(), h.begin(), h.end());
    put_le(t, 0, 4);
    t.push_back(106);
    for (int k = 0; k < 106; ++k) t.push_back(static_cast<uint8_t>(0x44 + ((seed + k) % 3)));
    put_le(t, 0xffffffffu, 4);
    t.push_back(1);
    put_le(t, 100000, 8);
    const uint8_t spk[] = {0x76, 0xa9, 0x14, 0x20, 0xcb, 0x5c, 0x22, 0xb1, 0xe4, 0xd5, 0x94, 0x7e, 0x5c,
                           0x11, 0x2c, 0x76, 0x96, 0xb5, 0x1a, 0xd9, 0xaf, 0x3c, 0x61, 0x88, 0xac};
    t.push_back(sizeof(spk));
    t.insert(t.end(), spk, spk + sizeof(spk));
    put_le(t, 0, 4);
    return art::to_hex(t);
}

// ── a minimal HTTP/1.1 server on 127.0.0.1 ──────────────────────────────────

struct HttpReq {
    QByteArray method, target, path, body;
    QUrlQuery query;
    std::map<QByteArray, QByteArray> headers; // lower-case names
};

struct HttpResp {
    int status = 200;
    QByteArray body;
    QByteArray extra_headers; // "Name: value\r\n" lines
    bool hang = false;        // never answer
};

class FakeHttp {
public:
    std::function<HttpResp(const HttpReq&)> handler;
    std::vector<HttpReq> log;

    bool listen()
    {
        QObject::connect(&server_, &QTcpServer::newConnection, [this] {
            while (QTcpSocket* s = server_.nextPendingConnection()) {
                QObject::connect(s, &QTcpSocket::readyRead, [this, s] { on_data(s); });
                QObject::connect(s, &QTcpSocket::disconnected, s, [this, s] {
                    bufs_.erase(s);
                    s->deleteLater();
                });
            }
        });
        return server_.listen(QHostAddress::LocalHost, 0);
    }
    quint16 port() const { return server_.serverPort(); }
    std::string url() const { return "http://127.0.0.1:" + std::to_string(port()); }

private:
    void on_data(QTcpSocket* s)
    {
        QByteArray& buf = bufs_[s];
        buf += s->readAll();
        for (;;) {
            const qsizetype end = buf.indexOf("\r\n\r\n");
            if (end < 0) return;
            const QList<QByteArray> lines = buf.left(end).split('\n');
            HttpReq r;
            const QList<QByteArray> first = lines.value(0).trimmed().split(' ');
            r.method = first.value(0);
            r.target = first.value(1);
            const qsizetype q = r.target.indexOf('?');
            r.path = q < 0 ? r.target : r.target.left(q);
            if (q >= 0) r.query = QUrlQuery(QString::fromLatin1(r.target.mid(q + 1)));
            qsizetype length = 0;
            for (int i = 1; i < lines.size(); ++i) {
                const QByteArray l = lines[i].trimmed();
                const qsizetype colon = l.indexOf(':');
                if (colon <= 0) continue;
                const QByteArray name = l.left(colon).trimmed().toLower();
                const QByteArray value = l.mid(colon + 1).trimmed();
                r.headers[name] = value;
                if (name == "content-length") length = value.toLongLong();
            }
            if (buf.size() < end + 4 + length) return;
            r.body = buf.mid(end + 4, length);
            buf.remove(0, end + 4 + length);
            log.push_back(r);
            const HttpResp resp = handler ? handler(r) : HttpResp{404, "{\"error\":\"no handler\"}", {}, false};
            if (resp.hang) continue;
            QByteArray out = "HTTP/1.1 " + QByteArray::number(resp.status) + " X\r\nContent-Type: application/json\r\n" +
                             "Content-Length: " + QByteArray::number(resp.body.size()) + "\r\n" + resp.extra_headers +
                             "\r\n" + resp.body;
            s->write(out);
        }
    }

    // Declared before the server: the server's destructor deletes the client
    // sockets, whose disconnected() handlers still touch the buffers.
    std::map<QTcpSocket*, QByteArray> bufs_;
    QTcpServer server_;
};

static HttpResp json_resp(int status, const QJsonObject& o)
{
    return HttpResp{status, QJsonDocument(o).toJson(QJsonDocument::Compact), {}, false};
}

// ── a DASH-like fake node over FakeHttp ─────────────────────────────────────

struct DashFake {
    FakeHttp http;
    int64_t tip = 2565300;
    bool enabled = true, wired = true;
    std::optional<int64_t> chainlock;   // bestchainlock height (exposed when set)
    std::set<QByteArray> mempool;       // txids
    std::map<QByteArray, int64_t> time_added;
    std::map<int64_t, std::vector<QByteArray>> blocks; // height -> txids
    QByteArray nonce;
    int submits = 0, applies = 0;
    int64_t boot = SystemClock().now_unix() - 100000; // /uptime base (a restart resets it)

    // The process restarts: empty mempool, /uptime from zero, the arm as the
    // unit flag leaves it; wired stays true (a fresh process publishes).
    void restart(bool unit_flag_arm)
    {
        mempool.clear();
        boot = SystemClock().now_unix();
        enabled = unit_flag_arm;
        wired = true;
    }

    static QByteArray hash_at(int64_t h)
    {
        char b[65];
        std::snprintf(b, sizeof(b), "%064llx", static_cast<unsigned long long>(h) * 7919ULL + 13);
        return QByteArray(b);
    }
    static QByteArray txid_of(const QByteArray& raw)
    {
        return QByteArray::fromStdString(art::crossgap_txid(raw.toStdString()));
    }
    bool in_blocks(const QByteArray& txid) const
    {
        for (const auto& b : blocks)
            for (const auto& t : b.second)
                if (t == txid) return true;
        return false;
    }
    void mine(const std::vector<QByteArray>& txids = {})
    {
        ++tip;
        blocks[tip] = txids;
        for (const auto& t : txids) mempool.erase(t);
    }

    HttpResp handle(const HttpReq& r)
    {
        if (r.method == "GET" && r.path == "/api/tx-inject-status") {
            QJsonObject pool{{"entries", static_cast<int>(mempool.size())}, {"bytes", 0}, {"max_entries", 1024},
                             {"max_total_bytes", 400000}, {"max_tx_bytes", 100000}};
            QJsonObject local{{"count_refused", 0}, {"bytes_refused", 0}, {"in_window", 0}, {"bytes_in_window", 0}};
            QJsonObject caps{{"max_per_window", 200}, {"max_bytes_per_window", 8388608}, {"window_sec", 60}};
            return json_resp(200, QJsonObject{{"wired", wired}, {"enabled", enabled}, {"updated_at", 1}, {"pool", pool},
                                              {"rate_limit", QJsonObject{{"local", local}, {"peers", local}, {"caps", caps}}}});
        }
        if (r.method == "GET" && r.path == "/uptime")
            return HttpResp{200, QByteArray::number(static_cast<qint64>(SystemClock().now_unix() - boot)), {}, false};
        if (r.method == "GET" && r.path == "/api/explorer/getblockchaininfo") {
            QJsonObject o{{"chain", "main"}, {"synced", true}, {"blocks", static_cast<qint64>(tip)},
                          {"headers", static_cast<qint64>(tip)}, {"bestblockhash", QString::fromLatin1(hash_at(tip))}};
            if (chainlock)
                o["bestchainlock"] = QJsonObject{{"height", static_cast<qint64>(*chainlock)},
                                                 {"blockhash", QString::fromLatin1(hash_at(*chainlock))}};
            return json_resp(200, o);
        }
        if (r.method == "GET" && r.path == "/api/explorer/getrawmempool") {
            QJsonArray a;
            for (const auto& t : mempool) a.append(QString::fromLatin1(t));
            return HttpResp{200, QJsonDocument(a).toJson(QJsonDocument::Compact), {}, false};
        }
        if (r.method == "GET" && r.path == "/api/explorer/getmempoolentry") {
            const QByteArray txid = r.query.queryItemValue("txid").toLatin1();
            if (!mempool.count(txid)) return json_resp(200, QJsonObject{{"error", "Transaction not in mempool"}});
            return json_resp(200, QJsonObject{{"txid", QString::fromLatin1(txid)},
                                              {"time_added", static_cast<qint64>(time_added[txid])}, {"size", 200}});
        }
        if (r.method == "GET" && r.path == "/api/explorer/getblock") {
            const int64_t h = r.query.queryItemValue("height").toLongLong();
            if (h < 1 || h > tip) return json_resp(200, QJsonObject{{"error", "height out of range"}});
            QJsonArray txs;
            txs.append(QJsonObject{{"txid", QString(64, QLatin1Char('c'))}});
            for (const auto& t : blocks[h]) txs.append(QJsonObject{{"txid", QString::fromLatin1(t)}});
            return json_resp(200, QJsonObject{{"hash", QString::fromLatin1(hash_at(h))}, {"height", static_cast<qint64>(h)},
                                              {"tx", txs}, {"nTx", txs.size()}});
        }
        if (r.method == "GET" && r.path == "/api/explorer/getblockhash") {
            const int64_t h = r.query.queryItemValue("height").toLongLong();
            if (h < 1 || h > tip) return json_resp(200, QJsonObject{{"error", "height above tip"}});
            return HttpResp{200, "\"" + hash_at(h) + "\"", {}, false}; // a bare JSON string, as the DASH hook serves it
        }
        if (r.method == "POST" && r.path == "/api/tx-inject/submit") {
            ++submits;
            const QJsonObject b = QJsonDocument::fromJson(r.body).object();
            if (b.value("control_token").toString() != QLatin1String(kToken))
                return json_resp(403, QJsonObject{{"ok", false}, {"cause", "missing or invalid control token"}});
            const QByteArray txid = txid_of(b.value("raw_tx").toString().toLatin1());
            const QString t = QString::fromLatin1(txid);
            if (!enabled) return json_resp(409, QJsonObject{{"ok", false}, {"cause", "inject-disabled"}, {"txid", t}, {"armed", false}});
            if (mempool.count(txid))
                return json_resp(422, QJsonObject{{"ok", false}, {"cause", "inject-already-known"}, {"txid", t}, {"armed", true}});
            if (in_blocks(txid))
                return json_resp(422, QJsonObject{{"ok", false}, {"cause", "inject-already-confirmed"}, {"txid", t}, {"armed", true}});
            mempool.insert(txid);
            time_added[txid] = SystemClock().now_unix();
            return json_resp(200, QJsonObject{{"ok", true}, {"cause", "ok"}, {"txid", t}, {"armed", true}});
        }
        if (r.method == "POST" && r.path == "/api/config/apply") {
            ++applies;
            const QJsonObject b = QJsonDocument::fromJson(r.body).object();
            if (b.value("control_token").toString() != QLatin1String(kToken))
                return json_resp(403, QJsonObject{{"status", "no_token"}, {"applied", false}});
            const QString v = b.value("changes").toObject().value("embedded.tx_inject").toString();
            if (!b.contains("money_nonce")) {
                nonce = "0123456789abcdef0123456789abcdef";
                return json_resp(200, QJsonObject{{"status", "need_confirm"}, {"need_confirm", true},
                                                  {"money_nonce", QString::fromLatin1(nonce)},
                                                  {"money_keys", QJsonArray{"embedded.tx_inject"}}, {"applied", false}});
            }
            if (!nonce.isEmpty() && b.value("money_nonce").toString().toLatin1() == nonce) {
                nonce.clear();
                enabled = v == QLatin1String("true");
                return json_resp(200, QJsonObject{{"status", "applied"}, {"applied", true},
                                                  {"applied_keys", QJsonArray{"embedded.tx_inject"}}});
            }
            return json_resp(409, QJsonObject{{"status", "money_gate"}, {"applied", false}});
        }
        return json_resp(404, QJsonObject{{"error", "no route"}});
    }

    bool start()
    {
        http.handler = [this](const HttpReq& r) { return handle(r); };
        return http.listen();
    }
};

static std::string write_file(const QString& path, const QByteArray& content, int mode)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return {};
    f.write(content);
    f.close();
    ::chmod(path.toLocal8Bit().constData(), static_cast<mode_t>(mode));
    return path.toStdString();
}

static QByteArray read_all(const QString& path)
{
    QFile f(path);
    return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
}

// ── Q1-Q9: the transport ────────────────────────────────────────────────────

static void q_transport()
{
    FakeHttp http;
    CHECK(http.listen(), "Q0: fake node listens on 127.0.0.1");
    http.handler = [](const HttpReq& r) -> HttpResp {
        if (r.path == "/hang") return HttpResp{200, {}, {}, true};
        if (r.path == "/redirect") return HttpResp{302, "{}", "Location: /target\r\n", false};
        if (r.path == "/target") return HttpResp{200, "{\"reached\":true}", {}, false};
        if (r.path == "/refuse") return json_resp(422, QJsonObject{{"ok", false}, {"cause", "inject-script-invalid"}});
        if (r.path == "/hash") return HttpResp{200, "\"00000000000000aa\"", {}, false};
        return json_resp(200, QJsonObject{{"echo", QString::fromLatin1(r.body)}});
    };
    std::string why;

    // Q9: the URL rule is enforced at construction.
    CHECK(!QtNodeApi::create("http://10.0.0.5:8080", why) && !QtNodeApi::create("https://127.0.0.1:8080", why) &&
              !QtNodeApi::create("http://node.example:8080", why),
          "Q9: non-loopback / TLS / named host refused");

    // Q8: a proxy in the environment is ignored (NoProxy).
    qputenv("http_proxy", "http://127.0.0.1:1");
    qputenv("HTTP_PROXY", "http://127.0.0.1:1");
    qputenv("all_proxy", "http://127.0.0.1:1");
    auto api = QtNodeApi::create(http.url(), why, 2000);
    CHECK(api != nullptr, "Q1: loopback URL accepted");
    if (!api) return;

    HttpReply g = api->get("/api/tx-inject-status");
    CHECK(g.transport_ok && g.status == 200 && g.body.find("echo") != std::string::npos,
          "Q1/Q8: GET reaches the node directly (proxy env ignored)");
    CHECK(!http.log.empty() && http.log.back().method == "GET" && http.log.back().target == "/api/tx-inject-status",
          "Q1: method and path as given");
    bool forwarded = false;
    for (const auto& h : http.log.back().headers)
        if (h.first.startsWith("x-forwarded") || h.first == "forwarded" || h.first == "x-real-ip") forwarded = true;
    CHECK(!forwarded, "Q1: no X-Forwarded-* / Forwarded / X-Real-IP header (the node's is_direct_local guard)");

    const std::string body = "{\"control_token\":\"" + std::string(kToken) + "\",\"raw_tx\":\"00\"}";
    HttpReply p = api->post_json("/api/tx-inject/submit", body);
    const HttpReq& pr = http.log.back();
    CHECK(p.transport_ok && p.status == 200 && pr.method == "POST" && pr.body == QByteArray::fromStdString(body),
          "Q2: POST body arrives byte-exact");
    CHECK(pr.headers.count("content-type") && pr.headers.at("content-type") == "application/json",
          "Q2: Content-Type: application/json");
    CHECK(count_of(pr.body, kToken) == 1, "Q2: the token travels once, in the body only");
    CHECK(!leaks_token(pr.target) && !pr.headers.count("authorization"), "Q2: never in the URL or an auth header");

    HttpReply r422 = api->get("/refuse");
    CHECK(r422.transport_ok && r422.status == 422 && r422.body.find("inject-script-invalid") != std::string::npos,
          "Q3: a 4xx keeps transport_ok, the status and the body");

    HttpReply h = api->get("/hash");
    CHECK(h.transport_ok && h.body == "\"00000000000000aa\"", "Q4: a bare JSON string body passes through verbatim");

    const size_t before = http.log.size();
    HttpReply rd = api->get("/redirect");
    CHECK(rd.transport_ok && rd.status == 302 && http.log.size() == before + 1,
          "Q5: a redirect is returned, never followed");

    QElapsedTimer t;
    t.start();
    HttpReply hang = api->get("/hang");
    const qint64 ms = t.elapsed();
    CHECK(!hang.transport_ok && hang.error.find("timeout") != std::string::npos && ms >= 1900 && ms < 6000,
          "Q6: no reply -> transport error after the per-request timeout");

    QTcpServer dead;
    dead.listen(QHostAddress::LocalHost, 0);
    const quint16 dead_port = dead.serverPort();
    dead.close();
    auto down = QtNodeApi::create("http://127.0.0.1:" + std::to_string(dead_port), why, 2000);
    HttpReply refused = down->get("/api/tx-inject-status");
    CHECK(!refused.transport_ok && !refused.error.empty(), "Q7: connection refused -> transport error");

    // Stop handling (daemon SIGTERM): no new request; an in-flight GET is
    // aborted; an in-flight POST is left to finish within its timeout.
    {
        bool stop = true;
        auto s2 = QtNodeApi::create(http.url(), why, 2000);
        s2->set_stop_check([&stop] { return stop; });
        const size_t n0 = http.log.size();
        HttpReply refused2 = s2->get("/api/tx-inject-status");
        CHECK(!refused2.transport_ok && refused2.error.find("not sent") != std::string::npos && http.log.size() == n0,
              "L2: stop requested -> the request is not sent");
        stop = false;
        QTimer::singleShot(300, [&stop] { stop = true; });
        QElapsedTimer st;
        st.start();
        HttpReply aborted = s2->get("/hang");
        CHECK(!aborted.transport_ok && aborted.error.find("aborted") != std::string::npos && st.elapsed() < 1500,
              "L2: an in-flight GET is aborted promptly on stop");
        stop = false;
        QTimer::singleShot(300, [&stop] { stop = true; });
        st.restart();
        HttpReply post_hang = s2->post_json("/hang", "{}");
        CHECK(!post_hang.transport_ok && post_hang.error.find("timeout") != std::string::npos && st.elapsed() >= 1900,
              "L2: an in-flight POST is not cut by the stop (it ends at its own timeout)");
    }

    // The ChainView over the real transport: the bare-string getblockhash.
    http.handler = [](const HttpReq&) { return HttpResp{200, "\"" + QByteArray(64, 'b') + "\"", {}, false}; };
    ChainView view(*api);
    std::string err;
    const auto bh = view.block_hash(5, err);
    CHECK(bh && *bh == std::string(64, 'b'), "Q4: ChainView parses getblockhash's bare string over QtNodeApi");

    qunsetenv("http_proxy");
    qunsetenv("HTTP_PROXY");
    qunsetenv("all_proxy");
}

// ── Q10: one scheduler tick over the real transport ─────────────────────────

struct CaptureSink : JournalSink {
    std::string all;
    void line(const std::string& t) override { all += t + "\n"; }
};

static void q_scheduler_over_qt(const QString& dir)
{
    DashFake node;
    CHECK(node.start(), "Q10: fake DASH node listens");
    const std::string tok = write_file(dir + "/q10.token", QByteArray(kToken) + "\n", 0600);
    Queue q;
    q.node.url = node.http.url();
    q.node.token_file = tok;
    EnqueueRequest req;
    req.hex_text = make_tx(10) + "\n";
    req.hex_path = "q10.hex";
    req.explicit_h0 = 2565145;
    const EnqueueResult er = enqueue(q, req, SystemClock().now_unix());
    CHECK(er.ok, "Q10: enqueue (bare hex + explicit h0)");
    std::string why;
    auto api = QtNodeApi::create(q.node.url, why);
    SystemClock clock;
    CaptureSink sink;
    Scheduler s(q, *api, clock, sink);
    const TickReport r = s.tick();
    CHECK(r.submits == 1 && q.items[0].state == State::Admitted, "Q10: tick over QtNodeApi -> submitted, admitted");
    QByteArray submit_body;
    for (const auto& lr : node.http.log)
        if (lr.path == "/api/tx-inject/submit") submit_body = lr.body;
    CHECK(count_of(submit_body, kToken) == 1, "Q10: token exactly once in the submit body");
    CHECK(!leaks_token(QByteArray::fromStdString(queue_to_json(q))) && !leaks_token(QByteArray::fromStdString(sink.all)),
          "Q10: token in neither the queue nor the journal");
    s.tick();
    CHECK(q.items[0].state == State::IsHold && q.items[0].why.find("rides after") != std::string::npos,
          "Q10: next tick sees it in the mempool -> is_hold with the ride ETA");
}

// ── Q11: the daemon binary end to end ───────────────────────────────────────

struct Proc {
    int rc = -1;
    QByteArray out, err;
};

static QStringList g_all_args;

static Proc schedd(const QStringList& args, const QProcessEnvironment& env)
{
    g_all_args += args;
    QProcess p;
    p.setProgram(QStringLiteral(C2WALLET_SCHEDD_BIN));
    p.setArguments(args);
    p.setProcessEnvironment(env);
    p.start();
    Proc r;
    if (!p.waitForStarted(10000)) return r;
    QElapsedTimer t;
    t.start();
    // Serve the fake node from this thread while the child runs.
    while (p.state() != QProcess::NotRunning && t.elapsed() < 120000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        p.waitForFinished(5);
    }
    if (p.state() != QProcess::NotRunning) {
        p.kill();
        p.waitForFinished(2000);
        return r;
    }
    r.rc = p.exitStatus() == QProcess::NormalExit ? p.exitCode() : -2;
    r.out = p.readAllStandardOutput();
    r.err = p.readAllStandardError();
    return r;
}

static void q_daemon_end_to_end(const QString& dir)
{
    DashFake node;
    CHECK(node.start(), "Q11: fake DASH node listens");
    const QString tok = dir + "/control.token";
    write_file(tok, QByteArray(kToken) + "\n", 0600);
    const QString queue = dir + "/data/c2wallet-qt/companion/queue.json";
    const std::string phex = make_tx(1101), chex = make_tx(1102);
    const QString ptx = QString::fromStdString(art::crossgap_txid(phex));
    const QString ctx = QString::fromStdString(art::crossgap_txid(chex));
    write_file(dir + "/parent.hex", QByteArray::fromStdString(phex + "\n"), 0644);
    write_file(dir + "/child.hex", QByteArray::fromStdString(chex + "\n"), 0644);

    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert("XDG_DATA_HOME", dir + "/xdg");
    env.insert("http_proxy", "http://127.0.0.1:1"); // ignored by the transport
    const QStringList base = {"--queue", queue};
    QByteArray all_output;
    auto run = [&](const QStringList& a) {
        Proc p = schedd(base + a, env);
        all_output += p.out + p.err;
        return p;
    };

    Proc p = run({"--token", kToken, "status"});
    CHECK(p.rc == 2 && p.err.contains("--token-file"), "Q11: --token VALUE is a usage error (exit 2)");
    all_output.clear(); // that run carried the token in argv on purpose; it is not counted below
    g_all_args.clear();

    p = run({"--node-url", QString::fromStdString(node.http.url()), "--token-file", tok, "init"});
    CHECK(p.rc == 0 && p.out.contains("(created)") && p.out.contains("readable by this user"),
          "Q11: init creates the queue and checks the token file without printing it");
    struct stat st {};
    CHECK(::stat(queue.toLocal8Bit().constData(), &st) == 0 && (st.st_mode & 0777) == 0600, "Q11: queue file mode 0600");
    const QByteArray fresh = read_all(queue);
    CHECK(fresh.contains("\"auto_arm\": false") && fresh.contains("\"consented_at\": null"),
          "Q11: a new queue never defaults to auto-arm");

    p = run({"add", "--hex", dir + "/parent.hex", "--h0", "2565145", "--label", "parent"});
    CHECK(p.rc == 0 && p.out.contains("submit at tip >= 2565244"), "Q11: add parent (bare hex, explicit h0)");
    p = run({"add", "--hex", dir + "/child.hex", "--h0", "2565145", "--label", "child", "--after-parent", ptx + ":1"});
    CHECK(p.rc == 0 && p.out.contains("final (ChainLocked"), "Q11: add child with --after-parent TXID:N");

    p = run({"arm-policy", "--auto-arm", "yes"});
    CHECK(p.rc == 2 && p.err.contains("--consent"), "Q11: auto-arm without a consent text refused");
    p = run({"arm-policy", "--auto-arm", "yes", "--consent", "hotel queue: operator consent recorded 2026-11-02"});
    const QByteArray armed = read_all(queue);
    CHECK(p.rc == 0 && armed.contains("\"auto_arm\": true") && armed.contains("\"auto_disarm_when_idle\": false") &&
              armed.contains("\"consent_text\": \"hotel queue: operator consent recorded 2026-11-02\"") &&
              !armed.contains("\"consented_at\": null"),
          "Q11: consent recorded with timestamp and text; auto-disarm stays off");

    p = run({"run", "--once"});
    CHECK(p.rc == 0 && node.submits == 1 && node.mempool.count(ptx.toLatin1()) == 1,
          "Q11: run --once submits the parent only (the child waits for a final parent)");
    CHECK(p.out.contains("runner: start") && p.out.contains("token file usable"), "Q11: runner start lines");

    node.mine({ptx.toLatin1()});
    p = run({"run", "--once"});
    CHECK(p.rc == 0 && node.submits == 1, "Q11: parent at 1 confirmation, no ChainLock field -> child still waits");
    p = run({"list"});
    CHECK(p.rc == 0 && p.out.contains("ChainLock not exposed by node; waiting for 2 confirmations"),
          "Q11: list shows why the child waits");
    node.mine();
    p = run({"run", "--once"});
    CHECK(p.rc == 0 && node.submits == 2 && node.mempool.count(ctx.toLatin1()) == 1,
          "Q11: 2 confirmations -> the child is submitted");
    p = run({"run", "--once"});
    p = run({"list"});
    CHECK(p.rc == 0 && p.out.contains("is_hold") && p.out.contains("IS-hold ends ~"), "Q11: list shows the IS-hold ETA");
    p = run({"show", ctx.left(12)});
    CHECK(p.rc == 0 && p.out.contains("IS-hold until") && p.out.contains("after parent"), "Q11: show by txid prefix");

    p = run({"status"});
    CHECK(p.rc == 1 && p.out.contains("ARM     standing") && p.out.contains("no runner holds the queue"),
          "Q11: status: standing arm; live items without a runner -> exit 1");

    {
        QueueLock held;
        std::string why;
        held.acquire(runner_lock_base(queue.toStdString()), false, why);
        p = run({"run", "--once"});
        CHECK(p.rc == 4 && p.err.contains("lock held"), "Q11: a second runner exits 4 (lock held)");
    }

    // The node restarts without its standing arm: mempool empty, enabled=false,
    // /uptime from zero (wired stays true, as on the real node).
    node.restart(false);
    p = run({"run", "--once"});
    CHECK(p.rc == 0 && p.out.contains("ALERT disarmed") && read_all(queue).contains("\"state\": \"dropped\""),
          "Q11: disarm after a restart detected and alerted; the child left the emptied mempool -> dropped");
    CHECK(node.applies == 0, "Q11: no arm while nothing is ready to submit");
    p = run({"run", "--once"});
    const QByteArray after = read_all(queue);
    CHECK(p.rc == 0 && node.applies == 2 && node.enabled && after.contains("ARMED by scheduler"),
          "Q11: consented auto-arm on the resubmit: two-phase apply, node armed");
    CHECK(node.mempool.count(ctx.toLatin1()) == 1 && after.contains("resubmit 1/3"),
          "Q11: the dropped child is resubmitted after the re-arm");

    // A deliberate runtime disarm (the node keeps running): never re-armed
    // until the operator records consent again.
    const std::string lhex = make_tx(1103);
    write_file(dir + "/late.hex", QByteArray::fromStdString(lhex + "\n"), 0644);
    const QByteArray ltx = QByteArray::fromStdString(art::crossgap_txid(lhex));
    node.enabled = false;
    p = run({"add", "--hex", dir + "/late.hex", "--h0", "2565145", "--label", "late"});
    p = run({"run", "--once"});
    CHECK(p.rc == 0 && p.out.contains("ALERT operator_disarm") && node.applies == 2 && !node.mempool.count(ltx),
          "Q11: deliberate disarm (uptime continuous) -> operator_disarm, no apply, the new item waits");
    p = run({"status"});
    CHECK(p.rc == 1 && p.out.contains("AUTO-ARM SUSPENDED") && p.out.contains("; up "),
          "Q11: status shows the suspension and the node uptime");
    p = run({"run", "--once"});
    CHECK(node.applies == 2, "Q11: still no apply on the next run");
    p = run({"arm-policy", "--auto-arm", "yes", "--consent", "hotel queue: resume after maintenance"});
    CHECK(p.rc == 0 && read_all(queue).contains("\"suspended_reason\": null"),
          "Q11: consent recorded again clears the suspension");
    p = run({"run", "--once"});
    CHECK(node.applies == 4 && node.enabled && node.mempool.count(ltx) == 1, "Q11: re-armed and the late item submitted");

    p = run({"pause", ctx.left(16)});
    CHECK(p.rc == 0, "Q11: pause by txid prefix");
    p = run({"rm", ctx.left(16)});
    CHECK(p.rc == 0 && !read_all(queue).contains(ctx.toLatin1()), "Q11: rm of a paused item");

    p = run({"ack-alerts"});
    CHECK(p.rc == 0, "Q11: ack-alerts");

    // The token never left the token file except inside the submit/apply bodies.
    CHECK(!leaks_token(all_output), "Q11: token in no stdout/stderr of any command");
    CHECK(!leaks_token(read_all(queue)), "Q11: token not in the queue file");
    CHECK(!leaks_token(g_all_args.join(' ').toLatin1()), "Q11: token in no argv");
    int bodies = 0, ok_bodies = 0;
    for (const auto& r : node.http.log) {
        if (r.method != "POST") continue;
        ++bodies;
        if (count_of(r.body, kToken) == 1 && !leaks_token(r.target)) ++ok_bodies;
    }
    CHECK(bodies > 0 && bodies == ok_bodies, "Q11: every POST carries the token once, in the body");
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir tmp;
    if (!tmp.isValid()) {
        std::printf("cannot create a temporary directory\n");
        return 2;
    }
    q_transport();
    q_scheduler_over_qt(tmp.path());
    q_daemon_end_to_end(tmp.path());
    std::printf("\n== c2wallet-qt-schedd Qt KATs: %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
