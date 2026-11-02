// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Qt KATs for slice S-C's transports, loopback only (no real dashd or node):
//   Q1 QtRpcApi refuses a non-loopback URL and an unusable credentials file
//   Q2 SourceDashd over QtRpcApi over HTTP: the export equals the in-process
//      scan's; Authorization: Basic from the 0600 file; JSON-RPC 1.0 bodies
//   Q3 HTTP 401 (bad cookie) -> scan-auth-refused
//   Q4 cancel during scantxoutset: QtRpcApi sends scantxoutset "abort" on a
//      second request, the held start returns, scan-cancelled within seconds
//   Q5 cancel during a node scan: QtNodeApi's stop check drops the GET
//   Q6 the c2wallet-qt-schedd binary: scan end to end; --dashd-auth VALUE
//      refused before any request
// The fake dashd answers through FakeDashd (scan_fakes.hpp), the fake node
// through FakeUtxoNode, each behind a minimal HTTP/1.1 server on 127.0.0.1.

#include "../scan/QtRpcApi.hpp"
#include "../scan/SourceC2pool.hpp"
#include "../scan/SourceDashd.hpp"
#include "../sched/QtNodeApi.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QHostAddress>
#include <QProcess>
#include <QProcessEnvironment>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QTimer>

#include <cstdio>
#include <map>

#include <sys/stat.h>
#include <unistd.h>

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                                                                   \
    do {                                                                                   \
        if (cond) { ++g_pass; }                                                            \
        else { ++g_fail; std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); }  \
    } while (0)

#include "scan_fakes.hpp"

using namespace scan_kat;
namespace scan = c2w::companion::scan;

// ── a minimal HTTP/1.1 server that can hold a request and answer it later ───

struct Req {
    QByteArray method, target, body;
    std::map<QByteArray, QByteArray> headers;
};
struct Resp {
    int status = 200;
    QByteArray body;
    bool hold = false; // keep the socket; answer it later with answer()
};

class Http {
public:
    std::function<Resp(const Req&, QTcpSocket*)> handler;
    std::vector<Req> log;

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
    std::string url() const { return "http://127.0.0.1:" + std::to_string(server_.serverPort()); }
    static void answer(QTcpSocket* s, const Resp& r)
    {
        s->write("HTTP/1.1 " + QByteArray::number(r.status) + " X\r\nContent-Type: application/json\r\nContent-Length: " +
                 QByteArray::number(r.body.size()) + "\r\n\r\n" + r.body);
    }

private:
    void on_data(QTcpSocket* s)
    {
        QByteArray& buf = bufs_[s];
        buf += s->readAll();
        for (;;) {
            const qsizetype end = buf.indexOf("\r\n\r\n");
            if (end < 0) return;
            const QList<QByteArray> lines = buf.left(end).split('\n');
            Req r;
            const QList<QByteArray> first = lines.value(0).trimmed().split(' ');
            r.method = first.value(0);
            r.target = first.value(1);
            qsizetype length = 0;
            for (int i = 1; i < lines.size(); ++i) {
                const QByteArray l = lines[i].trimmed();
                const qsizetype colon = l.indexOf(':');
                if (colon <= 0) continue;
                const QByteArray name = l.left(colon).trimmed().toLower();
                r.headers[name] = l.mid(colon + 1).trimmed();
                if (name == "content-length") length = r.headers[name].toLongLong();
            }
            if (buf.size() < end + 4 + length) return;
            r.body = buf.mid(end + 4, length);
            buf.remove(0, end + 4 + length);
            log.push_back(r);
            const Resp resp = handler ? handler(r, s) : Resp{404, "{}", false};
            if (!resp.hold) answer(s, resp);
        }
    }
    std::map<QTcpSocket*, QByteArray> bufs_;
    QTcpServer server_;
};

// dashd: JSON-RPC over Http, answered by FakeDashd; Basic auth checked.
struct DashdHttp {
    Http http;
    FakeDashd logic;
    QByteArray expect_auth;
    bool hold_scan = false;
    QTcpSocket* held = nullptr;
    int aborts = 0;

    bool start()
    {
        http.handler = [this](const Req& r, QTcpSocket* s) -> Resp {
            const auto a = r.headers.find("authorization");
            if (a == r.headers.end() || a->second != expect_auth) return Resp{401, "", false};
            const nj body = nj::parse(r.body.toStdString(), nullptr, false);
            if (!body.is_object()) return Resp{500, "{}", false};
            const std::string method = body.value("method", std::string());
            const nj params = body.value("params", nj::array());
            if (method == "scantxoutset" && params.size() >= 1 && params[0] == "abort") {
                ++aborts;
                if (held) {
                    Http::answer(held, Resp{200, R"({"result":{"success":false},"error":null,"id":1})", false});
                    held = nullptr;
                }
                return Resp{200, R"({"result":true,"error":null,"id":2})", false};
            }
            if (method == "scantxoutset" && hold_scan && params.size() >= 1 && params[0] == "start") {
                held = s;
                return Resp{200, "", true};
            }
            const RpcReply rep = logic.call(method, params.dump());
            return Resp{rep.http_status, QByteArray::fromStdString(rep.body), false};
        };
        return http.listen();
    }
};

struct NodeHttp {
    Http http;
    FakeUtxoNode logic;
    bool hold = false;
    bool start()
    {
        http.handler = [this](const Req& r, QTcpSocket*) -> Resp {
            if (hold && r.target.startsWith("/api/utxo/scan")) return Resp{200, "", true};
            const sched::HttpReply rep = logic.get(r.target.toStdString());
            return Resp{rep.status, QByteArray::fromStdString(rep.body), false};
        };
        return http.listen();
    }
};

static std::string put_file(const QString& dir, const char* name, const std::string& text, mode_t mode)
{
    const std::string path = dir.toStdString() + "/" + name;
    ::unlink(path.c_str());
    FILE* f = std::fopen(path.c_str(), "wb");
    if (f) {
        std::fwrite(text.data(), 1, text.size(), f);
        std::fclose(f);
    }
    ::chmod(path.c_str(), mode);
    return path;
}

static const std::string kCookie = "__cookie__:00112233445566778899aabbccddeeff";

static QByteArray basic_of(const std::string& cred)
{
    return "Basic " + QByteArray::fromStdString(cred).toBase64();
}

static void q1_q2_q3(const QString& dir)
{
    std::printf("[Q1-Q3 QtRpcApi: loopback rule, credentials file, Basic auth, 401]\n");
    const std::string auth = put_file(dir, "dashd.cookie", kCookie + "\n", 0600);
    const std::string loose = put_file(dir, "loose.cookie", kCookie + "\n", 0644);
    std::string why;
    CHECK(!scan::QtRpcApi::create("http://10.1.1.1:9998", auth, why) && !why.empty(), "Q1: a non-loopback URL refused");
    CHECK(!scan::QtRpcApi::create("http://127.0.0.1:9998", loose, why) && why.find("group or other") != std::string::npos,
          "Q1: a 0644 credentials file refused");

    DashdHttp d;
    d.logic.rows = fixture_rows();
    d.expect_auth = basic_of(kCookie);
    CHECK(d.start(), "fake dashd listens");
    auto api = scan::QtRpcApi::create(d.http.url(), auth, why);
    CHECK(api != nullptr, "Q2: transport created");
    if (!api) return;
    scan::SourceDashd src(*api);
    ScanResult r;
    CHECK(runs([&] { r = src.scan({kXdgf}, ScanOptions{}); }, "scan over HTTP"), "Q2: SourceDashd scans over QtRpcApi");
    FakeDashd local;
    local.rows = fixture_rows();
    CHECK(!r.imports.empty() && export_of(r) == export_of(dashd_scan(local)), "Q2: the export equals the in-process scan's");
    bool bodies = !d.http.log.empty(), auth_ok = true;
    for (const Req& q : d.http.log) {
        const nj b = nj::parse(q.body.toStdString(), nullptr, false);
        bodies &= q.method == "POST" && q.target == "/" && b.is_object() && b.value("jsonrpc", "") == "1.0" && b.contains("params");
        auth_ok &= q.headers.count("authorization") && q.headers.at("authorization") == basic_of(kCookie);
        auth_ok &= !q.headers.count("proxy-authorization") && !q.headers.count("cookie");
    }
    CHECK(bodies && auth_ok && d.http.log.size() == 3 + 170, "Q2: JSON-RPC 1.0 POSTs to /, Basic auth on each, nothing else");

    const std::string wrong = put_file(dir, "wrong.cookie", "__cookie__:ffff\n", 0600);
    auto bad = scan::QtRpcApi::create(d.http.url(), wrong, why);
    scan::SourceDashd src2(*bad);
    std::string what;
    CHECK(refuses([&] { src2.scan({kXdgf}, ScanOptions{}); }, cause::kAuthRefused, &what) &&
              what.find("cookie") != std::string::npos,
          "Q3: a wrong cookie: HTTP 401 -> scan-auth-refused");
}

static void q4_scantxoutset_abort(const QString& dir)
{
    std::printf("[Q4 cancel during scantxoutset: abort on a second request]\n");
    const std::string auth = put_file(dir, "dashd4.cookie", kCookie + "\n", 0600);
    DashdHttp d;
    d.logic.rows = fixture_rows();
    d.logic.addressindex = false;
    d.expect_auth = basic_of(kCookie);
    d.hold_scan = true;
    CHECK(d.start(), "fake dashd listens");
    std::string why;
    auto api = scan::QtRpcApi::create(d.http.url(), auth, why);
    if (!api) return;
    scan::SourceDashd src(*api);
    bool cancel = false;
    ScanOptions so;
    so.cancelled = [&] { return cancel; };
    QTimer::singleShot(300, [&] { cancel = true; });
    QElapsedTimer t;
    t.start();
    std::string what;
    CHECK(refuses([&] { src.scan({kXdgf}, so); }, cause::kCancelled, &what), "Q4: scan-cancelled");
    CHECK(d.aborts == 1 && d.held == nullptr && t.elapsed() < 5000, "Q4: one scantxoutset \"abort\", the start answered, < 5 s");
}

static void q5_node_scan_cancel()
{
    std::printf("[Q5 cancel during a node scan: the GET is dropped]\n");
    NodeHttp n;
    n.logic.rows = fixture_rows();
    n.hold = true;
    CHECK(n.start(), "fake node listens");
    std::string why;
    auto api = sched::QtNodeApi::create(n.http.url(), why, 130000);
    if (!api) return;
    bool cancel = false;
    api->set_stop_check([&] { return cancel; });
    scan::SourceC2pool src(*api);
    ScanOptions so;
    so.cancelled = [&] { return cancel; };
    QTimer::singleShot(300, [&] { cancel = true; });
    QElapsedTimer t;
    t.start();
    CHECK(refuses([&] { src.scan({kXdgf}, so); }, cause::kCancelled) && t.elapsed() < 3000,
          "Q5: scan-cancelled within 3 s (the node's 120 s pass is not waited for)");
    n.hold = false;
    auto api2 = sched::QtNodeApi::create(n.http.url(), why, 130000);
    scan::SourceC2pool src2(*api2);
    ScanResult r;
    CHECK(runs([&] { r = src2.scan({kXdgf}, ScanOptions{}); }, "scan") && r.imports.at(0).utxos.size() == 170,
          "Q5: the node scan over QtNodeApi (130 s timeout) when not cancelled");
}

struct Proc {
    int rc = -1;
    QByteArray out, err;
};

static Proc schedd(const QStringList& args)
{
    QProcess p;
    p.setProgram(QStringLiteral(C2WALLET_SCHEDD_BIN));
    p.setArguments(args);
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.remove("http_proxy");
    env.remove("HTTP_PROXY");
    p.setProcessEnvironment(env);
    p.start();
    Proc r;
    if (!p.waitForStarted(10000)) return r;
    QElapsedTimer t;
    t.start();
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

static void q6_daemon(const QString& dir)
{
    std::printf("[Q6 c2wallet-qt-schedd scan end to end]\n");
    const std::string auth = put_file(dir, "dashd6.cookie", kCookie + "\n", 0600);
    DashdHttp d;
    d.logic.rows = fixture_rows();
    d.expect_auth = basic_of(kCookie);
    CHECK(d.start(), "fake dashd listens");
    const QString base = dir + "/e2e";
    const QString queue = dir + "/queue.json";
    const Proc p = schedd({"--queue", queue, "scan", "--address", kXdgf, "--source", "dashd", "--dashd-url",
                           QString::fromStdString(d.http.url()), "--dashd-auth-file", QString::fromStdString(auth), "--out",
                           base});
    CHECK(p.rc == 0, "Q6: the daemon's scan exits 0");
    if (p.rc != 0) std::printf("    stdout: %s\n    stderr: %s\n", p.out.constData(), p.err.constData());
    const std::string ex = read_file(base.toStdString() + ".utxos.json");
    FakeDashd local;
    local.rows = fixture_rows();
    CHECK(ex == export_of(dashd_scan(local)) && !read_file(base.toStdString() + ".scanplan.json").empty() &&
              read_file(base.toStdString() + ".report.txt").find("plan ") != std::string::npos,
          "Q6: the three files, the export byte-equal to the in-process scan's");
    const size_t seen = d.http.log.size();
    const Proc q = schedd({"--queue", queue, "scan", "--address", kXdgf, "--source", "dashd", "--dashd-url",
                           QString::fromStdString(d.http.url()), "--dashd-auth", "s3cret-value"});
    CHECK(q.rc == 2 && d.http.log.size() == seen && !q.err.contains("s3cret-value") && q.err.contains("--dashd-auth-file"),
          "Q6: --dashd-auth VALUE: usage error, no request, the value not echoed");
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir tmp;
    if (!tmp.isValid()) {
        std::printf("cannot create a temporary directory\n");
        return 2;
    }
    q1_q2_q3(tmp.path());
    q4_scantxoutset_abort(tmp.path());
    q5_node_scan_cancel();
    q6_daemon(tmp.path());
    std::printf("\n== scan Qt KATs: %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
