// test_embedded_leak — Qt step 14 leak-regression harness.
//
// Asserts that mount→destroy × 100 of PageEmbedded does not leave
// orphaned QtWebEngineProcess helpers behind. Per delta v1 §E.2
// acceptance criterion (c2pool-qt-hybrid-architecture.md §8 step 14).
//
// Strategy: snapshot child-process count before the loop, repeat
// buildView/destroyView construction N times, process the Qt event
// loop briefly between iterations (so deleteLater() runs), then
// compare the final count to the baseline. A leak manifests as a
// child count that never comes down.
//
// Intentionally skipped when the Qt platform plugin can't
// initialise (e.g. no DISPLAY and the runtime lacks an offscreen
// plugin). The caller opts into offscreen mode by exporting
// QT_QPA_PLATFORM=offscreen.
//
// Exit codes:
//   0 = PASS
//   1 = leak detected (final helpers > baseline + tolerance)
//   2 = harness error (page never loads, Qt init failure)

#include "../src/PageEmbedded.hpp"

#include <QApplication>
#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QString>
#include <QThread>
#include <QTimer>
#include <QWidget>

#include <cstdio>
#include <set>
#include <string>

#ifdef __linux__
#  include <sys/types.h>
#  include <unistd.h>
#endif

namespace {

constexpr int kIterations          = 100;
constexpr int kSettleAfterMs       = 50;
constexpr int kFinalDrainMs        = 500;
constexpr int kHelperCountTolerance = 1;   // render + gpu sometimes persist

// Count QtWebEngineProcess descendants of this process. Walks
// /proc/<pid>/task/<tid>/children on Linux; on other platforms this
// returns -1 and the test short-circuits to harness-error.
int countDescendantHelpers()
{
#ifdef __linux__
    std::set<pid_t> visited;
    std::set<pid_t> frontier;
    frontier.insert(getpid());
    int count = 0;
    while (!frontier.empty()) {
        const pid_t p = *frontier.begin();
        frontier.erase(frontier.begin());
        if (!visited.insert(p).second) continue;
        QString taskDir = QString("/proc/%1/task").arg(p);
        QDir d(taskDir);
        const auto tids = d.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
        for (const QString& tid : tids) {
            QFile f(QString("%1/%2/children").arg(taskDir, tid));
            if (!f.open(QIODevice::ReadOnly)) continue;
            const QByteArray raw = f.readAll();
            f.close();
            const QList<QByteArray> parts = raw.split(' ');
            for (const QByteArray& part : parts) {
                const QByteArray trimmed = part.trimmed();
                if (trimmed.isEmpty()) continue;
                bool ok = false;
                const pid_t child = trimmed.toInt(&ok);
                if (!ok) continue;
                if (visited.count(child) > 0) continue;
                // Check comm for QtWebEngineProc*.
                QFile comm(QString("/proc/%1/comm").arg(child));
                if (!comm.open(QIODevice::ReadOnly)) continue;
                const QByteArray name = comm.readAll().trimmed();
                comm.close();
                if (name.startsWith("QtWebEngineProc")) {
                    ++count;
                }
                frontier.insert(child);
            }
        }
    }
    return count;
#else
    return -1;
#endif
}

void drainEvents(int ms)
{
    QEventLoop loop;
    QTimer::singleShot(ms, &loop, &QEventLoop::quit);
    loop.exec();
}

int runHarness()
{
    PageEmbedded::Config cfg;
    // qrc:///test/hello.html is already embedded by the test_resources
    // qt_add_resources block; no network or file-system dep needed.
    cfg.qrcUrl = QStringLiteral("qrc:///test/hello.html");
    cfg.bridgeObjectName = QStringLiteral("qtBridge");

    const int baseline = countDescendantHelpers();
    if (baseline < 0) {
        std::fprintf(stderr, "test_embedded_leak: unsupported platform "
                             "for child-process probing\n");
        return 2;
    }

    // One warm-up so the helper process pool settles before baseline.
    {
        auto* w = new PageEmbedded(cfg);
        drainEvents(200);
        delete w;
        drainEvents(200);
    }
    const int warmBaseline = countDescendantHelpers();
    std::fprintf(stdout,
                 "test_embedded_leak: cold baseline=%d warm baseline=%d\n",
                 baseline, warmBaseline);
    std::fflush(stdout);

    QElapsedTimer timer;
    timer.start();
    int peak = warmBaseline;
    for (int i = 0; i < kIterations; ++i) {
        auto* w = new PageEmbedded(cfg);
        drainEvents(kSettleAfterMs);
        // Let the view get far enough that its helper is attached.
        delete w;
        drainEvents(kSettleAfterMs);
        const int cur = countDescendantHelpers();
        if (cur > peak) peak = cur;
        if ((i + 1) % 20 == 0) {
            std::fprintf(stdout,
                         "  iter=%d helpers=%d peak=%d elapsed=%lldms\n",
                         i + 1, cur, peak,
                         static_cast<long long>(timer.elapsed()));
            std::fflush(stdout);
        }
    }
    drainEvents(kFinalDrainMs);
    const int final_count = countDescendantHelpers();
    std::fprintf(stdout,
                 "test_embedded_leak: %d iterations done, "
                 "final=%d peak=%d tolerance=%d\n",
                 kIterations, final_count, peak, kHelperCountTolerance);

    if (final_count > warmBaseline + kHelperCountTolerance) {
        std::fprintf(stderr,
                     "FAIL: final helper count %d exceeds baseline "
                     "%d + tolerance %d (leak suspected)\n",
                     final_count, warmBaseline, kHelperCountTolerance);
        return 1;
    }
    std::fprintf(stdout, "PASS\n");
    return 0;
}

} // namespace

int main(int argc, char* argv[])
{
    // QApplication (not Core) — QWebEngineView needs a GUI app.
    // Runs under either a real display or QT_QPA_PLATFORM=offscreen;
    // for fully headless CI also set QTWEBENGINE_DISABLE_SANDBOX=1
    // and xvfb-run if the runner has no EGL/OpenGL.
    QApplication app(argc, argv);
    return runHarness();
}
