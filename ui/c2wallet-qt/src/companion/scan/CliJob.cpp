// SPDX-License-Identifier: AGPL-3.0-or-later
#include "CliJob.hpp"

#include "QtRpcApi.hpp"

#include "../sched/Clock.hpp"
#include "../sched/QtNodeApi.hpp"
#include "../sched/SchedCli.hpp"

#include <QDeadlineTimer>
#include <QMetaObject>
#include <QThread>

#include <sstream>

namespace c2w::companion::scan {

CliJob::CliJob(QObject* receiver)
    : receiver_(receiver), relay_(std::make_unique<QObject>()), cancel_(std::make_shared<std::atomic<bool>>(false))
{
}

CliJob::~CliJob()
{
    cancel();
    wait(-1);
    delete thread_;
}

bool CliJob::running() const { return thread_ && thread_->isRunning(); }

void CliJob::cancel() { cancel_->store(true); }

bool CliJob::wait(int ms)
{
    if (!thread_) return true;
    return thread_->wait(ms < 0 ? QDeadlineTimer(QDeadlineTimer::Forever) : QDeadlineTimer(ms));
}

bool CliJob::start(std::vector<std::string> args, Done done)
{
    namespace sched = c2w::companion::sched;
    if (running()) return false;
    if (thread_) {
        thread_->wait();
        delete thread_;
        thread_ = nullptr;
    }
    cancel_->store(false);
    QObject* relay = relay_.get();
    const QPointer<QObject> receiver = receiver_;
    const std::shared_ptr<std::atomic<bool>> cancel = cancel_;
    thread_ = QThread::create([relay, receiver, cancel, args = std::move(args), done = std::move(done)]() {
        std::ostringstream os;
        sched::SystemClock clock;
        sched::cli::Env env;
        env.out = &os;
        env.err = &os;
        env.clock = &clock;
        env.make_api = [](const std::string& url, std::string& why) -> std::unique_ptr<sched::NodeApi> {
            return sched::QtNodeApi::create(url, why);
        };
        env.make_scan_api = [cancel](const std::string& url, std::string& why) -> std::unique_ptr<sched::NodeApi> {
            auto api = sched::QtNodeApi::create(url, why, 130000);
            if (api) api->set_stop_check([cancel] { return cancel->load(); });
            return api;
        };
        env.make_rpc = [](const std::string& url, const std::string& auth, std::string& why) -> std::unique_ptr<RpcApi> {
            return QtRpcApi::create(url, auth, why);
        };
        env.sleep_ms = [](int64_t) {};
        env.stop_requested = [cancel] { return cancel->load(); };
        const int rc = sched::cli::run(args, env);
        const std::string text = os.str();
        // Delivered on the relay's (the creating) thread, and only while the
        // receiver exists; the relay outlives this thread (the job joins it).
        QMetaObject::invokeMethod(
            relay,
            [receiver, done, rc, text] {
                if (receiver && done) done(rc, text);
            },
            Qt::QueuedConnection);
    });
    thread_->start();
    return true;
}

} // namespace c2w::companion::scan
