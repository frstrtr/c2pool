// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Scan & Plan (companion) — one c2wallet-qt-schedd command line
// (sched::cli::run) on a worker thread, for the companion GUI's Scan & Plan
// tab. Widget-free, so its lifetime rules have a KAT (scan_qt_kats Q7).
//
//   * The Qt transports (QtNodeApi, QtRpcApi) are created on the worker thread
//     and used only there.
//   * cancel() is the commands' cancel: a running scantxoutset is aborted, a
//     node scan request is dropped (the stop check of the scan transport).
//   * The done callback runs on the thread that created the job, and only
//     while `receiver` still exists: results are posted to a relay object the
//     job owns and checked against a QPointer there, never touched from the
//     worker. Closing the window (destroying the receiver) mid-run is safe.
//   * The destructor cancels and joins the worker: no worker outlives its job.
//
// Nothing here signs or arms: the job runs whatever command line the GUI
// builds (scan, preflight, add --preflight).

#include <QObject>
#include <QPointer>

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <vector>

class QThread;

namespace c2w::companion::scan {

class CliJob {
public:
    using Done = std::function<void(int rc, const std::string& output)>;

    explicit CliJob(QObject* receiver);
    ~CliJob();
    CliJob(const CliJob&) = delete;
    CliJob& operator=(const CliJob&) = delete;

    // false when a command is still running.
    bool start(std::vector<std::string> args, Done done);
    void cancel();
    bool running() const;
    // Join the worker; true when none runs (ms < 0: no limit).
    bool wait(int ms);

private:
    QPointer<QObject> receiver_;
    std::unique_ptr<QObject> relay_;
    std::shared_ptr<std::atomic<bool>> cancel_;
    QThread* thread_ = nullptr;
};

} // namespace c2w::companion::scan
