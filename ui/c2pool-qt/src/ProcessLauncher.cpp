#include "ProcessLauncher.hpp"

ProcessLauncher::ProcessLauncher(QObject* parent)
    : QObject(parent)
{
    process_.setProcessChannelMode(QProcess::MergedChannels);

    connect(&process_, &QProcess::started, this, &ProcessLauncher::started);

    connect(&process_,
            static_cast<void (QProcess::*)(int, QProcess::ExitStatus)>(&QProcess::finished),
            this, &ProcessLauncher::finished);

    connect(&process_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        emit errorOccurred(process_.errorString());
    });

    connect(&process_, &QProcess::readyReadStandardOutput, this, [this]() {
        while (process_.canReadLine()) {
            const QString line = QString::fromUtf8(process_.readLine()).trimmed();
            if (!line.isEmpty())
                emit outputLine(line);
        }
    });
}

void ProcessLauncher::start(const QString& program, const QStringList& arguments,
                            const QString& workingDir)
{
    if (process_.state() != QProcess::NotRunning)
        return;

    if (!workingDir.isEmpty())
        process_.setWorkingDirectory(workingDir);

    process_.start(program, arguments);
}

void ProcessLauncher::stop(int timeoutMs)
{
    if (process_.state() == QProcess::NotRunning)
        return;

    process_.terminate();
    if (!process_.waitForFinished(timeoutMs))
        process_.kill();
}

bool ProcessLauncher::isRunning() const
{
    return process_.state() != QProcess::NotRunning;
}

QString ProcessLauncher::errorString() const
{
    return process_.errorString();
}
