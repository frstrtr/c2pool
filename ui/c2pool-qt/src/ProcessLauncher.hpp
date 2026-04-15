#pragma once

#include <QObject>
#include <QProcess>
#include <QString>
#include <QStringList>

/// Cross-platform daemon process manager.
///
/// Wraps QProcess with direct program+arguments invocation (no shell wrapper)
/// so the same code works on Linux, macOS, and Windows.
class ProcessLauncher : public QObject
{
    Q_OBJECT
public:
    explicit ProcessLauncher(QObject* parent = nullptr);

    void start(const QString& program, const QStringList& arguments,
               const QString& workingDir);
    void stop(int timeoutMs = 3000);
    bool isRunning() const;
    QString errorString() const;

signals:
    void started();
    void finished(int exitCode, QProcess::ExitStatus status);
    void errorOccurred(const QString& message);
    void outputLine(const QString& line);

private:
    QProcess process_;
};
