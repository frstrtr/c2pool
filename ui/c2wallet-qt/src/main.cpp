// SPDX-License-Identifier: AGPL-3.0-or-later
//
// c2wallet-qt-signer — entry point for the air-gapped, network-incapable
// signer (design PR #1621, docs/design/c2wallet-qt.md §5.2).
//
// The binary links Qt6 Core/Gui/Widgets and the offline libraries only; the
// mechanical proof that it is physically incapable of network I/O is
// ci/check_no_network.sh (and its Mach-O / PE siblings for the packages).
//
// `--version` prints the build's version and Qt version and exits before any
// QApplication exists: no display, no platform plugin, nothing but the shared
// libraries the loader resolved. The release jobs run it on the PACKAGED
// binary as a smoke test.

#include "shell/MainWindow.hpp"

#include <QApplication>
#include <QtGlobal>

#include <cstdio>
#include <cstring>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#ifndef C2WALLET_QT_VERSION
#define C2WALLET_QT_VERSION "0.0.0-unknown"
#endif

namespace {

#ifdef _WIN32
// A packaged Windows build is a GUI-subsystem exe and starts without a console.
// When stdout is not redirected, write --version to the parent's console.
void attach_parent_console()
{
    const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (out != nullptr && out != INVALID_HANDLE_VALUE && GetFileType(out) != FILE_TYPE_UNKNOWN) return;
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) return;
    FILE* f = nullptr;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
}
#endif

int print_version()
{
#ifdef _WIN32
    attach_parent_console();
#endif
    std::printf("c2wallet-qt-signer %s\n"
                "network-incapable build: links Qt6 Core/Gui/Widgets and no networking library\n"
                "Qt %s (runtime %s)\n",
                C2WALLET_QT_VERSION, QT_VERSION_STR, qVersion());
    std::fflush(stdout);
    return 0;
}

} // namespace

int main(int argc, char* argv[])
{
    for (int i = 1; i < argc; ++i)
        if (std::strcmp(argv[i], "--version") == 0) return print_version();

    QApplication app(argc, argv);
    app.setApplicationName("c2wallet-qt (signer)");
    app.setOrganizationName("c2pool");

    MainWindow window;
    window.show();
    return app.exec();
}
