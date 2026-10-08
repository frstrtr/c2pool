// SPDX-License-Identifier: AGPL-3.0-or-later
//
// c2wallet-qt-signer — entry point for the air-gapped, network-incapable
// signer skeleton (design PR #1621, docs/design/c2wallet-qt.md §5.2).
//
// M0 stands up an empty Bitcoin-Core-like Widgets shell only. There are no
// keys, no signing, and no crypto in this phase; the value delivered here is
// the FOUNDATION plus the mechanical proof (ci/check_no_network.sh) that this
// binary is physically incapable of network I/O.

#include "shell/MainWindow.hpp"

#include <QApplication>

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("c2wallet-qt (signer)");
    app.setOrganizationName("c2pool");

    MainWindow window;
    window.show();
    return app.exec();
}
