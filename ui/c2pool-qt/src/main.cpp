#include "MainWindow.hpp"
#include "SettingsStore.hpp"

#include <QApplication>

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("c2pool Qt Control Panel");
    app.setOrganizationName("c2pool");

    // SettingsStore before the MainWindow so the schema v1→v2
    // migration runs before any page reads QSettings directly.
    // MainWindow receives it by reference and injects into pages.
    SettingsStore settings;
    settings.runMigrationsIfNeeded();

    MainWindow window(&settings);
    window.show();
    return app.exec();
}
