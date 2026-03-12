#include "MainWindow.hpp"

#include <QApplication>

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("c2pool Qt Control Panel");
    app.setOrganizationName("c2pool");

    MainWindow window;
    window.show();
    return app.exec();
}
