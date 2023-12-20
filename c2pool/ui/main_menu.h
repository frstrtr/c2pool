/********************************************************************************
** Form generated from reading UI file 'main_menuHYptEE.ui'
**
** Created by: Qt User Interface Compiler version 5.12.8
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef MAIN_MENUHYPTEE_H
#define MAIN_MENUHYPTEE_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_c2pool_menu
{
public:
    QWidget *centralwidget;
    QGridLayout *gridLayout;
    QHBoxLayout *horizontalLayout;
    QComboBox *networks;
    QPushButton *deleteNetwork;
    QLineEdit *new_net_name;
    QPushButton *new_net_button;
    QTableWidget *tableWidget;
    QPushButton *configure_button;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *c2pool_menu)
    {
        if (c2pool_menu->objectName().isEmpty())
            c2pool_menu->setObjectName(QString::fromUtf8("c2pool_menu"));
        c2pool_menu->resize(550, 500);
        c2pool_menu->setMinimumSize(QSize(550, 500));
        c2pool_menu->setMaximumSize(QSize(550, 500));
        centralwidget = new QWidget(c2pool_menu);
        centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
        gridLayout = new QGridLayout(centralwidget);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        networks = new QComboBox(centralwidget);
        networks->setObjectName(QString::fromUtf8("networks"));
        networks->setMinimumSize(QSize(150, 25));
        networks->setDuplicatesEnabled(false);

        horizontalLayout->addWidget(networks);

        deleteNetwork = new QPushButton(centralwidget);
        deleteNetwork->setObjectName(QString::fromUtf8("deleteNetwork"));

        horizontalLayout->addWidget(deleteNetwork);

        new_net_name = new QLineEdit(centralwidget);
        new_net_name->setObjectName(QString::fromUtf8("new_net_name"));

        horizontalLayout->addWidget(new_net_name);

        new_net_button = new QPushButton(centralwidget);
        new_net_button->setObjectName(QString::fromUtf8("new_net_button"));

        horizontalLayout->addWidget(new_net_button);


        gridLayout->addLayout(horizontalLayout, 0, 0, 1, 1);

        tableWidget = new QTableWidget(centralwidget);
        tableWidget->setObjectName(QString::fromUtf8("tableWidget"));

        gridLayout->addWidget(tableWidget, 1, 0, 1, 1);

        configure_button = new QPushButton(centralwidget);
        configure_button->setObjectName(QString::fromUtf8("configure_button"));

        gridLayout->addWidget(configure_button, 2, 0, 1, 1);

        c2pool_menu->setCentralWidget(centralwidget);
        menubar = new QMenuBar(c2pool_menu);
        menubar->setObjectName(QString::fromUtf8("menubar"));
        menubar->setGeometry(QRect(0, 0, 550, 22));
        c2pool_menu->setMenuBar(menubar);
        statusbar = new QStatusBar(c2pool_menu);
        statusbar->setObjectName(QString::fromUtf8("statusbar"));
        c2pool_menu->setStatusBar(statusbar);

        retranslateUi(c2pool_menu);

        QMetaObject::connectSlotsByName(c2pool_menu);
    } // setupUi

    void retranslateUi(QMainWindow *c2pool_menu)
    {
        c2pool_menu->setWindowTitle(QApplication::translate("c2pool_menu", "C2Pool", nullptr));
        deleteNetwork->setText(QApplication::translate("c2pool_menu", "Delete", nullptr));
        new_net_name->setPlaceholderText(QApplication::translate("c2pool_menu", "New network name (btc, ltc, etc.)...", nullptr));
        new_net_button->setText(QApplication::translate("c2pool_menu", "Create new", nullptr));
        configure_button->setText(QApplication::translate("c2pool_menu", "Configure", nullptr));
    } // retranslateUi

};

namespace Ui {
    class c2pool_menu: public Ui_c2pool_menu {};
} // namespace Ui

QT_END_NAMESPACE

#endif // MAIN_MENUHYPTEE_H
