/********************************************************************************
** Form generated from reading UI file 'net_configureqbXPWu.ui'
**
** Created by: Qt User Interface Compiler version 6.6.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef NET_CONFIGUREQBXPWU_H
#define NET_CONFIGUREQBXPWU_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPlainTextEdit>
#include <QtWidgets/QScrollArea>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_C2poolSettingsForm
{
public:
    QGridLayout *gridLayout;
    QTabWidget *tabWidget;
    QWidget *ConfigTab;
    QGridLayout *gridLayout_2;
    QScrollArea *scrollArea_3;
    QWidget *scrollAreaWidgetContents;
    QGridLayout *gridLayout_6;
    QFormLayout *formLayout_4;
    QCheckBox *config_testnet;
    QLabel *label_35;
    QLineEdit *config_address;
    QLabel *label_36;
    QLineEdit *config_numaddresses;
    QLabel *label_37;
    QLineEdit *config_timeaddresses;
    QLabel *label_38;
    QLineEdit *config_coind_address;
    QLabel *label_39;
    QLineEdit *config_coind_p2p_port;
    QLabel *label_40;
    QLineEdit *config_coind_config_path;
    QLabel *label_41;
    QLabel *label_42;
    QLabel *label_43;
    QLineEdit *config_coind_rpc_port;
    QLineEdit *config_coind_rpc_userpass;
    QLabel *label_44;
    QLineEdit *config_c2pool_port;
    QLabel *label_45;
    QLineEdit *config_max_conns;
    QLabel *label_46;
    QLineEdit *config_outgoing_conns;
    QLabel *label_47;
    QLineEdit *config_max_attempts;
    QLabel *label_48;
    QLineEdit *config_worker_port;
    QLabel *label_49;
    QLineEdit *config_worker_fee;
    QCheckBox *config_coind_rpc_ssl;
    QWidget *NetworksTab;
    QFormLayout *formLayout;
    QGridLayout *gridLayout_5;
    QGroupBox *poolGroup;
    QGridLayout *gridLayout_3;
    QScrollArea *scrollArea_2;
    QWidget *scrollAreaWidgetContents_3;
    QFormLayout *formLayout_2;
    QLabel *label_18;
    QLineEdit *pool_softforks_req;
    QLabel *label_19;
    QLineEdit *pool_bootstrap_addrs;
    QLabel *label_20;
    QLabel *label_21;
    QLabel *label_22;
    QLabel *label_23;
    QLabel *label_24;
    QLabel *label_25;
    QLabel *label_26;
    QLabel *label_27;
    QLabel *label_28;
    QLabel *label_29;
    QLabel *label_30;
    QLabel *label_32;
    QLabel *label_33;
    QLabel *label_34;
    QLineEdit *pool_prefix;
    QLineEdit *pool_identifier;
    QSpinBox *pool_segwit_activation_ver;
    QSpinBox *pool_min_protocol_ver;
    QSpinBox *pool_target_lookbehind;
    QSpinBox *pool_share_period;
    QSpinBox *pool_block_max_size;
    QSpinBox *pool_block_max_weight;
    QSpinBox *pool_real_chain_length;
    QSpinBox *pool_chain_length;
    QSpinBox *pool_spread;
    QLabel *label_31;
    QComboBox *pool_persist;
    QLineEdit *pool_min_target;
    QLineEdit *pool_max_target;
    QPlainTextEdit *pool_donation_script;
    QGroupBox *parentGroup;
    QGridLayout *gridLayout_4;
    QScrollArea *scrollArea;
    QWidget *scrollAreaWidgetContents_2;
    QFormLayout *formLayout_3;
    QLabel *label;
    QLineEdit *parent_symbol;
    QLabel *label_2;
    QLineEdit *parent_prefix;
    QLabel *label_3;
    QLineEdit *parent_p2p_address;
    QLabel *label_4;
    QLineEdit *parent_p2p_port;
    QLabel *label_5;
    QLineEdit *parent_addr_version;
    QLabel *label_6;
    QLineEdit *parent_addr_p2sh_version;
    QLabel *label_7;
    QLineEdit *parent_rpc_port;
    QLabel *label_8;
    QLineEdit *parent_block_period;
    QLabel *label_9;
    QLineEdit *parent_dumb_scrypt_diff;
    QLabel *label_10;
    QLineEdit *parent_dust_threshold;
    QLabel *label_11;
    QLineEdit *parent_sane_target_min;
    QLabel *label_12;
    QLineEdit *parent_sane_target_max;
    QLabel *label_13;
    QComboBox *parent_pow_func;
    QLabel *label_14;
    QComboBox *parent_subsidy_func;
    QLabel *label_15;
    QLineEdit *parent_block_explorer_url_prefix;
    QLabel *label_16;
    QLabel *label_17;
    QLineEdit *parent_address_explorer_url_prefix;
    QLineEdit *parent_tx_explorer_url_prefix;

    void setupUi(QWidget *C2poolSettingsForm)
    {
        if (C2poolSettingsForm->objectName().isEmpty())
            C2poolSettingsForm->setObjectName("C2poolSettingsForm");
        C2poolSettingsForm->setEnabled(true);
        C2poolSettingsForm->resize(800, 475);
        QSizePolicy sizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(C2poolSettingsForm->sizePolicy().hasHeightForWidth());
        C2poolSettingsForm->setSizePolicy(sizePolicy);
        C2poolSettingsForm->setMinimumSize(QSize(800, 475));
        C2poolSettingsForm->setMaximumSize(QSize(800, 475));
        C2poolSettingsForm->setAutoFillBackground(false);
        gridLayout = new QGridLayout(C2poolSettingsForm);
        gridLayout->setObjectName("gridLayout");
        tabWidget = new QTabWidget(C2poolSettingsForm);
        tabWidget->setObjectName("tabWidget");
        sizePolicy.setHeightForWidth(tabWidget->sizePolicy().hasHeightForWidth());
        tabWidget->setSizePolicy(sizePolicy);
        ConfigTab = new QWidget();
        ConfigTab->setObjectName("ConfigTab");
        gridLayout_2 = new QGridLayout(ConfigTab);
        gridLayout_2->setObjectName("gridLayout_2");
        scrollArea_3 = new QScrollArea(ConfigTab);
        scrollArea_3->setObjectName("scrollArea_3");
        scrollArea_3->setWidgetResizable(true);
        scrollAreaWidgetContents = new QWidget();
        scrollAreaWidgetContents->setObjectName("scrollAreaWidgetContents");
        scrollAreaWidgetContents->setGeometry(QRect(0, -46, 739, 454));
        gridLayout_6 = new QGridLayout(scrollAreaWidgetContents);
        gridLayout_6->setObjectName("gridLayout_6");
        formLayout_4 = new QFormLayout();
        formLayout_4->setObjectName("formLayout_4");
        config_testnet = new QCheckBox(scrollAreaWidgetContents);
        config_testnet->setObjectName("config_testnet");

        formLayout_4->setWidget(0, QFormLayout::LabelRole, config_testnet);

        label_35 = new QLabel(scrollAreaWidgetContents);
        label_35->setObjectName("label_35");

        formLayout_4->setWidget(1, QFormLayout::LabelRole, label_35);

        config_address = new QLineEdit(scrollAreaWidgetContents);
        config_address->setObjectName("config_address");

        formLayout_4->setWidget(1, QFormLayout::FieldRole, config_address);

        label_36 = new QLabel(scrollAreaWidgetContents);
        label_36->setObjectName("label_36");

        formLayout_4->setWidget(2, QFormLayout::LabelRole, label_36);

        config_numaddresses = new QLineEdit(scrollAreaWidgetContents);
        config_numaddresses->setObjectName("config_numaddresses");

        formLayout_4->setWidget(2, QFormLayout::FieldRole, config_numaddresses);

        label_37 = new QLabel(scrollAreaWidgetContents);
        label_37->setObjectName("label_37");

        formLayout_4->setWidget(3, QFormLayout::LabelRole, label_37);

        config_timeaddresses = new QLineEdit(scrollAreaWidgetContents);
        config_timeaddresses->setObjectName("config_timeaddresses");

        formLayout_4->setWidget(3, QFormLayout::FieldRole, config_timeaddresses);

        label_38 = new QLabel(scrollAreaWidgetContents);
        label_38->setObjectName("label_38");

        formLayout_4->setWidget(4, QFormLayout::LabelRole, label_38);

        config_coind_address = new QLineEdit(scrollAreaWidgetContents);
        config_coind_address->setObjectName("config_coind_address");

        formLayout_4->setWidget(4, QFormLayout::FieldRole, config_coind_address);

        label_39 = new QLabel(scrollAreaWidgetContents);
        label_39->setObjectName("label_39");

        formLayout_4->setWidget(5, QFormLayout::LabelRole, label_39);

        config_coind_p2p_port = new QLineEdit(scrollAreaWidgetContents);
        config_coind_p2p_port->setObjectName("config_coind_p2p_port");

        formLayout_4->setWidget(5, QFormLayout::FieldRole, config_coind_p2p_port);

        label_40 = new QLabel(scrollAreaWidgetContents);
        label_40->setObjectName("label_40");

        formLayout_4->setWidget(6, QFormLayout::LabelRole, label_40);

        config_coind_config_path = new QLineEdit(scrollAreaWidgetContents);
        config_coind_config_path->setObjectName("config_coind_config_path");

        formLayout_4->setWidget(6, QFormLayout::FieldRole, config_coind_config_path);

        label_41 = new QLabel(scrollAreaWidgetContents);
        label_41->setObjectName("label_41");

        formLayout_4->setWidget(7, QFormLayout::LabelRole, label_41);

        label_42 = new QLabel(scrollAreaWidgetContents);
        label_42->setObjectName("label_42");

        formLayout_4->setWidget(8, QFormLayout::LabelRole, label_42);

        label_43 = new QLabel(scrollAreaWidgetContents);
        label_43->setObjectName("label_43");

        formLayout_4->setWidget(9, QFormLayout::LabelRole, label_43);

        config_coind_rpc_port = new QLineEdit(scrollAreaWidgetContents);
        config_coind_rpc_port->setObjectName("config_coind_rpc_port");

        formLayout_4->setWidget(8, QFormLayout::FieldRole, config_coind_rpc_port);

        config_coind_rpc_userpass = new QLineEdit(scrollAreaWidgetContents);
        config_coind_rpc_userpass->setObjectName("config_coind_rpc_userpass");

        formLayout_4->setWidget(9, QFormLayout::FieldRole, config_coind_rpc_userpass);

        label_44 = new QLabel(scrollAreaWidgetContents);
        label_44->setObjectName("label_44");

        formLayout_4->setWidget(10, QFormLayout::LabelRole, label_44);

        config_c2pool_port = new QLineEdit(scrollAreaWidgetContents);
        config_c2pool_port->setObjectName("config_c2pool_port");

        formLayout_4->setWidget(10, QFormLayout::FieldRole, config_c2pool_port);

        label_45 = new QLabel(scrollAreaWidgetContents);
        label_45->setObjectName("label_45");

        formLayout_4->setWidget(11, QFormLayout::LabelRole, label_45);

        config_max_conns = new QLineEdit(scrollAreaWidgetContents);
        config_max_conns->setObjectName("config_max_conns");

        formLayout_4->setWidget(11, QFormLayout::FieldRole, config_max_conns);

        label_46 = new QLabel(scrollAreaWidgetContents);
        label_46->setObjectName("label_46");

        formLayout_4->setWidget(12, QFormLayout::LabelRole, label_46);

        config_outgoing_conns = new QLineEdit(scrollAreaWidgetContents);
        config_outgoing_conns->setObjectName("config_outgoing_conns");

        formLayout_4->setWidget(12, QFormLayout::FieldRole, config_outgoing_conns);

        label_47 = new QLabel(scrollAreaWidgetContents);
        label_47->setObjectName("label_47");

        formLayout_4->setWidget(13, QFormLayout::LabelRole, label_47);

        config_max_attempts = new QLineEdit(scrollAreaWidgetContents);
        config_max_attempts->setObjectName("config_max_attempts");

        formLayout_4->setWidget(13, QFormLayout::FieldRole, config_max_attempts);

        label_48 = new QLabel(scrollAreaWidgetContents);
        label_48->setObjectName("label_48");

        formLayout_4->setWidget(14, QFormLayout::LabelRole, label_48);

        config_worker_port = new QLineEdit(scrollAreaWidgetContents);
        config_worker_port->setObjectName("config_worker_port");

        formLayout_4->setWidget(14, QFormLayout::FieldRole, config_worker_port);

        label_49 = new QLabel(scrollAreaWidgetContents);
        label_49->setObjectName("label_49");

        formLayout_4->setWidget(15, QFormLayout::LabelRole, label_49);

        config_worker_fee = new QLineEdit(scrollAreaWidgetContents);
        config_worker_fee->setObjectName("config_worker_fee");

        formLayout_4->setWidget(15, QFormLayout::FieldRole, config_worker_fee);

        config_coind_rpc_ssl = new QCheckBox(scrollAreaWidgetContents);
        config_coind_rpc_ssl->setObjectName("config_coind_rpc_ssl");
        config_coind_rpc_ssl->setLayoutDirection(Qt::LeftToRight);

        formLayout_4->setWidget(7, QFormLayout::FieldRole, config_coind_rpc_ssl);


        gridLayout_6->addLayout(formLayout_4, 0, 0, 1, 1);

        scrollArea_3->setWidget(scrollAreaWidgetContents);

        gridLayout_2->addWidget(scrollArea_3, 0, 0, 1, 1);

        tabWidget->addTab(ConfigTab, QString());
        NetworksTab = new QWidget();
        NetworksTab->setObjectName("NetworksTab");
        formLayout = new QFormLayout(NetworksTab);
        formLayout->setObjectName("formLayout");
        gridLayout_5 = new QGridLayout();
        gridLayout_5->setObjectName("gridLayout_5");
        poolGroup = new QGroupBox(NetworksTab);
        poolGroup->setObjectName("poolGroup");
        QSizePolicy sizePolicy1(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(poolGroup->sizePolicy().hasHeightForWidth());
        poolGroup->setSizePolicy(sizePolicy1);
        gridLayout_3 = new QGridLayout(poolGroup);
        gridLayout_3->setSpacing(2);
        gridLayout_3->setObjectName("gridLayout_3");
        gridLayout_3->setContentsMargins(2, 2, 2, 2);
        scrollArea_2 = new QScrollArea(poolGroup);
        scrollArea_2->setObjectName("scrollArea_2");
        scrollArea_2->setWidgetResizable(true);
        scrollAreaWidgetContents_3 = new QWidget();
        scrollAreaWidgetContents_3->setObjectName("scrollAreaWidgetContents_3");
        scrollAreaWidgetContents_3->setGeometry(QRect(0, 0, 382, 543));
        formLayout_2 = new QFormLayout(scrollAreaWidgetContents_3);
        formLayout_2->setObjectName("formLayout_2");
        label_18 = new QLabel(scrollAreaWidgetContents_3);
        label_18->setObjectName("label_18");

        formLayout_2->setWidget(1, QFormLayout::LabelRole, label_18);

        pool_softforks_req = new QLineEdit(scrollAreaWidgetContents_3);
        pool_softforks_req->setObjectName("pool_softforks_req");

        formLayout_2->setWidget(1, QFormLayout::FieldRole, pool_softforks_req);

        label_19 = new QLabel(scrollAreaWidgetContents_3);
        label_19->setObjectName("label_19");

        formLayout_2->setWidget(2, QFormLayout::LabelRole, label_19);

        pool_bootstrap_addrs = new QLineEdit(scrollAreaWidgetContents_3);
        pool_bootstrap_addrs->setObjectName("pool_bootstrap_addrs");

        formLayout_2->setWidget(2, QFormLayout::FieldRole, pool_bootstrap_addrs);

        label_20 = new QLabel(scrollAreaWidgetContents_3);
        label_20->setObjectName("label_20");

        formLayout_2->setWidget(3, QFormLayout::LabelRole, label_20);

        label_21 = new QLabel(scrollAreaWidgetContents_3);
        label_21->setObjectName("label_21");

        formLayout_2->setWidget(4, QFormLayout::LabelRole, label_21);

        label_22 = new QLabel(scrollAreaWidgetContents_3);
        label_22->setObjectName("label_22");

        formLayout_2->setWidget(5, QFormLayout::LabelRole, label_22);

        label_23 = new QLabel(scrollAreaWidgetContents_3);
        label_23->setObjectName("label_23");

        formLayout_2->setWidget(6, QFormLayout::LabelRole, label_23);

        label_24 = new QLabel(scrollAreaWidgetContents_3);
        label_24->setObjectName("label_24");

        formLayout_2->setWidget(7, QFormLayout::LabelRole, label_24);

        label_25 = new QLabel(scrollAreaWidgetContents_3);
        label_25->setObjectName("label_25");

        formLayout_2->setWidget(8, QFormLayout::LabelRole, label_25);

        label_26 = new QLabel(scrollAreaWidgetContents_3);
        label_26->setObjectName("label_26");

        formLayout_2->setWidget(9, QFormLayout::LabelRole, label_26);

        label_27 = new QLabel(scrollAreaWidgetContents_3);
        label_27->setObjectName("label_27");

        formLayout_2->setWidget(10, QFormLayout::LabelRole, label_27);

        label_28 = new QLabel(scrollAreaWidgetContents_3);
        label_28->setObjectName("label_28");

        formLayout_2->setWidget(11, QFormLayout::LabelRole, label_28);

        label_29 = new QLabel(scrollAreaWidgetContents_3);
        label_29->setObjectName("label_29");

        formLayout_2->setWidget(12, QFormLayout::LabelRole, label_29);

        label_30 = new QLabel(scrollAreaWidgetContents_3);
        label_30->setObjectName("label_30");

        formLayout_2->setWidget(13, QFormLayout::LabelRole, label_30);

        label_32 = new QLabel(scrollAreaWidgetContents_3);
        label_32->setObjectName("label_32");

        formLayout_2->setWidget(15, QFormLayout::LabelRole, label_32);

        label_33 = new QLabel(scrollAreaWidgetContents_3);
        label_33->setObjectName("label_33");

        formLayout_2->setWidget(16, QFormLayout::LabelRole, label_33);

        label_34 = new QLabel(scrollAreaWidgetContents_3);
        label_34->setObjectName("label_34");

        formLayout_2->setWidget(17, QFormLayout::LabelRole, label_34);

        pool_prefix = new QLineEdit(scrollAreaWidgetContents_3);
        pool_prefix->setObjectName("pool_prefix");

        formLayout_2->setWidget(3, QFormLayout::FieldRole, pool_prefix);

        pool_identifier = new QLineEdit(scrollAreaWidgetContents_3);
        pool_identifier->setObjectName("pool_identifier");

        formLayout_2->setWidget(4, QFormLayout::FieldRole, pool_identifier);

        pool_segwit_activation_ver = new QSpinBox(scrollAreaWidgetContents_3);
        pool_segwit_activation_ver->setObjectName("pool_segwit_activation_ver");
        pool_segwit_activation_ver->setMaximum(9999999);
        pool_segwit_activation_ver->setValue(17);

        formLayout_2->setWidget(6, QFormLayout::FieldRole, pool_segwit_activation_ver);

        pool_min_protocol_ver = new QSpinBox(scrollAreaWidgetContents_3);
        pool_min_protocol_ver->setObjectName("pool_min_protocol_ver");
        pool_min_protocol_ver->setMinimum(-1);
        pool_min_protocol_ver->setMaximum(9999999);
        pool_min_protocol_ver->setValue(3301);

        formLayout_2->setWidget(5, QFormLayout::FieldRole, pool_min_protocol_ver);

        pool_target_lookbehind = new QSpinBox(scrollAreaWidgetContents_3);
        pool_target_lookbehind->setObjectName("pool_target_lookbehind");
        pool_target_lookbehind->setMaximum(9999999);
        pool_target_lookbehind->setValue(200);

        formLayout_2->setWidget(7, QFormLayout::FieldRole, pool_target_lookbehind);

        pool_share_period = new QSpinBox(scrollAreaWidgetContents_3);
        pool_share_period->setObjectName("pool_share_period");
        pool_share_period->setMaximum(9999999);
        pool_share_period->setValue(4);

        formLayout_2->setWidget(8, QFormLayout::FieldRole, pool_share_period);

        pool_block_max_size = new QSpinBox(scrollAreaWidgetContents_3);
        pool_block_max_size->setObjectName("pool_block_max_size");
        pool_block_max_size->setMaximum(999999999);
        pool_block_max_size->setValue(1000000);

        formLayout_2->setWidget(9, QFormLayout::FieldRole, pool_block_max_size);

        pool_block_max_weight = new QSpinBox(scrollAreaWidgetContents_3);
        pool_block_max_weight->setObjectName("pool_block_max_weight");
        pool_block_max_weight->setMaximum(999999999);
        pool_block_max_weight->setValue(4000000);

        formLayout_2->setWidget(10, QFormLayout::FieldRole, pool_block_max_weight);

        pool_real_chain_length = new QSpinBox(scrollAreaWidgetContents_3);
        pool_real_chain_length->setObjectName("pool_real_chain_length");
        pool_real_chain_length->setMaximum(999999999);
        pool_real_chain_length->setValue(400);

        formLayout_2->setWidget(11, QFormLayout::FieldRole, pool_real_chain_length);

        pool_chain_length = new QSpinBox(scrollAreaWidgetContents_3);
        pool_chain_length->setObjectName("pool_chain_length");
        pool_chain_length->setMaximum(999999999);
        pool_chain_length->setValue(400);

        formLayout_2->setWidget(12, QFormLayout::FieldRole, pool_chain_length);

        pool_spread = new QSpinBox(scrollAreaWidgetContents_3);
        pool_spread->setObjectName("pool_spread");
        pool_spread->setMaximum(999999999);
        pool_spread->setValue(3);

        formLayout_2->setWidget(13, QFormLayout::FieldRole, pool_spread);

        label_31 = new QLabel(scrollAreaWidgetContents_3);
        label_31->setObjectName("label_31");

        formLayout_2->setWidget(14, QFormLayout::LabelRole, label_31);

        pool_persist = new QComboBox(scrollAreaWidgetContents_3);
        pool_persist->addItem(QString());
        pool_persist->addItem(QString());
        pool_persist->setObjectName("pool_persist");

        formLayout_2->setWidget(14, QFormLayout::FieldRole, pool_persist);

        pool_min_target = new QLineEdit(scrollAreaWidgetContents_3);
        pool_min_target->setObjectName("pool_min_target");

        formLayout_2->setWidget(15, QFormLayout::FieldRole, pool_min_target);

        pool_max_target = new QLineEdit(scrollAreaWidgetContents_3);
        pool_max_target->setObjectName("pool_max_target");

        formLayout_2->setWidget(16, QFormLayout::FieldRole, pool_max_target);

        pool_donation_script = new QPlainTextEdit(scrollAreaWidgetContents_3);
        pool_donation_script->setObjectName("pool_donation_script");

        formLayout_2->setWidget(17, QFormLayout::FieldRole, pool_donation_script);

        scrollArea_2->setWidget(scrollAreaWidgetContents_3);

        gridLayout_3->addWidget(scrollArea_2, 0, 0, 1, 1);


        gridLayout_5->addWidget(poolGroup, 0, 0, 1, 1);

        parentGroup = new QGroupBox(NetworksTab);
        parentGroup->setObjectName("parentGroup");
        sizePolicy1.setHeightForWidth(parentGroup->sizePolicy().hasHeightForWidth());
        parentGroup->setSizePolicy(sizePolicy1);
        gridLayout_4 = new QGridLayout(parentGroup);
        gridLayout_4->setSpacing(2);
        gridLayout_4->setObjectName("gridLayout_4");
        gridLayout_4->setContentsMargins(2, 2, 2, 2);
        scrollArea = new QScrollArea(parentGroup);
        scrollArea->setObjectName("scrollArea");
        scrollArea->setWidgetResizable(true);
        scrollAreaWidgetContents_2 = new QWidget();
        scrollAreaWidgetContents_2->setObjectName("scrollAreaWidgetContents_2");
        scrollAreaWidgetContents_2->setGeometry(QRect(0, 0, 316, 488));
        formLayout_3 = new QFormLayout(scrollAreaWidgetContents_2);
        formLayout_3->setObjectName("formLayout_3");
        label = new QLabel(scrollAreaWidgetContents_2);
        label->setObjectName("label");

        formLayout_3->setWidget(0, QFormLayout::LabelRole, label);

        parent_symbol = new QLineEdit(scrollAreaWidgetContents_2);
        parent_symbol->setObjectName("parent_symbol");

        formLayout_3->setWidget(0, QFormLayout::FieldRole, parent_symbol);

        label_2 = new QLabel(scrollAreaWidgetContents_2);
        label_2->setObjectName("label_2");

        formLayout_3->setWidget(1, QFormLayout::LabelRole, label_2);

        parent_prefix = new QLineEdit(scrollAreaWidgetContents_2);
        parent_prefix->setObjectName("parent_prefix");

        formLayout_3->setWidget(1, QFormLayout::FieldRole, parent_prefix);

        label_3 = new QLabel(scrollAreaWidgetContents_2);
        label_3->setObjectName("label_3");

        formLayout_3->setWidget(2, QFormLayout::LabelRole, label_3);

        parent_p2p_address = new QLineEdit(scrollAreaWidgetContents_2);
        parent_p2p_address->setObjectName("parent_p2p_address");

        formLayout_3->setWidget(2, QFormLayout::FieldRole, parent_p2p_address);

        label_4 = new QLabel(scrollAreaWidgetContents_2);
        label_4->setObjectName("label_4");

        formLayout_3->setWidget(3, QFormLayout::LabelRole, label_4);

        parent_p2p_port = new QLineEdit(scrollAreaWidgetContents_2);
        parent_p2p_port->setObjectName("parent_p2p_port");

        formLayout_3->setWidget(3, QFormLayout::FieldRole, parent_p2p_port);

        label_5 = new QLabel(scrollAreaWidgetContents_2);
        label_5->setObjectName("label_5");

        formLayout_3->setWidget(4, QFormLayout::LabelRole, label_5);

        parent_addr_version = new QLineEdit(scrollAreaWidgetContents_2);
        parent_addr_version->setObjectName("parent_addr_version");

        formLayout_3->setWidget(4, QFormLayout::FieldRole, parent_addr_version);

        label_6 = new QLabel(scrollAreaWidgetContents_2);
        label_6->setObjectName("label_6");

        formLayout_3->setWidget(5, QFormLayout::LabelRole, label_6);

        parent_addr_p2sh_version = new QLineEdit(scrollAreaWidgetContents_2);
        parent_addr_p2sh_version->setObjectName("parent_addr_p2sh_version");

        formLayout_3->setWidget(5, QFormLayout::FieldRole, parent_addr_p2sh_version);

        label_7 = new QLabel(scrollAreaWidgetContents_2);
        label_7->setObjectName("label_7");

        formLayout_3->setWidget(6, QFormLayout::LabelRole, label_7);

        parent_rpc_port = new QLineEdit(scrollAreaWidgetContents_2);
        parent_rpc_port->setObjectName("parent_rpc_port");

        formLayout_3->setWidget(6, QFormLayout::FieldRole, parent_rpc_port);

        label_8 = new QLabel(scrollAreaWidgetContents_2);
        label_8->setObjectName("label_8");

        formLayout_3->setWidget(7, QFormLayout::LabelRole, label_8);

        parent_block_period = new QLineEdit(scrollAreaWidgetContents_2);
        parent_block_period->setObjectName("parent_block_period");

        formLayout_3->setWidget(7, QFormLayout::FieldRole, parent_block_period);

        label_9 = new QLabel(scrollAreaWidgetContents_2);
        label_9->setObjectName("label_9");

        formLayout_3->setWidget(8, QFormLayout::LabelRole, label_9);

        parent_dumb_scrypt_diff = new QLineEdit(scrollAreaWidgetContents_2);
        parent_dumb_scrypt_diff->setObjectName("parent_dumb_scrypt_diff");

        formLayout_3->setWidget(8, QFormLayout::FieldRole, parent_dumb_scrypt_diff);

        label_10 = new QLabel(scrollAreaWidgetContents_2);
        label_10->setObjectName("label_10");

        formLayout_3->setWidget(9, QFormLayout::LabelRole, label_10);

        parent_dust_threshold = new QLineEdit(scrollAreaWidgetContents_2);
        parent_dust_threshold->setObjectName("parent_dust_threshold");

        formLayout_3->setWidget(9, QFormLayout::FieldRole, parent_dust_threshold);

        label_11 = new QLabel(scrollAreaWidgetContents_2);
        label_11->setObjectName("label_11");
        label_11->setAutoFillBackground(false);

        formLayout_3->setWidget(10, QFormLayout::LabelRole, label_11);

        parent_sane_target_min = new QLineEdit(scrollAreaWidgetContents_2);
        parent_sane_target_min->setObjectName("parent_sane_target_min");

        formLayout_3->setWidget(10, QFormLayout::FieldRole, parent_sane_target_min);

        label_12 = new QLabel(scrollAreaWidgetContents_2);
        label_12->setObjectName("label_12");

        formLayout_3->setWidget(11, QFormLayout::LabelRole, label_12);

        parent_sane_target_max = new QLineEdit(scrollAreaWidgetContents_2);
        parent_sane_target_max->setObjectName("parent_sane_target_max");

        formLayout_3->setWidget(11, QFormLayout::FieldRole, parent_sane_target_max);

        label_13 = new QLabel(scrollAreaWidgetContents_2);
        label_13->setObjectName("label_13");

        formLayout_3->setWidget(12, QFormLayout::LabelRole, label_13);

        parent_pow_func = new QComboBox(scrollAreaWidgetContents_2);
        parent_pow_func->addItem(QString());
        parent_pow_func->setObjectName("parent_pow_func");

        formLayout_3->setWidget(12, QFormLayout::FieldRole, parent_pow_func);

        label_14 = new QLabel(scrollAreaWidgetContents_2);
        label_14->setObjectName("label_14");

        formLayout_3->setWidget(13, QFormLayout::LabelRole, label_14);

        parent_subsidy_func = new QComboBox(scrollAreaWidgetContents_2);
        parent_subsidy_func->addItem(QString());
        parent_subsidy_func->setObjectName("parent_subsidy_func");

        formLayout_3->setWidget(13, QFormLayout::FieldRole, parent_subsidy_func);

        label_15 = new QLabel(scrollAreaWidgetContents_2);
        label_15->setObjectName("label_15");

        formLayout_3->setWidget(14, QFormLayout::LabelRole, label_15);

        parent_block_explorer_url_prefix = new QLineEdit(scrollAreaWidgetContents_2);
        parent_block_explorer_url_prefix->setObjectName("parent_block_explorer_url_prefix");

        formLayout_3->setWidget(14, QFormLayout::FieldRole, parent_block_explorer_url_prefix);

        label_16 = new QLabel(scrollAreaWidgetContents_2);
        label_16->setObjectName("label_16");

        formLayout_3->setWidget(15, QFormLayout::LabelRole, label_16);

        label_17 = new QLabel(scrollAreaWidgetContents_2);
        label_17->setObjectName("label_17");

        formLayout_3->setWidget(16, QFormLayout::LabelRole, label_17);

        parent_address_explorer_url_prefix = new QLineEdit(scrollAreaWidgetContents_2);
        parent_address_explorer_url_prefix->setObjectName("parent_address_explorer_url_prefix");

        formLayout_3->setWidget(15, QFormLayout::FieldRole, parent_address_explorer_url_prefix);

        parent_tx_explorer_url_prefix = new QLineEdit(scrollAreaWidgetContents_2);
        parent_tx_explorer_url_prefix->setObjectName("parent_tx_explorer_url_prefix");

        formLayout_3->setWidget(16, QFormLayout::FieldRole, parent_tx_explorer_url_prefix);

        scrollArea->setWidget(scrollAreaWidgetContents_2);

        gridLayout_4->addWidget(scrollArea, 0, 0, 1, 1);


        gridLayout_5->addWidget(parentGroup, 0, 1, 1, 1);


        formLayout->setLayout(0, QFormLayout::SpanningRole, gridLayout_5);

        tabWidget->addTab(NetworksTab, QString());

        gridLayout->addWidget(tabWidget, 0, 0, 1, 1);


        retranslateUi(C2poolSettingsForm);

        tabWidget->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(C2poolSettingsForm);
    } // setupUi

    void retranslateUi(QWidget *C2poolSettingsForm)
    {
        C2poolSettingsForm->setWindowTitle(QCoreApplication::translate("C2poolSettingsForm", "C2pool setting", nullptr));
        config_testnet->setText(QCoreApplication::translate("C2poolSettingsForm", "Testnet", nullptr));
        label_35->setText(QCoreApplication::translate("C2poolSettingsForm", "Address", nullptr));
        config_address->setText(QString());
        label_36->setText(QCoreApplication::translate("C2poolSettingsForm", "Numaddresses", nullptr));
        config_numaddresses->setPlaceholderText(QString());
        label_37->setText(QCoreApplication::translate("C2poolSettingsForm", "Timeaddresses", nullptr));
        config_timeaddresses->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "172800", nullptr));
        label_38->setText(QCoreApplication::translate("C2poolSettingsForm", "Coind Address", nullptr));
        config_coind_address->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "0.0.0.0", nullptr));
        label_39->setText(QCoreApplication::translate("C2poolSettingsForm", "Coind P2P Port", nullptr));
        label_40->setText(QCoreApplication::translate("C2poolSettingsForm", "Coind Config Path", nullptr));
        label_41->setText(QCoreApplication::translate("C2poolSettingsForm", "Coind RPC SSL", nullptr));
        label_42->setText(QCoreApplication::translate("C2poolSettingsForm", "Coind RPC Port", nullptr));
        label_43->setText(QCoreApplication::translate("C2poolSettingsForm", "Coind RPC Userpass", nullptr));
        config_coind_rpc_port->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "19332", nullptr));
        config_coind_rpc_userpass->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "user:pass", nullptr));
        label_44->setText(QCoreApplication::translate("C2poolSettingsForm", "C2pool Port", nullptr));
        config_c2pool_port->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "3037", nullptr));
        label_45->setText(QCoreApplication::translate("C2poolSettingsForm", "Max conns", nullptr));
        config_max_conns->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "40", nullptr));
        label_46->setText(QCoreApplication::translate("C2poolSettingsForm", "Outgoing conns", nullptr));
        config_outgoing_conns->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "6", nullptr));
        label_47->setText(QCoreApplication::translate("C2poolSettingsForm", "Max attempts", nullptr));
        config_max_attempts->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "10", nullptr));
        label_48->setText(QCoreApplication::translate("C2poolSettingsForm", "Worker port", nullptr));
        config_worker_port->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "5027", nullptr));
        label_49->setText(QCoreApplication::translate("C2poolSettingsForm", "Worker Fee", nullptr));
        config_worker_fee->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "0", nullptr));
        config_coind_rpc_ssl->setText(QString());
        tabWidget->setTabText(tabWidget->indexOf(ConfigTab), QCoreApplication::translate("C2poolSettingsForm", "Config", nullptr));
        poolGroup->setTitle(QCoreApplication::translate("C2poolSettingsForm", "Pool", nullptr));
        label_18->setText(QCoreApplication::translate("C2poolSettingsForm", "SOFTFORKS REQUIRED", nullptr));
        pool_softforks_req->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "bip65 csv segwit taproot mweb", nullptr));
        label_19->setText(QCoreApplication::translate("C2poolSettingsForm", "BOOTSTRAP ADDRS", nullptr));
        pool_bootstrap_addrs->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "0.0.0.0:19338 0.0.0.0:19339 etc...", nullptr));
        label_20->setText(QCoreApplication::translate("C2poolSettingsForm", "Prefix", nullptr));
        label_21->setText(QCoreApplication::translate("C2poolSettingsForm", "Identifier", nullptr));
        label_22->setText(QCoreApplication::translate("C2poolSettingsForm", "Min protocol ver.", nullptr));
        label_23->setText(QCoreApplication::translate("C2poolSettingsForm", "Segwit activation ver.", nullptr));
        label_24->setText(QCoreApplication::translate("C2poolSettingsForm", "Target lookbehind", nullptr));
        label_25->setText(QCoreApplication::translate("C2poolSettingsForm", "Share period", nullptr));
        label_26->setText(QCoreApplication::translate("C2poolSettingsForm", "Block max size", nullptr));
        label_27->setText(QCoreApplication::translate("C2poolSettingsForm", "Block max weight", nullptr));
        label_28->setText(QCoreApplication::translate("C2poolSettingsForm", "Real chain length", nullptr));
        label_29->setText(QCoreApplication::translate("C2poolSettingsForm", "Chain length", nullptr));
        label_30->setText(QCoreApplication::translate("C2poolSettingsForm", "Spread", nullptr));
        label_32->setText(QCoreApplication::translate("C2poolSettingsForm", "Min target", nullptr));
        label_33->setText(QCoreApplication::translate("C2poolSettingsForm", "Max target", nullptr));
        label_34->setText(QCoreApplication::translate("C2poolSettingsForm", "Donation Script", nullptr));
        pool_prefix->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "(hex) ad9614f6466a39cf", nullptr));
        pool_identifier->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "(hex) cca5e24ec6408b1e", nullptr));
        label_31->setText(QCoreApplication::translate("C2poolSettingsForm", "Persist", nullptr));
        pool_persist->setItemText(0, QCoreApplication::translate("C2poolSettingsForm", "disable", nullptr));
        pool_persist->setItemText(1, QCoreApplication::translate("C2poolSettingsForm", "enable", nullptr));

        pool_min_target->setText(QString());
        pool_min_target->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "(hex) 0", nullptr));
        pool_max_target->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "(hex) ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccb", nullptr));
        pool_donation_script->setPlainText(QCoreApplication::translate("C2poolSettingsForm", "4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac", nullptr));
        pool_donation_script->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "(hex)", nullptr));
        parentGroup->setTitle(QCoreApplication::translate("C2poolSettingsForm", "Parent", nullptr));
        label->setText(QCoreApplication::translate("C2poolSettingsForm", "Symbol", nullptr));
        parent_symbol->setText(QString());
        parent_symbol->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "LTC, BTC, ETH, ...", nullptr));
        label_2->setText(QCoreApplication::translate("C2poolSettingsForm", "Prefix", nullptr));
        parent_prefix->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "(hex) fdd2c8f1", nullptr));
        label_3->setText(QCoreApplication::translate("C2poolSettingsForm", "P2P Address", nullptr));
        parent_p2p_address->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "0.0.0.0", nullptr));
        label_4->setText(QCoreApplication::translate("C2poolSettingsForm", "P2P Port", nullptr));
        parent_p2p_port->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "19335", nullptr));
        label_5->setText(QCoreApplication::translate("C2poolSettingsForm", "Addr ver.", nullptr));
        parent_addr_version->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "111", nullptr));
        label_6->setText(QCoreApplication::translate("C2poolSettingsForm", "Addr P2SH ver.", nullptr));
        parent_addr_p2sh_version->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "58", nullptr));
        label_7->setText(QCoreApplication::translate("C2poolSettingsForm", "RPC Port'", nullptr));
        parent_rpc_port->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "19332", nullptr));
        label_8->setText(QCoreApplication::translate("C2poolSettingsForm", "Block period", nullptr));
        parent_block_period->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "150", nullptr));
        label_9->setText(QCoreApplication::translate("C2poolSettingsForm", "Dumb SCRYPT DIFF", nullptr));
        parent_dumb_scrypt_diff->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "(hex) 10000", nullptr));
        label_10->setText(QCoreApplication::translate("C2poolSettingsForm", "DUST THRESHOLD", nullptr));
        parent_dust_threshold->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "(hex) 100000000", nullptr));
        label_11->setText(QCoreApplication::translate("C2poolSettingsForm", "SANE_TARGET_MIN", nullptr));
        parent_sane_target_min->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "(hex) 80000000000000000000000000000000", nullptr));
        label_12->setText(QCoreApplication::translate("C2poolSettingsForm", "SANE_TARGET_MAX", nullptr));
        parent_sane_target_max->setText(QString());
        parent_sane_target_max->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "(hex) 800000000000000000000000000000000000000000000000000000000000", nullptr));
        label_13->setText(QCoreApplication::translate("C2poolSettingsForm", "POW FUNC", nullptr));
        parent_pow_func->setItemText(0, QCoreApplication::translate("C2poolSettingsForm", "scrypt", nullptr));

        label_14->setText(QCoreApplication::translate("C2poolSettingsForm", "SUBSIDY FUNC", nullptr));
        parent_subsidy_func->setItemText(0, QCoreApplication::translate("C2poolSettingsForm", "ltc", nullptr));

        label_15->setText(QCoreApplication::translate("C2poolSettingsForm", "BLOCK_EXPLORER_URL_PREFIX", nullptr));
        parent_block_explorer_url_prefix->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "https://chain.so/block/LTCTEST/", nullptr));
        label_16->setText(QCoreApplication::translate("C2poolSettingsForm", "ADDRESS_EXPLORER_URL_PREFIX", nullptr));
        label_17->setText(QCoreApplication::translate("C2poolSettingsForm", "TX_EXPLORER_URL_PREFIX", nullptr));
        parent_address_explorer_url_prefix->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "https://chain.so/address/LTCTEST/", nullptr));
        parent_tx_explorer_url_prefix->setPlaceholderText(QCoreApplication::translate("C2poolSettingsForm", "https://chain.so/tx/LTCTEST/", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(NetworksTab), QCoreApplication::translate("C2poolSettingsForm", "Networks", nullptr));
    } // retranslateUi

};

namespace Ui {
    class C2poolSettingsForm: public Ui_C2poolSettingsForm {};
} // namespace Ui

QT_END_NAMESPACE

#endif // NET_CONFIGUREQBXPWU_H
