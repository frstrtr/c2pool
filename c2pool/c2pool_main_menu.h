#pragma once
#include <QtWidgets/QApplication>
#include <QEventLoop>
#include <QDialog>
#include <QDir>
#include <QSettings>
#include <utility>

#include "ui/main_menu.h"
#include "ui/configure_window.h"

namespace c2pool::ui
{
    class NetworkConfigWindow : public Ui::C2poolSettingsForm, public QDialog
    {
        QString net_name;
    public:
        explicit NetworkConfigWindow(QString _net_name) : net_name(std::move(_net_name))
        {
            setupUi(this);
        }

        void save()
        {
            auto cfgPath = QApplication::applicationDirPath() + "/" + net_name + "/";
            QSettings net(cfgPath + "network.cfg", QSettings::IniFormat);

            //Network
            //--Pool Network
            net.setValue("network/SOFTFORKS_REQUIRED", pool_softforks_req->text());
            net.setValue("network/BOOTSTRAP_ADDRS", pool_bootstrap_addrs->text());
            net.setValue("network/PREFIX", pool_prefix->text());
            net.setValue("network/IDENTIFIER", pool_identifier->text());
            net.setValue("network/MINIMUM_PROTOCOL_VERSION", pool_min_protocol_ver->text());
            net.setValue("network/SEGWIT_ACTIVATION_VERSION", pool_segwit_activation_ver->text());
            net.setValue("network/TARGET_LOOKBEHIND", pool_target_lookbehind->text());
            net.setValue("network/SHARE_PERIOD", pool_share_period->text());
            net.setValue("network/BLOCK_MAX_SIZE", pool_block_max_size->text());
            net.setValue("network/BLOCK_MAX_WEIGHT", pool_block_max_weight->text());
            net.setValue("network/REAL_CHAIN_LENGTH", pool_real_chain_length->text());
            net.setValue("network/CHAIN_LENGTH", pool_chain_length->text());
            net.setValue("network/SPREAD", pool_spread->text());
            net.setValue("network/PERSIST", (bool) pool_persist->currentIndex());
            net.setValue("network/MIN_TARGET", pool_min_target->text());
            net.setValue("network/MAX_TARGET", pool_max_target->text());
            net.setValue("network/DONATION_SCRIPT", pool_donation_script->toPlainText());

            //--Parent Network
            net.setValue("parent_network/SYMBOL", parent_symbol->text());
            net.setValue("parent_network/PREFIX", parent_prefix->text());
            net.setValue("parent_network/P2P_ADDRESS", parent_p2p_address->text());
            net.setValue("parent_network/P2P_PORT", parent_p2p_port->text());
            net.setValue("parent_network/ADDRESS_VERSION", parent_addr_version->text());
            net.setValue("parent_network/ADDRESS_P2SH_VERSION", parent_addr_p2sh_version->text());
            net.setValue("parent_network/RPC_PORT", parent_rpc_port->text());
            net.setValue("parent_network/BLOCK_PERIOD", parent_block_period->text());
            net.setValue("parent_network/DUMB_SCRYPT_DIFF", parent_dumb_scrypt_diff->text());
            net.setValue("parent_network/DUST_THRESHOLD", parent_dust_threshold->text());
            net.setValue("parent_network/SANE_TARGET_RANGE_MIN", parent_sane_target_min->text());
            net.setValue("parent_network/SANE_TARGET_RANGE_MAX", parent_sane_target_max->text());
            net.setValue("parent_network/POW_FUNC", parent_pow_func->currentText());
            net.setValue("parent_network/SUBSIDY_FUNC", parent_subsidy_func->currentText());
            net.setValue("parent_network/BLOCK_EXPLORER_URL_PREFIX", parent_block_explorer_url_prefix->text());
            net.setValue("parent_network/ADDRESS_EXPLORER_URL_PREFIX", parent_address_explorer_url_prefix->text());
            net.setValue("parent_network/TX_EXPLORER_URL_PREFIX", parent_tx_explorer_url_prefix->text());

            //Config
            QSettings cfg(cfgPath + "config.cfg", QSettings::IniFormat);

            cfg.setValue("testnet", config_testnet->isChecked());
            cfg.setValue("address", config_address->text());
            cfg.setValue("numaddresses", config_numaddresses->text());
            cfg.setValue("timeaddresses", config_timeaddresses->text());
            cfg.setValue("coind/coind-address", config_coind_address->text());
            cfg.setValue("coind/coind-p2p-port", config_coind_p2p_port->text());
            cfg.setValue("coind/coind-config-path", config_coind_config_path->text());
            cfg.setValue("coind/coind-rpc-ssl", config_coind_rpc_ssl->isChecked());
            cfg.setValue("coind/coind-rpc-port", config_coind_rpc_port->text());
            cfg.setValue("coind/coind_rpc_userpass", config_coind_rpc_userpass->text());
            cfg.setValue("pool/c2pool_port", config_c2pool_port->text());
            cfg.setValue("pool/max_conns", config_max_conns->text());
            cfg.setValue("pool/outgoing_conns", config_outgoing_conns->text());
            cfg.setValue("pool/max_attempts", config_max_attempts->text());
            cfg.setValue("worker/worker_port", config_worker_port->text());
            cfg.setValue("worker/fee", config_worker_fee->text());

        }

        void load()
        {
            auto cfgPath = QApplication::applicationDirPath() + "/" + net_name + "/";
            QSettings net(cfgPath + "network.cfg", QSettings::IniFormat);

            //Network
            //--Pool Network
            pool_softforks_req->setText(net.value("network/SOFTFORKS_REQUIRED").toString());
            pool_bootstrap_addrs->setText(net.value("network/BOOTSTRAP_ADDRS").toString());
            pool_prefix->setText(net.value("network/PREFIX").toString());
            pool_identifier->setText(net.value("network/IDENTIFIER").toString());
            pool_min_protocol_ver->setValue(net.value("network/MINIMUM_PROTOCOL_VERSION").toInt());
            pool_segwit_activation_ver->setValue(net.value("network/SEGWIT_ACTIVATION_VERSION").toInt());
            pool_target_lookbehind->setValue(net.value("network/TARGET_LOOKBEHIND").toInt());
            pool_share_period->setValue(net.value("network/SHARE_PERIOD").toInt());
            pool_block_max_size->setValue(net.value("network/BLOCK_MAX_SIZE").toInt());
            pool_block_max_weight->setValue(net.value("network/BLOCK_MAX_WEIGHT").toInt());
            pool_real_chain_length->setValue(net.value("network/REAL_CHAIN_LENGTH").toInt());
            pool_chain_length->setValue(net.value("network/CHAIN_LENGTH").toInt());
            pool_spread->setValue(net.value("network/SPREAD").toInt());
            pool_persist->setCurrentIndex((int) net.value("network/PERSIST").toBool());
            pool_min_target->setText(net.value("network/MIN_TARGET").toString());
            pool_max_target->setText(net.value("network/MAX_TARGET").toString());
            pool_donation_script->setPlainText(net.value("network/DONATION_SCRIPT").toString());

            //--Parent Network
            parent_symbol->setText(net.value("parent_network/SYMBOL").toString());
            parent_prefix->setText(net.value("parent_network/PREFIX").toString());
            parent_p2p_address->setText(net.value("parent_network/P2P_ADDRESS").toString());
            parent_p2p_port->setText(net.value("parent_network/P2P_PORT").toString());
            parent_addr_version->setText(net.value("parent_network/ADDRESS_VERSION").toString());
            parent_addr_p2sh_version->setText(net.value("parent_network/ADDRESS_P2SH_VERSION").toString());
            parent_rpc_port->setText(net.value("parent_network/RPC_PORT").toString());
            parent_block_period->setText(net.value("parent_network/BLOCK_PERIOD").toString());
            parent_dumb_scrypt_diff->setText(net.value("parent_network/DUMB_SCRYPT_DIFF").toString());
            parent_dust_threshold->setText(net.value("parent_network/DUST_THRESHOLD").toString());
            parent_sane_target_min->setText(net.value("parent_network/SANE_TARGET_RANGE_MIN").toString());
            parent_sane_target_max->setText(net.value("parent_network/SANE_TARGET_RANGE_MAX").toString());
            parent_pow_func->setCurrentIndex(
                    parent_pow_func->findText(net.value("parent_network/POW_FUNC").toString()));
            parent_subsidy_func->setCurrentIndex(
                    parent_subsidy_func->findText(net.value("parent_network/SUBSIDY_FUNC").toString()));
            parent_block_explorer_url_prefix->setText(net.value("parent_network/BLOCK_EXPLORER_URL_PREFIX").toString());
            parent_address_explorer_url_prefix->setText(
                    net.value("parent_network/ADDRESS_EXPLORER_URL_PREFIX").toString());
            parent_tx_explorer_url_prefix->setText(net.value("parent_network/TX_EXPLORER_URL_PREFIX").toString());

            //Config
            QSettings cfg(cfgPath + "config.cfg", QSettings::IniFormat);

            config_testnet->setChecked(cfg.value("testnet").toBool());
            config_address->setText(cfg.value("address").toString());
            config_numaddresses->setText(cfg.value("numaddresses").toString());
            config_timeaddresses->setText(cfg.value("timeaddresses").toString());
            config_coind_address->setText(cfg.value("coind/coind-address").toString());
            config_coind_p2p_port->setText(cfg.value("coind/coind-p2p-port").toString());
            config_coind_config_path->setText(cfg.value("coind/coind-config-path").toString());
            config_coind_rpc_ssl->setChecked(cfg.value("coind/coind-rpc-ssl").toBool());
            config_coind_rpc_port->setText(cfg.value("coind/coind-rpc-port").toString());
            config_coind_rpc_userpass->setText(cfg.value("coind/coind_rpc_userpass").toString());
            config_c2pool_port->setText(cfg.value("pool/c2pool_port").toString());
            config_max_conns->setText(cfg.value("pool/max_conns").toString());
            config_outgoing_conns->setText(cfg.value("pool/outgoing_conns").toString());
            config_max_attempts->setText(cfg.value("pool/max_attempts").toString());
            config_worker_port->setText(cfg.value("worker/worker_port").toString());
            config_worker_fee->setText(cfg.value("worker/fee").toString());
        }
    };

    class MainMenu
    {
        QMainWindow *window;
        Ui::c2pool_menu *main_menu;
        QSettings *networks;

    private:
        void open_configure()
        {
            QString net_name;
            if (main_menu->networks->count())
                net_name = main_menu->networks->currentText();
            else
                return;

            window->setEnabled(false);

//        NetworkConfigWindow d("tLC");
            NetworkConfigWindow d(net_name);
            d.load();

            if (!d.exec())
            {
                d.save();
                window->setEnabled(true);
            }
        }

        void recalculate_networks()
        {
            main_menu->networks->clear();

            if (networks->allKeys().empty())
            {
                main_menu->networks->setEnabled(false);
                main_menu->deleteNetwork->setEnabled(false);
                main_menu->configure_button->setEnabled(false);
            } else
            {
                main_menu->networks->setEnabled(true);
                main_menu->deleteNetwork->setEnabled(true);
                main_menu->configure_button->setEnabled(true);
            }

            for (const auto &net: networks->allKeys())
            {
                main_menu->networks->addItem(net);
            }
        }

        void create_new_network()
        {
            auto net_name = main_menu->new_net_name->text();
            if (main_menu->new_net_name->text().isEmpty() || networks->contains(net_name))
            {
                return;
            }

//        qDebug() << main_menu->new_net_name->text();

            networks->setValue(net_name, true);
            QDir().mkdir(net_name);

            recalculate_networks();
            main_menu->networks->setCurrentIndex(main_menu->networks->count() - 1);
        }

        void delete_network()
        {
            auto selected_net = main_menu->networks->currentText();
//        qDebug() << QDir(selected_net);
            QDir(selected_net).removeRecursively();
            networks->remove(selected_net);
            recalculate_networks();
        }

    public:
        MainMenu()
        {
            window = new QMainWindow();

            main_menu = new Ui::c2pool_menu();
            main_menu->setupUi(window);

            networks = new QSettings(QApplication::applicationDirPath() + "/networks.cfg", QSettings::IniFormat);
//        config_window = new QWidget();
//        settings = new Ui::C2poolSettingsForm();
//        settings->setupUi(config_window);

            // open configure menu button
            QObject::connect(main_menu->configure_button, &QPushButton::clicked, main_menu->configure_button, [&]()
            {
                open_configure();
            });

            // create new network button
            QObject::connect(main_menu->new_net_button, &QPushButton::clicked, main_menu->new_net_button, [&]()
            {
                create_new_network();
            });

            // create delete network button
            QObject::connect(main_menu->deleteNetwork, &QPushButton::clicked, main_menu->deleteNetwork, [&]()
            {
                delete_network();
            });

            recalculate_networks();

        }

        void show() const
        {
            window->show();
        }
    };
}