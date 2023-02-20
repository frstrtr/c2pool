#include "config.h"

#include <fstream>
#include <istream>
#include <string>


namespace c2pool::dev
{
    c2pool_config *c2pool_config::_instance = nullptr;

    std::istream &operator>>(std::istream &in, c2pool::dev::DebugState &value)
    {
        int token;
        try
        {
            in >> token;
            value = (c2pool::dev::DebugState) token;
        } catch (...)
        {
            throw std::invalid_argument("Invalid DebugState!");
        }
        return in;
    }

    void c2pool_config::INIT()
    {
        if (_instance == nullptr)
        {
            _instance = new c2pool_config();
        }
        else
        {
            //TODO: [LOG] instance already exists
        }
    }

    c2pool_config *c2pool_config::get()
    {
        //TODO: check for exist _instance
        return _instance;
    }

    std::shared_ptr<coind_config> load_config_file(const std::string &name)
    {
        auto path = boost::filesystem::current_path() / name;

        // Проверка на существование пути, создание его, в случае отсутствия.
        boost::system::error_code ec;
        if (!boost::filesystem::exists(path))
        {
            boost::filesystem::create_directories(path, ec);
            if (ec)
                std::cout << "Error when opening config[" << name << "] " << ".cfg: " << ec.message() << std::endl;
        }

        // Проверка и создание default config файла.
        if (!boost::filesystem::exists(path/"config.cfg"))
        {
            std::fstream f((path/"config.cfg").string(), std::ios_base::out);
            boost::property_tree::write_ini(f, c2pool::dev::coind_config::make_default_config());
            f.close();
        }

        // Загрузка из файла
        boost::property_tree::ptree pt;
        boost::property_tree::ini_parser::read_ini((path/"config.cfg").string(), pt);

        return std::make_shared<c2pool::dev::coind_config>(name, pt);
    }

    coind_config::coind_config(std::string _name, boost::property_tree::ptree &pt) : coind_config(std::move(_name))
    {
        testnet = pt.get<bool>("testnet");
        address = pt.get<std::string>("address");
        numaddresses = pt.get<int>("numaddresses");
        timeaddresses = pt.get<int>("timeaddresses");

        // Coind
        auto _coind = pt.get_child("coind");
        coind_ip = _coind.get<std::string>("coind-address");
        coind_port = _coind.get<std::string>("coind-p2p-port");
        coind_config_path = _coind.get<std::string>("coind-config-path");
        coind_rpc_ssl = _coind.get<bool>("coind-rpc-ssl");
        jsonrpc_coind_port = _coind.get<std::string>("coind-rpc-port");
        jsonrpc_coind_login = _coind.get<std::string>("coind_rpc_userpass");

        // Pool Node
        auto _node = pt.get_child("pool");
        c2pool_port = _node.get<int>("c2pool_port");
        max_conns = _node.get<int>("max_conns");
        desired_conns = _node.get<int>("outgoing_conns");
        max_attempts = _node.get<int>("max_attempts");

        // Worker
        auto _worker = pt.get_child("worker");
        worker_port = _worker.get<std::string>("worker_port");
        fee = _worker.get<float>("fee");
    }

    boost::property_tree::ptree coind_config::make_default_config()
    {
        using boost::property_tree::ptree;

        ptree root;

        root.put("testnet", false);
        root.put("address", "");
        root.put("numaddresses", 2);
        root.put("timeaddresses", 172800);

        // Coind
        ptree coind;
        coind.put("coind-address", "127.0.0.1");
        coind.put("coind-p2p-port", "");
        coind.put("coind-config-path", "");
        coind.put("coind-rpc-ssl", false);
        coind.put("coind-rpc-port", "");
        coind.put("coind_rpc_userpass", "");

        // Pool Node
        ptree pool;
        pool.put("c2pool_port", 3037);
        pool.put("max_conns", 40);
        pool.put("outgoing_conns", 6);
        pool.put("max_attempts", 10);

        // Worker
        ptree worker;
        worker.put("worker_port", 5027);
        worker.put("fee", 0);

        root.push_back(
                ptree::value_type("coind", coind)
        );
        root.push_back(
                ptree::value_type("pool", pool)
        );
        root.push_back(
                ptree::value_type("worker", worker)
        );

        return root;
    }

} // namespace c2pool::dev