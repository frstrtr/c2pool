#include "stratum.h"
#include <libnet/worker.h>

namespace coind::jsonrpc
{
    svc_mining reverse_string_svc_mining(std::string key)
    {
        try
        {
            return _reverse_string_svc_mining.at(key);
        }
        catch (const std::out_of_range &e)
        {
            LOG_WARNING << "\"" << key << "\" out of range in reverse_svc_mining";
            return svc_mining::error;
        }
    }

    Proxy::Proxy(shared_ptr<coind::jsonrpc::StratumRPC> _rpc) : rpc(_rpc)
    {
    }

    void Proxy::send(std::string method, UniValue params)
    {
        int32_t _id = 0; //TODO: ?

        UniValue data(UniValue::VOBJ);
        data.pushKV("jsonrpc", "2.0");
        data.pushKV("method", method);
        data.pushKV("params", params);
        data.pushKV("id", _id);

        string data_str = data.write();
        boost::asio::async_write(rpc.lock()->_socket, boost::asio::buffer(data_str, data_str.size()), [](const boost::system::error_code &ec, std::size_t len)
                                 {
                                     if (!ec)
                                     {
                                     }
                                     else
                                     {
                                         cout << "Proxy::send async_write error: " << ec.message() << endl;
                                     }
                                 });
    }

    StratumRPC::StratumRPC(ip::tcp::socket __socket) : _socket(std::move(__socket))
    {
        cout << "1" << endl;
        read();
    }

    void StratumRPC::handle(UniValue req)
    {
        if (req.exists("error") || req.exists("result"))
        {
            return;
        }

        if (!(req.exists("id") && req.exists("method") && req.exists("params")))
        {
            //TODO: error
            return;
        }

        auto id = req["id"].get_int();

        auto method_str = req["method"].get_str();
        std::vector<string> methods;
        boost::split(methods, method_str, boost::is_any_of("."));

        auto params = req["params"].get_array();

        if (methods[0] != "mining")
        {
            //TODO: error
            return;
        }

        svc_mining method_code = reverse_string_svc_mining(methods[1].c_str());
        UniValue result;
        UniValue error;

        switch (method_code)
        {
        case svc_mining::authorize:
            break;
        case svc_mining::capabilities:
            break;
        case svc_mining::get_transactions:
            break;
        case svc_mining::submit:
            break;
        case svc_mining::subscribe:
            result = rpc_subscribe(params);
            break;
        case svc_mining::suggest_difficulty:
            break;
        case svc_mining::suggest_target:
            break;
        default:
            break;
        }

        UniValue returnValue(UniValue::VOBJ);
        returnValue.pushKV("jsonrpc", "2.0");
        returnValue.pushKV("id", id);
        returnValue.pushKV("result", result);
        returnValue.pushKV("error", error);

        string return_data = returnValue.write();
        cout << return_data << endl;
        boost::asio::async_write(_socket, boost::asio::buffer(return_data, return_data.size()), [&](const boost::system::error_code &ec, std::size_t len)
                                 {
                                     if (!ec)
                                     {
                                     }
                                     cout << "Writed data: " << ec.message() << endl;
                                 });
    }

    StratumNode::StratumNode(const ip::tcp::endpoint &listen_ep, const c2pool::libnet::NodeMember &member) : NodeMember(member), _context(1), _acceptor(_context, listen_ep)
    {
        _thread.reset(new std::thread([&]()
                                      {
                                          start();
                                          _context.run();
                                      }));
    }
}