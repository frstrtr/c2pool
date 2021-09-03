#include <memory>
#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <thread>
#include <string>
#include <set>
#include <tuple>
#include <libnet/node_member.h>
#include <univalue.h>
#include <boost/algorithm/string.hpp>

namespace io = boost::asio;
namespace ip = io::ip;

using namespace std;
namespace c2pool
{
    namespace libnet
    {
        class Worker;
    }
}

namespace coind::jsonrpc
{
    struct StratumMessage
    {
        boost::asio::streambuf b;
        std::string d;
    };

    enum svc_mining
    {
        error,
        authorize,
        capabilities,
        get_transactions,
        submit,
        subscribe,
        suggest_difficulty,
        suggest_target
    };

    const std::map<std::string, svc_mining> _reverse_string_svc_mining = {
        {"error", svc_mining::error},
        {"authorize", svc_mining::authorize},
        {"capabilities", svc_mining::capabilities},
        {"get_transactions", svc_mining::get_transactions},
        {"submit", svc_mining::submit},
        {"subscribe", svc_mining::subscribe},
        {"suggest_difficulty", svc_mining::suggest_difficulty},
        {"suggest_target", svc_mining::suggest_target},
    };

    svc_mining reverse_string_svc_mining(std::string key);

    struct StratumRPC
    {
        //TODO: shared_ptr<c2pool::libnet::Worker> worker; //in p2pool - wb/WorkerBridge
        ip::tcp::socket _socket;
        string username;

        StratumRPC(ip::tcp::socket __socket);

        void read()
        {
            cout << "Start to read" << endl;
            auto msg = std::make_shared<StratumMessage>();
            // boost::asio::streambuf b;
            // io::async_read_until(_socket, b, '\n', [this, &b, msg](boost::system::error_code ec, std::size_t len)
            //                      {
            //                          cout << "Read until msg" << endl;
            //                          std::istream is(&b);
            //                          std::getline(is, msg->data);
            //                          cout << msg->data << endl;
            //                      });

            io::async_read_until(_socket, msg->b, "\n",
                                 [this, msg](const boost::system::error_code &ec, std::size_t len)
                                 {
                                     cout << "accepted msg: " << ec.value() << endl;
                                     if (!ec)
                                     {
                                         cout << "accepted msg!" << endl;
                                         std::istream is(&msg->b);
                                         std::getline(is, msg->d);

                                         cout << "Encoded msg: " << msg->d << endl;

                                         UniValue decoded_message;
                                         decoded_message.read(msg->d);

                                         cout << "decoded msg: " << decoded_message.write() << endl;
                                         handle(decoded_message);

                                         read();
                                     }
                                     else
                                     {
                                         cout << ec.message() << endl;
                                     }
                                 });

            // io::async_read(_socket, boost::asio::buffer(msg->data, 4),
            //                [this, msg](boost::system::error_code ec, std::size_t len)
            //                {
            //                    cout << msg->data << endl;
            //                    //TODO: postprocess for data
            //                });
        }

        void handle(UniValue req);

        UniValue rpc_authorize(string _username, string password)
        {
            username = _username;
        }

        UniValue rpc_subscribe(UniValue params)
        {
            cout << "Called rpc_subscribe" << endl;
            //TODO: _send_work

            UniValue result(UniValue::VARR);

            UniValue sub_details(UniValue::VARR);
            sub_details.push_back("mining.notify");
            sub_details.push_back("ae6812eb4cd7735a302a8a9dd95cf71f");
            result.push_back(sub_details);
            result.push_back(""); //extranonce1
            result.push_back(8);

            return result;
        }
    };

    class StratumNode
    {
        std::unique_ptr<std::thread> _thread;
        io::io_context _context;
        ip::tcp::acceptor _acceptor;

        set<shared_ptr<StratumRPC>> stratum_connections;

    public:
        void start()
        {
            std::cout << "Started stratum Node" << endl;
            _acceptor.async_accept([this](boost::system::error_code ec, ip::tcp::socket socket)
                                   {
                                       cout << "Stratum connection accepted" << endl;
                                       if (!ec)
                                       {
                                           auto _proto = std::make_shared<StratumRPC>(std::move(socket));
                                           stratum_connections.insert(_proto);
                                       }
                                       else
                                       {
                                           //error when try to accept connection.
                                       }
                                       start();
                                   });
        }

        StratumNode(const ip::tcp::endpoint &listen_ep) : _context(1), _acceptor(_context, listen_ep)
        {
            _thread.reset(new std::thread([&]()
                                          {
                                              start();
                                              _context.run();
                                          }));
        }
    };
}