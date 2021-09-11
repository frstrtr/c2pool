#include <memory>
#include <iostream>
#include <string>
#include <thread>
#include <string>
#include <set>
#include <tuple>

#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>

#include <univalue.h>
#include <libnet/node_manager.h>
#include <btclibs/uint256.h>

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

    struct StratumRPC;

    class Proxy
    {
        weak_ptr<coind::jsonrpc::StratumRPC> rpc;

    public:
        Proxy(shared_ptr<coind::jsonrpc::StratumRPC> _rpc);

        void send(std::string method, UniValue params);

        void mining_set_difficulty(uint256 difficulty)
        {
            UniValue data(UniValue::VARR);
            data.push_back(difficulty.ToString());
            cout << data.write() << endl;
            send("mining.set_difficulty", data);
        }

        struct NotifyParams
        {
            uint128 jobid;
            string prevhash;
            string coinb1;
            string coinb2;
            vector<uint256> merkle_branch;
            string version;
            string nbits;
            string ntime;
            bool clean_jobs;

            NotifyParams() {}

            NotifyParams(uint128 _jobid, uint256 _prevhash, uint256 _coinb1, uint256 _coinb2, vector<uint256> _merkle_branch, string _version, string _nbits, string _ntime, bool _clean_jobs)
            {
                // getwork._swap4(pack.IntType(256).pack(x['previous_block'])).encode('hex'), # prevhash
                // x['coinb1'].encode('hex'), # coinb1
                // x['coinb2'].encode('hex'), # coinb2
                // [pack.IntType(256).pack(s).encode('hex') for s in x['merkle_link']['branch']], # merkle_branch
                // getwork._swap4(pack.IntType(32).pack(x['version'])).encode('hex'), # version
                // getwork._swap4(pack.IntType(32).pack(x['bits'].bits)).encode('hex'), # nbits
                // getwork._swap4(pack.IntType(32).pack(x['timestamp'])).encode('hex'), # ntime
                // True, # clean_jobs
            }

            UniValue get()
            {
                UniValue result(UniValue::VARR);

                result.push_back(jobid.ToString());
                result.push_back(prevhash);
                result.push_back(coinb1);
                result.push_back(coinb2);

                UniValue branch(UniValue::VARR);
                //TODO: branch
                result.push_back(branch);

                result.push_back(version);
                result.push_back(nbits);
                result.push_back(ntime);
                result.push_back(clean_jobs);

                return result;
            }
        };

        void mining_notify(NotifyParams params)
        {
            auto data = params.get();
            cout << data.write() << endl;
            send("mining.notify", data);
        }
    };

    struct StratumRPC : public std::enable_shared_from_this<StratumRPC>
    {
        //TODO: shared_ptr<c2pool::libnet::Worker> worker; //in p2pool - wb/WorkerBridge
        ip::tcp::socket _socket;
        shared_ptr<Proxy> proxy;
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

        void send_work()
        {
            uint256 difficulty;
            difficulty.SetHex("27");

            proxy->mining_set_difficulty(difficulty);
            proxy->mining_notify({});
        }

        UniValue rpc_authorize(string _username, string password)
        {
            username = _username;
        }

        UniValue rpc_subscribe(UniValue params)
        {
            cout << "Called rpc_subscribe" << endl;
            send_work();

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

    class StratumNode : public c2pool::libnet::NodeMember
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
                                           _proto->proxy = std::make_shared<Proxy>(_proto);
                                           stratum_connections.insert(_proto);
                                       }
                                       else
                                       {
                                           //error when try to accept connection.
                                       }
                                       start();
                                   });
        }

        StratumNode(const ip::tcp::endpoint &listen_ep, const c2pool::libnet::NodeMember& member);
    };
}