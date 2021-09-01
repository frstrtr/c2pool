#include <memory>
#include <string>
#include <boost/asio.hpp>

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
    struct StratumRPC
    {
        shared_ptr<c2pool::libnet::Worker> worker; //in p2pool - wb/WorkerBridge
        string username;

        StratumRPC() {}

        StratumRPC()
        {
        }

        void rpc_authorize(string _username, string password)
        {
            username = _username;
        }
    };

    class StratumNode
    {
    public:
    };
}