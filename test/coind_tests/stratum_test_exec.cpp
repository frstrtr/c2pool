#include <iostream>
#include <boost/asio.hpp>
#include <libcoind/jsonrpc/stratum.h>
#include <libnet/node_manager.h>

using namespace std;
using namespace coind::jsonrpc;

int main()
{
    cout << "test" << endl;
    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), 5025);
    std::shared_ptr<c2pool::libnet::TestNodeManager> manager;
    coind::jsonrpc::StratumNode node(ep, member); //TODO: fix
    
    while (true)
    {
    }
}