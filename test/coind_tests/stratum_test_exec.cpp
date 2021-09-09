#include <iostream>
#include <boost/asio.hpp>
#include <coind/jsonrpc/stratum.h>
#include <libnet/node_member.h>
#include <libnet/node_manager.h>

using namespace std;
using namespace coind::jsonrpc;

int main()
{
    cout << "test" << endl;
    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), 5025);
    std::shared_ptr<c2pool::libnet::TestNodeManager> manager;
    c2pool::libnet::INodeMember member(manager);
    coind::jsonrpc::StratumNode node(ep, member);
    
    while (true)
    {
    }
}