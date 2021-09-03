#include <iostream>
#include <boost/asio.hpp>
#include <coind/jsonrpc/stratum.h>

using namespace std;
using namespace coind::jsonrpc;

int main()
{
    cout << "test" << endl;
    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), 5025);
    coind::jsonrpc::StratumNode node(ep);
    while (true)
    {
    }
}