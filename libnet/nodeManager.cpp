#include "nodeManager.h"
#include "p2p_node.h"
#include <boost/asio.hpp>
using boost::asio::ip::tcp;

namespace c2pool::libnet{

    void NodeManager::run()
        {
            tcp::endpoint listen_endpoint(tcp::v4(), _config->listenPort);//atoi(_port.c_str())); 
            p2pnode = std::make_shared<c2pool::libnet::p2p::P2PNode>(shared_from_this(), listen_endpoint);
            p2pnode->start();
        }
}