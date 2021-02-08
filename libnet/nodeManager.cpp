#include "nodeManager.h"
#include "p2p_node.h"
#include <boost/asio.hpp>
using boost::asio::ip::tcp;

namespace c2pool::libnet{

    void NodeManager::run()
        {
            std::cout << shared_from_this().get() << std::endl;
            //c2pool::p2p::P2PNode* _p2pnode = new c2pool::p2p::P2PNode(shared_from_this());
            tcp::endpoint listen_endpoint(tcp::v4(), _config->listenPort);//atoi(_port.c_str())); 
            p2pnode = std::make_shared<c2pool::p2p::P2PNode>(shared_from_this(), listen_endpoint);
            std::cout << p2pnode.get() << std::endl;
            p2pnode->start();
        }
}