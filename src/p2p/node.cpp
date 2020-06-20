#include "node.h"

#include <map>
#include <set>
#include <boost/exception/all.hpp> //TODO: all reason = boost::exception???
#include <boost/asio.hpp>
#include <memory>
#include "config.h"
#include "other.h"
#include <iostream>
#include "protocol.h"

//c2pool::p2p::Node
namespace c2pool::p2p
{
    Node::Node(c2pool::p2p::NodesManager *_nodes, std::string _port) : INode(_nodes), _think_timer(_nodes->io_context(), boost::posix_time::seconds(0))
    {
        nonce = c2pool::random::RandomNonce();
        port = _port;

        client = std::make_shared<c2pool::p2p::Client>(); // client.start()
        server = std::make_shared<c2pool::p2p::Server>(); // server.start()

        //todo? self.singleclientconnectors = [reactor.connectTCP(addr, port, SingleClientFactory(self)) for addr, port in self.connect_addrs]

        _think_timer.async_wait(_think);
    }

    void Node::got_conn(c2pool::p2p::Protocol *protocol)
    {
        if (peers.count(protocol->nonce()) != 0)
        {
            std::cout << "Already have peer!" << std::endl; //TODO: raise ValueError('already have peer')
        }
        peers.insert(std::pair<int, c2pool::p2p::Protocol *>(protocol->nonce(), protocol));
    }

    void Node::lost_conn(c2pool::p2p::Protocol *protocol, boost::exception *reason)
    {
        if (peers.count(protocol->nonce()) == 0)
        {
            std::cout << "Don't have peer!" << std::endl; //TODO: raise ValueError('''don't have peer''')
            return;
        }

        if (protocol != peers.at(protocol->nonce()))
        {
            std::cout << "Wrong conn!" << std::endl; //TODO: raise ValueError('wrong conn')
            return;
        }

        delete protocol; //todo: delete for smart pointer

        //todo: print 'Lost peer %s:%i - %s' % (conn.addr[0], conn.addr[1], reason.getErrorMessage())
    }

    void Node::_think()
    { //TODO: rename method
        if (peers.size() > 0)
        {
            c2pool::random::RandomChoice(peers)->send_getaddrs(8); //TODO: add send_getaddrs to c2pool::p2p::Protocol
        }
        boost::posix_time::milliseconds interval(static_cast<int>(c2pool::random::Expovariate(1.0 / 20)*1000));
        _think_timer.expires_at(_think_timer.expires_at() + interval);
        _think_timer.async_wait(_think);
    }
} // namespace c2pool::p2p