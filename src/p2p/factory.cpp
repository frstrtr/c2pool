#include "factory.h"
#include "protocol.h"
#include "node.h"
#include "boost/asio.hpp"
#include <vector>
#include <algorithm>
#include <map>
#include <boost/algorithm/string.hpp>
#include <boost/exception/all.hpp>

namespace c2pool::p2p
{

    //Factory

    Factory::Factory(c2pool::p2p::P2PNode *_node)
    {
        node = _node;
    }

    std::string Factory::_host_to_ident(std::string host)
    {
        std::vector<std::string> res;
        boost::split(res, host, [](char c) { return c == '.'; });
        if (res.size() == 4)
        {
            return res[0] + res[1];
        }
        else
        {
            return "ERROR";
            //TODO: debug error, ip is not xxx.xxx.xxx.xxx
        }
    }

    //Server

    Server::Server(c2pool::p2p::P2PNode *_node, int _max_conns) : Factory(_node)
    {
        max_conns = _max_conns;
    }

    Protocol *Server::buildProtocol(std::string addrs)
    {
        /*
        //TODO: check connections + string or tcp::endpoint addrs?
        if sum(self.conns.itervalues()) >= self.max_conns or self.conns.get(self._host_to_ident(addr.host), 0) >= 3:
            return None
        if addr.host in self.node.bans and self.node.bans[addr.host] > time.time():
            return None
        */
        Protocol *p = new Protocol(node);
        p->setFactory(this);
        //TODO: Debug mode {"Got peer connection from:"}
        return p;
    }

    void Server::proto_made_connection(Protocol *proto)
    {
        std::string ident = _host_to_ident(proto->getHost());
        auto _conn = connections.find(ident);
        if (_conn != connections.end())
        {
            connections[ident] += 1;
        }
        else
        {
            connections[ident] = 1;
        }
    }

    void Server::proto_lost_connection(Protocol *proto, boost::exception &reason) //todo: proto
    {
        std::string ident = _host_to_ident(proto->getHost());
        if (connections.find(ident) != connections.end())
        {
            connections[ident] -= 1;
        }
        else
        {
            //todo: debug not found connection
        }
    }

    void Server::proto_connected(Protocol *proto)
    {
        node->got_conn(proto);
    }

    void Server::proto_disconnected(Protocol *proto, boost::exception &reason)
    {
        node->lost_conn(proto, reason);
    }

    void Server::start()
    {
        //TODO: assert not self.running
        running = true;

        //TODO: boost::asio listen tcp port
        /*
             def attempt_listen():
            if self.running:
                self.listen_port = reactor.listenTCP(self.node.port, self)
        deferral.retry('Error binding to P2P port:', traceback=False)(attempt_listen)()
             */
    }

    void Server::stop()
    {
        //todo: debug assert self.running
        running = false;
        //todo: return self.listen_port.stopListening()
    }

    //Client

    Client::Client(c2pool::p2p::P2PNode *node, int _desired_conns, int _max_attempts) : Factory(node)
    {
        desired_conns = _desired_conns;
        max_attempts = _max_attempts;
    }

    Protocol *Client::buildProtocol(string addrs)
    {
        Protocol *p = new Protocol(node); //todo: p = Protocol(self.node, False); false???
        p->setFactory(this);
        return p;
    }

    void Client::startedConnecting(auto connector)
    {                                                            //todo: type connector: https://twistedmatrix.com/documents/8.2.0/api/twisted.internet.tcp.Connector.html
        string ident = _host_to_ident(/*connector.[...].host*/); //TODO: get ip host
        if (find(attempts.begin(), attempts.end(), ident) != attempts.end())
        {
            //todo: debug raise AssertionError('already have attempt')
        }
        attempts.insert(atteempts.begin(), ident);
    }

    void Client::clientConnectionFailed(auto connector, boost::exception reason) //todo: connector, reason
    {
        string ident = _host_to_ident(/*connector.[...].host*/); //TODO: get ip host
        auto find_pos = find(attempts.begin(), attempts.end(), ident);
        if (find_pos != attempts.end())
        {
            attempts.erase(find_pos); //remove <ident> from attempts
        }
    }

    void Client::clientConnectionLost(auto connector, boost::exception reason) //todo: connector, reason
    {
        string ident = _host_to_ident(/*connector.[...].host*/); //TODO: get ip host
        auto find_pos = find(attempts.begin(), attempts.end(), ident);
        if (find_pos != attempts.end())
        {
            attempts.erase(find_pos); //remove <ident> from attempts
        }
    }

    void Client::proto_connected(Protocol *proto)
    {                                                   //todo: proto
        connections.insert(connections.begin(), proto); //todo: insert endpoint
        node->got_conn(proto);
    }

    void Client::proto_disconnected(Protocol *proto, boost::exception& reason)
    {
        auto find_pos = find(connections.begin(), connections.end(), proto);
        if (find_pos != connections.end())
        {
            connections.erase(find_pos);
        }
        node->lost_conn(proto, reason);
    }

    void Client::start()
    {
        //TODO: assert not self.running
        running = true;
        //todo: self._stop_thinking = deferral.run_repeatedly(self._think)
    }

    void Client::stop()
    {
        //TODO: assert self.running
        running = false;
        //todo: self._stop_thinking()
    }

    /* todo:???
         def _think(self):
        try:
            if len(self.conns) < self.desired_conns and len(self.attempts) < self.max_attempts and self.node.addr_store:
                (host, port), = self.node.get_good_peers(1)

                if self._host_to_ident(host) in self.attempts:
                    pass
                elif host in self.node.bans and self.node.bans[host] > time.time():
                    pass
                else:
                    #print 'Trying to connect to', host, port
                    reactor.connectTCP(host, port, self, timeout=5)
        except:
            log.err()

        return random.expovariate(1/1)
     */

} // namespace c2pool::p2p