#ifndef CPOOL_FACTORY_H
#define CPOOL_FACTORY_H

#include "boost/asio.hpp"
#include "protocol.h"
#include <vector>
#include <algorithm>
#include <map>
#include <boost/algorithm/string.hpp>

namespace c2pool::p2p {
    class P2PNode;
    class Protocol;
}

using namespace std;

namespace c2pool::p2p {

    class Factory {
    public:
        Factory(c2pool::p2p::P2PNode* _node){
            node = _node;
        }

        virtual void start() = 0;
        virtual Protocol* buildProtocol(string addrs) = 0;

    protected:
        bool running = false;
        c2pool::p2p::P2PNode* node;


        string _host_to_ident(string host){
            vector<string> res;
            boost::split(res, host, [](char c){return c == '.'});
            if (res.size() == 4) {
                return res[0]+res[1];
            } else {
                //TODO: debug error, ip is not xxx.xxx.xxx.xxx
            }
        }

    };

    class Server : Factory {
    public:
        Server(c2pool::p2p::P2PNode* _node, int _max_conns): Factory(_node){
            max_conns = _max_conns;
        }

        Protocol* buildProtocol(string addrs){ //TODO: string or tcp::endpoint addrs?
            //TODO: check connections
            Protocol* p = new Protocol(_node);
            p->_factory = this;
            //TODO: Debug mode {"Got peer connection from:"}
            return p;
        }

        void proto_made_connection(Protocol* proto){ //todo: proto
            string ident = _host_to_ident(/*proto.[...].host*/); //TODO: get ip host
            if (connections.find(ident) != connections.end()){
                connections[ident] += 1;
            } else {
                connections[ident] = 1;
            }
        }

        void proto_lost_connection(Protocol* proto, auto reason) { //todo: proto, reason
            string ident = _host_to_ident(/*proto.[...].host*/); //TODO: get ip host
            if (connections.find(ident) != connections.end()){
                connections[ident] -= 1;
            } else {
                //todo: debug not found connection
            }
        }

        void proto_connected(Protocol* proto){ //todo: proto
            node->got_conn(proto);
        }

        void proto_disconnected(Protocol* proto, auto reason){ //todo: proto, reason
            node->lost_conn(proto, reason);
        }

        void start(){
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

        void stop(){
            //todo: debug assert self.running
            running = false;
            //todo: return self.listen_port.stopListening()
            int max_conns;
            auto listen_port; //TODO: type
        }

    private:
        map<boost::asio::ip::tcp::endpoint, int> connections; //Список текущих подключений.
    };

    class Client : Factory {
    public:
        Client(c2pool::p2p::P2PNode* node, int _desired_conns, int _max_attempts): Factory(node){
            desired_conns = _desired_conns;
            max_attempts = _max_attempts;
        }

        Protocol buildProtocol(string addrs){ //TODO: string or tcp::endpoint?
            Protocol* p = new Protocol(_node);
            p->_factory = this;
            //TODO: Debug mode {"Got peer connection from:"}
            return p;
        }

        void startedConnecting(auto connector) { //todo: type connector: https://twistedmatrix.com/documents/8.2.0/api/twisted.internet.tcp.Connector.html
            string ident = _host_to_ident(/*connector.[...].host*/); //TODO: get ip host
            if (find(attempts.begin(), attempts.end(), ident) != attempts.end()){
                //todo: debug raise AssertionError('already have attempt')
            }
            attempts.insert(atteempts.begin(), ident);
        }

        void clientConnectionFailed(auto connector, auto reason){ //todo: connector, reason
            string ident = _host_to_ident(/*connector.[...].host*/); //TODO: get ip host
            auto find_pos = find(attempts.begin(), attempts.end(), ident);
            if (find_pos != attempts.end()){
                attempts.erase(find_pos); //remove <ident> from attempts
            }
        }

        void clientConnectionLost(auto connector, auto reason){ //todo: connector, reason
            string ident = _host_to_ident(/*connector.[...].host*/); //TODO: get ip host
            auto find_pos = find(attempts.begin(), attempts.end(), ident);
            if (find_pos != attempts.end()){
                attempts.erase(find_pos); //remove <ident> from attempts
            }
        }

        /*
         * ???
         * def proto_made_connection(self, proto):
        pass
    def proto_lost_connection(self, proto, reason):
        pass
         */

        void proto_connected(Protocol* proto){ //todo: proto
            connections.insert(connections.begin(), proto);
            node->got_conn(proto);
        }

        void proto_disconnected(Protocol* proto, auto reason){ //todo: proto, reason
            auto find_pos = find(connections.begin(), connections.end(), ident);
            if (find_pos != connections.end()){
                connections.erase(find_pos);
            }
            node->lost_conn(proto, reason);
        }

        void start(){
            //TODO: assert not self.running
            running = true;
            //todo: self._stop_thinking = deferral.run_repeatedly(self._think)
        }

        void stop(){
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

    private:
        vector<boost::asio::ip::tcp::endpoint> connections; //Список текущих подключений.
        vector<string> attempts;
        int desired_conns;
        int max_attempts;
    };
}

#endif //CPOOL_FACTORY_H
