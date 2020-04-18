#ifndef CPOOL_NODE_H
#define CPOOL_NODE_H

#include "boost/asio.hpp"
#include "factory.h"
#include "protocol.h"
#include "other/other.cpp"
#include "log.cpp"

namespace c2pool::p2p {
    class Server;
    class Client;
    class Protocol;
}

namespace c2pool::p2p {
    class P2PNode {
        //p2p.py::Node + node.py::P2PNode
        /*,*/
        P2PNode(Node* _node, /*,best_share_hash_func*/ int _port, auto _addr_store,
                auto _connect_addrs, int des_out_cons = 10, int max_out_attempts = 30,
                int max_in_conns=50, int pref_storage=1000, bool _advertise_ip = true
                , auto external_ip = nullptr){
            node = _node;
            port = _port;
            addr_store = _addr_store;
            connect_addrs = _connect_addrs;
            preferred_storage = pref_storage;
            advertise_ip = _advertise_ip;

            //bans?
            client = new Client(this, des_out_cons, max_out_attempts);
            server = new Server(this, max_in_conns);
            running = false;
        }

        void start(){
            if (running){
                //TODO: DEBUG raise already running
            }
            client->start();
            server->start();
            //todo: [bost.asio connection] self.singleclientconnectors = [reactor.connectTCP(addr, port, SingleClientFactory(self)) for addr, port in self.connect_addrs]
            running = true;
            //todo: self._stop_thinking = deferral.run_repeatedly(self._think)


            //Ниже node.py::P2PNode.start()
            //
            //
        }

        float _think(){
            try {
                if ((addr_store.size() < preferred_storage) && (peers != nullptr)){ //TODO: peers != null && peers.size != 0
                    c2pool::random::RandomChoice(*peers).send_getaddrs(8);
                }
            } catch (/*todo*/...) {
                //todo: except: log.err()
            }
            return c2pool::random::Expovariate(1.0/20);
        }

        //TODO: @defer.inlineCallbacks ???
        void stop(){
            if (!running){
                //TODO: DEBUG raise ValueError('already stopped')
            }
            running = false;
            //_stop_thinking(); //TODO: from twister.reactor.CallLater to BoostAsio

            /* TODO:
        yield self.clientfactory.stop()
        yield self.serverfactory.stop()
        for singleclientconnector in self.singleclientconnectors:
            yield singleclientconnector.factory.stopTrying()
            yield singleclientconnector.disconnect()
        del self.singleclientconnectors
             */
        }

        void got_conn(Protocol* conn){
            if (peers.count(conn->nonce) != 0){
                //TODO: raise ValueError('already have peer')
            }
            peers.insert(pair<int, Protocol*>(conn->nonce, conn));
            Log::Write('%s peer %s:%i established. p2pool version: %i %r' % ('Incoming connection from' if conn.incoming else 'Outgoing connection to', conn.addr[0], conn.addr[1], conn.other_version, conn
                .other_sub_version)); //TODO: format str
        }

        void lost_conn(Protocol* conn, auto reason){ //TODO: type for reason
            if (peers.count(conn->nonce) == 0){
                //TODO: raise ValueError('''don't have peer''')
            }
            if (conn != peers.at(conn->nonce)){
                //TODO: raise ValueError('wrong conn')
            }
            peers.erase(conn->nonce);
            delete conn; //TODO: remove or change??

            Log::Write('Lost peer %s:%i - %s' % (conn.addr[0], conn.addr[1], reason.getErrorMessage()))
            //TODO: format str in log
        }

        void got_addr((host, port), services, timestamp){
            /*
             if (host, port) in self.addr_store:
            old_services, old_first_seen, old_last_seen = self.addr_store[host, port]
            self.addr_store[host, port] = services, old_first_seen, max(old_last_seen, timestamp)
        else:
            if len(self.addr_store) < 10000:
                self.addr_store[host, port] = services, timestamp, timestamp
             */
        }

        auto get_good_peers(auto max_count){
            /*
             t = time.time()
        return [x[0] for x in sorted(self.addr_store.iteritems(), key=lambda (k, (services, first_seen, last_seen)):
            -math.log(max(3600, last_seen - first_seen))/math.log(max(3600, t - last_seen))*random.expovariate(1)
        )][:max_count]
             */

            int t = c2pool::time::timestamp;

            for(map<string, string>::iterator it = addr_store.begin(); it != addr_store.end(); ++it) { //TODO ++it; iterator type
                /* TODO:
                 return [x[0] for x in sorted(self.addr_store.iteritems(), key=lambda (k, (services, first_seen, last_seen)):
            -math.log(max(3600, last_seen - first_seen))/math.log(max(3600, t - last_seen))*random.expovariate(1)
        )][:max_count]
                 */
            }

        }
    //private:
    public:
        Node* node;
        bool running;



        c2pool::p2p::Client* client;
        c2pool::p2p::Server* server;

        //p2p.py
        int port;
        map<string, string> addr_store; //TODO: change type
        set<string> connect_addrs;
        int preferred_storage;
        map<int, Protocol*> peers; //TODO: type???
        bool advertise_ip;
    };


    class Node{
        //node.py, Node
    public:
        P2PNode* p2p_node;
        Client* factory;
        //TODO: <type?> bitcoind;

        //TODO: self.best_share_var = variable.Variable(None)


        Node(Client* _factory /*, bitcoind*/ /*,shares */ /*,known_verified_share_hashes*/ ){ //net in global config
            factory = _factory;
        }

        void start(){ //TODO: coroutine?

        }

        void set_best_share(){
            //TODO:
        }
    };
}

#endif //CPOOL_NODE_H
