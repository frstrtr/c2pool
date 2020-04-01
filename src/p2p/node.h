#ifndef CPOOL_NODE_H
#define CPOOL_NODE_H

#include "boost/asio.hpp"
#include "factory.h"

namespace c2pool::p2p {
    class Server;
    class Client;
}

namespace c2pool::p2p {
    class P2PNode {
        /*,*/
        P2PNode(Node* _node, /*,best_share_hash_func*/ int _port, auto _addr_store,
                auto _connect_addrs, int des_out_cons = 10, int max_out_attempts = 30,
                int max_in_conns=50, int pref_storage=1000 /*, known_txs_va*/
                /*,mining_txs_var*/ /*,mining2_txs_var*/, bool _advertise_ip = true
                , external_ip=""){
            node = _node;
            port = _port;
            addr_store = _addr_store;
            connect_addrs = _connect_addrs;
            advertise_ip = _advertise_ip;
        }

        void start(){
            if (running){
                //TODO: DEBUG raise already running
            }
            client.start();
            server.start();
            //self.singleclientconnectors = [reactor.connectTCP(addr, port, SingleClientFactory(self)) for addr, port in self.connect_addrs]
            running = true;
            //self._stop_thinking = deferral.run_repeatedly(self._think)
        }

    private:
        Node* node;
        bool running;



        c2pool::p2p::Client client;
        c2pool::p2p::Server server;

        //p2p.py
        int port;
        map<string, string> addr_store;
        set<string> connect_addrs;
        bool advertise_ip
    };

    class Node{
        //node.py, Node
    public:
        P2PNode* p2p_node;
        Client* factory;
        //TODO: <type?> bitcoind;
        //TODO: tracker

        //TODO:
        /*self.known_txs_var = variable.VariableDict({}) # hash -> tx
        self.mining_txs_var = variable.Variable({}) # hash -> tx
        self.mining2_txs_var = variable.Variable({}) # hash -> tx
        self.best_share_var = variable.Variable(None)
        self.desired_var = variable.Variable(None)
        self.txidcache = {} */

        Node(Client* _factory /*, bitcoind*/ /*,shares */ /*,known_verified_share_hashes*/ ){ //net in global config
            factory = _factory;
        }

        void start(){ //TODO: coroutine?

        }

        void set_best_share(){
            //TODO:
        }

        void clean_tracker(){
            //TODO:
        }

        auto get_current_txouts(){
            //TODO: return
        }
    };
}

#endif //CPOOL_NODE_H
