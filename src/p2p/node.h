#ifndef CPOOL_NODE_H
#define CPOOL_NODE_H

#include "boost/asio.hpp"
#include "factory.h"
#include "protocol.h"

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
                int max_in_conns=50, int pref_storage=1000 /*, known_txs_va*/
                /*,mining_txs_var*/ /*,mining2_txs_var*/, bool _advertise_ip = true
                , auto external_ip = nullptr){
            node = _node;
            port = _port;
            addr_store = _addr_store;
            connect_addrs = _connect_addrs;
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
            client.start();
            server.start();
            //self.singleclientconnectors = [reactor.connectTCP(addr, port, SingleClientFactory(self)) for addr, port in self.connect_addrs]
            running = true;
            //self._stop_thinking = deferral.run_repeatedly(self._think)
        }

        /*
         def _think(self):
        try:
            if len(self.addr_store) < self.preferred_storage and self.peers:
                random.choice(self.peers.values()).send_getaddrs(count=8)
        except:
            log.err()

        return random.expovariate(1/20)
         */

        //TODO: @defer.inlineCallbacks ???
        void stop(){
            /*
             if not self.running:
            raise ValueError('already stopped')

        self.running = False

        self._stop_thinking()
        yield self.clientfactory.stop()
        yield self.serverfactory.stop()
        for singleclientconnector in self.singleclientconnectors:
            yield singleclientconnector.factory.stopTrying()
            yield singleclientconnector.disconnect()
        del self.singleclientconnectors
             */
        }

        void got_conn(Protocol* conn){ //TODO: type for conn
            /*
             if conn.nonce in self.peers:
            raise ValueError('already have peer')
        self.peers[conn.nonce] = conn

        print '%s peer %s:%i established. p2pool version: %i %r' % ('Incoming connection from' if conn.incoming else 'Outgoing connection to', conn.addr[0], conn.addr[1], conn.other_version, conn.other_sub_version)
             */
        }

        void lost_conn(Protocol* conn, auto reason){ //TODO: type for conn, reason
            /*
             if conn.nonce not in self.peers:
            raise ValueError('''don't have peer''')
        if conn is not self.peers[conn.nonce]:
            raise ValueError('wrong conn')
        del self.peers[conn.nonce]

        self.lost_updated_conn(conn, reason) #проверка и удаление обновленного пира.

        print 'Lost peer %s:%i - %s' % (conn.addr[0], conn.addr[1], reason.getErrorMessage())
             */
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

        /*

         virtual methods:

         def handle_shares(self, shares, peer):
        print 'handle_shares', (shares, peer)

    def handle_share_hashes(self, hashes, peer):
        print 'handle_share_hashes', (hashes, peer)

    def handle_get_shares(self, hashes, parents, stops, peer):
        print 'handle_get_shares', (hashes, parents, stops, peer)

    def handle_bestblock(self, header, peer):
        print 'handle_bestblock', header

         */

        auto get_good_peers(auto max_count){
            /*
             t = time.time()
        return [x[0] for x in sorted(self.addr_store.iteritems(), key=lambda (k, (services, first_seen, last_seen)):
            -math.log(max(3600, last_seen - first_seen))/math.log(max(3600, t - last_seen))*random.expovariate(1)
        )][:max_count]
             */
        }

        /*
         def _think(self):
        try:
            if len(self.addr_store) < self.preferred_storage and self.peers:
                random.choice(self.peers.values()).send_getaddrs(count=8)
        except:
            log.err()

        return random.expovariate(1/20)
         */

    private:
        Node* node;
        bool running;



        c2pool::p2p::Client* client;
        c2pool::p2p::Server* server;

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
