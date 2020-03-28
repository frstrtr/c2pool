#ifndef CPOOL_NODE_H
#define CPOOL_NODE_H

#include "boost/asio.hpp"
#include "factory.h"

namespace c2pool::p2p {
    class Server;
    class Client;
}

namespace c2pool::p2p {
    class Node {

        Node(){

        }

        Node(int _port, ){
            port = _port;

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
        bool running;
        int port;
        map<string, string> addr_store;
        set<string> connect_addrs;
        c2pool::p2p::Client client;
        c2pool::p2p::Server server;
    };
}

#endif //CPOOL_NODE_H
