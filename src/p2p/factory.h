#ifndef CPOOL_FACTORY_H
#define CPOOL_FACTORY_H

#include "boost/asio.hpp"
#include "protocol.h"
#include <vector>

namespace c2pool::p2p {
    class Node;
}

using namespace std;

namespace c2pool::p2p {
    class Factory {
    public:
        Factory(c2pool::p2p::Node* node){
            _node = node;
        }

        virtual void start() = 0;
        virtual BaseProtocol protocolBuild(string addrs) = 0;

    protected:
        c2pool::p2p::Node* _node;
        vector<boost::asio::ip::tcp::endpoint> connections; //Список текущих подключений.
    };

    class Server : Factory {
    public:
        Server(c2pool::p2p::Node* node):Factory(node){

        }

        BaseProtocol protocolBuild(string addrs){ //TODO: string or tcp::endpoint addrs?
            //TODO: check connections
            BaseProtocol* p = new BaseProtocol(_node);
            p->_factory = this;
            //TODO: Debug mode {"Got peer connection from:"}
            return p;
        }

        void start(){

        }

    private:
    };

    class Client : Factory {
    public:
        Client(c2pool::p2p::Node* node):Factory(node){

        }

        BaseProtocol protocolBuild(string addrs){ //TODO: string or tcp::endpoint?
            BaseProtocol* p = new BaseProtocol(_node);
            p->_factory = this;
            //TODO: Debug mode {"Got peer connection from:"}
            return p;
        }

        void start(){

        }

    private:
    };
}

#endif //CPOOL_FACTORY_H
