#ifndef CPOOL_FACTORY_H
#define CPOOL_FACTORY_H

#include "boost/asio.hpp"
#include "protocol.h"
#include "node.h"
#include <vector>


using namespace std;

namespace c2pool::p2p {
    class Factory {
    public:
        Factory(Node* node){
            _node = node;
        }

        virtual BaseProtocol protocolBuild(string addrs) = 0;

    protected:
        Node* _node;
        vector<boost::asio::ip::tcp::endpoint> connections; //Список текущих подключений.
    };

    class Server : Factory {
    public:
        Server(Node* node):Factory(node){

        }

        BaseProtocol protocolBuild(string addrs){ //TODO: string or tcp::endpoint addrs?
            //TODO: check connections
            BaseProtocol* p = new BaseProtocol(_node);
            p->_factory = this;
            //TODO: Debug mode {"Got peer connection from:"}
            return p;
        }

    private:
    };

    class Client : Factory {
    public:
        Client(Node* node):Factory(node){

        }

        BaseProtocol protocolBuild(string addrs){ //TODO: string or tcp::endpoint?
            BaseProtocol* p = new BaseProtocol(_node);
            p->_factory = this;
            //TODO: Debug mode {"Got peer connection from:"}
            return p;
        }

    private:
    };
}

#endif //CPOOL_FACTORY_H
