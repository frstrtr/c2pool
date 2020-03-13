#ifndef CPOOL_PROTOCOL_H
#define CPOOL_PROTOCOL_H

#include "boost/asio.hpp"
#include "factory.h"
#include "node.h"


namespace c2pool::p2p {
    class Protocol {
    public:

        Protocol(boost::asio::io_context io, int _max_payload_length);

        void sendVersion(){
            //TODO: init struct Version
        }
    private:

        Protocol(boost::asio::io_context io);

        ///called, when start connection
        void connectionMade(){

        }

    private:
        Node*_node;
        Factory* _factory;
        const unsigned int version = 3301;
        const unsigned long max_remembered_txs_size = 25000000;

        boost::asio::steady_timer timeout_delayed; //Таймер для автодисконнекта, если нет никакого ответа в течении работы таймера. Сбрасывается каждый раз, как получает какие-то пакеты.

        int max_payload_length;
        friend class Factory;
    };
}

#endif //CPOOL_PROTOCOL_H
