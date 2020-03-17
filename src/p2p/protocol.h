#ifndef CPOOL_PROTOCOL_H
#define CPOOL_PROTOCOL_H

#include "boost/asio.hpp"
#include "factory.h"
#include "node.h"
#include <stdio>
#include <string>
#include <pystruct.h>
#include <sstream>
#include "config.cpp"
using namespace std;

namespace c2pool::p2p {
    class Protocol {
    public:

        Protocol(boost::asio::io_context io, unsigned long _max_payload_length);

        void sendVersion(){
            //TODO: init struct Version
        }
    private:
        Protocol(boost::asio::io_context io);

        ///called, when start connection
        void connectionMade(){

        }

        void sendPacket(baseMessage payload2){
            if (payload.command.length() > 12){
                //TODO: raise ValueError('command too long')
            }
            char* payload = payload2.pack();
            if ((int)strlen(payload) > max_payload_length){
                //TODO: raise TooLong('payload too long')
            }

            stringstream ss;
            ss << payload.command << ", " << (int)strlen(payload);
            string data = c2pool::config::PREFIX + pystruct::pack("<12sI", ss) + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] + payload; //TODO: cstring + cstring; sha256
            //TODO: self.transport.write(data)
        }

        void disconnect(){
            //TODO: ec check??
            boost::system::error_code ec;
            socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
            socket.close(ec);
        }

        void dataReceived(string data){
            size_t prefix_pos = data.find(c2pool::config::PREFIX);
            if (prefix_pos != std::string::npos){
                data = data.substr(prefix_pos + c2pool::config::PREFIX.length());
            } else {
                //TODO: Debug_log: PREFIX NOT FOUND
                return;
            }
            string command = data.substr(0, 12); //TODO: check for '\0'???

            string lengthPacked; //TODO: value?
            int length;
            stringstream ss = pystruct::unpack("<I", lengthPacked);
            ss >> length;
            if (length > max_payload_length){
                //TODO: Debug_log: length too large
            }

            string checksum = data.substr(?,?); //TODO
            string payload = data.substr(?,?); //TODO:

            //TODO: HASH
            if (hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum){
                //TODO: Debug_log: invalid hash
                disconnect();
            }



        }

        void packetReceived(){

        }



    private:
        Node*_node;
        Factory* factory;
        tcp::socket socket;
        const unsigned int version = 3301;
        const unsigned long max_remembered_txs_size = 25000000;
        unsigned long max_payload_length;

        boost::asio::steady_timer timeout_delayed; //Таймер для автодисконнекта, если нет никакого ответа в течении работы таймера. Сбрасывается каждый раз, как получает какие-то пакеты.

        friend class Factory;
    };
}

#endif //CPOOL_PROTOCOL_H
