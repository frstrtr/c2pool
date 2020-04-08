#include "protocol.h"
#include "messages.h"
#include "boost/asio.hpp"

using namespace c2pool::p2p;
BaseProtocol::BaseProtocol(boost::asio::io_context io, unsigned long _max_payload_length = 8000000) : timeout_delayed(io), socket(io) {
    max_payload_length = _max_payload_length;
}

BaseProtocol::BaseProtocol(boost::asio::io_context io) : timeout_delayed(io), socket(io){

}

void BaseProtocol::sendPacket(c2pool::messages::message *payload2){ //todo error definition
    if (payload2->command.length() > 12){
        //TODO: raise ValueError('command too long')
    }
    char* payload = payload2->pack(); //TODO: cast str to char*
    if ((int)strlen(payload) > max_payload_length){
        //TODO: raise TooLong('payload too long')
    }

    stringstream ss;
    ss << payload.command << ", " << (int)strlen(payload);
    string data = c2pool::config::PREFIX + pystruct::pack("<12sI", ss) + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] + payload; //TODO: cstring + cstring; sha256
    //TODO: self.transport.write(data)
}