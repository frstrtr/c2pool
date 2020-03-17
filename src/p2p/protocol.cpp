//
// Created by vasil on 13.03.2020.
//

#include "protocol.h"
#include "boost/asio.hpp"
using namespace c2pool::p2p;
Protocol::Protocol(boost::asio::io_context io, unsigned long _max_payload_length = 8000000) : timeout_delayed(io), socket(io) {
    max_payload_length = _max_payload_length;
}

Protocol::Protocol(boost::asio::io_context io) : timeout_delayed(io), socket(io){

}