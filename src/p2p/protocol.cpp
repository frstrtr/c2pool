//
// Created by vasil on 13.03.2020.
//

#include "protocol.h"
#include "boost/asio.hpp"
using namespace c2pool::p2p;
Protocol::Protocol(boost::asio::io_context io) : timeout_delayed(io){

}

Protocol::Protocol(boost::asio::io_context io, int _max_payload_length) : timeout_delayed(io){

}