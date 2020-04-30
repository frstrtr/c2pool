#include "protocol.h"
#include "messages.h"
#include "boost/asio.hpp"
#include "log.cpp"

using namespace c2pool::p2p;
BaseProtocol::BaseProtocol(boost::asio::io_context* _io, unsigned int _version, unsigned long _max_payload_length = 8000000) : timeout_delayed(_io), socket(_io), io(_io) {
    io = _io;
    max_payload_length = _max_payload_length;
}

BaseProtocol::BaseProtocol(boost::asio::io_context io) : timeout_delayed(_io), socket(_io), io(_io){

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

void BaseProtocol::disconnect() {
    //TODO: ec check??
    boost::system::error_code ec;
    socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    socket.close(ec);
}

void BaseProtocol::dataReceived(string data) {
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

    //TODO: HASH, check for hash function btc-core
    if (hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum){
        //TODO: Debug_log: invalid hash
        disconnect();
        //return; //todo:
    }

    message* msg = c2pool::messages::fromStr(command);

    if (msg->command == "error"){
        Log::Debug("no type for ", false);
        Log::Debug(command);
    }

    packetReceived(msg);



}

void BaseProtocol::packetReceived(message *msg) {
    msg->handle(this);
}

Protocol::Protocol(boost::asio::io_context io) : BaseProtocol(io, 3301){ //TODO: base constructor

}

Protocol::Protocol(boost::asio::io_context io, unsigned long _max_payload_length) : BaseProtocol(io, _max_payload_length, 3301){ //TODO: base constructor

}

void Protocol::connectionMade() {
    factory->proto_made_connection(this);

    //self.connection_lost_event = variable.Event()

    //TODO: getPeer() and getHost()
    addr = make_tuple(socket.remote_endpoint().address().to_string(), socket.remote_endpoint().port().to_string()); //todo: move remote_endpoint to method

    send_version(version, 0, c2pool::messages::address_type(0, socket.remote_endpoint().address(), socket.remote_endpoint().port()),
                 c2pool::messages::address_type(0, gethost, gethost), node->nonce, /*todo: p2pool.__version__*/, 1, /*node->best_share_hash_func*/)
    //_____________

    timeout_delayed = new boost::asio::steady_timer(io, boost::asio::chrono::seconds(10));
    timeout_delayed->async_wait(boost::bind(_connect_timeout, boost::asio::placeholders::error)); //todo: thread
}


