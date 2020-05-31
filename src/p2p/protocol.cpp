#include <cstdlib>
#include <iostream>
#include <thread>
#include <boost/asio.hpp>
#include <deque>
#include <list>
#include <memory>
#include <set>
#include <utility>
using boost::asio::ip::tcp;

#include "protocol.h"
#include "factory.h"

//-----------------------------------------------------------

class Node;
namespace c2pool::messages
{
    class message;
}
//-----------------------------------------------------------

namespace c2pool::p2p
{

    //Protocol
    Protocol::Protocol(boost::asio::ip::tcp::socket _socket, c2pool::p2p::Factory *_factory) : socket(std::move(_socket)), version(3301)
    {
        factory = _factory;
    }

    //msg.data(), msg.length()
    void Protocol::write(char *msg, size_t length)
    {
        boost::asio::async_write(socket,
                                 boost::asio::buffer(msg, length),
                                 [this](boost::system::error_code ec, std::size_t /*length*/) {
                                     if (!ec)
                                     {
                                     }
                                     else
                                     {
                                         disconnect();
                                     }
                                 });
    }

    void Protocol::read_header(c2pool::messages::IMessageReader& msg)
    {
        boost::asio::async_read(socket,
                            boost::asio::buffer(read_msg_.data(), 12/*todo:header_length*/),
                            [this](boost::system::error_code ec, std::size_t /*length*/) {
                              if (!ec && read_msg_.decode_header())
                              {
                                do_read_body();
                              }
                              else
                              {
                                socket_.close();
                              }
                            });
    }

    void Protocol::read_body()
    {
    }

    void Protocol::disconnect()
    {
        boost::asio::post(factory->io_context, [this]() { socket.close(); });
    }

    //OLD: fromStr
    void Protocol::handle(std::stringstream ss)
    {
        //В Python скрипте, команда передается, как int, эквивалентный c2pool::messages::commands
        int cmd;
        ss >> cmd;
        c2pool::messages::message *res;

        switch (cmd)
        {
        case c2pool::messages::commands::cmd_addrs:
            handle(GenerateMsg<c2pool::messages::message_addrs>(ss));
            break;
        case c2pool::messages::commands::cmd_version:
            handle(GenerateMsg<c2pool::messages::message_version>(ss));
            break;
        case c2pool::messages::commands::cmd_ping:
            handle(GenerateMsg<c2pool::messages::message_ping>(ss));
            break;
        case c2pool::messages::commands::cmd_addrme:
            handle(GenerateMsg<c2pool::messages::message_addrme>(ss));
            break;
        case c2pool::messages::commands::cmd_getaddrs:
            handle(GenerateMsg<c2pool::messages::message_getaddrs>(ss));
            break;
        default:
            handle(GenerateMsg<c2pool::messages::message_error>(ss));
            break;
        }
    }

    template <class MsgType>
    MsgType *Protocol::GenerateMsg(std::stringstream &ss)
    {
        MsgType *msg = new MsgType();
        msg->unpack(ss);
        return msg;
    }

    void Protocol::handle(c2pool::messages::message_version *msg)
    {
    }

    void Protocol::handle(c2pool::messages::message_addrs *msg)
    {
    }

    void Protocol::handle(c2pool::messages::message_addrme *msg)
    {
    }

    void Protocol::handle(c2pool::messages::message_ping *msg)
    {
    }

    void Protocol::handle(c2pool::messages::message_getaddrs *msg)
    {
    }

    void Protocol::handle(c2pool::messages::message_error *msg)
    {
    }
    //end_Protocol

    ClientProtocol::ClientProtocol(boost::asio::ip::tcp::socket _socket, c2pool::p2p::Factory *_factory, const boost::asio::ip::tcp::resolver::results_type endpoints) : Protocol(std::move(_socket), _factory)
    {
        do_connect(endpoints);
    }

    void ClientProtocol::do_connect(const boost::asio::ip::tcp::resolver::results_type endpoint)
    {
    }

    ServerProtocol::ServerProtocol(boost::asio::ip::tcp::socket _socket, c2pool::p2p::Factory *_factory) : Protocol(std::move(_socket), _factory)
    {
        start();
    }

    void ServerProtocol::start()
    {
        boost::asio::async_write(socket, boost::asio::buffer("TEST DATA", 9), [](const boost::system::error_code &error, std::size_t bytes_transferred) {

        });
    }
} // namespace c2pool::p2p

// #include "protocol.h"
// #include "messages.h"
// #include "boost/asio.hpp"
// #include "log.cpp"
// #include "boost/bind.hpp"
// #include "factory.h"
// #include "node.h"
// //#include <stdio>
// #include <string>
// #include "pystruct.h"
// #include <sstream>
// #include "config.cpp"
// #include <map>
// #include <iostream>
// #include <boost/algorithm/string.hpp>

// #include "converter.cpp"
// #include "other.h"

// namespace c2pool::p2p
// {
//     c2pool::messages::message *Protocol::fromStr(std::stringstream ss)
//     {
//         //В Python скрипте, команда передается, как int, эквивалентный c2pool::messages::commands
//         int cmd;
//         ss >> cmd;
//         c2pool::messages::message *res;

//         switch (cmd)
//         {
//         case c2pool::messages::commands::cmd_addrs:
//             res = new c2pool::messages::message_addrs();
//             break;
//         case c2pool::messages::commands::cmd_version:
//             res = new c2pool::messages::message_version();
//             break;
//         case c2pool::messages::commands::cmd_ping:
//             res = new c2pool::messages::message_ping();
//             break;
//         case c2pool::messages::commands::cmd_addrme:
//             res = new c2pool::messages::message_addrme();
//             break;
//         case c2pool::messages::commands::cmd_getaddrs:
//             res = new c2pool::messages::message_getaddrs();
//             break;
//         default:
//             res = new c2pool::messages::message_error();
//             break;
//         }

//         res->unpack(ss);
//         res->handle(this);
//         return res;
//     }

//     //BASEPROTOCOL

//     BaseProtocol::BaseProtocol(boost::asio::io_context &_io, int _version, long _max_payload_length) : version(_version), socket(_io)
//     {
//         max_payload_length = _max_payload_length;
//     }

//     BaseProtocol::BaseProtocol(boost::asio::io_context &_io, int _version) : version(_version), socket(_io)
//     {
//     }

//     void BaseProtocol::BaseProtocol::sendPacket(c2pool::messages::message *payload2)
//     { //todo error definition
//         if (payload2->command.length() > 12)
//         {
//             //TODO: raise ValueError('command too long')
//         }
//         char *payload;
//         std::strcpy(payload, payload2->pack().c_str());
//         if ((int)strlen(payload) > max_payload_length)
//         {
//             //TODO: raise TooLong('payload too long')
//         }

//         stringstream ss;
//         ss << payload.command << ", " << (int)strlen(payload);                                                                                         //TODO: payload.command
//         string data = c2pool::config::PREFIX + pystruct::pack("<12sI", ss) + hashlib.sha256(hashlib.sha256(payload).digest()).digest() [:4] + payload; //TODO: cstring + cstring; sha256
//         //TODO: self.transport.write(data)
//     }

//     void BaseProtocol::disconnect()
//     {
//         //TODO: ec check??
//         boost::system::error_code ec;
//         socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
//         socket.close(ec);
//     }

//     void BaseProtocol::dataReceived(string data)
//     {
//         size_t prefix_pos = data.find(c2pool::config::PREFIX);
//         if (prefix_pos != std::string::npos)
//         {
//             data = data.substr(prefix_pos + c2pool::config::PREFIX.length());
//         }
//         else
//         {
//             //TODO: Debug_log: PREFIX NOT FOUND
//             return;
//         }
//         string command = data.substr(0, 12); //TODO: check for '\0'???

//         string lengthPacked; //TODO: value?
//         int length;
//         stringstream ss = pystruct::unpack("<I", lengthPacked);
//         ss >> length;
//         if (length > max_payload_length)
//         {
//             //TODO: Debug_log: length too large
//         }

//         string checksum = data.substr(?,?); //TODO
//         string payload = data.substr(?,?); //TODO:

//         //TODO: HASH, check for hash function btc-core
//         if (hashlib.sha256(hashlib.sha256(payload).digest()).digest() [:4] != checksum)
//         {
//             //TODO: Debug_log: invalid hash
//             disconnect();
//             //return; //todo:
//         }

//         c2pool::messages::message *msg = c2pool::messages::fromStr(command);

//         if (msg->command == "error")
//         {
//             Log::Debug("no type for ", false);
//             Log::Debug(command);
//         }

//         packetReceived(msg);
//     }

//     //PROTOCOL

//     Protocol::Protocol(boost::asio::io_context &io) : BaseProtocol(io, 3301), timeout_delayed(io)
//     { //TODO: base constructor
//     }

//     Protocol::Protocol(boost::asio::io_context &io, unsigned long _max_payload_length = 8000000) : BaseProtocol(io, 3301, _max_payload_length), timeout_delayed(io)
//     { //TODO: base constructor
//     }

//     void Protocol::connectionMade()
//     {
//         factory->proto_made_connection(this); //TODO

//         //self.connection_lost_event = variable.Event()

//         //TODO: getPeer() and getHost()
//         addr = make_tuple(socket.remote_endpoint().address().to_string(), socket.remote_endpoint().port().to_string()); //todo: move remote_endpoint to method

//         send_version(version, 0, c2pool::messages::address_type(0, socket.remote_endpoint().address(), socket.remote_endpoint().port()),
//                      c2pool::messages::address_type(0, gethost, gethost), node->nonce, /*todo: p2pool.__version__*/, 1,
//                      /*node->best_share_hash_func*/)
//             //_____________

//             timeout_delayed = new boost::asio::steady_timer(io, boost::asio::chrono::seconds(10));
//         timeout_delayed->async_wait(boost::bind(_connect_timeout, boost::asio::placeholders::error)); //todo: thread
//     }

//     void Protocol::packetReceived(c2pool::messages::message *msg)
//     {
//         msg->handle(this);
//     }

//     void Protocol::connect_timeout(const boost::system::error_code & /*e*/)
//     {
//         delete timeout_delayed; //todo: stop timer
//         //TODO: Log.Write(Handshake timed out, disconnecting from %s:%i) /  print 'Handshake timed out, disconnecting from %s:%i' % self.addr
//         disconnect();
//     }

//     void Protocol::_timeout(const boost::system::error_code & /*e*/)
//     {
//         delete timeout_delayed;
//         //TODO: Log.Write()/print 'Connection timed out, disconnecting from %s:%i' % self.addr
//         disconnect();
//     }

//     void Protocol::send_version(int ver, int serv, c2pool::messages::address_type to, c2pool::messages::address_type from, long _nonce, std::string sub_ver, int _mode, long best_hash)
//     {
//         c2pool::messages::message_version *msg = new c2pool::messages::message_version(ver, serv, to, from, _nonce, sub_ver, _mode, best_hash); //TODO: when 'new', wanna delete
//         sendPacket(msg);
//     }

//     void Protocol::handle_version(int ver, int serv, c2pool::messages::address_type to, c2pool::messages::address_type from, long _nonce, std::string sub_ver, int _mode, long best_hash)
//     {

//         std::cout << "Peer " << from.address << ":" << from.port << " says protocol version is " << ver << ", client version " << sub_ver; //TODO: to Log system

//         if (other_version != -1)
//         {
//             //TODO: DEBUG: raise PeerMisbehavingError('more than one version message')
//         }
//         if (ver < c2pool::config::MINIMUM_PROTOCOL_VERSION)
//         {
//             //TODO: DEBUG: raise PeerMisbehavingError('peer too old')
//         }

//         other_version = ver;
//         other_sub_version = sub_ver;
//         other_services = serv;

//         if (_nonce == node->nonce) //TODO: add nonce in Node
//         {
//             //TODO: DEBUG: raise PeerMisbehavingError('was connected to self')
//         }

//         //detect duplicate in node->peers
//         for (auto _peer : node->peers)
//         {
//             if (_peer.first == _nonce)
//             {
//                 string err = "Detected duplicate connection, disconnecting from " + std::get<0>(addr) + ":" + to_string(std::get<1>(addr));
//                 Log::Debug(err);
//                 disconnect();
//                 return;
//             }
//         }

//         nonce = _nonce;
//         connected2 = true;

//         //TODO: safe thrade cancel
//         timeout_delayed.cancel();
//         //timeout_delayed = new boost::asio::steady_timer(io, boost::asio::chrono::seconds(100)); //todo: timer io from constructor
//         timeout_delayed.async_wait(boost::bind(_timeout, boost::asio::placeholders::error)); //todo: thread
//         //_____________

//         /* TODO: TIMER + DELEGATE
//              old_dataReceived = self.dataReceived
//         def new_dataReceived(data):
//             if self.timeout_delayed is not None:
//                 self.timeout_delayed.reset(100)
//             old_dataReceived(data)
//         self.dataReceived = new_dataReceived
//              */

//         factory->proto_connected(this);

//         /* TODO: thread (coroutine?):
//              self._stop_thread = deferral.run_repeatedly(lambda: [
//             self.send_ping(),
//         random.expovariate(1/100)][-1])

//              if self.node.advertise_ip:
//             self._stop_thread2 = deferral.run_repeatedly(lambda: [
//                 self.sendAdvertisement(),
//             random.expovariate(1/(100*len(self.node.peers) + 1))][-1])
//              */

//         if (best_hash != -1)
//         {                                                 // -1 = None
//             node->handle_share_hashes([best_hash], this); //TODO: best_share_hash in []?
//         }
//     }

//     void Protocol::sendAdvertisement()
//     {
//         if (node->server->getListenPort() != 0) // (!= 0) = (is not None) for port
//         {
//             string host = node->external_ip;               //todo: add node.external_ip
//             int port = node->server->listen_port(/*???*/); //TODO
//             if (host != "")
//             {
//                 if (host.find(":") != string::npos)
//                 {
//                     vector<string> res;

//                     boost::split(res, host, [](char c) { return c == ':'; });
//                     host = res[0];
//                     port = Converter::StrToInt(res[1]);
//                 }

//                 string err = "Advertising for incoming connections: " + host + ":" + to_string(port);
//                 Log::Debug(err);

//                 int timestamp = c2pool::time::timestamp();
//                 vector<c2pool::messages::addr> adr = {c2pool::messages::addr(c2pool::messages::address_type(other_services, host, port), timestamp)};
//                 send_addrs(adr);
//             }
//             else
//             {
//                 if (Log::DEBUG)
//                 {
//                     Log::Debug("Advertising for incoming connections");
//                     send_addrme(port);
//                 }
//             }
//         }
//     }

//     void Protocol::send_addrs(std::vector<c2pool::messages::addr> _addrs)
//     {
//         c2pool::messages::message_addrs *msg = new c2pool::messages::message_addrs(_addrs); //TODO: when 'new', wanna delete
//         sendPacket(msg);
//     }

//     void Protocol::handle_addrs(std::vector<c2pool::messages::addr> addrs)
//     {
//         for (auto data : addrs)
//         {
//             node->got_addr(data, c2pool::time::timestamp());
//             if ((c2pool::random::RandomFloat(0, 1) < 0.8) && node->peers != nullptr)
//             { // TODO: вместо != null, size() == 0???
//                 c2pool::random::RandomChoice(*node->peers).send_addrs(vector<c2pool::messages::addrs> buff{data});
//             }
//         }
//     }

//     void Protocol::send_addrme(int port)
//     {
//         c2pool::messages::message_addrme *msg = new c2pool::messages::message_addrme(port); //in if from todo debug //TODO: when 'new', wanna delete
//         sendPacket(msg);
//     }

//     void Protocol::handle_addrme(int port)
//     {
//         string host = ; //TODO: self.transport.getPeer().host

//         if (host == "127.0.0.1")
//         {
//             if ((c2pool::random::RandomFloat(0, 1) < 0.8) && node->peers.size() != 0)
//             { // TODO: вместо != null, size() == 0???
//                 c2pool::random::RandomChoice(*node->peers).send_addrme(port);
//             }
//         }
//         else
//         {
//             c2pool::messages::addr _addr(other_services, socket.remote_endpoint().address().to_string(), port, c2pool::time::timestamp()); //TODO: move remote_endpoint to method
//             if ((c2pool::random::RandomFloat(0, 1) < 0.8) && node->peers.size() != 0)
//             { // TODO: вместо != null, size() == 0???
//                 std::vector<c2pool::messages::addr> _addr2(other_services, host, port, c2pool::time::timestamp())
//                     c2pool::random::RandomChoice(node->peers)
//                         .send_addrs(_addr2);
//             }
//         }
//     }

//     void Protocol::send_ping()
//     {
//         c2pool::messages::message_ping *msg = new c2pool::messages::message_ping(); //TODO: when 'new', wanna delete
//         sendPacket(msg);
//     }

//     void Protocol::handle_ping(long long _nonce)
//     {
//         //pass
//     }

//     void Protocol::send_getaddrs(int _count)
//     {
//         c2pool::messages::message_getaddrs *msg = new c2pool::messages::message_getaddrs(_count); //TODO: when 'new', wanna delete
//         sendPacket(msg);
//     }

//     void Protocol::handle_getaddrs(int count)
//         { //todo: доделать
//             if (count > 100)
//             {
//                 count = 100;
//             }
//             std::vector<string> good_peers = node->get_good_peers(count); //TODO: type for vector
//             std::vector<c2pool::messages::addr> addrs;
//             for (i = 0; i < count; i++)
//             { //todo: доделать
//                 c2pool::messages::addr buff_addr = c2pool::messages::addr(
//                     c2pool::messages::address_type(
//                         node->addr_store[good_peers[i]][0], //todo: array index
//                         host,
//                         port),
//                     node->addr_store[host, port][2] //todo: array index
//                 );
//             }
//             std::vector<c2pool::messages::address_type> adr = {c2pool::messages::address_type(other_services, host, port)};
//             int timestamp = ; //TODO: INIT
//             c2pool::messages::message_addrs msg = c2pool::messages::message_addrs(adr, timestamp);
//         }

// } // namespace c2pool::p2p