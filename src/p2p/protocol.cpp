#include <cstdlib>
#include <iostream>
#include <thread>
#include <boost/asio.hpp>
#include <deque>
#include <list>
#include <memory>
#include <set>
#include <utility>
#include <sstream>
using boost::asio::ip::tcp;

#include "protocol.h"
#include "factory.h"
#include "node.h"
#include "console.h"
#include "messages.h"
#include "pystruct.h"
#include "other.h"

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
        nodes = factory->getNode(); //TODO: изменить на NodeManager
    }

    void Protocol::connectionMade()
    {
        update_addr();

        c2pool::messages::address_type addr_to(0, std::get<0>(addr), c2pool::str::str_to_int(std::get<1>(addr)));
        c2pool::messages::address_type addr_from(0, std::get<0>(addrHost), c2pool::str::str_to_int(std::get<1>(addrHost)));
        //c2pool::messages::message_version *firstMsg = new c2pool::messages::message_version(1, 2, addrs1, addrs2, 1008386737136591102, "16", 17, 18);
        auto msg_version = new c2pool::messages::message_version(
            version,
            1,
            addr_to,
            addr_from,
            nodes->p2p_node->nonce,
            "c2pool", //todo
            1,
            1 //todo
        );
        send(msg_version);

        /*
        self.send_version(
            version=self.VERSION,
            services=0,
            addr_to=dict(
                services=0,
                address=self.transport.getPeer().host,
                port=self.transport.getPeer().port,
            ),
            addr_from=dict(
                services=0,
                address=self.transport.getHost().host,
                port=self.transport.getHost().port,
            ),
            nonce=self.node.nonce,
            sub_version=p2pool.__version__,
            mode=1,
            best_share_hash=self.node.best_share_hash_func(),
        )
        
        self.timeout_delayed = reactor.callLater(10, self._connect_timeout)
        
        self.get_shares = deferral.GenericDeferrer(
            max_id=2**256,
            func=lambda id, hashes, parents, stops: self.send_sharereq(id=id, hashes=hashes, parents=parents, stops=stops),
            timeout=15,
            on_timeout=self.disconnect,
        )
        
        self.remote_tx_hashes = set() # view of peer's known_txs # not actually initially empty, but sending txs instead of tx hashes won't hurt
        self.remote_remembered_txs_size = 0
        
        self.remembered_txs = {} # view of peer's mining_txs
        self.remembered_txs_size = 0
        self.known_txs_cache = {}
        */
    }

    // //msg.data(), msg.length()
    // void Protocol::write(unique_ptr<c2pool::messages::message> msg)
    // {
    //     boost::asio::async_write(socket,
    //                              boost::asio::buffer(msg->data, msg->get_length()),
    //                              [this](boost::system::error_code ec, std::size_t /*length*/) {
    //                                  if (!ec)
    //                                  {
    //                                  }
    //                                  else
    //                                  {
    //                                      disconnect();
    //                                  }
    //                              });
    // }

    void Protocol::read_prefix()
    {
        tempMessage = new c2pool::messages::IMessage(/*TODO: net.PREFIX*/);
        tempMessage->prefix = new char[nodes->p2p_node->net()->PREFIX_LENGTH];
        //char* temp;

        boost::asio::async_read(socket,
                                boost::asio::buffer(tempMessage->prefix, nodes->p2p_node->net()->PREFIX_LENGTH),
                                [this](boost::system::error_code ec, std::size_t /*length*/) {
                                    if (!ec && c2pool::str::compare_str(tempMessage->prefix, nodes->p2p_node->net()->PREFIX, nodes->p2p_node->net()->PREFIX_LENGTH))
                                    {
                                        LOG_DEBUG << "prefix: " << c2pool::messages::python::other::debug_log(tempMessage->prefix, nodes->p2p_node->net()->PREFIX_LENGTH);
                                        // LOG_INFO << "MSG: " << tempMessage->command;
                                        read_command();
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void Protocol::read_command()
    {
        boost::asio::async_read(socket,
                                boost::asio::buffer(tempMessage->command, tempMessage->command_length),
                                [this](boost::system::error_code ec, std::size_t /*length*/) {
                                    if (!ec)
                                    {
                                        LOG_DEBUG << "command: " << c2pool::messages::python::other::debug_log(tempMessage->command, tempMessage->command_length);
                                        //LOG_INFO << "read_command";
                                        read_length();
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void Protocol::read_length()
    {
        boost::asio::async_read(socket,
                                boost::asio::buffer(tempMessage->length, tempMessage->payload_length),
                                [this](boost::system::error_code ec, std::size_t /*length*/) {
                                    if (!ec)
                                    {
                                        LOG_DEBUG << "length: " << c2pool::messages::python::other::debug_log(tempMessage->length, tempMessage->payload_length);
                                        tempMessage->set_unpacked_length();
                                        // LOG_INFO << "read_length";
                                        read_checksum();
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void Protocol::read_checksum()
    {
        boost::asio::async_read(socket,
                                boost::asio::buffer(tempMessage->checksum, tempMessage->checksum_length),
                                [this](boost::system::error_code ec, std::size_t /*length*/) {
                                    if (!ec)
                                    {
                                        LOG_DEBUG << "checksum: " << c2pool::messages::python::other::debug_log(tempMessage->checksum, tempMessage->checksum_length);
                                        // LOG_INFO << "read_checksum";
                                        read_payload();
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void Protocol::read_payload()
    {
        boost::asio::async_read(socket,
                                boost::asio::buffer(tempMessage->payload, tempMessage->unpacked_length()),
                                [this](boost::system::error_code ec, std::size_t /*length*/) {
                                    if (!ec)
                                    {
                                        LOG_DEBUG << "payload: " << c2pool::messages::python::other::debug_log(tempMessage->payload, tempMessage->unpacked_length());
                                        // LOG_INFO << "read_payload";
                                        //TODO: move tempMesssage -> new message
                                        handle(tempMessage);
                                        read_prefix();
                                    }
                                    else
                                    {
                                        LOG_ERROR << ec << " " << ec.message();
                                        disconnect();
                                    }
                                });
    }

    void Protocol::disconnect()
    {
        boost::asio::post(factory->io_context, [this]() { socket.close(); });
    }

    void Protocol::send(c2pool::messages::message *msg)
    {        
        // msg->send();
        // LOG_DEBUG << "just data: " << c2pool::messages::python::other::debug_log(msg->data, msg->get_length());
        // char* pref = new char[nodes->p2p_node->net()->PREFIX_LENGTH];
        // memcpy(pref, nodes->p2p_node->net()->PREFIX, nodes->p2p_node->net()->PREFIX_LENGTH);
        // LOG_DEBUG << "just prefix: " << c2pool::messages::python::other::debug_log(pref, nodes->p2p_node->net()->PREFIX_LENGTH);
        
        auto msg_data = msg->send_data(nodes->p2p_node->net()->PREFIX, nodes->p2p_node->net()->PREFIX_LENGTH);
        boost::asio::async_write(socket,
                                 boost::asio::buffer(std::get<0>(msg_data), std::get<1>(msg_data)),
                                 [this, msg_data](boost::system::error_code ec, std::size_t /*length*/) {
                                     if (!ec)
                                     {
                                         LOG_DEBUG << "Send data: " << c2pool::messages::python::other::debug_log(std::get<0>(msg_data), std::get<1>(msg_data));
                                     }
                                     else
                                     {
                                         LOG_ERROR << "When try to send msg: " << ec;
                                         disconnect();
                                     }
                                 });
    }

    c2pool::messages::commands Protocol::getCommand(char *_cmd)
    {
        std::stringstream ss;
        ss << _cmd;
        std::string cmd;
        ss >> cmd;

        if (cmd == "addrs")
        {
            return c2pool::messages::commands::cmd_addrs;
        }
        if (cmd == "version")
        {
            return c2pool::messages::commands::cmd_version;
        }
        if (cmd == "getaddrs")
        {
            return c2pool::messages::commands::cmd_getaddrs;
        }
        if (cmd == "addrme")
        {
            return c2pool::messages::commands::cmd_addrme;
        }
        if (cmd == "ping")
        {
            return c2pool::messages::commands::cmd_ping;
        }

        return c2pool::messages::commands::cmd_error;
    }

    //OLD: fromStr
    //handle for msg from c2pool
    //TODO: move to c2pool protocol
    void Protocol::handle(std::stringstream ss)
    {
        char *_cmd = new char[12];
        ss >> _cmd;
        c2pool::messages::commands cmd = getCommand(_cmd);

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

    //GenerateMsg for msg from c2pool
    template <class MsgType>
    MsgType *Protocol::GenerateMsg(std::stringstream &ss)
    {
        MsgType *msg = new MsgType();
        msg->unpack(ss);
        return msg;
    }

    //handle for msg from p2pool
    void Protocol::handle(c2pool::messages::IMessage *_msg)
    {
        c2pool::messages::commands cmd = getCommand(_msg->command);

        switch (cmd) //todo: switch -> if (" " == cmd)
        {
        case c2pool::messages::commands::cmd_addrs:
            handle(GenerateMsg<c2pool::messages::message_addrs>(_msg));
            break;
        case c2pool::messages::commands::cmd_version:
            handle(GenerateMsg<c2pool::messages::message_version>(_msg));
            break;
        case c2pool::messages::commands::cmd_ping:
            handle(GenerateMsg<c2pool::messages::message_ping>(_msg));
            break;
        case c2pool::messages::commands::cmd_addrme:
            handle(GenerateMsg<c2pool::messages::message_addrme>(_msg));
            break;
        case c2pool::messages::commands::cmd_getaddrs:
            handle(GenerateMsg<c2pool::messages::message_getaddrs>(_msg));
            break;
        default:
            handle(GenerateMsg<c2pool::messages::message_error>(_msg));
            break;
        }
    }

    //GenerateMsg for msg from p2pool
    template <class MsgType>
    MsgType *Protocol::GenerateMsg(c2pool::messages::IMessage *_msg)
    {
        MsgType *msg = static_cast<MsgType *>(_msg);
        return msg;
    }

    void Protocol::handle(c2pool::messages::message_version *msg)
    {

        std::cout << "Peer " << msg->addr_from.address << ":" << msg->addr_from.port << " says protocol version is " << msg->version << ", client version " << msg->sub_version; //TODO: to Log system

        if (other_version != -1)
        {
            //TODO: DEBUG: raise PeerMisbehavingError('more than one version message')
        }
        if (msg->version < nodes->p2p_node->net()->MINIMUM_PROTOCOL_VERSION)
        {
            //TODO: DEBUG: raise PeerMisbehavingError('peer too old')
        }

        other_version = msg->version;
        other_sub_version = msg->sub_version;
        other_services = msg->services;

        if (msg->nonce == nodes->p2p_node->nonce) //TODO: add nonce in Node
        {
            //TODO: DEBUG: raise PeerMisbehavingError('was connected to self')
        }

        //detect duplicate in node->peers
        for (auto _peer : nodes->p2p_node->peers)
        {
            if (_peer.first == msg->nonce)
            {
                LOG_WARNING << "Detected duplicate connection, disconnecting from " << std::get<0>(addr) << ":" << std::get<1>(addr);
                disconnect();
                return;
            }
        }

        _nonce = msg->nonce;
        //connected2 = true; //?

        //TODO: safe thrade cancel
        //todo: timeout_delayed.cancel();
        //timeout_delayed = new boost::asio::steady_timer(io, boost::asio::chrono::seconds(100)); //todo: timer io from constructor
        //todo: timeout_delayed.async_wait(boost::bind(_timeout, boost::asio::placeholders::error)); //todo: thread
        //_____________

        /* TODO: TIMER + DELEGATE
             old_dataReceived = self.dataReceived
        def new_dataReceived(data):
            if self.timeout_delayed is not None:
                self.timeout_delayed.reset(100)
            old_dataReceived(data)
        self.dataReceived = new_dataReceived
             */

        factory->protocol_connected(shared_from_this());

        /* TODO: thread (coroutine?):
             self._stop_thread = deferral.run_repeatedly(lambda: [
            self.send_ping(),
        random.expovariate(1/100)][-1])

             if self.node.advertise_ip:
            self._stop_thread2 = deferral.run_repeatedly(lambda: [
                self.sendAdvertisement(),
            random.expovariate(1/(100*len(self.node.peers) + 1))][-1])
             */

        //best_hash = 0 default?
        // if (best_hash != -1)
        // {                                                 // -1 = None
        //     node->handle_share_hashes([best_hash], this); //TODO: best_share_hash in []?
        // }
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

    void Protocol::update_addr()
    {
        boost::asio::ip::tcp::endpoint ep = socket.remote_endpoint();

        addr = std::make_tuple(ep.address().to_string(), std::to_string(ep.port()));
        LOG_INFO << "Connect to " << std::get<0>(addr) << ":" << std::get<1>(addr);

        ep = socket.local_endpoint();
        addrHost = std::make_tuple(ep.address().to_string(), std::to_string(ep.port()));

        LOG_DEBUG << "Connect from " << std::get<0>(addrHost) << ":" << std::get<1>(addrHost);
    }

    //ClientProtocol
    ClientProtocol::ClientProtocol(boost::asio::ip::tcp::socket _socket, c2pool::p2p::Factory *_factory, const boost::asio::ip::tcp::resolver::results_type endpoints) : Protocol(std::move(_socket), _factory)
    {
        LOG_INFO << "ClientProtocol created.";
        do_connect(endpoints);
    }

    void ClientProtocol::do_connect(const boost::asio::ip::tcp::resolver::results_type endpoints)
    {
        boost::asio::async_connect(socket, endpoints, [this](boost::system::error_code ec, tcp::endpoint) {
            connectionMade();
            if (!ec)
            {
                // c2pool::messages::address_type addrs1(3, "4.5.6.7", 8);
                // c2pool::messages::address_type addrs2(9, "10.11.12.13", 14);
                // c2pool::messages::message* firstMsg = new c2pool::messages::message_version(version, 0, addrs1, addrs2, nodes->p2p_node->nonce, "16", 1, 18);
                // send(firstMsg);
                read_prefix();
            }
            else
            {
                LOG_ERROR << ec;
            }
        });
    }

    //ServerProtocol
    ServerProtocol::ServerProtocol(boost::asio::ip::tcp::socket _socket, c2pool::p2p::Factory *_factory) : Protocol(std::move(_socket), _factory)
    {
        LOG_INFO << "ServerProtocol created.";
        start();
    }

    void ServerProtocol::start()
    {
        connectionMade();
        read_prefix();
    }
} // namespace c2pool::p2p