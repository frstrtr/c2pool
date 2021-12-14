#pragma once

#include <memory>

#include <univalue.h>
#include <btclibs/uint256.h>

#include "messages.h"
#include "p2p_node.h"
#include "p2p_socket.h"
#include <networks/network.h>
#include <libdevcore/logger.h>
#include <sharechains/share.h>
#include <libdevcore/types.h>

using namespace c2pool::libnet::messages;
using std::shared_ptr, std::weak_ptr, std::make_shared;
using std::vector;

namespace c2pool::libnet::p2p
{
    class P2PSocket;
}

namespace c2pool::libnet::p2p
{
    class Protocol
    {
    public:
        const int version;

        unsigned int other_version = -1;
        std::string other_sub_version;
        uint64_t other_services;
        unsigned long long _nonce;

    protected:
        shared_ptr<c2pool::libnet::p2p::P2PSocket> _socket;

    protected:
        Protocol(shared_ptr<c2pool::libnet::p2p::P2PSocket> _sct);

    public:

        virtual void write(std::shared_ptr<base_message> msg){
            _socket->write(msg);
        }

        virtual void handle(shared_ptr<raw_message> RawMSG) {}

        virtual shared_ptr<raw_message> make_raw_message(std::string cmd) { return make_shared<raw_message>(cmd); }
    };

    class P2P_Protocol : public Protocol
    {
    private:
        std::shared_ptr<c2pool::Network> _net;
        std::shared_ptr<libnet::p2p::P2PNode> _p2p_node;
    public:
        P2P_Protocol(shared_ptr<c2pool::libnet::p2p::P2PSocket> socket, std::shared_ptr<c2pool::Network> __net, std::shared_ptr<libnet::p2p::P2PNode> __p2p_node) : Protocol(socket), _net(__net), _p2p_node(__p2p_node)
        {
            LOG_TRACE << "P2P_Protocol: "
                      << "start constructor";


            c2pool::messages::address_type addrs1(3, "192.168.10.10", 8);
            c2pool::messages::address_type addrs2(9, "192.168.10.11", 9999);

            uint256 best_hash_test_answer;
            best_hash_test_answer.SetHex("06abb7263fc73665f1f5b129959d90419fea5b1fdbea6216e8847bcc286c14e9");
//            auto msg = make_message<message_version>(version, 0, addrs1, addrs2, _p2p_node->get_nonce(), "c2pool-test", 1, best_hash_test_answer);
            auto msg = make_message<message_version>(version, 0, addrs1, addrs2, 254, "c2pool-test", 1, best_hash_test_answer);
            write(msg);
        }

        void handle(shared_ptr<raw_message> RawMSG) override
        {
            LOG_DEBUG << "called HANDLE msg in p2p_protocol" << ", with name_type = " << RawMSG->command;
            switch (reverse_string_commands(RawMSG->command.c_str()))
            {
            case commands::cmd_version:
                handle(GenerateMsg<message_version>(RawMSG->value));
                break;
            case commands::cmd_ping:
                handle(GenerateMsg<message_ping>(RawMSG->value));
                break;
            case commands::cmd_addrme:
                handle(GenerateMsg<message_addrme>(RawMSG->value));
                break;
            case commands::cmd_addrs:
                LOG_TRACE << "addrs1";
                handle(GenerateMsg<message_addrs>(RawMSG->value));
                LOG_TRACE << "addrs2";
                break;
            case commands::cmd_getaddrs:
                handle(GenerateMsg<message_getaddrs>(RawMSG->value));
                break;
            //new:
            case commands::cmd_shares:
                handle(GenerateMsg<message_shares>(RawMSG->value));
                break;
            case commands::cmd_sharereq:
                handle(GenerateMsg<message_sharereq>(RawMSG->value));
                break;
            case commands::cmd_sharereply:
                handle(GenerateMsg<message_sharereply>(RawMSG->value));
                break;
            //TODO:
            // case commands::cmd_best_block:
            //     handle(GenerateMsg<message_best_block>(RawMSG->value));
            //     break;
            case commands::cmd_have_tx:
                handle(GenerateMsg<message_have_tx>(RawMSG->value));
                break;
            case commands::cmd_losing_tx:
                handle(GenerateMsg<message_losing_tx>(RawMSG->value));
                break;
            case commands::cmd_error:
                handle(GenerateMsg<message_error>(RawMSG->value));
                break;
            }
        }

        template <class message_type, class... Args>
        shared_ptr<message_type> make_message(Args &&...args)
        {
            auto msg = std::make_shared<message_type>(args...);
            return msg;
        }

    protected:
        template <class MsgType>
        //template <class MsgType<>, class ct = converter_type>
        shared_ptr<MsgType> GenerateMsg(PackStream &stream)
        {
            shared_ptr<MsgType> msg = make_shared<MsgType>();
            stream >> *msg;
            return msg;
        }

        void handle(shared_ptr<message_version> msg)
        {
            LOG_DEBUG << "handle message_version";
            LOG_INFO << "Peer " << msg->addr_from.address.get() << ":" << msg->addr_from.port.get() << " says protocol version is " << msg->version.get() << ", client version " << msg->sub_version.get();

            if (other_version != -1)
            {
                LOG_DEBUG << "more than one version message"; 
            }
            if (msg->version.get() < _net->MINIMUM_PROTOCOL_VERSION){
                LOG_DEBUG << "peer too old";
            }

            other_version = msg->version.get() ;
            other_sub_version = msg->sub_version.get();
            other_services = msg->services.get() ;

            if (msg->nonce.get() == _p2p_node->get_nonce()){
                LOG_WARNING << "was connected to self";
                //TODO: assert
            }

            //detect duplicate in node->peers
            if (_p2p_node->get_peers().find(msg->nonce.get()) != _p2p_node->get_peers().end()){

            }
            if (_p2p_node->get_peers().count(msg->nonce.get()) != 0){
                auto addr = _socket->get_addr();
                LOG_WARNING << "Detected duplicate connection, disconnecting from " << std::get<0>(addr) << ":" << std::get<1>(addr);
                _socket->disconnect();
                return;
            }

            _nonce = msg->nonce.get();
            //TODO: После получения message_version, ожидание сообщения увеличивается с 10 секунд, до 100.
            //*Если сообщение не было получено в течении этого таймера, то происходит дисконект.

            //TODO: send_ping, раз в random.expovariate(1/100)

            //TODO: if (p2p_node->advertise_ip):
            //TODO:     раз в random.expovariate(1/100*len(p2p_node->peers.size()+1), отправляется sendAdvertisement()

            //TODO: msg->best_share_hash != nullptr: p2p_node.handle_share_hashes(...)

            //TODO: <Методы для обработки транзакций>: send_have_tx; send_remember_tx
        }
        void handle(shared_ptr<message_addrs> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_addrme> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_ping> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_getaddrs> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_error> msg)
        {
            LOG_WARNING << "Handled message_error! command = " << msg->command.get() << " ; error_text = " << msg->error_text.get();
        }
        void handle(shared_ptr<message_shares> msg)
        {
            //t0
            vector<tuple<shared_ptr<c2pool::shares::BaseShare>, vector<UniValue>>> result; //share, txs
            for (auto wrappedshare : msg->raw_shares)
            {
                int _type = wrappedshare["type"].get_int();
                if (_type < 17) //TODO: 17 = minimum share version; move to macros
                    continue;

                shared_ptr<c2pool::shares::BaseShare> share = c2pool::shares::load_share(wrappedshare, _net, _socket->get_addr());
                std::vector<UniValue> txs;
                if (_type >= 13)
                {
                    for (auto tx_hash : share->new_transaction_hashes)
                    {
                        //TODO: txs
                        /*
                        for tx_hash in share.share_info['new_transaction_hashes']:
                    if tx_hash in self.node.known_txs_var.value:
                        tx = self.node.known_txs_var.value[tx_hash]
                    else:
                        for cache in self.known_txs_cache.itervalues():
                            if tx_hash in cache:
                                tx = cache[tx_hash]
                                print 'Transaction %064x rescued from peer latency cache!' % (tx_hash,)
                                break
                        else:
                            print >>sys.stderr, 'Peer referenced unknown transaction %064x, disconnecting' % (tx_hash,)
                            self.disconnect()
                            return
                    txs.append(tx)
                        */
                    }
                }
                result.push_back(std::make_tuple(share, txs));
            }
            //TODO: p2pNode()->handle_shares(result, shared_from_this()); //TODO: create handle_shares in p2p_node

            /*t1
            if p2pool.BENCH: print "%8.3f ms for %i shares in handle_shares (%3.3f ms/share)" % ((t1-t0)*1000., len(shares), (t1-t0)*1000./ max(1, len(shares))) */
        }
        void handle(shared_ptr<message_sharereq> msg)
        {
            //TODO:
            // auto _shares = p2pNode()->handle_get_shares(msg->hashes, msg->parents, msg->stops, _socket->get_addr());//TODO: handle_get_shares
            // vector<UniValue> packed_shares;
            // //msg data: //uint256 _id, ShareReplyResult _result, std::vector<c2pool::shares::RawShare> _shares
            // try
            // {
            //     for (auto share : _shares)
            //     {
            //         packed_shares.push_back(share); //TODO: pack share to UniValue[type + contents]
            //     }
            //     shared_ptr<message_sharereply> answer_msg = make_message<message_sharereply>(msg->id, 0, _shares);
            //     _socket->write(answer_msg);
            // }
            // catch (const std::invalid_argument &e) //TODO: when throw Payload too long
            // {
            //     packed_shares.clear();
            //     shared_ptr<message_sharereply> answer_msg = make_message<message_sharereply>(msg->id, 1, _shares);
            //     _socket->write(answer_msg);
            // }
        }
        void handle(shared_ptr<message_sharereply> msg)
        {
            std::vector<shared_ptr<c2pool::shares::BaseShare>> res;
            if (msg->result.value == 0)
            {
                for (auto share : msg->shares.l)
                {
                    if (share["type"].get_int() >= 17) //TODO: 17 = minimum share version; move to macros
                    {
                        shared_ptr<c2pool::shares::BaseShare> _share = c2pool::shares::load_share(share, _net, _socket->get_addr());
                        res.push_back(_share);
                    }
                }
            }
            else
            {
                //TODO: res = failure.Failure(self.ShareReplyError(result))
            }
            //TODO: self.get_shares.got_response(id, res)
        }
        //TODO:
        // void handle(shared_ptr<message_best_block> msg){
        //TODO:
        //}
        void handle(shared_ptr<message_have_tx> msg)
        {
            //TODO:
        }
        void handle(shared_ptr<message_losing_tx> msg)
        {
            //TODO:
        }
    };
} // namespace c2pool::p2p