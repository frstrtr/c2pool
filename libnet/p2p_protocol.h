#pragma once

#include "messages.h"
#include <devcore/logger.h>
#include "p2p_socket.h"
#include "node_member.h"
#include <sharechains/share.h>
#include <util/types.h>
#include "p2p_node.h"
using namespace c2pool::libnet::messages;

#include <univalue.h>
#include <btclibs/uint256.h>

#include <memory>
using std::shared_ptr, std::weak_ptr, std::make_shared;
using std::vector;

namespace c2pool::libnet::p2p
{
    class P2PSocket;
}

namespace c2pool::libnet::p2p
{
    class Protocol : public INodeMember
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
        Protocol(shared_ptr<c2pool::libnet::p2p::P2PSocket> _sct, const c2pool::libnet::INodeMember &member);

    public:
        virtual void handle(shared_ptr<raw_message> RawMSG) {}

        virtual shared_ptr<raw_message> make_raw_message() { return make_shared<raw_message>(); }
    };

    class P2P_Protocol : public Protocol
    {
    public:
        //TODO: constructor (shared_ptr<initialize_network_protocol>)
        P2P_Protocol(shared_ptr<c2pool::libnet::p2p::P2PSocket> socket, const c2pool::libnet::INodeMember& member) : Protocol(socket, member)
        {
            LOG_TRACE << "P2P_Protocol: "
                      << "start constructor";
        }

        void handle(shared_ptr<raw_message> RawMSG) override
        {
            LOG_DEBUG << "called HANDLE msg in p2p_protocol";

            switch (RawMSG->name_type.get())
            {
            case commands::cmd_version:
                handle(GenerateMsg<message_version>(json_value));
                break;
            case commands::cmd_ping:
                handle(GenerateMsg<message_ping>(json_value));
                break;
            case commands::cmd_addrme:
                handle(GenerateMsg<message_addrme>(json_value));
                break;
            case commands::cmd_addrs:
                LOG_TRACE << "addrs1";
                handle(GenerateMsg<message_addrs>(json_value));
                LOG_TRACE << "addrs2";
                break;
            case commands::cmd_getaddrs:
                handle(GenerateMsg<message_getaddrs>(json_value));
                break;
            //new:
            case commands::cmd_shares:
                handle(GenerateMsg<message_shares>(json_value));
                break;
            case commands::cmd_sharereq:
                handle(GenerateMsg<message_sharereq>(json_value));
                break;
            case commands::cmd_sharereply:
                handle(GenerateMsg<message_sharereply>(json_value));
                break;
            //TODO:
            // case commands::cmd_best_block:
            //     handle(GenerateMsg<message_best_block>(json_value));
            //     break;
            case commands::cmd_have_tx:
                handle(GenerateMsg<message_have_tx>(json_value));
                break;
            case commands::cmd_losing_tx:
                handle(GenerateMsg<message_losing_tx>(json_value));
                break;
            case commands::cmd_error:
                handle(GenerateMsg<message_error>(json_value));
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
        shared_ptr<MsgType> GenerateMsg(UniValue &value)
        {
            shared_ptr<MsgType> msg = make_shared<MsgType>();
            *msg = value;
            return msg;
        }

        void handle(shared_ptr<message_version> msg)
        {
            LOG_DEBUG << "handle message_version";
            LOG_TRACE << msg->best_share_hash.GetHex();
            LOG_INFO << "Peer " << msg->addr_from.address << ":" << msg->addr_from.port << " says protocol version is " << msg->version << ", client version " << msg->sub_version;

            if (other_version != -1)
            {
                LOG_DEBUG << "more than one version message"; 
            }
            if (msg->version < net()->MINIMUM_PROTOCOL_VERSION){
                LOG_DEBUG << "peer too old";
            }

            other_version = msg->version;
            other_sub_version = msg->sub_version;
            other_services = msg->services;

            if (msg->nonce == p2pNode()->get_nonce()){
                LOG_DEBUG << "was connected to self";
            }

            //detect duplicate in node->peers
            // for (auto _peer : nodes->p2p_node->peers)
            // {
            //     if (_peer.first == msg->nonce)
            //     {
            //         LOG_WARNING << "Detected duplicate connection, disconnecting from " << std::get<0>(addr) << ":" << std::get<1>(addr);
            //         disconnect();
            //         return;
            //     }
            // }

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

            // factory->protocol_connected(shared_from_this());

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
            //--------

            // message_version* msg = new message_version()
            int ver = version;
            std::string test_sub_ver = "16";
            unsigned long long test_nonce = 6535423;
            c2pool::messages::address_type addrs1(3, "4.5.6.7", 8);
            c2pool::messages::address_type addrs2(9, "10.11.12.13", 14);
            uint256 best_hash_test_answer;
            best_hash_test_answer.SetHex("0123");
            shared_ptr<message_version> answer_msg = make_message<message_version>(ver, 0, addrs1, addrs2, test_nonce, test_sub_ver, 18, best_hash_test_answer);
            LOG_TRACE << "set converter type for answer msg";
            LOG_TRACE << "write answer msg for socket";
            _socket->write(answer_msg);
            // _socket->write()
            //TODO:
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
            LOG_WARNING << "Handled message_error! command = " << msg->command << " ; error_text = " << msg->error_text;
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

                shared_ptr<c2pool::shares::BaseShare> share = c2pool::shares::load_share(wrappedshare, net(), _socket->get_addr());
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
            p2pNode()->handle_shares(result, shared_from_this()); //TODO: create handle_shares in p2p_node

            /*t1
            if p2pool.BENCH: print "%8.3f ms for %i shares in handle_shares (%3.3f ms/share)" % ((t1-t0)*1000., len(shares), (t1-t0)*1000./ max(1, len(shares))) */
        }
        void handle(shared_ptr<message_sharereq> msg)
        {
            auto _shares = p2pNode()->handle_get_shares(msg->hashes, msg->parents, msg->stops, _socket->get_addr());//TODO: handle_get_shares
            vector<UniValue> packed_shares;
            //msg data: //uint256 _id, ShareReplyResult _result, std::vector<c2pool::shares::RawShare> _shares
            try
            {
                for (auto share : _shares)
                {
                    packed_shares.push_back(share); //TODO: pack share to UniValue[type + contents]
                }
                shared_ptr<message_sharereply> answer_msg = make_message<message_sharereply>(msg->id, 0, _shares);
                _socket->write(answer_msg);
            }
            catch (const std::invalid_argument &e) //TODO: when throw Payload too long
            {
                packed_shares.clear();
                shared_ptr<message_sharereply> answer_msg = make_message<message_sharereply>(msg->id, 1, _shares);
                _socket->write(answer_msg);
            }
        }
        void handle(shared_ptr<message_sharereply> msg)
        {
            std::vector<shared_ptr<c2pool::shares::BaseShare>> res;
            if (msg->result == 0)
            {
                for (auto share : msg->shares)
                {
                    if (share["type"].get_int() >= 17) //TODO: 17 = minimum share version; move to macros
                    {
                        shared_ptr<c2pool::shares::BaseShare> _share = c2pool::shares::load_share(share, net(), _socket->get_addr());
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