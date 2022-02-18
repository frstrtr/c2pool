#pragma once

#include <memory>
#include <string>
#include <iterator>
#include <algorithm>
#include <univalue.h>
#include <btclibs/uint256.h>

#include <boost/bind.hpp>

#include "messages.h"
#include "p2p_node.h"
#include "p2p_socket.h"
#include <networks/network.h>
#include <libdevcore/random.h>
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

        virtual void write(std::shared_ptr<base_message> msg)
        {
            _socket->write(msg);
        }

        virtual void handle(shared_ptr<raw_message> RawMSG)
        {}

        virtual shared_ptr<raw_message> make_raw_message(std::string cmd)
        { return make_shared<raw_message>(cmd); }
    };

    class P2P_Protocol : public Protocol
    {
    private:
        std::shared_ptr<c2pool::Network> _net;
        std::shared_ptr<libnet::p2p::P2PNode> _p2p_node;

        std::set<uint256> remote_tx_hashes;
        int32_t remote_remembered_txs_size = 0;

        std::map<uint256, coind::data::stream::TransactionType_stream> remembered_txs;
        int32_t remembered_txs_size;
        //TODO: known_txs_cache

    public:
        P2P_Protocol(shared_ptr<c2pool::libnet::p2p::P2PSocket> socket, std::shared_ptr<c2pool::Network> __net,
                     std::shared_ptr<libnet::p2p::P2PNode> __p2p_node) : Protocol(socket), _net(__net),
                                                                         _p2p_node(__p2p_node)
        {
            LOG_TRACE << "P2P_Protocol: "
                      << "start constructor";


            c2pool::messages::address_type addrs1(3, "192.168.10.10", 8);
            c2pool::messages::address_type addrs2(9, "192.168.10.11", 9999);

            uint256 best_hash_test_answer;
            best_hash_test_answer.SetHex("06abb7263fc73665f1f5b129959d90419fea5b1fdbea6216e8847bcc286c14e9");
//            auto msg = make_message<message_version>(version, 0, addrs1, addrs2, _p2p_node->get_nonce(), "c2pool-test", 1, best_hash_test_answer);
            auto msg = make_message<message_version>(version, 0, addrs1, addrs2, 254, "c2pool-test", 1,
                                                     best_hash_test_answer);
            write(msg);

            _socket->auto_disconnect_timer.expires_from_now(boost::asio::chrono::seconds(10));
            _socket->auto_disconnect_timer.async_wait([&](const boost::system::error_code &ec)
                                                      {
                                                          if (!ec)
                                                          {
                                                              _socket->disconnect();
                                                              LOG_INFO << "Auto disconnect, peer: "
                                                                       << std::get<0>(_socket->get_addr()) << ":"
                                                                       << std::get<1>(_socket->get_addr());
                                                          }
                                                      });
        }

        void refresh_autodisconnect_timer()
        {
            _socket->auto_disconnect_timer.expires_from_now(boost::asio::chrono::seconds(100));
            _socket->auto_disconnect_timer.async_wait([&](const boost::system::error_code &ec)
                                                      {
                                                          if (!ec)
                                                          {
                                                              _socket->disconnect();
                                                              LOG_INFO << "Auto disconnect, peer: "
                                                                       << std::get<0>(_socket->get_addr()) << ":"
                                                                       << std::get<1>(_socket->get_addr());
                                                          }
                                                      });
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
                    handle(GenerateMsg<message_addrs>(RawMSG->value));
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
                case commands::cmd_forget_tx:
                    handle(GenerateMsg<message_forget_tx>(RawMSG->value));
                    break;
                case commands::cmd_remember_tx:
                    handle(GenerateMsg<message_remember_tx>(RawMSG->value));
                    break;
                case commands::cmd_error:
                    //TODO: fix
                    handle(GenerateMsg<message_error>(RawMSG->value));
                    break;
            }
            refresh_autodisconnect_timer();
        }

        template<class message_type, class... Args>
        shared_ptr<message_type> make_message(Args &&...args)
        {
            auto msg = std::make_shared<message_type>(args...);
            return msg;
        }

    protected:
        template<class MsgType>
        //template <class MsgType<>, class ct = converter_type>
        shared_ptr<MsgType> GenerateMsg(PackStream &stream)
        {
            shared_ptr<MsgType> msg = make_shared<MsgType>();
            stream >> *msg;
            return msg;
        }

        void ping_timer_func(const boost::system::error_code &ec)
        {
            int _time = (int) c2pool::random::Expovariate(100);
            //LOG_TRACE << "TIME FROM EXPOVARIATE: " << _time;
            _socket->ping_timer.expires_from_now(boost::asio::chrono::seconds(_time));
            _socket->ping_timer.async_wait(boost::bind(&P2P_Protocol::ping_timer_func, this, _1));

            auto msg = make_message<message_ping>();
            write(msg);
        }

        void handle(shared_ptr<message_version> msg)
        {
            LOG_DEBUG << "handle message_version";
            LOG_INFO << "Peer " << msg->addr_from.address.get() << ":" << msg->addr_from.port.get()
                     << " says protocol version is " << msg->version.get() << ", client version "
                     << msg->sub_version.get();

            if (other_version != -1)
            {
                LOG_DEBUG << "more than one version message";
            }
            if (msg->version.get() < _net->MINIMUM_PROTOCOL_VERSION)
            {
                LOG_DEBUG << "peer too old";
            }

            other_version = msg->version.get();
            other_sub_version = msg->sub_version.get();
            other_services = msg->services.get();

            if (msg->nonce.get() == _p2p_node->get_nonce())
            {
                LOG_WARNING << "was connected to self";
                //TODO: assert
            }

            //detect duplicate in node->peers
            if (_p2p_node->get_peers().find(msg->nonce.get()) != _p2p_node->get_peers().end())
            {

            }
            if (_p2p_node->get_peers().count(msg->nonce.get()) != 0)
            {
                auto addr = _socket->get_addr();
                LOG_WARNING << "Detected duplicate connection, disconnecting from " << std::get<0>(addr) << ":"
                            << std::get<1>(addr);
                _socket->disconnect();
                return;
            }

            _nonce = msg->nonce.get();
            //TODO: После получения message_version, ожидание сообщения увеличивается с 10 секунд, до 100.
            //*Если сообщение не было получено в течении этого таймера, то происходит дисконект.

            _socket->ping_timer.expires_from_now(
                    boost::asio::chrono::seconds((int) c2pool::random::Expovariate(1.0 / 100)));
            _socket->ping_timer.async_wait(boost::bind(&P2P_Protocol::ping_timer_func, this, _1));

            //TODO: if (p2p_node->advertise_ip):
            //TODO:     раз в random.expovariate(1/100*len(p2p_node->peers.size()+1), отправляется sendAdvertisement()

            //TODO: msg->best_share_hash != nullptr: p2p_node.handle_share_hashes(...)

            //TODO: <Методы для обработки транзакций>: send_have_tx; send_remember_tx
        }

        void handle(shared_ptr<message_addrs> msg)
        {
            for (auto addr_record: msg->addrs.l)
            {
                auto addr = addr_record.get();
                _p2p_node->got_addr(std::make_tuple(addr.address.address, std::to_string(addr.address.port)),
                                    addr.address.services, std::min((int64_t) dev::timestamp(), addr.timestamp));

                if ((c2pool::random::RandomFloat(0, 1) < 0.8) && (!_p2p_node->get_peers().empty()))
                {
                    auto _proto = c2pool::random::RandomChoice(_p2p_node->get_peers());
                    std::vector<c2pool::messages::stream::addr_stream> _addrs{addr_record};
                    _proto->write(make_message<message_addrs>(_addrs));
                }
            }
        }

        //TODO: test:
        void handle(shared_ptr<message_addrme> msg)
        {
            auto host = std::get<0>(_socket->get_addr());

            if (host.compare("127.0.0.1") == 0)
            {
                if ((c2pool::random::RandomFloat(0, 1) < 0.8) && (!_p2p_node->get_peers().empty()))
                {
                    auto _proto = c2pool::random::RandomChoice(_p2p_node->get_peers());
                    _proto->write(make_message<message_addrme>(msg->port.get()));
                }
            } else
            {
                _p2p_node->got_addr(std::make_tuple(host, std::to_string(msg->port.get())), other_services,
                                    dev::timestamp());
                if ((c2pool::random::RandomFloat(0, 1) < 0.8) && (!_p2p_node->get_peers().empty()))
                {
                    auto _proto = c2pool::random::RandomChoice(_p2p_node->get_peers());
                    std::vector<c2pool::messages::addr> _addrs{
                            c2pool::messages::addr(dev::timestamp(), other_services, host, msg->port.get())
                    };
                    _proto->write(make_message<message_addrs>(_addrs));
                }
            }
        }

        void handle(shared_ptr<message_ping> msg)
        {

        }

        //TODO: TEST
        void handle(shared_ptr<message_getaddrs> msg)
        {
            uint32_t count = msg->count.get();
            if (count > 100)
            {
                count = 100;
            }

            std::vector<c2pool::messages::addr> _addrs;
            for (auto v: _p2p_node->get_good_peers(count))
            {
                auto _addr = _p2p_node->get_addr_store()->Get(v);
                _addrs.push_back(
                        c2pool::messages::addr(_addr.last_seen,
                                               _addr.service, std::get<0>(v), dev::str_to_int<int>(std::get<1>(v)))
                );
            }

            write(make_message<message_addrs>(_addrs));
        }

        void handle(shared_ptr<message_error> msg)
        {
            LOG_WARNING << "Handled message_error! command = " << msg->command.get() << " ; error_text = "
                        << msg->error_text.get();
        }

        void handle(shared_ptr<message_shares> msg)
        {
            //t0
            vector<tuple<shared_ptr<c2pool::shares::BaseShare>, vector<UniValue>>> result; //share, txs
            for (auto wrappedshare: msg->raw_shares)
            {
                int _type = wrappedshare["type"].get_int();
                if (_type < 17)
                { //TODO: 17 = minimum share version; move to macros
                    continue;
                }

                shared_ptr<c2pool::shares::BaseShare> share = c2pool::shares::load_share(wrappedshare, _net,
                                                                                         _socket->get_addr());
                std::vector<UniValue> txs;
                if (_type >= 13)
                {
                    for (auto tx_hash: share->new_transaction_hashes)
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
            std::vector<uint256> hashes;
            for (auto hash: msg->hashes.l)
            {
                hashes.push_back(hash.get());
            }

            std::vector<uint256> stops;
            for (auto hash: msg->stops.l)
            {
                stops.push_back(hash.get());
            }

            //std::vector<uint256> hashes, uint64_t parents, std::vector<uint256> stops, std::tuple<std::string, std::string> peer_addr
            auto shares = _p2p_node->handle_get_shares(hashes, msg->parents.value, stops, _socket->get_addr());

            std::vector<share_type> _shares;
            try
            {
                for (auto share: shares)
                {
                    auto contents = share->to_contents();
                    share_type _share(share->SHARE_VERSION, contents.write());
                    _shares.push_back(_share);
                }
                auto reply_msg = make_message<message_sharereply>(msg->id.get(), good, _shares);
                write(reply_msg);
            }
            catch (const std::invalid_argument &e)
            {
                auto reply_msg = make_message<message_sharereply>(msg->id.get(), too_long, _shares);
                write(reply_msg);
            }
        }

        void handle(shared_ptr<message_sharereply> msg)
        {
            std::vector<shared_ptr<c2pool::shares::BaseShare>> res;
            if (msg->result.value == 0)
            {
                for (auto share: msg->shares.l)
                {
                    if (share.type.value >= 17) //TODO: 17 = minimum share version; move to macros
                    {
                        UniValue contents(UniValue::VOBJ);
                        contents.read(share.contents.get());

                        shared_ptr<c2pool::shares::BaseShare> _share = c2pool::shares::load_share(contents, _net,
                                                                                                  _socket->get_addr());
                        res.push_back(_share);
                    }
                }
            } else
            {
                //TODO: res = failure.Failure(self.ShareReplyError(result))
            }
            //TODO: self.get_shares.got_response(id, res)
        }

        void handle(shared_ptr<message_bestblock> msg)
        {
            _p2p_node->handle_bestblock(msg->header);
        }

        void handle(shared_ptr<message_have_tx> msg)
        {
            remote_tx_hashes.insert(msg->tx_hashes.l.begin(), msg->tx_hashes.l.end());
            if (remote_tx_hashes.size() > 10000)
            {
                remote_tx_hashes.erase(remote_tx_hashes.begin(),
                                       std::next(remote_tx_hashes.begin(), remote_tx_hashes.size() - 10000));
            }
        }

        void handle(shared_ptr<message_losing_tx> msg)
        {
            //remove all msg->txs hashes from remote_tx_hashes
            std::set<uint256> losing_txs;
            losing_txs.insert(msg->tx_hashes.l.begin(), msg->tx_hashes.l.end());

            std::set<uint256> diff_txs;
            std::set_difference(remote_tx_hashes.begin(), remote_tx_hashes.end(),
                                losing_txs.begin(), losing_txs.end(),
                                std::inserter(diff_txs, diff_txs.begin()));

            remote_tx_hashes = diff_txs;
        }

        void handle(shared_ptr<message_remember_tx> msg)
        {
            for (auto tx_hash: msg->tx_hashes.l)
            {
                if (remembered_txs.find(tx_hash.get()) != remembered_txs.end())
                {
                    LOG_WARNING << "Peer referenced transaction twice, disconnecting";
                    _socket->disconnect();
                    return;
                }

                coind::data::stream::TransactionType_stream tx;
                //TODO: _p2p_node.known_txs_var
                if (_p2p_node->known_txs_var.find(tx_hash.get()) != _p2p_node->known_txs_var.end())
                {
                    tx = _p2p_node.known_txs_var[tx_hash.get()];
                } else
                {
                    for (auto cache : known_txs_cache)
                    {
                        if (cache.find(tx_hash.get()) != cache.end())
                        {
                            tx = cache[tx_hash.get()];
                            LOG_INFO << "Transaction " << tx_hash.get().ToString() << " rescued from peer latency cache!";
                            break;
                        } else
                        {
                            LOG_WARNING << "Peer referenced unknown transaction " << tx_hash.get().ToString() << " disconnecting";
                            _socket->disconnect();
                            return;
                        }
                    }
                }
            }

            if (remembered_txs_size >= max_remembered_txs_size)
            {
                throw std::runtime_error("too much transaction data stored!");
            }
        }

        void handle(shared_ptr<message_forget_tx> msg)
        {
            for (auto tx_hash : msg->tx_hashes.l)
            {
                PackStream stream;
                stream << remembered_txs[tx_hash.get()];
                remembered_txs_size -= 100 + stream.size();
                assert(remembered_txs_size >= 0);
                remembered_txs.erase(tx_hash.get());
            }
        }
    };
} // namespace c2pool::p2p