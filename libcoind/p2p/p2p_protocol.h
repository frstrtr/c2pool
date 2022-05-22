#pragma once

#include "messages.h"
#include "p2p_socket.h"
#include <libdevcore/logger.h>
#include <libdevcore/events.h>
#include <libdevcore/deferred.h>
#include <libcoind/transaction.h>
#include <sharechains/data.h>
#include <sharechains/share_types.h>
using namespace coind::p2p::messages;
using namespace c2pool::libnet;
using namespace c2pool::deferred;

#include <univalue.h>
#include <btclibs/uint256.h>

#include <vector>
#include <memory>
#include <optional>
using std::shared_ptr, std::weak_ptr, std::make_shared;

#include <boost/asio.hpp>

namespace coind::p2p
{
    class P2PSocket;
}

namespace coind::p2p
{
    //https://en.bitcoin.it/wiki/Protocol_documentation
    class CoindProtocol
    {
    protected:
        shared_ptr<boost::asio::io_context> _context;
        shared_ptr<coind::p2p::P2PSocket> _socket;

    public:
        CoindProtocol(std::shared_ptr<boost::asio::io_context> cxt, shared_ptr<coind::p2p::P2PSocket> _sct);

    public:
        Event<uint256> new_block;    //block_hash
        Event<coind::data::tx_type> new_tx;      //bitcoin_data.tx_type
        Event<coind::data::types::BlockHeaderType> new_headers; //bitcoin_data.block_header_type

        std::shared_ptr<c2pool::deferred::ReplyMatcher<uint256, coind::data::types::BlockType, uint256>> get_block;
        std::shared_ptr<c2pool::deferred::ReplyMatcher<uint256, coind::data::types::BlockHeaderType, uint256>> get_block_header;

        void init(Event<uint256> _new_block, Event<coind::data::tx_type> _new_tx, Event<coind::data::types::BlockHeaderType> _new_headers)
        {
            new_block = _new_block;
            new_tx = _new_tx;
            new_headers = _new_headers;
        }

    private:
        std::shared_ptr<boost::asio::steady_timer> pinger_timer;
        void pinger(int delay);

    public:
//        void get_block_header(uint256 hash);

    public:
        void write(std::shared_ptr<base_message> msg)
        {
            _socket->write(msg);
        }

        shared_ptr<raw_message> make_raw_message() { return make_shared<raw_message>(); }

        void handle(shared_ptr<raw_message> RawMSG)
        {
            LOG_DEBUG << "called HANDLE msg in p2p_protocol";

            switch (RawMSG->name_type.value)
            {
            case commands::cmd_version:
                handle(GenerateMsg<message_version>(RawMSG->value));
                break;
            case commands::cmd_verack:
                handle(GenerateMsg<message_verack>(RawMSG->value));
                break;
            case commands::cmd_ping:
                handle(GenerateMsg<message_ping>(RawMSG->value));
                break;
            case commands::cmd_pong:
                handle(GenerateMsg<message_pong>(RawMSG->value));
                break;
            case commands::cmd_alert:
                handle(GenerateMsg<message_alert>(RawMSG->value));
                break;
            case commands::cmd_getaddr:
                handle(GenerateMsg<message_getaddr>(RawMSG->value));
                break;
            case commands::cmd_addr:
                handle(GenerateMsg<message_addr>(RawMSG->value));
                break;
            case commands::cmd_inv:
                handle(GenerateMsg<message_inv>(RawMSG->value));
                break;
            case commands::cmd_getdata:
                handle(GenerateMsg<message_getdata>(RawMSG->value));
                break;
            case commands::cmd_reject:
                handle(GenerateMsg<message_reject>(RawMSG->value));
                break;
            case commands::cmd_getblocks:
                handle(GenerateMsg<message_getblocks>(RawMSG->value));
                break;
            case commands::cmd_getheaders:
                handle(GenerateMsg<message_getheaders>(RawMSG->value));
                break;
            case commands::cmd_tx:
                handle(GenerateMsg<message_tx>(RawMSG->value));
                break;
            case commands::cmd_block:
                handle(GenerateMsg<message_block>(RawMSG->value));
                break;
            case commands::cmd_headers:
                handle(GenerateMsg<message_headers>(RawMSG->value));
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
        shared_ptr<MsgType> GenerateMsg(PackStream &stream)
        {
            shared_ptr<MsgType> msg = make_shared<MsgType>();
            stream >> *msg;
            return msg;
        }

        void handle(shared_ptr<message_version> msg)
        {
            auto verack = make_message<message_verack>();
            write(verack);
        }

        void handle(shared_ptr<message_verack> msg)
        {
            get_block = std::make_shared<ReplyMatcher<uint256, coind::data::types::BlockType, uint256>>(_context, [&](uint256 hash) -> void {
                auto _msg = make_message<message_getdata>(std::vector<inventory>{{block, hash}});
                write(_msg);
            });

            get_block_header = std::make_shared<c2pool::deferred::ReplyMatcher<uint256, coind::data::types::BlockHeaderType, uint256>> (_context, [&](uint256 hash){
                auto  _msg = make_message<message_getheaders>(1, std::vector<uint256>{}, hash);
                write(_msg);
            });

            pinger(30);
        }

        void handle(shared_ptr<message_ping> msg)
        {
            auto msg_pong = make_message<message_pong>(msg->nonce.get());
            _socket->write(msg_pong);
        }

        void handle(shared_ptr<message_pong> msg)
        {
            LOG_DEBUG << "Handle_PONG";
        }
        void handle(shared_ptr<message_alert> msg)
        {
            //pass # print 'ALERT:', (message, signature)
            //or not todo
        }

        void handle(shared_ptr<message_getaddr> msg)
        {
            // empty
        }
        void handle(shared_ptr<message_addr> msg)
        {
            // empty
        }
        void handle(shared_ptr<message_inv> msg)
        {
            for (auto _inv : msg->invs.get())
            {
                auto inv = _inv.get();
                switch (inv.type)
                {
                case inventory_type::tx:
                {
                    LOG_TRACE << "HANDLED TX";
                    std::vector<c2pool::messages::inventory> inv_vec = {inv};
                    auto msg_getdata = make_message<message_getdata>(inv_vec);
                    _socket->write(msg_getdata);
                }
                break;
                case inventory_type::block:
                    LOG_TRACE << "HANDLED BLOCK, with hash: " << inv.hash.GetHex();
                    new_block.happened(inv.hash); //self.factory.new_block.happened(inv['hash'])
                    break;
                default:
                    //when Unkown inv type
                    LOG_WARNING << "Unknown inv type";
                    break;
                }
            }
        }

        void handle(shared_ptr<message_getdata> msg)
        {
            // empty
        }
        void handle(shared_ptr<message_reject> msg)
        {
            // if p2pool.DEBUG:
            //      print >>sys.stderr, 'Received reject message (%s): %s' % (message, reason)
        }

        void handle(shared_ptr<message_getblocks> msg)
        {
            // empty
        }

        void handle(shared_ptr<message_getheaders> msg)
        {
            // empty
        }

        void handle(shared_ptr<message_tx> msg)
        {
            new_tx.happened(msg->tx.tx);
        }

        void handle(shared_ptr<message_block> msg)
        {
            PackStream packed_header;
            packed_header << msg->block;

            auto block_hash = coind::data::hash256(packed_header);
            get_block->got_response(block_hash, block);
            //TODO!?:
            /*
            block_hash = bitcoin_data.hash256(bitcoin_data.block_header_type.pack(block['header']))
            self.get_block.got_response(block_hash, block)
            self.get_block_header.got_response(block_hash, block['header'])
            */
        }

        void handle(shared_ptr<message_headers> msg)
        {
            //TODO!?:
            // for header in headers:
            //     header = header['header']
            //     self.get_block_header.got_response(bitcoin_data.hash256(bitcoin_data.block_header_type.pack(header)), header)
            // self.factory.new_headers.happened([header['header'] for header in headers])
        }

        void handle(shared_ptr<message_error> msg)
        {
            LOG_WARNING << "Handled message_error! command = " << msg->command.get() << " ; error_text = " << msg->error_text.get();
        }
    };
} // namespace c2pool::p2p