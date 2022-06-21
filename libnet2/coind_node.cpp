#include "coind_node.h"

#include <libdevcore/deferred.h>

void CoindNode::work_poller()
{
    coind_work = coind->getwork(txidcache, known_txs.value());
    work_poller_t.expires_from_now(boost::posix_time::seconds(15));
    work_poller_t.async_wait(bind(&CoindNode::work_poller, this));
}

void CoindNode::poll_header()
{
    if (!protocol)
        return;
    //TODO update protocol: handle_header(protocol->get_block_header(coind_work.value().previous_block));
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_version> msg, std::shared_ptr<CoindProtocol> protocol)
{
    auto verack = std::make_shared<coind::messages::message_verack>();
    protocol->write(verack);
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_verack> msg, std::shared_ptr<CoindProtocol> protocol)
{
    protocol->get_block = std::make_shared<c2pool::deferred::ReplyMatcher<uint256, coind::data::types::BlockType, uint256>>(context, [&](uint256 hash) -> void {
        auto _msg = std::make_shared<coind::messages::message_getdata>(std::vector<inventory>{{block, hash}});
        protocol->write(_msg);
    });

    protocol->get_block_header = std::make_shared<c2pool::deferred::ReplyMatcher<uint256, coind::data::types::BlockHeaderType, uint256>> (context, [&](uint256 hash){
        auto  _msg = std::make_shared<coind::messages::message_getheaders>(1, std::vector<uint256>{}, hash);
        protocol->write(_msg);
    });

//    pinger(30); //TODO: wanna for this?
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_ping> msg, std::shared_ptr<CoindProtocol> protocol)
{
    auto msg_pong = std::make_shared<coind::messages::message_pong>(msg->nonce.get());
    protocol->write(msg_pong);
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_pong> msg, std::shared_ptr<CoindProtocol> protocol)
{
    LOG_DEBUG << "Handle_PONG";
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_alert> msg, std::shared_ptr<CoindProtocol> protocol)
{
    LOG_WARNING << "Handled message_alert signature: " << msg->signature.get();
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_getaddr> msg, std::shared_ptr<CoindProtocol> protocol)
{
// empty
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_addr> msg, std::shared_ptr<CoindProtocol> protocol)
{
// empty
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_inv> msg, std::shared_ptr<CoindProtocol> protocol)
{
    for (auto _inv : msg->invs.get())
    {
        auto inv = _inv.get();
        switch (inv.type)
        {
            case inventory_type::tx:
            {
                LOG_TRACE << "HANDLED TX";
                std::vector<inventory> inv_vec = {inv};
                auto msg_getdata = std::make_shared<coind::messages::message_getdata>(inv_vec);
                protocol->write(msg_getdata);
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

void CoindNode::handle(std::shared_ptr<coind::messages::message_getdata> msg, std::shared_ptr<CoindProtocol> protocol)
{
// empty
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_reject> msg, std::shared_ptr<CoindProtocol> protocol)
{
// if p2pool.DEBUG:
    //      print >>sys.stderr, 'Received reject message (%s): %s' % (message, reason)
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_getblocks> msg, std::shared_ptr<CoindProtocol> protocol)
{
// empty
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_getheaders> msg, std::shared_ptr<CoindProtocol> protocol)
{
// empty
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_tx> msg, std::shared_ptr<CoindProtocol> protocol)
{
    new_tx.happened(msg->tx.tx);
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_block> msg, std::shared_ptr<CoindProtocol> protocol)
{
    PackStream packed_header;
    packed_header << msg->block;
    auto block_hash = coind::data::hash256(packed_header);

    coind::data::BlockTypeA block;
    block.set_stream(msg->block);

    protocol->get_block->got_response(block_hash, *block.get());
    protocol->get_block_header->got_response(block_hash, block.get()->header);
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_headers> msg, std::shared_ptr<CoindProtocol> protocol)
{
    std::vector<coind::data::types::BlockHeaderType> _new_headers;

    for (auto _block : msg->headers.get())
    {
        coind::data::BlockTypeA block;
        block.set_stream(_block);

        PackStream packed_header;
        packed_header << _block;
        auto block_hash = coind::data::hash256(packed_header);

        protocol->get_block_header->got_response(block_hash, block->header);

        _new_headers.push_back(block->header);
    }

    new_headers.happened(_new_headers);
}
