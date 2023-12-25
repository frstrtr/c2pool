#include "coind_node.h"

#include <libdevcore/deferred.h>

#include <boost/range/combine.hpp>
#include <boost/foreach.hpp>

void CoindNode::start()
{
	LOG_INFO << "... CoindNode<" << parent_net->net_name << "> starting...";
	connect(NetAddress(parent_net->P2P_ADDRESS, parent_net->P2P_PORT));
	//COIND:
	coind_work->set(coind->getwork(txidcache));
    get_height_rel_highest.set_get_best_block_func([_coind_work = coind_work->value()](){return _coind_work.previous_block; });
	new_block->subscribe([&](uint256 _value)
						{
							//Если получаем новый блок, то обновляем таймер
							work_poller_t.expires_from_now(boost::posix_time::seconds(15));
						});
	work_poller();

	//PEER:
	coind_work->changed->subscribe([&](coind::getwork_result result){
		this->poll_header();
	});
	poll_header();

	//BEST SHARE
	coind_work->changed->subscribe([&](coind::getwork_result result)
    {
		set_best_share();
	});
	set_best_share();

	// p2p logic and join p2pool network

	// update mining_txs according to getwork results
	coind_work->changed->run_and_subscribe([&](){
        std::map<uint256, coind::data::tx_type> new_mining_txs;
        std::map<uint256, coind::data::tx_type> added_known_txs;

        uint256 _tx_hash;
		coind::data::tx_type _tx;

        BOOST_FOREACH(boost::tie(_tx_hash, _tx), boost::combine(coind_work->value().transaction_hashes,coind_work->value().transactions))
		{
			new_mining_txs[_tx_hash] = _tx;

            if (!known_txs->exist(_tx_hash))
                added_known_txs[_tx_hash] = _tx;
		}

        mining_txs->set(new_mining_txs);
        known_txs->add(added_known_txs);
	});

	// add p2p transactions from bitcoind to known_txs
	new_tx->subscribe([&](coind::data::tx_type _tx)
    {
		known_txs->add(coind::data::hash256(pack<coind::data::stream::TransactionType_stream>(_tx)), _tx);
	});

	// forward transactions seen to bitcoind
    if (cur_share_version < 34)
    {
        known_txs->transitioned->subscribe(
                [&](std::map<uint256, coind::data::tx_type> before, std::map<uint256, coind::data::tx_type> after)
                {
//		//TODO: for what???
//		// yield deferral.sleep(random.expovariate(1/1))
//
                    if (!protocol)
                        return;

                    std::map<uint256, coind::data::tx_type> diff;
                    std::set_difference(after.begin(), after.end(), before.begin(), before.end(),
                                        std::inserter(diff, diff.begin()));

                    for (auto [tx_hash, tx]: diff)
                    {
                        auto msg = std::make_shared<coind::messages::message_tx>(after[tx_hash]);
                        LOG_DEBUG_COIND << "Protocol write message_tx with: " << tx_hash << ": " << *tx;
                        protocol->write(msg);
                    }
                });
    }

    /* TODO: GOT BLOCK FROM PEER! Passing to bitcoind!
     *
     * if share.VERSION >= 34:
                print 'GOT BLOCK FROM PEER! %s %s%064x' % (
                        p2pool_data.format_hash(share.hash),
                        self.net.PARENT.BLOCK_EXPLORER_URL_PREFIX,
                        share.header_hash)
                return
    tracker->verified.added->subscribe([&](const ShareType& share){
        if (UintToArith256(share->pow_hash) > UintToArith256(FloatingInteger(share->header->bits).target()))
            return;

        block = share->as_b
    });
    */

    if (cur_share_version < 34)
        forget_old_txs();

	/* TODO:
	t = deferral.RobustLoopingCall(self.clean_tracker)
	t.start(5)
	stop_signal.watch(t.stop)
	 */

	LOG_INFO << "... CoindNode[" << parent_net->net_name << "] " << "started!";
}

void CoindNode::work_poller()
{
    coind_work->set(coind->getwork(txidcache, known_txs->value()));
    work_poller_t.expires_from_now(boost::posix_time::seconds(15));
    work_poller_t.async_wait([&](const boost::system::error_code &ec){ work_poller(); });
}

void CoindNode::poll_header()
{
    if (!protocol || !is_connected())
        return;

	protocol->get_block_header->yield(coind_work->value().previous_block, [&](coind::data::BlockHeaderType new_header){ handle_header(new_header); }, coind_work->value().previous_block);
}

void CoindNode::forget_old_txs()
{
    std::map<uint256, coind::data::tx_type> new_known_txs;

    if (pool_node)
    {
        for (const auto& peer : pool_node->peers)
        {
            for (auto [hash, tx] : peer.second->remembered_txs)
                new_known_txs[hash] = tx.get();
        }
    }

    for (auto [hash, tx]: mining_txs->value())
        new_known_txs[hash] = tx;

    for (auto [hash, tx]: mining2_txs->value())
        new_known_txs[hash] = tx;

    auto chainf = tracker->get_chain(best_share->value(), min(120, tracker->get_height(best_share->value())));

    uint256 hash;
    while (chainf(hash))
    {
        auto _share = tracker->get(hash);
        assert(_share);

        if (_share->VERSION >= 34)
            continue;
        for (auto tx_hash : *_share->new_transaction_hashes)
        {
            if (known_txs->exist(tx_hash))
                new_known_txs[tx_hash] = known_txs->value()[tx_hash];
        }
    }
    known_txs->set(new_known_txs);

    forget_old_txs_t.expires_from_now(boost::posix_time::seconds(10));
    forget_old_txs_t.async_wait([&](const boost::system::error_code &ec){ forget_old_txs(); });
}


void CoindNode::handle_message_version(std::shared_ptr<coind::messages::message_version> msg, std::shared_ptr<CoindProtocol> protocol)
{
    auto verack = std::make_shared<coind::messages::message_verack>();
    protocol->write(verack);
}

void CoindNode::handle_message_verack(std::shared_ptr<coind::messages::message_verack> msg, std::shared_ptr<CoindProtocol> protocol)
{
    protocol->get_block = std::make_shared<c2pool::deferred::ReplyMatcher<uint256, coind::data::types::BlockType, uint256>>(context, [&, _proto = protocol](uint256 hash) -> void {
        auto _msg = std::make_shared<coind::messages::message_getdata>(std::vector<inventory>{{block, hash}});
        _proto->write(_msg);
    });

    protocol->get_block_header = std::make_shared<c2pool::deferred::ReplyMatcher<uint256, coind::data::BlockHeaderType, uint256>> (context, [&, _proto = protocol](uint256 hash){
        auto  _msg = std::make_shared<coind::messages::message_getheaders>(1, std::vector<uint256>{}, hash);
        _proto->write(_msg);
    });

    set_connection_status(true);

//    pinger(30); //TODO: wanna for this?
}

void CoindNode::handle_message_ping(std::shared_ptr<coind::messages::message_ping> msg, std::shared_ptr<CoindProtocol> protocol)
{
    auto msg_pong = std::make_shared<coind::messages::message_pong>(msg->nonce.get());
    protocol->write(msg_pong);
}

void CoindNode::handle_message_pong(std::shared_ptr<coind::messages::message_pong> msg, std::shared_ptr<CoindProtocol> protocol)
{
    LOG_DEBUG_COIND << "Handle_PONG";
}

void CoindNode::handle_message_alert(std::shared_ptr<coind::messages::message_alert> msg, std::shared_ptr<CoindProtocol> protocol)
{
    LOG_WARNING << "Handled message_alert signature: " << msg->signature.get();
}

void CoindNode::handle_message_getaddr(std::shared_ptr<coind::messages::message_getaddr> msg, std::shared_ptr<CoindProtocol> protocol)
{
// empty
}

void CoindNode::handle_message_addr(std::shared_ptr<coind::messages::message_addr> msg, std::shared_ptr<CoindProtocol> protocol)
{
// empty
}

void CoindNode::handle_message_inv(std::shared_ptr<coind::messages::message_inv> msg, std::shared_ptr<CoindProtocol> protocol)
{
    std::vector<inventory> inv_vec;

    for (auto _inv : msg->invs.get())
    {
        auto inv = _inv.get();
        switch (inv.type)
        {
            case inventory_type::tx:
            {
//                LOG_TRACE << "HANDLED TX";
                inv_vec.push_back(inv);
            }
                break;
            case inventory_type::block:
//                LOG_TRACE << "HANDLED BLOCK, with hash: " << inv.hash.GetHex();
                new_block->happened(inv.hash);
                break;
            default:
                //when Unkown inv type
                LOG_WARNING << "Unknown inv type";
                break;
        }
    }

    if (!inv_vec.empty())
    {
        auto msg_getdata = std::make_shared<coind::messages::message_getdata>(inv_vec);
        protocol->write(msg_getdata);
    }
}

void CoindNode::handle_message_getdata(std::shared_ptr<coind::messages::message_getdata> msg, std::shared_ptr<CoindProtocol> protocol)
{
// empty
}

void CoindNode::handle_message_reject(std::shared_ptr<coind::messages::message_reject> msg, std::shared_ptr<CoindProtocol> protocol)
{
// if p2pool.DEBUG:
    //      print >>sys.stderr, 'Received reject message (%s): %s' % (message, reason)
}

void CoindNode::handle_message_getblocks(std::shared_ptr<coind::messages::message_getblocks> msg, std::shared_ptr<CoindProtocol> protocol)
{
// empty
}

void CoindNode::handle_message_getheaders(std::shared_ptr<coind::messages::message_getheaders> msg, std::shared_ptr<CoindProtocol> protocol)
{
// empty
}

void CoindNode::handle_message_tx(std::shared_ptr<coind::messages::message_tx> msg, std::shared_ptr<CoindProtocol> protocol)
{
    new_tx->happened(msg->tx.tx);
}

void CoindNode::handle_message_block(std::shared_ptr<coind::messages::message_block> msg, std::shared_ptr<CoindProtocol> protocol)
{
    PackStream packed_header;
    packed_header << msg->block;
    auto block_hash = coind::data::hash256(packed_header);

    coind::data::BlockTypeA block;
    block.set_stream(msg->block);

    protocol->get_block->got_response(block_hash, *block.get());

	coind::data::BlockHeaderType _header;
	_header.set_value(block->header);
	protocol->get_block_header->got_response(block_hash, _header);
}

void CoindNode::handle_message_headers(std::shared_ptr<coind::messages::message_headers> msg, std::shared_ptr<CoindProtocol> protocol)
{
    std::vector<coind::data::types::BlockHeaderType> _new_headers;

    for (auto _block : msg->headers.get())
    {
        PackStream packed_header;
        packed_header << _block.header;
        auto block_hash = coind::data::hash256(packed_header, true);

        coind::data::BlockHeaderType _header;
		_header.set_stream(_block.header);

        protocol->get_block_header->got_response(block_hash, _header);

        _new_headers.push_back(*_header.get());
    }

    new_headers->happened(_new_headers);
}