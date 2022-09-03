#include "coind_node.h"

#include <libdevcore/deferred.h>

#include <boost/range/combine.hpp>
#include <boost/foreach.hpp>

void CoindNode::start()
{
	LOG_INFO << "... CoindNode<" << parent_net->net_name << "> starting...";
	connect(std::make_tuple(parent_net->P2P_ADDRESS, std::to_string(parent_net->P2P_PORT)));
	//COIND:
	coind_work = Variable<coind::getwork_result>(coind->getwork(txidcache));
	new_block.subscribe([&](uint256 _value)
						{
							//TODO: check!
							//Если получаем новый блок, то обновляем таймер
							work_poller_t.expires_from_now(boost::posix_time::seconds(15));
						});
	work_poller();

	//PEER:
	coind_work.changed->subscribe([&](coind::getwork_result result){
		this->poll_header();
	});
	poll_header();

	//BEST SHARE
	coind_work.changed->subscribe([&](coind::getwork_result result){
		set_best_share();
	});
	set_best_share();

	// p2p logic and join p2pool network

	// update mining_txs according to getwork results
	coind_work.changed->run_and_subscribe([&](){
//		std::map<uint256, coind::data::tx_type> new_mining_txs;
//		auto new_known_txs = known_txs.value();
//
//		uint256 _tx_hash;
//		coind::data::tx_type _tx;
//		BOOST_FOREACH(boost::tie(_tx_hash, _tx), boost::combine(coind_work.value().transaction_hashes,coind_work.value().transactions))
//		{
//			new_mining_txs[_tx_hash] = _tx;
//			new_known_txs[_tx_hash] = _tx;
//		}
//
//		mining_txs = new_mining_txs;
//		known_txs = new_known_txs;
	});

	// add p2p transactions from bitcoind to known_txs
	new_tx.subscribe([&](coind::data::tx_type _tx){
		coind::data::stream::TransactionType_stream packed_tx = _tx;
		PackStream stream_tx;
		stream_tx << packed_tx;
		known_txs.add(coind::data::hash256(stream_tx), _tx);
	});

	// forward transactions seen to bitcoind
	known_txs.transitioned->subscribe([&](std::map<uint256, coind::data::tx_type> before, std::map<uint256, coind::data::tx_type> after){
//		//TODO: for what???
//		// yield deferral.sleep(random.expovariate(1/1))
//
		if (!protocol)
			return;
//
//		std::map<uint256, coind::data::tx_type> trans_difference;
//		std::set_difference(before.begin(), before.end(), after.begin(), after.end(), std::inserter(trans_difference, trans_difference.begin()));
//
//		for (auto [tx_hash, tx] : trans_difference)
//		{
//			//TODO: update coind::message
////                auto msg = protocol->make_message<message_tx>(tx);
////                protocol->write(msg);
//		}
	});

	/* TODO:
	 * # forward transactions seen to bitcoind
	@self.known_txs_var.transitioned.watch
	@defer.inlineCallbacks
	def _(before, after):
		yield deferral.sleep(random.expovariate(1/1))
		if self.factory.conn.value is None:
			return
		for tx_hash in set(after) - set(before):
			self.factory.conn.value.send_tx(tx=after[tx_hash])

	@self.tracker.verified.added.watch
	def _(share):
		if not (share.pow_hash <= share.header['bits'].target):
			return

		block = share.as_block(self.tracker, self.known_txs_var.value)
		if block is None:
			print >>sys.stderr, 'GOT INCOMPLETE BLOCK FROM PEER! %s bitcoin: %s%064x' % (p2pool_data.format_hash(share.hash), self.net.PARENT.BLOCK_EXPLORER_URL_PREFIX, share.header_hash)
			return
		helper.submit_block(block, True, self.factory, self.bitcoind, self.bitcoind_work, self.net)
		print
		print 'GOT BLOCK FROM PEER! Passing to bitcoind! %s bitcoin: %s%064x' % (p2pool_data.format_hash(share.hash), self.net.PARENT.BLOCK_EXPLORER_URL_PREFIX, share.header_hash)
		print

	def forget_old_txs():
		new_known_txs = {}
		if self.p2p_node is not None:
			for peer in self.p2p_node.peers.itervalues():
				new_known_txs.update(peer.remembered_txs)
		new_known_txs.update(self.mining_txs_var.value)
		for share in self.tracker.get_chain(self.best_share_var.value, min(120, self.tracker.get_height(self.best_share_var.value))):
			for tx_hash in share.new_transaction_hashes:
				if tx_hash in self.known_txs_var.value:
					new_known_txs[tx_hash] = self.known_txs_var.value[tx_hash]
		self.known_txs_var.set(new_known_txs)
	t = deferral.RobustLoopingCall(forget_old_txs)
	t.start(10)
	stop_signal.watch(t.stop)

	t = deferral.RobustLoopingCall(self.clean_tracker)
	t.start(5)
	stop_signal.watch(t.stop)

	 */

	LOG_INFO << "... CoindNode started!"; //TODO: log coind name
}

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
	protocol->get_block_header->yield(coind_work.value().previous_block, std::bind(&CoindNode::handle_header, this, placeholders::_1), coind_work.value().previous_block);
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
//        protocol->write(_msg);
    });

//    pinger(30); //TODO: wanna for this?
}

void CoindNode::handle_message_ping(std::shared_ptr<coind::messages::message_ping> msg, std::shared_ptr<CoindProtocol> protocol)
{
    auto msg_pong = std::make_shared<coind::messages::message_pong>(msg->nonce.get());
    protocol->write(msg_pong);
}

void CoindNode::handle_message_pong(std::shared_ptr<coind::messages::message_pong> msg, std::shared_ptr<CoindProtocol> protocol)
{
    LOG_DEBUG << "Handle_PONG";
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
                LOG_TRACE << "HANDLED TX";
                inv_vec.push_back(inv);
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
    new_tx.happened(msg->tx.tx);
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

        std::cout << _block.header.merkle_root.get().GetHex() << std::endl;
        std::cout << _block.header.bits.get() << std::endl;
        std::cout << _block.header.timestamp.get() << std::endl;
        std::cout << _block.header.version.get() << std::endl;
        std::cout << _block.header.nonce.get() << std::endl;
        std::cout << _block.header.previous_block.get().GetHex() << std::endl;

        coind::data::BlockHeaderType _header;
		_header.set_stream(_block.header);
        std::cout << block_hash.GetHex() << std::endl;

        protocol->get_block_header->got_response(block_hash, _header);

        _new_headers.push_back(*_header.get());
    }

    new_headers.happened(_new_headers);
}
