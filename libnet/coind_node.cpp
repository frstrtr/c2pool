#include "coind_node.h"

#include <boost/range/combine.hpp>
#include <boost/foreach.hpp>

#include <networks/network.h>
#include <libcoind/p2p/p2p_socket.h>
#include <libcoind/p2p/p2p_protocol.h>
#include <libdevcore/common.h>
#include <btclibs/arith_uint256.h>

namespace c2pool::libnet
{

    CoindNode::CoindNode(std::shared_ptr<io::io_context> __context, shared_ptr<coind::ParentNetwork> __parent_net, shared_ptr<coind::JSONRPC_Coind> __coind, shared_ptr<ShareTracker> __tracker) : _context(__context), _parent_net(__parent_net), _coind(__coind), _resolver(*_context), work_poller_t(*_context), _tracker(__tracker),
                                                                                                                                                                                                   get_height_rel_highest(_coind, [&](){return coind_work.value().previous_block; })
    {
        LOG_INFO << "CoindNode constructor";
    }

    void CoindNode::start()
    {
        LOG_INFO << "... CoindNode<" << _parent_net->net_name << "> starting...";
        _resolver.async_resolve(_parent_net->P2P_ADDRESS, std::to_string(_parent_net->P2P_PORT),
                                [this](const boost::system::error_code &er,
                                       const boost::asio::ip::tcp::resolver::results_type endpoints)
                                {
                                    ip::tcp::socket socket(*_context);
                                    auto _socket = make_shared<coind::p2p::P2PSocket>(std::move(socket), _parent_net);

                                    protocol = make_shared<coind::p2p::CoindProtocol>(_socket);
                                    protocol->init(new_block, new_tx, new_headers);
                                    _socket->init(endpoints, protocol);
                                });
        //COIND:
        coind_work = Variable<coind::getwork_result>(_coind->getwork(txidcache));
        new_block.subscribe([&](uint256 _value)
                             {
                                //TODO: check!
                                 //Если получаем новый блок, то обновляем таймер
                                 work_poller_t.expires_from_now(boost::posix_time::seconds(15));
                             });
        work_poller();

        //PEER:
        coind_work.changed->subscribe([&](getwork_result result){
            this->poll_header();
        });
        poll_header();

        //BEST SHARE
        coind_work.changed->subscribe([&](getwork_result result){
            set_best_share();
        });
        set_best_share();

        // p2p logic and join p2pool network

        // update mining_txs according to getwork results
        coind_work.changed->run_and_subscribe([&](){
            std::map<uint256, coind::data::tx_type> new_mining_txs;
            auto new_known_txs = known_txs.value();

            uint256 _tx_hash;
            coind::data::tx_type _tx;
            BOOST_FOREACH(boost::tie(_tx_hash, _tx), boost::combine(coind_work.value().transaction_hashes,coind_work.value().transactions))
                        {
                            new_mining_txs[_tx_hash] = _tx;
                            new_known_txs[_tx_hash] = _tx;
                        }

            mining_txs = new_mining_txs;
            known_txs = new_known_txs;
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
            //TODO: for what???
            // yield deferral.sleep(random.expovariate(1/1))

            if (!protocol)
                return;

            std::map<uint256, coind::data::tx_type> trans_difference;
            std::set_difference(before.begin(), before.end(), after.begin(), after.end(), std::inserter(trans_difference, trans_difference.begin()));

            for (auto [tx_hash, tx] : trans_difference)
            {
                //TODO: update coind::message
//                auto msg = protocol->make_message<message_tx>(tx);
//                protocol->write(msg);
            }
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

    shared_ptr<ShareTracker> CoindNode::tracker()
    {
        return _tracker;
    }

    //Каждые 15 секунд или получение ивента new_block, вызываем getwork у coind'a.
    void CoindNode::work_poller()
    {
        coind_work = _coind->getwork(txidcache, known_txs.value());
        work_poller_t.expires_from_now(boost::posix_time::seconds(15));
        work_poller_t.async_wait(bind(&CoindNode::work_poller, this));
    }

    void CoindNode::handle_header(BlockHeaderType new_header)
    {
        auto packed_new_header = new_header.get_pack();
        arith_uint256 hash_header = UintToArith256(_parent_net->POW_FUNC(packed_new_header));
        //check that header matches current target
        if (!(hash_header <= UintToArith256(coind_work.value().bits.target())))
            return;

        auto coind_best_block = coind_work.value().previous_block;

        if (best_block_header.isNull() ||
            ((new_header->previous_block == coind_best_block) && (coind::data::hash256(packed_new_header) == coind_best_block)) ||
            ((coind::data::hash256(packed_new_header) == coind_best_block) && (best_block_header.value()->previous_block != coind_best_block)))
        {
            best_block_header = new_header;
        }
    }

    void CoindNode::poll_header()
    {
        if (!protocol)
            return;
        //TODO update protocol: handle_header(protocol->get_block_header(coind_work.value().previous_block));
    }

    void CoindNode::set_best_share()
    {

        auto [_best, _desired, _decorated_heads, _bad_peer_addresses] = tracker()->think(get_height_rel_highest, coind_work.value().previous_block, coind_work.value().bits.get(), known_txs.value());

        best_share = _best;
        desired = _desired;

        //TODO: Проверка подключения на p2p_node.
        // if (_node_manager->p2pNode() != nullptr)
        // {
        //     for (auto bad_peer_address : bad_peer_addresses)
        //     {
        //         for (auto peer : _node_manager->p2pNode()->peers)
        //         {
        //             if (peer.addr == bad_peer_address)
        //             {
        //                 peer.badPeerHappened();
        //                 break;
        //             }
        //         }
        //     }
        // }
    }

    void CoindNode::clean_tracker()
    {
        //TODO:
        auto [_best, _desired, _decorated_heads, _bad_peer_addresses] = tracker()->think(get_height_rel_highest, coind_work.value().previous_block, coind_work.value().bits.get(), known_txs.value());

        // if (decorated_heads.size() > 0)
        // {
        //     for (int i = 0; i < 1000; i++)
        //     {
        //         bool skip_flag = false;
        //         std::set<uint256> to_remove;
        //         for (auto head : tracker.heads)
        //         {
        //             for (int h = decorated_heads.size() - 5; h < decorated_heads.size(); h++)
        //             {
        //                 if (decorated_heads[h] == head.share_hash)
        //                 {
        //                     skip_flag = true;
        //                 }
        //             }

        //             if (tracker.items[head.share_hash].time_seen > c2pool::time::timestamp() - 300)
        //             {
        //                 skip_flag = true;
        //             }

        //             if (tracker.verified.items.find(head.share_hash) == tracker.verified.items.end())
        //             {
        //                 skip_flag = true;
        //             }

        //             //TODO:
        //             //if max(self.tracker.items[after_tail_hash].time_seen for after_tail_hash in self.tracker.reverse.get(tail)) > time.time() - 120: # XXX stupid
        //             //  continue

        //             if (!skip_flag)
        //             {
        //                 to_remove.insert(head.share_hash);
        //             }
        //         }
        //         if (to_remove.size() == 0)
        //         {
        //             break;
        //         }
        //         for (auto share_hash : to_remove)
        //         {
        //             if (tracker.verified.items.find(share_hash) != tracker.verified.items.end())
        //             {
        //                 tracker.verified.items.erase(share_hash);
        //             }
        //             tracker.remove(share_hash);
        //         }
        //     }
        // }

        // for (int i = 0; i < 1000; i++)
        // {
        //     bool skip_flag = false;
        //     std::set<uint256, set<uint256>> to_remove;

        //     for (auto tail : tracker.tails)
        //     {
        //         int min_height = INT_MAX;
        //         for (auto head : tail.heads)
        //         {
        //             min_height = std::min(min_height, tracker.get_heigth(head));
        //             if (min_height < 2 * tracker->net->CHAIN_LENGTH + 10)
        //             {
        //                 continue
        //             }
        //             to_remove.insert(tracker.reverse.get(head.tail, set<uint256>()));
        //         }
        //     }

        //     if (to_remove.size() == 0)
        //     {
        //         break;
        //     }

        //     //# if removed from this, it must be removed from verified
        //     for (auto aftertail : to_remove)
        //     {
        //         if (tracker.tails.find(tracker.items[aftertail].previous_hash) == tracker.tails.end())
        //         {
        //             continue;
        //         }
        //         if (tracker.verified.items.find(aftertail) != tracker.verified.items.end())
        //         {
        //             tracker.verified.remove(aftertail);
        //         }
        //         tracker.remove(aftertail);
        //     }
        // }

        set_best_share();
    }

}