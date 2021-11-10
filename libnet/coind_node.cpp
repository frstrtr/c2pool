#include "coind_node.h"

#include <networks/network.h>
#include <libcoind/p2p/p2p_socket.h>
#include <libcoind/p2p/p2p_protocol.h>
#include <libdevcore/common.h>
#include <btclibs/arith_uint256.h>

namespace c2pool::libnet
{

    CoindNode::CoindNode(std::shared_ptr<io::io_context> __context, shared_ptr<coind::ParentNetwork> __parent_net, shared_ptr<coind::JSONRPC_Coind> __coind) : _context(__context), _parent_net(__parent_net), _coind(__coind), _resolver(*_context), work_poller_t(*_context)
    {
        LOG_INFO << "CoindNode constructor";
        new_block = std::make_shared<Event<uint256>>();
        new_tx = std::make_shared<Event<coind::data::tx_type>>();
        new_headers = std::make_shared<Event<c2pool::shares::BlockHeaderType>>();
    }

    void CoindNode::start()
    {
        LOG_INFO << "... CoindNode<" << _parent_net->net_name << ">starting...";
        std::cout << 1 << std::endl;
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
        std::cout << 1 << std::endl;
        //COIND:
        coind_work = Variable<coind::getwork_result>(_coind->getwork(txidcache));
        std::cout << 1 << std::endl;
        new_block->subscribe([&](uint256 _value)
                             {
                                 //Если получаем новый блок, то обновляем таймер
                                 work_poller_t.expires_from_now(boost::posix_time::seconds(15));
                             });
        std::cout << 1 << std::endl;
        work_poller();
        std::cout << 1 << " (after work_poller calling)" << std::endl;

        //PEER:
        std::cout << 1 << std::endl;
        coind_work.changed.subscribe(&CoindNode::poll_header, this);
        std::cout << 1 << std::endl;
        poll_header();
        std::cout << 1 << std::endl;

        //BEST SHARE
        std::cout << 1 << std::endl;
        coind_work.changed.subscribe(&CoindNode::set_best_share, this);
        std::cout << 1 << std::endl;
        set_best_share();
        std::cout << 1 << std::endl;

        // p2p logic and join p2pool network

        // update mining_txs according to getwork results
        // coind_work.changed.run_and_subscribe([&]()
        // {
        //     /* TODO:
        //         new_mining_txs = {}
        //         new_known_txs = dict(self.known_txs_var.value)
        //         for tx_hash, tx in zip(self.bitcoind_work.value['transaction_hashes'], self.bitcoind_work.value['transactions']):
        //             new_mining_txs[tx_hash] = tx
        //             new_known_txs[tx_hash] = tx
        //         self.mining_txs_var.set(new_mining_txs)
        //         self.known_txs_var.set(new_known_txs)
        //     */
        //    auto new_mining_txs;
        //    auto new_known_txs;

        // });

        LOG_INFO << "... CoindNode started!"; //TODO: log coind name
    }

    //Каждые 15 секунд или получение ивента new_block, вызываем getwork у coind'a.
    void CoindNode::work_poller()
    {
        coind_work = _coind->getwork(txidcache, known_txs.value);
        work_poller_t.expires_from_now(boost::posix_time::seconds(15));
        work_poller_t.async_wait(bind(&CoindNode::work_poller, this));
    }

    //TODO: test
    void CoindNode::handle_header(const BlockHeaderType &new_header)
    {
        PackStream packed_new_header;
        PackShareType(BlockHeaderType, new_header, packed_new_header);

        arith_uint256 hash_header = UintToArith256(_parent_net->POW_FUNC(packed_new_header));
        //check that header matches current target
        if (!(hash_header <= UintToArith256(coind_work.value.bits.target())))
            return;

        auto coind_best_block = coind_work.value.previous_block;

        PackStream packed_best_block_header;
        PackShareType(BlockHeaderType, best_block_header.value.value(), packed_best_block_header);

        if (!best_block_header.value.has_value() ||
            ((new_header.previous_block == coind_best_block) && (coind::data::hash256(packed_best_block_header) == coind_best_block)) ||
            ((coind::data::hash256(packed_new_header) == coind_best_block) && (best_block_header.value->previous_block != coind_best_block)))
        {
            best_block_header = new_header;
        }
    }

    void CoindNode::poll_header()
    {
        if (!protocol)
            return;
        //TODO: handle_header(protocol->get_block_header(coind_work.value.previous_block));
    }

    void CoindNode::set_best_share()
    {
        //TODO:
        // auto tracker_think_result = coind()->think(/*TODO: self.get_height_rel_highest, self.coind_work.value['previous_block'], self.coind_work.value['bits'], self.known_txs_var.value*/);

        // best_share_var = tracker_think_result.best;
        //TODO: self.desired_var.set(desired)

        //TODO:
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
        // c2pool::shares::TrackerThinkResult think_result = tracker->think();

        // auto best = think_result.best_hash;
        // auto desired = think_result.desired;
        // auto decorated_heads = think_result.decorated_heads;
        // auto bad_peer_addresses = think_result.bad_peer_addresses;

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
        //     set_best_share();
        // }
    }

}