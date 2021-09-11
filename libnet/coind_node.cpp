#include "coind_node.h"
#include "node_manager.h"
#include "node_manager.h"
#include <coind/p2p/p2p_socket.h>
#include <coind/p2p/p2p_protocol.h>

namespace c2pool::libnet
{

    CoindNode::CoindNode(shared_ptr<NodeManager> node_manager) : _context(1), _resolver(_context), c2pool::libnet::NodeMember(node_manager)
    {
        new_block = std::make_shared<Event<uint256>>();
        new_tx = std::make_shared<Event<UniValue>>();
        new_headers = std::make_shared<Event<UniValue>>();
    }

    void CoindNode::start()
    {
        LOG_INFO << "... CoindNode starting..."; //TODO: log coind name
        _thread.reset(new std::thread([&]() {
            _resolver.async_resolve(netParent()->P2P_ADDRESS, std::to_string(netParent()->P2P_PORT), [this](const boost::system::error_code &er, const boost::asio::ip::tcp::resolver::results_type endpoints) {
                ip::tcp::socket socket(_context);
                auto _socket = make_shared<coind::p2p::P2PSocket>(std::move(socket), *this);

                protocol = make_shared<coind::p2p::CoindProtocol>(_socket, *this);
                protocol->init(new_block, new_tx, new_headers);
                _socket->init(endpoints, protocol);
            });

            //COIND:
            coind_work = std::make_shared<Variable<coind::jsonrpc::data::getwork_result>>(coind()->getwork());
            work_poller();

            //PEER:
            coind_work->changed.subscribe(&CoindNode::poll_header, this);

            //TODO:
            _context.run();
        }));
        LOG_INFO << "... CoindNode started!"; //TODO: log coind name
    }

    void CoindNode::work_poller()
    {
        //TODO:
    }

    void CoindNode::poll_header()
    {
        //TODO: remake
        // //TODO: check for coind p2p connection, if true:
        // uint256 block_header = protocol->get_block_header(coind_work->value.previous_block); //new_header
        // auto _block_header_type = block_header;                                              //TODO: bitcoin_data.block_header_type.pack(new_header)
        // if (netParent()->POW_FUNC(_block_header_type) <= coind_work->value.bits) //bits.target?
        // {
        //     return;
        // }

        // auto coind_best_block = coind_work->value.previous_block;
        // if ((best_block_header->value == nullptr) ||
        //         (block_header.previous_block == coind_best_block && hash256(/*todo: pack for block_header*/))){

        // }
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