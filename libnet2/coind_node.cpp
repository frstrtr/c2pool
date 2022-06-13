#include "coind_node.h"

void CoindNodeData::handle_header(coind::data::BlockHeaderType new_header)
{
    auto packed_new_header = new_header.get_pack();
    arith_uint256 hash_header = UintToArith256(parent_net->POW_FUNC(packed_new_header));
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

void CoindNodeData::set_best_share()
{

}

void CoindNodeData::clean_tracker()
{

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
    //TODO update protocol: handle_header(protocol->get_block_header(coind_work.value().previous_block));
}
