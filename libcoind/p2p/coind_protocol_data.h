#pragma once

#include <libdevcore/logger.h>
#include <libdevcore/events.h>
#include <libdevcore/deferred.h>
#include <btclibs/uint256.h>
#include <libcoind/transaction.h>
#include <libcoind/types.h>

struct CoindProtocolData
{
    Event<uint256> new_block;    //block_hash
    Event<coind::data::tx_type> new_tx;      //bitcoin_data.tx_type
    Event<std::vector<coind::data::types::BlockHeaderType>> new_headers; //bitcoin_data.block_header_type

    std::shared_ptr<c2pool::deferred::ReplyMatcher<uint256, coind::data::types::BlockType, uint256>> get_block;
    std::shared_ptr<c2pool::deferred::ReplyMatcher<uint256, coind::data::BlockHeaderType, uint256>> get_block_header;

    void init(Event<uint256> _new_block, Event<coind::data::tx_type> _new_tx, Event<std::vector<coind::data::types::BlockHeaderType>> _new_headers)
    {
        new_block = _new_block;
        new_tx = _new_tx;
        new_headers = _new_headers;
    }
};