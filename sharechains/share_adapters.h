#pragma once

#include <memory>

#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>

#include "share_types.h"
#include "share_streams.h"

struct SmallBlockHeaderType :
        StreamTypeAdapter<shares::SmallBlockHeaderType, shares::stream::SmallBlockHeaderType_stream>
{
    void _to_stream() override
    {
        make_stream(*_value);
    }

    void _to_value() override
    {
        make_value(_stream->version.value, _stream->previous_block.get(), _stream->timestamp.get(), _stream->bits.get(), _stream->nonce.get());
    }
};

struct MerkleLink :
        StreamTypeAdapter<shares::MerkleLink, shares::stream::MerkleLink_stream>
{
    void _to_stream() override
    {
        make_stream(*_value);//, _value->index);
    }

    void _to_value() override
    {
        std::vector<uint256> branch = _stream->branch.get();
        make_value(branch);
    }
};

struct BlockHeaderType :
        StreamTypeAdapter<shares::BlockHeaderType, shares::stream::BlockHeaderType_stream>
{
    void _to_stream() override
    {
        make_stream(*_value);
    }

    void _to_value() override
    {
        make_value(_stream->version.value, _stream->previous_block.get(), _stream->timestamp.get(), _stream->bits.get(), _stream->nonce.get(), _stream->merkle_root.get());
    }
};

struct HashLinkType :
        StreamTypeAdapter<shares::HashLinkType, shares::stream::HashLinkType_stream>
{
    void _to_stream() override
    {
		make_stream(*_value);
    }

    void _to_value() override
    {
		make_value(_stream->state.get(), _stream->extra_data.get(), _stream->length.value);
    }
};

struct SegwitData :
        StreamTypeAdapter<shares::SegwitData, shares::stream::SegwitData_stream>
{
    void _to_stream() override
    {
		make_stream(*_value);
    }

    void _to_value() override
    {
		MerkleLink merkleLink;
		merkleLink.set_stream(_stream->txid_merkle_link);
		make_value(*merkleLink.get(), _stream->wtxid_merkle_root.get());
    }
};

struct ShareData :
        StreamTypeAdapter<shares::ShareData, shares::stream::ShareData_stream>
{
    void _to_stream() override
    {
		make_stream(*_value);
    }

    void _to_value() override
    {
		make_value(_stream->previous_share_hash.get(), _stream->coinbase.get(),
				   _stream->nonce.get(), _stream->pubkey_hash.get(), _stream->subsidy.get(),
				   _stream->donation.get(), _stream->stale_info.get(), _stream->desired_version.get());
    }
};

struct ShareInfo :
        StreamTypeAdapter<shares::ShareInfo, shares::stream::ShareInfo_stream>
{
    void _to_stream() override
    {
		make_stream(*_value);
    }

    void _to_value() override
    {
		make_value(_stream->far_share_hash.get(), _stream->max_bits.get(), _stream->bits.get(),
				   _stream->timestamp.get(), _stream->new_transaction_hashes.get(), _stream->transaction_hash_refs.get(),
				   _stream->absheight.get(), _stream->abswork.get());
    }
};