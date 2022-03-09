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
        make_stream(_value->version, _value->previous_block, _value->timestamp, _value->bits, _value->nonce);
    }

    void _to_value() override
    {
        make_value(_stream->version.value, _stream->previous_block.get().get(), _stream->timestamp.get(), _stream->bits.get(), _stream->nonce.get());
    }
};

struct MerkleLink :
        StreamTypeAdapter<shares::MerkleLink, shares::stream::MerkleLink_stream>
{
    void _to_stream() override
    {
        //TODO:
    }

    void _to_value() override
    {
        //TODO:
    }
};

struct BlockHeaderType :
        StreamTypeAdapter<shares::BlockHeaderType, shares::stream::BlockHeaderType_stream>
{
    void _to_stream() override
    {
        //TODO:
    }

    void _to_value() override
    {
        //TODO:
    }
};

struct HashLinkType :
        StreamTypeAdapter<shares::HashLinkType, shares::stream::HashLinkType_stream>
{
    void _to_stream() override
    {
        //TODO:
    }

    void _to_value() override
    {
        //TODO:
    }
};

struct SegwitData :
        StreamTypeAdapter<shares::SegwitData, shares::stream::SegwitData_stream>
{
    void _to_stream() override
    {
        //TODO:
    }

    void _to_value() override
    {
        //TODO:
    }
};

struct ShareData :
        StreamTypeAdapter<shares::ShareData, shares::stream::ShareData_stream>
{
    void _to_stream() override
    {
        //TODO:
    }

    void _to_value() override
    {
        //TODO:
    }
};

struct ShareInfo :
        StreamTypeAdapter<shares::ShareInfo, shares::stream::ShareInfo_stream>
{
    void _to_stream() override
    {
        //TODO:
    }

    void _to_value() override
    {
        //TODO:
    }
};