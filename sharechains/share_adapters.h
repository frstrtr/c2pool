#pragma once

#include <memory>

#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>

#include "share_types.h"
#include "share_streams.h"

struct SmallBlockHeaderType :
        BasicShareTypeAdapter<shares::SmallBlockHeaderType, shares::stream::SmallBlockHeaderType_stream>
{
    void to_stream() override
    {

    }

    void to_value() override
    {

    }
};