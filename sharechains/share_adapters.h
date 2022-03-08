#pragma once

#include <memory>

#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>

#include "share_types.h"
#include "share_stream.h"

template <typename ValueType, StreamObjType StreamType>
class BasicShareTypeAdapter
{
private:
    std::shared_ptr<ValueType> value;
    std::shared_ptr<StreamType> stream;

public:
    BasicShareTypeAdapter() = default;

    std::shared_ptr<ValueType> operator->()
    {
        return value;
    }

    PackStream &write(PackStream &_stream)
    {
        _stream << *stream;
        return stream;
    }

    PackStream &read(PackStream &_stream)
    {
        _stream >> *stream;
        return stream;
    }
};