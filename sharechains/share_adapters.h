#pragma once

#include <memory>

#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>

#include "share_types.h"
#include "share_streams.h"

template<typename ValueType, StreamObjType StreamType>
class BasicShareTypeAdapter
{
private:
    std::shared_ptr<ValueType> _value;
    std::shared_ptr<StreamType> _stream;

public:
    BasicShareTypeAdapter() = default;

    std::shared_ptr<ValueType> operator->()
    {
        return value;
    }

    PackStream &write(PackStream &stream)
    {
        stream << *_stream;
        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        stream >> *_stream;
        return stream;
    }

    std::shared_ptr<ValueType> get()
    {
        return _value;
    }

    std::shared_ptr<StreamType> stream()
    {
        return _stream;
    }

private:
    virtual void to_stream() = 0;
    virtual void to_value() = 0;
};