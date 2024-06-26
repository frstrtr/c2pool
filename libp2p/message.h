#pragma once

#include <string>
#include <utility>

#include <libdevcore/stream.h>

// Base class for messages in protocol
class Message
{
public:
    std::string command;

public:
    Message(const char *_command) : command(_command)
    {}

    Message(std::string _command) : command(std::move(_command))
    {}

    virtual PackStream &write(PackStream &stream)
    { return stream; }

    virtual PackStream &read(PackStream &stream)
    { return stream; }
};

class RawMessage : public Message
{
public:
    PackStream value;

    RawMessage(std::string _command) : Message(_command) { }

    PackStream &write(PackStream &stream) override
    {
        stream << value;
        return stream;
    }

    PackStream &read(PackStream &stream) override
    {
        stream >> value;
        return stream;
    }
};