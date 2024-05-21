#pragma once

#include <string>
#include <utility>

#include <core/pack.hpp>

namespace c2pool
{

namespace pool
{
    
// Base class for messages in protocol
class Message
{
public:
    std::string m_command;

public:
    Message(const char *command) : m_command(command) {}

    Message(std::string command) : m_command(std::move(command)) {}

    virtual PackStream &write(PackStream &stream)
    { 
        return stream; 
    }

    virtual PackStream &read(PackStream &stream)
    { 
        return stream;
    }
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

} // namespace pool

} // namespace c2pool
