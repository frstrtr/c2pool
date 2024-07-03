#pragma once

#include <string>
#include <utility>

#include <core/pack.hpp>

namespace c2pool
{
   
// Base class for messages in protocol
class Message
{
public:
    std::string m_command;

public:
    Message(const char *command) : m_command(command) {}
    Message(std::string command) : m_command(std::move(command)) {}

    // virtual PackStream &write(PackStream &stream) = 0;
    // virtual PackStream &read(PackStream &stream) = 0;
};

struct RawMessage : Message
{
    PackStream m_data;

    RawMessage(const char *command, PackStream&& data) : Message(command), m_data(std::move(data)) {}
    RawMessage(std::string command, PackStream&& data) : Message(std::move(command)), m_data(std::move(data)) {}
};

} // namespace c2pool
