#pragma once

#include <string>
#include <utility>
#include <memory>
#include <variant>
#include <map>

#include <core/pack.hpp>

// Base class for messages in protocol
class Message
{
public:
    std::string m_command;

public:
    Message(const char *command) : m_command(command) {}
    Message(std::string command) : m_command(std::move(command)) {}
};

struct RawMessage : Message
{
    PackStream m_data;

    RawMessage(const char *command, PackStream&& data) : Message(command), m_data(std::move(data)) {}
    RawMessage(std::string command, PackStream&& data) : Message(std::move(command)), m_data(std::move(data)) {}
};

template <typename...MessageTypes>
class MessageHandler
{
public:
    using result_t = std::variant<std::unique_ptr<MessageTypes>...>;
    using handlers_t = std::map<std::string, std::function<result_t(std::unique_ptr<RawMessage>&)>>;

private:
    static handlers_t m_handlers;

    template <typename MsgT>
    static void add_handlers()
    {
        MsgT msg; // tip for get Message::m_command
        m_handlers[msg.m_command] = [](std::unique_ptr<RawMessage>& rmsg){
            auto res = std::make_unique<MsgT>();
            // Save raw bytes before parsing (for AuxPoW fallback in headers handler)
            if constexpr (requires { res->m_raw_payload; }) {
                auto* raw = reinterpret_cast<const uint8_t*>(rmsg->m_data.data());
                res->m_raw_payload.assign(raw, raw + rmsg->m_data.size());
            }
            try {
                rmsg->m_data >> *res;
            } catch (...) {
                if constexpr (requires { res->m_raw_payload; }) {
                    // Parse failure (e.g., DOGE AuxPoW headers) — m_raw_payload
                    // has the data; the handler re-parses from the raw bytes.
                } else {
                    // No raw-bytes fallback for this type: swallowing here
                    // would deliver a PARTIALLY-PARSED message (e.g. a block
                    // whose tx vector stopped mid-stream) with no error ever
                    // logged. Rethrow — every p2p dispatch site wraps parse()
                    // in a catch that logs and drops the message.
                    throw;
                }
            }
            return res;
        };
    }

    static handlers_t init_handlers()
    {
        handlers_t handlers;
        (( add_handlers<MessageTypes>() ), ...);
        return handlers;
    }

    void remove_zeros(std::string& command)
    {
        size_t pos = command.find('\0');
        if (pos != std::string::npos)
        {
            command = command.substr(0, pos);
        }
    }

public:
    result_t parse(std::unique_ptr<RawMessage>& rmsg)
    {
        remove_zeros(rmsg->m_command);

        if (m_handlers.contains(rmsg->m_command))
            return m_handlers[rmsg->m_command](rmsg);
        else
            throw std::out_of_range("MessageHandler not contain " + rmsg->m_command);
    }
};

template <typename...T>
typename MessageHandler<T...>::handlers_t MessageHandler<T...>::m_handlers = MessageHandler<T...>::init_handlers();