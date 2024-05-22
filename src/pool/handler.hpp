#pragma once

#include <memory>

#include <pool/message.hpp>
#include <core/pack.hpp>

namespace c2pool
{

namespace pool
{

template <typename PROTOCOL_TYPE>
class MessageHandler
{
protected:
    using protocol_type = PROTOCOL_TYPE;
    using callback_type = std::function<void(protocol_type*, PackStream&)>;

    template <typename MESSAGE_TYPE>
    static std::unique_ptr<MESSAGE_TYPE> parse_message(PackStream &stream)
    {
        static_assert(std::is_base_of<Message, MESSAGE_TYPE>());
        auto msg = std::make_unique<MESSAGE_TYPE>();
        stream >> *msg;
        return std::move(msg);
    }

public:
    virtual const std::map<std::string, callback_type>& getFunctionMap() const = 0;

    void invoke(std::string cmd, PackStream& msg) const
    {
        protocol_type* p = const_cast<protocol_type*>(static_cast<const protocol_type*>(this));
        
        auto& m = getFunctionMap();
        try
        {
            auto& func = m.at(cmd);
            func(p, msg);
        } catch (const std::out_of_range& ex)
        {
            std::cout << "out range" << std::endl;
        }
    }
};

} // namespace pool

} // namespace c2pool

#define BEGIN_INIT_MESSAGE_HANDLER()                                                                    \
    static std::map<std::string, callback_type> &getFunctionMapStatic()                                 \
    {                                                                                                   \
        static std::map<std::string, callback_type> functionMap = {

#define END_INIT_MESSAGE_HANDLER()                                                                     \
        };                                                                                             \
        return functionMap;                                                                            \
    }                                                                                                  \
                                                                                                       \
    const std::map<std::string, callback_type> &getFunctionMap() const override                        \
    {                                                                                                  \
        return getFunctionMapStatic();                                                                 \
    }

#define ADD_MESSAGE_CALLBACK_CUSTOM(cmd, msg_type) {#cmd, [&](protocol_type *protocol, PackStream& stream) { auto msg = parse_message<msg_type>(stream); protocol->cmd(std::move(msg)); }},
#define ADD_MESSAGE_CALLBACK(cmd) ADD_MESSAGE_CALLBACK_CUSTOM(cmd, message_##cmd)

#define MESSAGE_CALLBACK_CUSTOM(cmd, msg_type) void cmd(std::unique_ptr<msg_type> message)
#define MESSAGE_CALLBACK(cmd) MESSAGE_CALLBACK_CUSTOM(cmd, message_##cmd)