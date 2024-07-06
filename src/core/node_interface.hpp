#pragma once

#include <memory>

#include <boost/asio/io_context.hpp>
#include <core/message.hpp>
#include <core/pack.hpp>

namespace c2pool
{

struct INode
{
    using message_error_type = std::string;

    boost::asio::io_context* m_ctx;
    std::vector<std::byte> m_prefix;

    virtual void handle(std::unique_ptr<RawMessage> msg) const = 0;
    virtual void error(const message_error_type& err) = 0;
    virtual void connected() = 0;
    virtual void disconnect() = 0;

    INode() {}
    INode(boost::asio::io_context* ctx, const std::vector<std::byte>& prefix) : m_ctx(ctx), m_prefix(prefix) {}
};

// template <typename PROTOCOL_TYPE>
// class MessageHandler : public IMessageHandler
// {
// protected:
//     using protocol_type = PROTOCOL_TYPE;
//     using callback_type = std::function<void(protocol_type*, PackStream&)>;
//     using message_error_type = std::string;

//     template <typename MESSAGE_TYPE>
//     static std::unique_ptr<MESSAGE_TYPE> parse_message(PackStream &stream)
//     {
//         static_assert(std::is_base_of<Message, MESSAGE_TYPE>());
//         auto msg = std::make_unique<MESSAGE_TYPE>();
//         stream >> *msg;
//         return std::move(msg);
//     }

// public:
//     virtual const std::map<std::string, callback_type>& getFunctionMap() const = 0;

//     void handle(std::unique_ptr<RawMessage> msg) const override
//     {
//         protocol_type* p = const_cast<protocol_type*>(static_cast<const protocol_type*>(this));
        
//         auto& m = getFunctionMap();
//         try
//         {
//             auto& func = m.at(msg->m_command);
//             func(p, msg->m_data);
//         } catch (const std::out_of_range& ex)
//         {
//             std::cout << "out range" << std::endl;
//         }
//     }
// };

} // namespace c2pool

// #define BEGIN_INIT_MESSAGE_HANDLER()                                                                    \
//     static std::map<std::string, callback_type> &getFunctionMapStatic()                                 \
//     {                                                                                                   \
//         static std::map<std::string, callback_type> functionMap = {

// #define END_INIT_MESSAGE_HANDLER()                                                                     \
//         };                                                                                             \
//         return functionMap;                                                                            \
//     }                                                                                                  \
//                                                                                                        \
//     const std::map<std::string, callback_type> &getFunctionMap() const override                        \
//     {                                                                                                  \
//         return getFunctionMapStatic();                                                                 \
//     }

// #define ADD_MESSAGE_CALLBACK_CUSTOM(cmd, msg_type) {#cmd, [&](protocol_type *protocol, PackStream& stream) { auto msg = parse_message<msg_type>(stream); protocol->handle_##cmd(std::move(msg)); }},
// #define ADD_MESSAGE_CALLBACK(cmd) ADD_MESSAGE_CALLBACK_CUSTOM(cmd, message_##cmd)

// #define MESSAGE_CALLBACK_CUSTOM(cmd, msg_type) void handle_##cmd(std::unique_ptr<msg_type> message)
// #define MESSAGE_CALLBACK(cmd) MESSAGE_CALLBACK_CUSTOM(cmd, message_##cmd)