#pragma once

namespace c2pool
{

namespace pool
{

template <typename ProtocolType>
class MessageHandler
{
protected:
    using protocol_type = ProtocolType;

public:
    virtual const std::map<std::string, std::function<void(protocol_type*)>>& getFunctionMap() const = 0;

    void invoke(std::string cmd) const
    {
        protocol_type* p = const_cast<protocol_type*>(static_cast<const protocol_type*>(this));
        
        auto& m = getFunctionMap();
        try
        {
            auto& func = m.at(cmd);
            func(p);
        } catch (const std::out_of_range& ex)
        {
            std::cout << "out range" << std::endl;
        }
    }
}

} // namespace pool

}

#define INIT_MESSAGE_HANDLER_BEGIN                                                                     \
    static std::map<std::string, std::function<void(protocol_type *)>> &getFunctionMapStatic() \
    {                                                                                          \
        static std::map<std::string, std::function<void(protocol_type *)>> functionMap = {

#define INIT_MESSAGE_HANDLER_FINISH                                                                            \
        };                                                                                             \
        return functionMap;                                                                            \
    }                                                                                                  \
                                                                                                       \
    const std::map<std::string, std::function<void(protocol_type *)>> &getFunctionMap() const override \
    {                                                                                                  \
        return getFunctionMapStatic();                                                                 \
    }

#define MESSAGE_CALLBACK(name) {#name, [&](protocol_type *protocol) { protocol->name(); }},