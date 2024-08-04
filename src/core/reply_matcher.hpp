#pragma once

#include <core/timer.hpp>

#include <map>
#include <functional>

namespace core::deffered
{

template <typename ResponseFunc>
class ResponseWrapper
{
private:
    ResponseFunc m_func;
    std::unique_ptr<core::Timer> m_timer;

public:
    ResponseWrapper() {}
    ResponseWrapper(ResponseFunc func, std::unique_ptr<core::Timer>&& timer) : m_func(func), m_timer(std::move(timer))
    {
        
    }

    template <typename T>
    void operator()(T result)
    {
        m_func(result);
        m_timer->stop();
    }
};

template <typename IdType, typename ResponseType, typename... RequestArgs>
struct Matcher
{
    using id_type = IdType;
    using response_func = std::function<void(ResponseType)>;
    using request_func = std::function<void(RequestArgs...)>;
    using wrapper_type = ResponseWrapper<response_func>;

    const int TIMEOUT = 5;

    boost::asio::io_context* m_context;

    request_func m_req;
    std::map<id_type, wrapper_type> m_watchers;

    // response_func m_resp;


    Matcher(boost::asio::io_context* context, request_func req) : m_context(context), m_req(req) { }

    void request(id_type id, response_func resp, RequestArgs... args)
    {
        if (!m_watchers.contains(id))
        {
            auto timer = std::make_unique<core::Timer>(m_context);
            timer->start(TIMEOUT, [&, id = id](){ m_watchers.erase(id); });

            m_watchers[id] = wrapper_type(resp, std::move(timer));

            m_req(args...);
        }
    }

    void got_response(id_type id, ResponseType response)
    {
        if (m_watchers.contains(id))
        {
            m_watchers[id](response);
            m_watchers.erase(id);
        } else
        {
            throw std::invalid_argument("ReplyMatcher doesn't store this key!");
        }
    }
};

template <typename IdType, typename ResponseType>
struct ResponseCreator
{
    ResponseCreator() = delete;

    template <typename... RequestArgs>
    using REQUEST = Matcher<IdType, ResponseType, RequestArgs...>;
};

template <typename IdType>
struct IdCreator
{
    IdCreator() = delete;

    template <typename RequestType>
    using RESPONSE = ResponseCreator<IdType, RequestType>;
};

} // namespace core::deffered

struct ReplyMatcher
{
    ReplyMatcher() = delete;

    template<typename IdType>
    using ID = core::deffered::IdCreator<IdType>;
};
