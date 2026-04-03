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

    ~ResponseWrapper()
    {
        if (m_timer)
            m_timer->stop();
    }

    ResponseWrapper(ResponseWrapper&& other) : m_func(std::move(other.m_func)), m_timer(std::move(other.m_timer))
    {

    }

    ResponseWrapper& operator=(ResponseWrapper&& other) noexcept
    {
        if (this != &other)
        {
            m_func = std::move(other.m_func);
            m_timer = std::move(other.m_timer);
        }
        return *this;
    }

    ResponseWrapper(const ResponseWrapper&) = delete;
    ResponseWrapper& operator=(const ResponseWrapper&) = delete;

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

    int m_timeout{5};

    boost::asio::io_context* m_context;

    request_func m_req;
    std::map<id_type, wrapper_type> m_watchers;

    // response_func m_resp;


    Matcher(boost::asio::io_context* context, request_func req, int timeout_sec = 5)
        : m_timeout(timeout_sec), m_context(context), m_req(req) { }

    void request(id_type id, response_func resp, RequestArgs... args)
    {
        if (!m_watchers.contains(id))
        {
            auto timer = std::make_unique<core::Timer>(m_context);
            // p2pool deferral.py:137-140: timeout fires df.errback(TimeoutError).
            // The Deferred IS invoked — the caller handles the error and retries.
            // c2pool equivalent: invoke the callback with a default-constructed
            // (empty) response. This completes the async contract — every request
            // produces exactly one callback invocation on all code paths.
            timer->start(m_timeout, [&, id = id](){
                auto it = m_watchers.find(id);
                if (it != m_watchers.end()) {
                    it->second(ResponseType{});
                    m_watchers.erase(it);
                }
            });

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

    // p2pool p2p.py:595 equivalent: cancel specific pending request by id.
    // Invokes callback with empty response (completing the async contract),
    // then removes the watcher. Returns true if id was found and cancelled.
    bool cancel(id_type id)
    {
        auto it = m_watchers.find(id);
        if (it == m_watchers.end())
            return false;
        it->second(ResponseType{});
        m_watchers.erase(it);
        return true;
    }

    // Cancel ALL pending requests (p2pool respond_all).
    // Use only when all in-flight requests are invalid (e.g. shutdown).
    void respond_all()
    {
        auto pending = std::move(m_watchers);
        m_watchers.clear();
        for (auto& [id, wrapper] : pending)
            wrapper(ResponseType{});
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
