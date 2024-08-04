#include <iostream>
#include <functional>

template <typename IdType, typename ResponseType, typename... RequestTypes>
struct Matcher
{
    using id_type = IdType;
    using response_func = std::function<void(ResponseType)>;
    using request_func = std::function<void(RequestTypes...)>;

    id_type m_id;
    response_func m_resp;
    request_func m_req;

    Matcher(id_type id, response_func resp, request_func req) : m_id(id), m_resp(resp), m_req(req) { }
};

template <typename IdType, typename ResponseType>
struct ResponseCreator
{
    ResponseCreator() = delete;

    template <typename... RequestTypes>
    using REQUEST = Matcher<IdType, ResponseType, RequestTypes...>;
};

template <typename IdType>
struct IdCreator
{
    IdCreator() = delete;

    template <typename RequestType>
    using RESPONSE = ResponseCreator<IdType, RequestType>;
};

struct ReplyMatcher
{
    ReplyMatcher() = delete;

    template<typename IdType>
    using ID = IdCreator<IdType>;
};

int main()
{
    ReplyMatcher::ID<int>::RESPONSE<int>::REQUEST<std::string> match
        (
            10,
            [](int res) { std::cout << res << std::endl; },
            [](std::string str) { std::cout << "text: " << str << std::endl; }
        );

    std::cout << match.m_id << std::endl;
    match.m_req("asd");
    match.m_resp(123);
}