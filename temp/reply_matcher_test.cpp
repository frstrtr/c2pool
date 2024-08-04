#include <iostream>

#include <boost/asio.hpp>

#include <core/reply_matcher.hpp>

int main()
{
    int result = 0;

    boost::asio::io_context* context = new boost::asio::io_context();

    ReplyMatcher::ID<int>::RESPONSE<int>::REQUEST<std::string> match(context, [&](std::string req){ std::cout << "request for: " << req << std::endl; result = std::stoi(req); });

    match.request(5, [](int res){ std::cout << "response * 10 = " << res*10 << std::endl;  }, "22");

    boost::asio::steady_timer t1(*context, std::chrono::seconds(3));
    t1.async_wait(
        [&](const auto& ec)
        {
            try
            {
                match.got_response(5, result);
            } catch (const std::invalid_argument& ec)
            {
                std::cout << ec.what() << std::endl;
            }
        }
    );

    context->run();
}