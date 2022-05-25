#include <gtest/gtest.h>
#include <iostream>
#include <libdevcore/deferred.h>
using namespace c2pool::deferred;

TEST(Deferred, Deferred_system)
{
    std::shared_ptr<io::io_context> context = std::make_shared<io::io_context>(2);

    shared_defer<int> defer;
    context->post([&]()
                  {
                      defer = Deferred<int>::yield(context, [&](std::shared_ptr<Deferred<int>> def)
                                                   {
                                                       def->add_callback([&](int i)
                                                                         { std::cout << "RESULT: " << i << std::endl; });
                                                       def->sleep(3s);

                                                       def->external_timer([&, def](const boost::system::error_code &ec)
                                                                           { def->returnValue(15); },
                                                                           5s);
                                                       // def->returnValue(15);
                                                       def->sleep(2s);
                                                   });
                  });

    io::steady_timer timer(*context, 1s);
    timer.async_wait([&](const boost::system::error_code &ec)
                     { std::cout << "timer" << std::endl; });

    context->run();
}

TEST(Deferred, ReplyMatcher)
{
    std::shared_ptr<boost::asio::io_context> context = std::make_shared<boost::asio::io_context>();
    ReplyMatcher2<int, int, int> reply(context, [&](const int &i){
        std::cout << "CALLED WITH PARAM: " << i << std::endl;
    });

    boost::asio::steady_timer timer(*context);
    timer.expires_from_now(4s);
    timer.async_wait([&](const boost::system::error_code &ec)
                     {
                         if (!ec)
                                 reply.got_response(1337, 7331);
                     });

    reply.yield(1337, [&](int reply_mathcer_result){
        std::cout << reply_mathcer_result << std::endl;
    }, 1337);

    context->run();
}