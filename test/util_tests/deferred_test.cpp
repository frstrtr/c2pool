#include <gtest/gtest.h>
#include <iostream>
#include <libdevcore/deferred.h>
using namespace c2pool::deferred;

#ifdef DefAlgo
TEST(Deferred, Deferred_system)
{
    std::shared_ptr<io::io_context> context = std::make_shared<io::io_context>(2);

    shared_defer_algo<int> defer;
    context->post([&]()
                  {
                      defer = DeferredAlgo<int>::yield(context, [&](std::shared_ptr<DeferredAlgo<int>> def)
                                                   {
                                                       def->add_callback([&](int i)
                                                                         { std::cout << "RESULT: " << i << std::endl; });
                                                       std::cout << "ADDED CALLBACK!" << std::endl;
                                                       def->sleep(3s);
                                                       std::cout << "after sleep 3s" << std::endl;

                                                       def->external_timer([&, def](const boost::system::error_code &ec)
                                                                           { def->returnValue(15); },
                                                                           1s);
                                                       // def->returnValue(15);
                                                       std::cout << "before sleep 2s\n";
                                                       def->sleep(2s);
                                                       std::cout << "after sleep 2s\n";
                                                   });
                  });

    io::steady_timer timer(*context, 1s);
    timer.async_wait([&](const boost::system::error_code &ec)
                     { std::cout << "timer" << std::endl; });

    context->run();
}

TEST(Deferred, Deferred_system2)
{
    std::shared_ptr<io::io_context> context = std::make_shared<io::io_context>(1);

    context->post([&, defer = shared_defer_algo<int>()]() mutable
                  {
                      defer = DeferredAlgo<int>::yield(context, [&](std::shared_ptr<DeferredAlgo<int>> def)
                      {
                          while (true)
                          {
//                          def->add_callback([&](int i)
//                                            { std::cout << "RESULT: " << i << std::endl; });
//                          std::cout << "ADDED CALLBACK!" << std::endl;
                              std::cout << time(NULL) << "before sleep 3s" << std::endl;
                              def->sleep(3s);
                              std::cout << time(NULL) << "after sleep 3s" << std::endl;

//                          def->external_timer([&, def](const boost::system::error_code &ec)
//                                              { def->returnValue(15); },
//                                              1s);
                              // def->returnValue(15);
                              std::cout << time(NULL) << " before sleep 2s\n";
                              def->sleep(2s);
                              std::cout << time(NULL) << "after sleep 2s\n";
                          }
                      });
                  });

    io::steady_timer timer(*context, 10s);
    timer.async_wait([&](const boost::system::error_code &ec)
                     { std::cout << "timer" << std::endl; });

    context->run();
}
#endif

TEST(Deferred, ReplyMatcher)
{
    std::shared_ptr<boost::asio::io_context> context = std::make_shared<boost::asio::io_context>();
    ReplyMatcher<int, int, int> reply(context, [&](const int &i){
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

shared_deferred<int> test_deferred_method(std::shared_ptr<boost::asio::io_context> _context)
{
    auto def = make_deferred<int>();

    auto* _t = new boost::asio::steady_timer(*_context);
    _t->expires_from_now(std::chrono::seconds(3));
    _t->async_wait([&, def = def](const auto &ec)
                   {
                       std::cout << "SET VALUE!" << std::endl;
                       def->result.set_value(1337);
                   });
    return def;
}

TEST(Deferred, FiberDeffered)
{
    auto context = std::make_shared<boost::asio::io_context>(1);

    int value = 0;

    Fiber::run(context, [&](std::shared_ptr<Fiber> fiber)
    {
        value = test_deferred_method(context)->yield(fiber);

        using namespace std::chrono_literals;
        fiber->sleep(2s);

        std::cout << "After sleep 2 seconds" << std::endl;
    });

    boost::asio::steady_timer t1(*context, std::chrono::seconds(1));
    t1.async_wait([&](const auto &ec){
        std::cout << "First check value == 0" << std::endl;
        ASSERT_EQ(value, 0);
    });

    boost::asio::steady_timer t2(*context, std::chrono::seconds(4));
    t2.async_wait([&](const auto &ec){
        std::cout << "Second check value == 1337" << std::endl;
        ASSERT_EQ(value, 1337);
    });

    boost::asio::steady_timer t3(*context, std::chrono::seconds(6));
    t3.async_wait([&](const auto &ec){
        std::cout << "Timer3 after sleep!" << std::endl;
        ASSERT_EQ(value, 1337);
    });

    context->run();
}

class TestClass{
    int i;
    std::shared_ptr<boost::asio::io_context> context;
public:
    TestClass(std::shared_ptr<boost::asio::io_context> _context) : context(std::move(_context)) {};
    TestClass(int _i, std::shared_ptr<boost::asio::io_context> _context) : i(_i), context(std::move(_context)) {};

    void run(){
        Fiber::run(context, [&](std::shared_ptr<Fiber> fiber)
        {
            value = test_deferred_method(context)->yield(fiber);

            using namespace std::chrono_literals;
            fiber->sleep(2s);

            std::cout << "After sleep 2 seconds" << std::endl;
        });
    }
};

TEST(Deferred, FiberDeffered)
{
    auto context = std::make_shared<boost::asio::io_context>(1);

    int value = 0;


}