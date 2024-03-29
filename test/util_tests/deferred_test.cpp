#include <gtest/gtest.h>
#include <iostream>
#include <libdevcore/deferred.h>
#include <libdevcore/events.h>
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
        std::cout << "[" << c2pool::dev::timestamp() << "]" << "CALLED WITH PARAM: " << i << std::endl;
    });

    boost::asio::steady_timer timer(*context);
    timer.expires_from_now(4s);
    timer.async_wait([&](const boost::system::error_code &ec)
                     {
                         if (!ec)
                                 reply.got_response(1337, 7331);
                     });

    try
    {
        reply.yield(1337, [&](int reply_mathcer_result)
        {
            std::cout << "[" << c2pool::dev::timestamp() << "]" << reply_mathcer_result << std::endl;
        }, 1337);
    } catch (...)
    {
        std::cout << "TIMEOUT!!" << std::endl;
    }
    context->run();
}

TEST(Deferred, ReplyMatcherTimeout)
{
    std::shared_ptr<boost::asio::io_context> context = std::make_shared<boost::asio::io_context>();
    ReplyMatcher<int, int, int> reply(context, [&](const int &i){
        std::cout << "[" << c2pool::dev::timestamp() << "]" << "CALLED WITH PARAM: " << i << std::endl;
    });

    boost::asio::steady_timer timer(*context);
    timer.expires_from_now(6s);
    timer.async_wait([&](const boost::system::error_code &ec)
                     {
                         if (!ec)
                         {
                             std::cout << "before got_response" << std::endl;
                             reply.got_response(1337, 7331);
                             std::cout << "after got_response" << std::endl;
                         }
                     });

    reply.yield(1337, [&](int reply_mathcer_result){
        std::cout << "[" << c2pool::dev::timestamp() << "]" << reply_mathcer_result << std::endl;
    }, 1337)->add_errback([](std::string msg){
        std::cout << "ERRBACK: " << msg << std::endl;
    });

    ASSERT_ANY_THROW({reply.got_response(1338,7332);});

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

class TestClass : public std::enable_shared_from_this<TestClass> {

    std::shared_ptr<boost::asio::io_context> context;
public:
    int i;
    Variable<int> var;

    TestClass(std::shared_ptr<boost::asio::io_context> _context) : context(std::move(_context)) {};
    TestClass(int _i, std::shared_ptr<boost::asio::io_context> _context) : i(_i), context(std::move(_context)) {};

    void run(){
        Fiber::run(context, [&, _i = &i](std::shared_ptr<Fiber> fiber)
        {
            auto ddd = shared_from_this();
            int h = 123;
            auto &____i = _i;
            std::cout << "i:" <<  *____i << std::endl;
            std::cout << "i(this):" <<  ddd->i << std::endl;
            auto des = var.get_when_satisfies([&](const auto &__i){
                return __i != 0;
            })->yield(fiber);
            std::cout << "i:" <<  *____i << std::endl;
            std::cout << des << std::endl;
            std::cout << h << std::endl;
            std::cout << "i(this):" <<  ddd->i << std::endl;

//            value = test_deferred_method(context)->yield(fiber);

            using namespace std::chrono_literals;
            fiber->sleep(2s);

            std::cout << "After sleep 2 seconds" << std::endl;
        });
    }
};

TEST(Deferred, FiberDefferedWithVariable)
{
    auto context = std::make_shared<boost::asio::io_context>(1);
    int value = 0;

    std::shared_ptr<TestClass> tc = std::make_shared<TestClass>(10, context);

    tc->run();

    boost::asio::steady_timer t1(*context, std::chrono::seconds(1));
    t1.async_wait([&](const auto &ec){
//        tc->i += 1;
        tc->var.set(10);
//        std::cout << "First check value == 0" << std::endl;
//        ASSERT_EQ(value, 0);
    });

//    boost::asio::steady_timer t2(*context, std::chrono::seconds(4));
//    t2.async_wait([&](const auto &ec){
//        std::cout << "Second check value == 1337" << std::endl;
//        ASSERT_EQ(value, 1337);
//    });
//
//    boost::asio::steady_timer t3(*context, std::chrono::seconds(6));
//    t3.async_wait([&](const auto &ec){
//        std::cout << "Timer3 after sleep!" << std::endl;
//        ASSERT_EQ(value, 1337);
//    });

    context->run();
}

class TestNode : public std::enable_shared_from_this<TestNode>
{
public:
    std::shared_ptr<boost::asio::io_context> context;
    std::vector<uint64_t> data;

    c2pool::deferred::QueryDeferrer<std::vector<uint64_t>> get_data;
    boost::asio::steady_timer _get_data_timer;

    Variable<std::vector<uint64_t>> desired;
public:
    TestNode(std::shared_ptr<boost::asio::io_context> _context) : context(std::move(_context)), _get_data_timer(*context), get_data([&](uint256 id){
        std::cout << c2pool::dev::timestamp() << " GET_DATA_CALLED!\n";
        _get_data_timer.expires_from_now(2s);
        _get_data_timer.async_wait([&, _id = id](const boost::system::error_code& ec){
            if (!ec)
            {
                auto result = c2pool::random::randomNonce();
                std::cout << c2pool::dev::timestamp() << " GET_DATA_RESULTED = " << result << "\n";
                get_data.got_response(_id, std::vector<uint64_t>{result});
            } else {
                std::cout << "EC: " << ec.message() << std::endl;
            }
        });
    })
    {

    }

    void start_download()
    {
        Fiber::run(context, [&](const std::shared_ptr<c2pool::deferred::Fiber> &fiber){
            auto node = shared_from_this();
            std::cout << "Started download!" << std::endl;

            while (true)
            {
                std::cout << "WAIT FOR DESIRED" << std::endl;
                node->desired.get_when_satisfies([](const std::vector<uint64_t> &v)
                {
                    std::cout << "SATISFIES!: ";
                    for (auto _v : v){
                        std::cout << _v << ", ";
                    }
                    std::cout << std::endl;
                    return v.size() != 0;
                })->yield(fiber);

                std::cout << c2pool::dev::timestamp() << " " << "DOWNLOAD PREPARE" << std::endl;
                fiber->sleep(1s);
                std::cout << c2pool::dev::timestamp() << " " << "DOWNLOAD START" << std::endl;
                auto _data = node->get_data.yield(fiber);
                std::cout << c2pool::dev::timestamp() << " " << "DOWNLOAD FINISHED!" << std::endl;
            }
        });
    }
};

TEST(Deferred, TestDownloadInNode)
{
    auto context = std::make_shared<boost::asio::io_context>();

    auto node = std::make_shared<TestNode>(context);
    node->start_download();

    std::vector<boost::asio::steady_timer> timers;

    for (int i = 0; i < 10; i++)
    {
        auto &timer = timers.emplace_back(*context);
        timer.expires_from_now(3s + 3s*i);
        timer.async_wait([&](const boost::system::error_code& ec)
        {
            std::cout << c2pool::dev::timestamp() << " SET" << std::endl;
            node->desired.set({c2pool::random::randomNonce()});
        });
    }
    context->run();
}