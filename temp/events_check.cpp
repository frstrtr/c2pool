#include <iostream>
#include <thread>
#include <core/events.hpp>

int main()
{
    Event<int> event;

    std::thread th1{
    [&]{
        std::cout << "happened thread: \t" << std::this_thread::get_id() << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(3));
        event.happened(112);
    }};

    boost::asio::io_context* context = new boost::asio::io_context();

    event.async_subscribe(context, 
        [](int value)
        {
            std::cout << "subscriber thread: \t" << std::this_thread::get_id() << std::endl;
            std::cout << value << std::endl;
        });

    boost::asio::steady_timer t1(*context, std::chrono::seconds(4));
    t1.async_wait([](const auto& ec){});
    

    context->run();

    if (th1.joinable())
        th1.join();
}



////////////////////////////////////////////////////////////////////////////////////////////////////
// {
//     Variable<int> var(0);

//     std::thread th1{
//         [&]
//         {
//             auto dis = var.changed.subscribe([&](int v)
//                 { 
//                     if ((v % 10) == 0)
//                     {
//                         std::cout << "%" << v << " or " << var.value() << std::endl;
//                         var.set(v + 1);
//                     }
//                 }
//             );

//             while (var.value() < 10000)
//             {}

//             dis->dispose();
//         }
//     };

//     std::thread th2{
//         [&]
//         {
//             auto dis = var.transitioned.subscribe(
//                 [&](int old, int v)
//                 {
//                     if (((v % 10) == 5) && ((old % 10) == 4))
//                     {
//                         std::cout << "!%" << v << " or " << var.value() << ", for old = " << old << std::endl;
//                         var.set(v + 1);
//                     }
//                 }
//             );

//             while (var.value() < 11000)
//             {}
//             dis->dispose();
//         }
//     };

//     while (var.value() < 12000)
//     {
//         var.set(var.value() + 1);
//     }

//     if (th1.joinable())
//         th1.join();
//     if (th2.joinable())
//         th2.join();
// }


////////////////////////////////////////////////////////////////////////////////////////////////////
// {
//     Event e_1;
//     bool* flag = new bool(false);
//     std::thread th
//     {
//         [flag]
//         {
//             while(!*flag)
//             {
//                 // std::this_thread::sleep_for(std::chrono::milliseconds(100));
//             }
//             std::cout << "READY!" << std::endl;
//         }
//     };
//     e_1.subscribe([&]{ std::cout << "happened!" << std::endl; *flag = true; });
    
//     std::this_thread::sleep_for(std::chrono::seconds(2));
//     e_1.happened();
    
//     if (th.joinable())
//         th.join();

//     delete flag;
// }

////////////////////////////////////////////////////////////////////////////////////////////////////
// {
//     Event e_1;
//     e_1.subscribe([]{ std::cout << "hi" << std::endl; });
//     e_1.happened();
// }