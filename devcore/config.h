#pragma once
#include <istream>
#include <string>

namespace c2pool::dev
{
    enum DebugState
    {
        trace = 0,
        debug = 1,
        normal = 2
    };

    class c2pool_config
    {
    public:
        DebugState debug = normal;

    private:
        static c2pool_config *_instance;

    public:
        static void INIT();
        static c2pool_config *get();
    };

    class coind_config
    {
    public:
        //TODO: initialization methods
    public:
        int listenPort = 3035;
        int max_conns = 40;    //server max connections
        int desired_conns = 6; //client max connections
        int max_attempts = 10; //client максимум одновременно обрабатываемых попыток подключения
        //попытка подключения = подключение, которое произошло, но не проверенно на версию и прочие условия.
    };
} // namespace c2pool::dev

std::istream &operator>>(std::istream &in, c2pool::dev::DebugState &value);