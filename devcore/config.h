#pragma once

namespace c2pool::dev
{
    class c2pool_config
    {
    public:
        bool debug = false;

    private:
        static c2pool_config *_instance;
    public:
        static void INIT();
        static c2pool_config *get();
    };

    class coind_config
    {
    public:
        int listenPort = -1;
        int max_conns;     //server max connections
        int desired_conns; //client max connections
        int max_attempts;  //client максимум одновременно обрабатываемых попыток подключения
        //попытка подключения = подключение, которое произошло, но не проверенно на версию и прочие условия.
    };
} // namespace c2pool::dev