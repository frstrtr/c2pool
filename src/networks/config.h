#ifndef CONFIG_H
#define CONFIG_H

#include <vector>
#include <string>

namespace c2pool::config
{
    class Network
    {
    public:
        std::vector<std::string> BOOTSTRAP_ADDRS{"127.0.0.1"};
        std::string PREFIX = "1234567890";
        int MINIMUM_PROTOCOL_VERSION = 1600;
    public:
        Network();
    };

    /*
    template for test config:
    class TestNetwork : Network{
    public:
        TestNetwork(){
            ...
            PREFIX = "TESTNETWORK";
            ...
        }
    }
    */
} // namespace c2pool::config

#endif //CONFIG_H