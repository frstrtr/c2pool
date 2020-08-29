#ifndef CONFIG_H
#define CONFIG_H

#include <vector>
#include <string>
#include <tuple>

namespace c2pool::config
{
    #define CREATE_ADDR(addr, port) std::make_tuple<std::string, std::string>(addr, port)
    
    class Network
    {
    public:
        //std::tuple<std::string, std::string> = ADDR
        std::vector<std::tuple<std::string, std::string>> BOOTSTRAP_ADDRS; //217.72.6.241
        int PREFIX_LENGTH;
        //prefix: codecs.decode("1bfe01eff5ba4e38", "hex"), where prefix: 1b fe 01 ef f5 ba 4e 38, with 0x
        const unsigned char *PREFIX;
        const unsigned char *IDENTIFIER;
        int MINIMUM_PROTOCOL_VERSION;

    protected:
        Network();
    };

    class DigibyteNetwork : public Network
    {
    public:
        DigibyteNetwork();
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