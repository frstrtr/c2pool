#pragma once

#include "btclibs/uint256.h"

#include <vector>
#include <string>
#include <tuple>
#include <memory>
using std::shared_ptr;

namespace coind::jsonrpc
{
    class Coind;
}

namespace c2pool
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
        int SEGWIT_ACTIVATION_VERSION;
        int TARGET_LOOKBEHIND;
        int SHARE_PERIOD;
        int BLOCK_MAX_SIZE;
        int BLOCK_MAX_WEIGHT;
        int REAL_CHAIN_LENGTH;
        int CHAIN_LENGTH;
        int SPREAD;

        uint256 MAX_TARGET;

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
} // namespace c2pool

namespace coind
{
    class ParentNetwork
    {

        /*
    template for test config:
    class TestParentNetwork : ParentNetwork{
    public:
        TestNetwork(){
            ...
            PREFIX = "TESTNETWORK";
            ...
        }
    }
    */
    public:
        int PREFIX_LENGTH;
        //prefix: codecs.decode("1bfe01eff5ba4e38", "hex"), where prefix: 1b fe 01 ef f5 ba 4e 38, with 0x
        const unsigned char *PREFIX;

        std::string P2P_ADDRESS;
        int P2P_PORT;
        int ADDRESS_VERSION;
        int RPC_PORT;

    public:
        virtual bool jsonrpc_check(shared_ptr<coind::jsonrpc::Coind> coind) = 0;

        virtual bool version_check(int version) = 0;
    };

    class DigibyteParentNetwork : public ParentNetwork
    {
    public:
        DigibyteParentNetwork();

    public:
        bool jsonrpc_check(shared_ptr<coind::jsonrpc::Coind> coind) override;

        bool version_check(int version) override;
    };
}