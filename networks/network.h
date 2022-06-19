#pragma once

#include <vector>
#include <string>
#include <tuple>
#include <memory>
#include <set>

#include "btclibs/uint256.h"
#include <libdevcore/stream.h>

using std::shared_ptr;

namespace coind::jsonrpc
{
    class Coind;
}

namespace coind{
    class ParentNetwork;
}

namespace c2pool
{
#define CREATE_ADDR(addr, port) std::make_tuple<std::string, std::string>(addr, port)

    class Network
    {
    public:
        const std::string net_name;
    public:
        std::shared_ptr<coind::ParentNetwork> parent;
    public:
		std::set<std::string> SOFTFORKS_REQUIRED;
        //std::tuple<std::string, std::string> = addr
        std::vector<std::tuple<std::string, std::string>> BOOTSTRAP_ADDRS; //217.72.6.241
        int PREFIX_LENGTH;
        //prefix: codecs.decode("1bfe01eff5ba4e38", "hex"), where prefix: 1b fe 01 ef f5 ba 4e 38, with 0x
        const unsigned char *PREFIX;

        int IDENTIFIER_LENGHT;
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
        int ADDRESS_VERSION;
        bool PERSIST;

        uint256 MIN_TARGET;
        uint256 MAX_TARGET;
    public:
        std::vector<unsigned char> DONATION_SCRIPT; //TODO: INIT (from share)
        std::vector<unsigned char> gentx_before_refhash; //TODO: INIT (from share)

    protected:
        Network(std::string name, std::shared_ptr<coind::ParentNetwork> _parent_net);
    };

    class DigibyteNetwork : public Network
    {
    public:
        DigibyteNetwork(std::shared_ptr<coind::ParentNetwork> _parent);
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
    class ParentNetwork
    {
    public:
        const std::string net_name;
        
    public:
        int PREFIX_LENGTH;
        //prefix: codecs.decode("1bfe01eff5ba4e38", "hex"), where prefix: 1b fe 01 ef f5 ba 4e 38, with 0x
        const unsigned char *PREFIX;

        int32_t BLOCK_PERIOD;
        std::string P2P_ADDRESS;
        int P2P_PORT;
        int ADDRESS_VERSION;
        int RPC_PORT;

		int DUMB_SCRYPT_DIFF;
        int DUST_THRESHOLD;
        uint256 SANE_TARGET_RANGE_MIN;
        uint256 SANE_TARGET_RANGE_MAX;
    public:
        ParentNetwork(std::string name);

        //TODO:
        // virtual bool jsonrpc_check(shared_ptr<coind::jsonrpc::Coind> coind) = 0;
        virtual bool jsonrpc_check() = 0;

        virtual bool version_check(int version) = 0;

        virtual uint256 POW_FUNC(PackStream& packed_block_header) = 0;

		virtual unsigned long long SUBSIDY_FUNC(int32_t height) = 0;
    };

    class DigibyteParentNetwork : public ParentNetwork
    {
    public:
        DigibyteParentNetwork();

    public:
        //TODO:
        bool jsonrpc_check() override;

        bool version_check(int version) override;

        virtual uint256 POW_FUNC(PackStream& packed_block_header) override;

		virtual unsigned long long SUBSIDY_FUNC(int32_t height) override;
    };
}