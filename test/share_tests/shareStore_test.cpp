#include <gtest/gtest.h>
#include <tuple>
#include <string>


#include "share.h"
#include "shareTypes.h"
#include "shareStore.h"
#include <config.h>
#include "uint256.h"
#include "arith_uint256.h"


using namespace std;

class TestNetwork : public c2pool::config::Network
{
public:
    TestNetwork() : Network()
    {
        BOOTSTRAP_ADDRS = {
            CREATE_ADDR("192.168.0.1", "5024")
        };
        PREFIX_LENGTH = 8;
        PREFIX = new unsigned char[PREFIX_LENGTH]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
        IDENTIFIER = new unsigned char[8]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
        MINIMUM_PROTOCOL_VERSION = 1600;
        SEGWIT_ACTIVATION_VERSION = 17;

        TARGET_LOOKBEHIND = 200;
        SHARE_PERIOD = 25;
        BLOCK_MAX_SIZE = 1000000;
        BLOCK_MAX_WEIGHT = 4000000;
        REAL_CHAIN_LENGTH = 24*60*60/10;
        CHAIN_LENGTH = 24*60*60/10;
        SPREAD = 30;
    }
};

class ShareStoreTest : public ::testing::Test
{
protected:
    shared_ptr<TestNetwork> net;
    BaseShare* share;
    ShareStore* store;

protected:
    template <typename UINT_TYPE>
    UINT_TYPE CreateUINT(string hex){
        UINT_TYPE _number;
        _number.SetHex(hex);
        return _number;
    }

    virtual void SetUp()
    {
        net = make_shared<TestNetwork>();
        tuple<string, string> peer_addr = make_tuple<std::string, std::string>("192.168.0.1", "1337");

        ShareType share_type( 
            make_shared<SmallBlockHeaderType>(
                1,
                CreateUINT<uint256>("2"),
                3,
                4,
                5
            ),
            make_shared<ShareInfoType>(
                make_shared<ShareData>(
                    CreateUINT<uint256>("2"),
                    "empty",
                    5,
                    CreateUINT<uint160>("33"),
                    11,
                    1,
                    StaleInfo::None,
                    1337
                ),
                vector<uint256>(),
                vector<TransactionHashRef>(),
                CreateUINT<uint256>("2"),
                10000,
                9999,
                100123123,
                12,
                CreateUINT<uint128>("321"),
                make_shared<SegwitData>(
                    make_shared<MerkleLink>(),
                    CreateUINT<uint256>("0")
                )
            ),
            make_shared<MerkleLink>(),
            5,
            make_shared<HashLinkType>("state", "", 5),
            make_shared<MerkleLink>()
        );


        share = new BaseShare(net, peer_addr, share_type, ShareVersion::NewShare);
        //share = new BaseShare();


        store = new ShareStore("test_share_store");
    }

    virtual void TearDown()
    {
        delete share;
        delete store;
    }
};

TEST_F(ShareStoreTest, InitShareStore)
{
    
}

TEST_F(ShareStoreTest, AddReadShareStore)
{
    store->add_share(*share);
    BaseShare second_share;


    store->Read(share->hash.ToString(), second_share);
}
