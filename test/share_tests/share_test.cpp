#include <gtest/gtest.h>
#include <tuple>
#include <string>


#include "share.h"
#include "shareTypes.h"
#include <config.h>
#include "uint256.h"
#include "arith_uint256.h"
#include "univalue.h"


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

class BaseShareTest : public ::testing::Test
{
protected:
    shared_ptr<TestNetwork> net;
    BaseShare* share;

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
    }

    virtual void TearDown()
    {
        delete share;
    }
};

TEST_F(BaseShareTest, InitBaseShare)
{
    cout << share->timestamp << endl;
}

TEST_F(BaseShareTest, GenerateTransaction){
    //TODO:
}

TEST_F(BaseShareTest, TestSerialize){
    string share_json = share->SerializeJSON();
    string json = "{\"TYPE\":33,\"contents\":{\"min_header\":{\"version\":1,\"previous_block\":\"0000000000000000000000000000000000000000000000000000000000000002\",\"timestamp\":3,\"bits\":4,\"nonce\":5},\"share_info\":{\"share_data\":{\"previous_share_hash\":\"0000000000000000000000000000000000000000000000000000000000000002\",\"coinbase\":\"empty\",\"nonce\":5,\"pubkey_hash\":\"0000000000000000000000000000000000000033\",\"subsidy\":11,\"donation\":1,\"stale_info\":0,\"desired_version\":1337},\"segwit_data\":{\"txid_merkle_link\":{\"branch\":[],\"index\":0},\"wtxid_merkle_root\":\"0000000000000000000000000000000000000000000000000000000000000000\"},\"new_transaction_hashes\":[],\"transaction_hash_refs\":[],\"far_share_hash\":\"0000000000000000000000000000000000000000000000000000000000000002\",\"max_bits\":10000,\"bits\":9999,\"timestamp\":100123123,\"absheigth\":12,\"abswork\":\"00000000000000000000000000000321\"},\"ref_merkle_link\":{\"branch\":[],\"index\":0},\"last_txout_nonce\":5,\"hash_link\":{\"state\":\"state\",\"extra_data\":\"\",\"length\":5},\"merkle_link\":{\"branch\":[],\"index\":0}}}";
    ASSERT_EQ(share_json, json);
}

TEST_F(BaseShareTest, TestDeserialize){
    string json = share->SerializeJSON();

    BaseShare share_from_json;
    share_from_json.DeserializeJSON(json);

    ASSERT_EQ(share->contents.min_header->nonce, share_from_json.contents.min_header->nonce);
}