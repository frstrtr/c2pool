#include <gtest/gtest.h>
#include <tuple>
#include <string>
#include <sstream>
#include <iostream>
#include <optional>
#include <vector>

#include <btclibs/uint256.h>
#include <libcoind/types.h>
#include <libcoind/data.h>

#include <boost/range/combine.hpp>
#include <boost/foreach.hpp>
using namespace std;

TEST(CoindData, calculate_merkle_link_test)
{
    std::vector<uint256> arr{uint256::ZERO, uint256S("f57657b1b38a9766c736c9195d1df87f7053fcbbcc7540da12fb6afee7a2c58d")};
    auto res = coind::data::calculate_merkle_link(arr, 0);

    LOG_TRACE << "index: " << res.index << "; branch: ";
    for (auto v : res.branch)
    {
        LOG_TRACE << "\t" << v.GetHex();
    }
    ASSERT_EQ(res.branch.size(), 1);
    ASSERT_EQ(res.branch.back(), uint256S("f57657b1b38a9766c736c9195d1df87f7053fcbbcc7540da12fb6afee7a2c58d"));
    ASSERT_EQ(res.index, 0);

    std::vector<uint256> arr2 = {uint256::ZERO, uint256S("f57657b1b38a9766c736c9195d1df87f7053fcbbcc7540da12fb6afee7a2c58d"), uint256S("d85c2a7eefa6bf21ad0457ccbbcf3507f78fd1d5919c637c6679a83b1b75675f")};
    auto res2 = coind::data::calculate_merkle_link(arr2, 1);

    LOG_TRACE << "index: " << res2.index << "; branch: ";
    for (auto v : res2.branch)
    {
        LOG_TRACE << "\t" << v.GetHex();
    }

    ASSERT_EQ(res2.branch.size(), 2);
    std::vector<uint256> assert_arr{uint256::ZERO, uint256S("4e982e45bfc83686d1c881cda6c753f12286f0659c646cb4fa4959bfea568176")};
    ASSERT_EQ(res2.branch, assert_arr);
    ASSERT_EQ(res2.index, 1);
}

TEST(CoindData, CheckMerkleLink)
{
    auto gentx_hash = uint256S("e63b9f78cbc9a9d6749bd79b961699afae50f23a4054f5b0202a1d4dff0370f7");
    coind::data::MerkleLink merkle_link(std::vector<uint256>{uint256S("66102b718408d8da8fed1bf04438f881a67c35e12aba341a30ae7e8d5bd64f15"), uint256S("06da12f71256344a9fe06c07119727a81bfbeb9e0f04f7fd1fb315f935983e73")}, 0);

    auto merkle_root = coind::data::check_merkle_link(gentx_hash, merkle_link);
    std::cout << "merkle_root = " << merkle_root.GetHex() << std::endl;
    ASSERT_EQ(uint256S("858be6cf1d46d02b345ef6693329e68eb35c8fd46c4d4d5295ddb4574a588cd0"), merkle_root);
}

TEST(CoindData, txid_test)
{
//    uint32_t _version,
//    vector<TxInType> _tx_ins,
//    vector<TxOutType> _tx_outs,
//    uint32_t _locktime,
//    std::optional<WitnessTransactionData> _wdata = std::nullopt

    uint32_t version = 1;
    std::vector<coind::data::TxInType> tx_ins {
            coind::data::TxInType
            {
                coind::data::PreviousOutput
                {
                    uint256S("2aa4df9c1835c6896625bdae20aaf537ae26204e08c0f3b718e784091e9ee170"),
                    1
                },
                std::vector<unsigned char>{},
                4294967295
            }
    };
    std::vector<coind::data::TxOutType> tx_outs
    {
        coind::data::TxOutType{0, std::vector<unsigned char>{106, 76, 80, 217, 21, 81, 160, 202, 172, 239, 66, 221, 245, 1, 163, 210, 160, 176, 66, 143, 154, 154, 221, 166, 26, 105, 66, 44, 163, 133, 229, 167, 73, 73, 66, 168, 142, 145, 119, 41, 136, 177, 65, 3, 8, 240, 46, 80, 192, 176, 65, 51, 178, 14, 47, 110, 4, 125, 65, 173, 37, 13, 46, 254, 49, 62, 65, 97, 252, 6, 50, 244, 192, 215, 65, 118, 64, 156, 182, 34, 209, 125, 65}},
        coind::data::TxOutType{931401000, std::vector<unsigned char>{0, 20, 253, 163, 127, 183, 36, 159, 226, 17, 129, 202, 161, 120, 116, 49, 242, 191, 157, 73, 184, 33}}
    };
    uint32_t locktime = 0;

    // witness data

    auto _witness1 = std::vector<unsigned char>{48, 68, 2, 32, 48, 67, 6, 98, 155, 39, 67, 72, 244, 68, 204, 126, 16, 168, 20, 23, 159, 8, 172, 252, 135, 144, 253, 180, 193, 146, 77, 62, 124, 80, 115, 12, 2, 32, 17, 40, 231, 119, 53, 96, 188, 54, 183, 84, 184, 165, 17, 113, 200, 27, 80, 231, 57, 173, 28, 57, 69, 209, 88, 22, 42, 138, 115, 62, 176, 171, 1};
    auto witness1 = std::string(_witness1.begin(), _witness1.end());

    auto _witness2 = std::vector<unsigned char>{3, 74, 109, 112, 14, 31, 207, 206, 180, 117, 64, 178, 93, 115, 157, 217, 28, 132, 209, 3, 49, 145, 84, 188, 224, 109, 45, 235, 90, 97, 241, 42, 65};
    auto witness2 = std::string(_witness2.begin(), _witness2.end());
    // =================

    std::optional<coind::data::WitnessTransactionData> wdata = std::make_optional<coind::data::WitnessTransactionData>
            (
                    0,
                    1,
                    std::vector<std::vector<std::string>>
                    {
                        std::vector<std::string>
                        {
                            witness1,
                            witness2
                        }
                    }
            );

    auto tx = std::make_shared<coind::data::TransactionType>(version, tx_ins, tx_outs, locktime, wdata);

    auto tx_hash = uint256S("d537fddd084484c24367b4db7beb1e091b6d75db9bd043e5e5562d740a2926f");

    auto txid = coind::data::get_txid(tx);
    ASSERT_EQ(txid, uint256S("dc5351c6a8df8e8ef9f7e825c02d4bae86c89801d319cee22f03852df63946b7"));
    std::cout << "txid = " << txid << std::endl;

    auto wtxid = coind::data::get_wtxid(tx, txid, tx_hash);
    ASSERT_EQ(wtxid, uint256S("d537fddd084484c24367b4db7beb1e091b6d75db9bd043e5e5562d740a2926f"));
    std::cout << "wtxid = " << wtxid << std::endl;
}

TEST(CoindaData, merkle_hash)
{
    std::vector<std::string> hashes_str{
            "b53802b2333e828d6532059f46ecf6b313a42d79f97925e457fbbfda45367e5c",
            "326dfe222def9cf571af37a511ccda282d83bedcc01dabf8aa2340d342398cf0",
            "5d2e0541c0f735bac85fa84bfd3367100a3907b939a0c13e558d28c6ffd1aea4",
            "8443faf58aa0079760750afe7f08b759091118046fe42794d3aca2aa0ff69da2",
            "4d8d1c65ede6c8eab843212e05c7b380acb82914eef7c7376a214a109dc91b9d",
            "1d750bc0fa276f89db7e6ed16eb1cf26986795121f67c03712210143b0cb0125",
            "5179349931d714d3102dfc004400f52ef1fed3b116280187ca85d1d638a80176",
            "a8b3f6d2d566a9239c9ad9ae2ed5178dee4a11560a8dd1d9b608fd6bf8c1e75",
            "ab4d07cd97f9c0c4129cff332873a44efdcd33bdbfc7574fe094df1d379e772f",
            "f54a7514b1de8b5d9c2a114d95fba1e694b6e3e4a771fda3f0333515477d685b",
            "894e972d8a2fc6c486da33469b14137a7f89004ae07b95e63923a3032df32089",
            "86cdde1704f53fce33ab2d4f5bc40c029782011866d0e07316d695c41e32b1a0",
            "f7cf4eae5e497be8215778204a86f1db790d9c27fe6a5b9f745df5f3862f8a85",
            "2e72f7ddf157d64f538ec72562a820e90150e8c54afc4d55e0d6e3dbd8ca50a",
            "9f27471dfbc6ce3cbfcf1c8b25d44b8d1b9d89ea5255e9d6109e0f9fd662f75c",
            "995f4c9f78c5b75a0c19f0a32387e9fa75adaa3d62fba041790e06e02ae9d86d",
            "b11ec2ad2049aa32b4760d458ee9effddf7100d73c4752ea497e54e2c58ba727",
            "a439f288fbc5a3b08e5ffd2c4e2d87c19ac2d5e4dfc19fabfa33c7416819e1ec",
            "3aa33f886f1357b4bbe81784ec1cf05873b7c5930ab912ee684cc6e4f06e4c34",
            "cab9a1213037922d94b6dcd9c567aa132f16360e213c202ee59f16dde3642ac7",
            "a2d7a3d2715eb6b094946c6e3e46a88acfb37068546cabe40dbf6cd01a625640",
            "3d02764f24816aaa441a8d472f58e0f8314a70d5b44f8a6f88cc8c7af373b24e",
            "cc5adf077c969ebd78acebc3eb4416474aff61a828368113d27f72ad823214d0",
            "f2d8049d1971f02575eb37d3a732d46927b6be59a18f1bd0c7f8ed123e8a58a",
            "94ffe8d46a1accd797351894f1774995ed7df3982c9a5222765f44d9c3151dbb",
            "82268fa74a878636261815d4b8b1b01298a8bffc87336c0d6f13ef6f0373f1f0",
            "73f441f8763dd1869fe5c2e9d298b88dc62dc8c75af709fccb3622a4c69e2d55",
            "eb78fc63d4ebcdd27ed618fd5025dc61de6575f39b2d98e3be3eb482b210c0a0",
            "13375a426de15631af9afdf00c490e87cc5aab823c327b9856004d0b198d72db",
            "67d76a64fa9b6c5d39fde87356282ef507b3dec1eead4b54e739c74e02e81db4"
    };

    std::vector<uint256> hashes;
    for (auto s : hashes_str)
    {
        hashes.push_back(uint256S(s));
    }

    auto merkle_hash = coind::data::merkle_hash(hashes);
    std::cout << merkle_hash << std::endl;

    ASSERT_EQ(merkle_hash, uint256S("37a43a3b812e4eb665975f46393b4360008824aab180f27d642de8c28073bc44"));
}

TEST(CoindaData, merkle_hash2)
{
    std::vector<std::string> hashes_str{
            "b53802b2333e828d6532059f46ecf6b313a42d79f97925e457fbbfda45367e5c",
            "326dfe222def9cf571af37a511ccda282d83bedcc01dabf8aa2340d342398cf0",
            "5d2e0541c0f735bac85fa84bfd3367100a3907b939a0c13e558d28c6ffd1aea4"
    };

    std::vector<uint256> hashes;
    for (auto s : hashes_str)
    {
        hashes.push_back(uint256S(s));
    }

    auto merkle_hash = coind::data::merkle_hash(hashes);
    std::cout << merkle_hash << std::endl;

    ASSERT_EQ(merkle_hash, uint256S("6aef4ad75d13e3b7daab2f36995660a7c3df3e1bf9f8fcddc39993d97b814743"));
}

TEST(CoindData, calculate_merkle_link_test_perfomance)
{
    std::vector<uint256> hashes;
    hashes.push_back(uint256::ZERO);

    std::fstream file("merkle_link_hashes.txt", std::ios::in);

    std::string str;
    while (file >> str)
    {
        hashes.push_back(uint256S(str));
    }

    auto t1 = clock();
    auto merkle_link = coind::data::calculate_merkle_link(hashes, 0);
    auto t2 = clock();
    const double work_time = ((t2 - t1) / double(CLOCKS_PER_SEC)) * 1000;
    std::cout << merkle_link << std::endl;
    std::cout << "TIME: " << work_time << "ms"<< std::endl;

    std::vector<uint256> res_branch{
        uint256S("f7a71d7aac33994cf19eb2f45cc19f1e90a58b1ddeea712f119addc14d606bf5"),
        uint256S("89960601d0f6a4abc20018acc3276404d3ebaba63f55605ccad3fadd356d5ef2"),
        uint256S("93c95e0483c4e293659ceb14dc8b8418ad32c06e0ed3e5a1e2191df19be74bb7"),
        uint256S("4e4b23f71f4c9e49956d0ea816fb501f4dfc42cee469642d915773eece02ad2a"),
        uint256S("53af3e3a2f03a4138acd485e780d21558023ffaddeca6588eaa0fd464fb1dc4b"),
        uint256S("3f95318e882aae1e15b8d75ee25c8f65b55fbc8d31e6875566ec169561a4caed"),
        uint256S("d781dc348e134203635b7e263c9117dee86e75641cf3a594fe3324706845d4da"),
        uint256S("97e803db96b6184557c4ec20ba15707a94d8607b48ce2e6f6ab6cc4023786c40"),
        uint256S("c7fa553133d24aade53aa134f73d5eec4905112c6e86753e43dc3271ce7d50b8"),
        uint256S("3e4fe8ca4a22273a84c43d0bc377a6d2229b58fb8491bfea4f3bc584779ad88f"),
        uint256S("bcbf46fcc81b3f21b63c1346feaa1439e663c045e1fd317932eee010a8010ce0"),
        uint256S("53cf4bdbfeca32c146c254be797996a2b4cff90dc4f92bf804b986b225479c78"),
    };
    coind::data::MerkleLink merkle_result(res_branch, 0);

    ASSERT_EQ(merkle_result, merkle_link);
}