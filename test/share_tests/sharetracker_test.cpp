#include <gtest/gtest.h>

#include <memory>
#include <utility>

#include <libdevcore/common.h>
#include <sharechains/tracker.h>
#include <sharechains/share_store.h>
#include <sharechains/generate_tx.h>
#include <networks/network.h>
#include <btclibs/script/script.h>
#include <sharechains/data.h>

class TestNetwork : public c2pool::Network
{
public:
    TestNetwork(std::shared_ptr<coind::ParentNetwork> _par) : c2pool::Network("test_sharechain")
    {
        parent = std::move(_par);

        SOFTFORKS_REQUIRED = {"nversionbips", "csv", "segwit", "reservealgo", "odo"};
        BOOTSTRAP_ADDRS = {
                CREATE_ADDR("0.0.0.0", "5024")
        };
        PREFIX_LENGTH = 8;
        PREFIX = new unsigned char[PREFIX_LENGTH]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
        IDENTIFIER_LENGTH = 8;
        IDENTIFIER = new unsigned char[IDENTIFIER_LENGTH]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x66};
        MINIMUM_PROTOCOL_VERSION = 1600;
        SEGWIT_ACTIVATION_VERSION = 17;

        TARGET_LOOKBEHIND = 200;
        SHARE_PERIOD = 25;
        BLOCK_MAX_SIZE = 1000000;
        BLOCK_MAX_WEIGHT = 4000000;
        REAL_CHAIN_LENGTH = 24 * 60 * 60 / 10;
        CHAIN_LENGTH = 24 * 60 * 60 / 10;
        SPREAD = 30;
        ADDRESS_VERSION = 30;
        PERSIST = true;

        MIN_TARGET.SetHex("0");
        MAX_TARGET.SetHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // 2**256/2**20 - 1

        DONATION_SCRIPT = ParseHex("5221038ab82f3a4f569c4571c483d56729e83399795badb32821cab64d04e7b5d106864104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664b410457a337b86557f5b15c94544ad267f96a582dc2b91e6873968ff7ba174fda6874af979cd9af41ec2032dfdfd6587be5b14a4355546d541388c3f1555a67d11c2d53ae");

        // init gentx_before_refhash
        {
            PackStream gentx_stream;

            StrType dnt_scpt(DONATION_SCRIPT);
            gentx_stream << dnt_scpt;

            IntType(64) empty_64int(0);
            gentx_stream << empty_64int;

            PackStream second_str_stream(std::vector<unsigned char>{0x6a, 0x28});
            IntType(256) empty_256int(uint256::ZERO);
            second_str_stream << empty_256int;
            second_str_stream << empty_64int;

            PackStream for_cut;
            StrType second_str(second_str_stream.data);
            for_cut << second_str;
            for_cut.data.erase(for_cut.data.begin() + 3 , for_cut.data.end());

            gentx_stream << for_cut;
            gentx_before_refhash = gentx_stream.data;

//            std::cout << gentx_stream.size() << std::endl;
//            for (auto v : gentx_stream.data){
//                std::cout << (unsigned int) v << " ";
//            }
//            std::cout << std::endl;

        }
    }
};

class SharechainsTest : public ::testing::Test
{
protected:
    shared_ptr<TestNetwork> net;

protected:

    virtual void SetUp()
    {
        C2Log::Logger::Init();
        C2Log::Logger::enable_trace();

        auto pt = coind::ParentNetwork::make_default_network();
        std::shared_ptr<coind::ParentNetwork> parent_net = std::make_shared<coind::ParentNetwork>("dgb", pt);
        net = make_shared<TestNetwork>(parent_net);
    }

    virtual void TearDown()
    {
    }
};

TEST_F(SharechainsTest, tracker_base_tests)
{
    std::shared_ptr<ShareTracker> tracker = std::make_shared<ShareTracker>(net);

    uint256 hash = uint256S("1");

    // tracker assert in get_pool_attempts_per_second
    ASSERT_DEATH({
                     auto attempts1 = tracker->get_pool_attempts_per_second(hash, 1);
                 }, "get_pool_attempts_per_second: assert for dist >= 2");
}

//TEST_F(SharechainsTest, tracker_empty)
//{
//    std::shared_ptr<ShareTracker> tracker = std::make_shared<ShareTracker>(net);
//
//    uint256 hash = uint256S("1");
//
//
//    // Remove
//    std::cout << "Remove" << std::endl;
//    tracker->remove(hash);
//
//    // Pool attempts for dist = 1
//    std::cout << "Pool attempts for dist = 1" << std::endl;
//    ASSERT_DEATH({
//                     auto attempts1 = tracker->get_pool_attempts_per_second(hash, 1);
//                 }, "get_pool_attempts_per_second: assert for dist >= 2");
//
//    // Pool attempts for dist = 10
//    std::cout << "Pool attempts for dist = 10" << std::endl;
//    ASSERT_THROW({auto attempts10 = tracker->get_pool_attempts_per_second(hash, 10);}, std::invalid_argument);
//
//    // Desired version dist = 1
//    std::cout << "Desired version dist = 1" << std::endl;
//    auto desired_version1 = tracker->get_desired_version_counts(hash, 1);
//    for (auto v : desired_version1)
//    {
//        std::cout << v.first << ": " << v.second.ToString() << std::endl;
//    }
//
//    // Desired version dist = 10
//    std::cout << "Desired version dist = 10" << std::endl;
//    auto desired_version10 = tracker->get_desired_version_counts(hash, 10);
//    for (auto v : desired_version10)
//    {
//        std::cout << v.first << ": " << v.second.ToString() << std::endl;
//    }
//
//    // Get
//    std::cout << "Get" << std::endl;
//    auto share = tracker->get(hash);
//    ASSERT_EQ(share, nullptr);
//}

TEST_F(SharechainsTest, just_share_load)
{
    PackStream stream_share;
    stream_share.from_hex("21fd0702fe02000020617dfa46bf73eb96548e0b039a647d35b387ed0cb1a6e51c80092175857d3f5b3ac4ff62f1a9001bc0254dda4d00fe065ba137d8e108ef134db29b7e33f46327f13626975c0c2a190082018f3d04d03aee002cfabe6d6d21102609e852babee96639fbb3b65588bbcc419720fec56da52e47120c4804a501000000000000000a5f5f6332706f6f6c5f5ffc88aa669a2cd3c1310067ae7e47a7869b330d30b691c61b46fb483b0a0000000000002102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203517d2164368b766e6b9d0598510a7bbfc9882940ebfe3f65bb72173c3dbf105802f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5ef1025a29236b072d75cde8637584a3ed2fe0bcd4aadb5824b61cc42b4414e143d020000000195cbb26f405ead27fcd8cf84155cfcfab722a0cfdb3a2c735fce15fb19bc8ae4ffff0f1e8888001e3bc4ff62cc210000df798a25160000000000000000000000000000000001000000986dae33074d8c439a5dc61c2019a86726ebd1cf0eb0240582ccc0b249d12ba7fd9c0102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203");
//    stream_share.from_hex("21fd4301fe020000206201af0a6930f520a4e89c2a024731e401b2d9cf976e4d0a82dcf9c206c1370b4ce02763d1f5001b03e0d41cfb866ba9fec6e8c456dd721b850a1b012b923dbbe9aa615a6de390230eebb5f53d04a9e9f0002cfabe6d6d4644c9e477f93b03c5c33cd6d61f16165c57f360325d75630d58dddac2ab635301000000000000000a5f5f6332706f6f6c5f5fd0ba3068bb351fc9fbbd8e1f40942130e77131978df6de41541d0d1e0a0000000000002100000000000000000000000000000000000000000000000000000000000000000000007c943b346fed7bc58a33254406d6a67c55c8b3759f8b87e11de3513cd5e67c12ee83021ee476151d4de02763d4aa0000502cdf03b40000000000000000000000000000000001000000e1a45914351179267e8d373f31778ba4792ef4227f68752459acff124bb965b7fd7a0100");
//    stream_share.from_hex("21fdad02fe0200002039cc52f3e1412ce3e0dcfd3c53ce0f8b62edecdd82b4ac3b45b483dcfa4b71d1351a28638fd2001b335ab26f3626eafdcee83bb1ac57b757a7f73ce919d0690964b361f97171cc32cb2cab983d0474edf0002cfabe6d6ddd5bd8f3360ee89b84a17f0fd30446a5620888d9342d5d49d1255527ed6cbef501000000000000000a5f5f6332706f6f6c5f5f347623c9bb351fc9fbbd8e1f40942130e77131978df6de413288101e0a0000000000fe21031d30c187f67e4d41a4e069f648413865c5d093de552a86d09bd81480c1c4da5169b87cc45a6debf0832392165de663983a5e6dadc6c3c0d789fb68547d1e2b2f0210bea6d2a99698b42cd62a71c2769bcf28a9e176ec3ee7f3e6b1b77785a79357efbc35825402100550ec1ba19cda3f01b25ffc5587acc90f4bcdd2998e1a4405b80c7f452d6d846290ca65b75caf21aa7cfe08672bc20f83d9b55a3ee87fed6c2b58b75c1eb34aee44912beaf81298a6981cd27336c407f530f71a1ec8a40790e19149645601a62beaf9442b76557b8fa48767bb8daf22d3d26a8c922b8bbdadd3a92eba693decb11345556a4915a91f5a0c072960d3b97da275b09a7815a639f2346d24027e63ea93693073b70ac29714f3b6ed8edf6d46db711fb99f249e030500000001000200030004d812db8ae1f908a68bf7072153ca319f247a86d6fd8a9f2218d312544f71b97dc29c071e68f5401d3b1a28639bac000015650778b5000000000000000000000000000000000100000009557e7d9e53aeb227850a55d32310a57c64744f18a2d2c362e83ecc9505102efd7a0103b80c7f452d6d846290ca65b75caf21aa7cfe08672bc20f83d9b55a3ee87fed6c69b87cc45a6debf0832392165de663983a5e6dadc6c3c0d789fb68547d1e2b2f0210bea6d2a99698b42cd62a71c2769bcf28a9e176ec3ee7f3e6b1b77785a793");
//    stream_share.from_hex("21fd0702fe02000020462750c8ee349d5cdf644f2f387eae5e83f09c516d80f6b7bff6bb5077f492cf501c286382d0001b336009dfc05bb320693870ee52f31b1a7acdf59fd62a06304c2226ec71372e2dd81038443d04abedf0002cfabe6d6dbb98999c619b01360f5f78fb757361280a0fc6d86e64af39883cd4c32c1bb41f01000000000000000a5f5f6332706f6f6c5f5feafa8b19bb351fc9fbbd8e1f40942130e77131978df6de41c5bc0d1e0a0000000000002102ba60a71143d79b34ce2763688d2dc47431699e946cfba3bc09f0538db16c247603f5fd54628f9524c7816a13bfdcbb294bfbf910c856dd6d2867e3fea75e6ff0fa575b274b856f98e04e2e4e137d1aec6ff73ac3abe10198b9e2a4cacebb32a602ba60a71143d79b34ce2763688d2dc47431699e946cfba3bc09f0538db16c24761f66f6ca39e76964e7c66d2d6ce0c0f53a41c240c21ac01f9f1ca7a88d3a40530200000001e541da22b7db053fbc6cdcd45cf4ebd37b17704c4845fcc9ab41f01ff85e935e78ee081e3b374c1d521c2863a7ac00000ef2e2a1b50000000000000000000000000000000001000000849846b13fc97f2930fda8c079866515eb86fed117a26ec0d91a47406e1caadefd7a0102ba60a71143d79b34ce2763688d2dc47431699e946cfba3bc09f0538db16c247603f5fd54628f9524c7816a13bfdcbb294bfbf910c856dd6d2867e3fea75e6ff0");
//    stream_share.from_hex("0121fd8b02fe020000200a323e9e21d6312c35f0860b867aff6f1a645657ff2d3cf39fd97cbe90523e1bb11275630be5001bcf691a3680ae0862fa882cdb89b7c93ad6e8a1d1bb864e5b3dd1b3637176cfecea470f003d04e913f6002cfabe6d6d9af7e5ceeeb550fe519d93acf6180dfac960ba8de50867804e3e1266e46b954a01000000000000000a5f5f6332706f6f6c5f5ffb33ee19bb351fc9fbbd8e1f40942130e77131978df6de41003491e40900000000000021032a2d7839465665319802c1d2401a5f34e0d005db96427ffdf85d89a4bd790f89e8730a3419d5cbc24437811d655837ef8d79d4c59ccbd0ab0f424ebe6e50ce897601ebe4afd19d9c7447f36c674ae2b8b61729af8ef8d9391b18720c2a1e913e8ec095db066afdcc3ea407a1a637d3ae50e59b803459c8f1625347879b4822d404d0b67f5551fa156fd06f3e63d73ee843cc118407d7cbec43773eac140bd61e9ffe06f6165185f6b84d1841d06739274739ad0c1ef895e4c4a76a2edd6ac5e3a033aace1fc2fc77a6b6c285d6b3a0652b89c5278ce6c361f9aa7bf19343af2493521dd01d1a3e3d21ba6b5c5ed270135053a3e097751355eac119d0b6c4e401520400000001000200035c0a675aca574df4b241e747e1c9b9bc2b024bc4169804aedd3ab0f1df6217fda15d031e95b81c1db21275635f2503005e7790d165030000000000000000000000000000002000000039f585f5bf9c60686f9e79cc4a2523ea01a02ada2d6b13d3c2f77b8585960900fd7a0103d0b67f5551fa156fd06f3e63d73ee843cc118407d7cbec43773eac140bd61e9f14336e2c78108a38e6bd8bcc645084bebb91a3d6c12c74a46d05a6ced7c46cea073d2ca698c4c03ee7dfadcf497dcaa34705c1083dcebae543439d179f415584");
    auto share = load_share(stream_share, net, {"0.0.0.0", "0"});
    std::cout << *share->subsidy << ":" << (*share->share_data)->subsidy;
}

//TEST_F(SharechainsTest, handle_share_test)
//{
//    VariableDict<uint256, coind::data::tx_type> known_txs = VariableDict<uint256, coind::data::tx_type>(true);
//
//
//    PackStream stream_share;
//    stream_share.from_hex(
//            "21fd0702fe02000020462750c8ee349d5cdf644f2f387eae5e83f09c516d80f6b7bff6bb5077f492cf501c286382d0001b336009dfc05bb320693870ee52f31b1a7acdf59fd62a06304c2226ec71372e2dd81038443d04abedf0002cfabe6d6dbb98999c619b01360f5f78fb757361280a0fc6d86e64af39883cd4c32c1bb41f01000000000000000a5f5f6332706f6f6c5f5feafa8b19bb351fc9fbbd8e1f40942130e77131978df6de41c5bc0d1e0a0000000000002102ba60a71143d79b34ce2763688d2dc47431699e946cfba3bc09f0538db16c247603f5fd54628f9524c7816a13bfdcbb294bfbf910c856dd6d2867e3fea75e6ff0fa575b274b856f98e04e2e4e137d1aec6ff73ac3abe10198b9e2a4cacebb32a602ba60a71143d79b34ce2763688d2dc47431699e946cfba3bc09f0538db16c24761f66f6ca39e76964e7c66d2d6ce0c0f53a41c240c21ac01f9f1ca7a88d3a40530200000001e541da22b7db053fbc6cdcd45cf4ebd37b17704c4845fcc9ab41f01ff85e935e78ee081e3b374c1d521c2863a7ac00000ef2e2a1b50000000000000000000000000000000001000000849846b13fc97f2930fda8c079866515eb86fed117a26ec0d91a47406e1caadefd7a0102ba60a71143d79b34ce2763688d2dc47431699e946cfba3bc09f0538db16c247603f5fd54628f9524c7816a13bfdcbb294bfbf910c856dd6d2867e3fea75e6ff0");
//    auto share = load_share(stream_share, net, {"0.0.0.0", "0"});
//
//    //t0
//    vector<tuple<ShareType, std::vector<coind::data::tx_type>>> result; //share, txs
//
//
//    std::vector<coind::data::tx_type> txs;
//    if (true)
//    {
//        for (auto tx_hash: *share->new_transaction_hashes)
//        {
//            coind::data::tx_type tx;
//            if (known_txs.value().find(tx_hash) != known_txs.value().end())
//            {
//                tx = known_txs.value()[tx_hash];
//            }
////            else
////            {
////                for (auto cache: protocol->known_txs_cache)
////                {
////                    if (cache.find(tx_hash) != cache.end())
////                    {
////                        tx = cache[tx_hash];
////                        LOG_INFO
////                            << boost::format("Transaction %0% rescued from peer latency cache!") % tx_hash.GetHex();
////                        break;
////                    }
////                }
////            }
//            txs.push_back(tx);
//        }
//    }
//    result.emplace_back(share, txs);
//
////    handle_shares(result, protocol);
//// HANDLE SHARES:
//
////    int32_t new_count = 0;
//    std::map<uint256, coind::data::tx_type> all_new_txs;
//    auto [_share, new_txs] = result[0];
//    {
//        if (!new_txs.empty())
//        {
//            for (const auto& new_tx : new_txs)
//            {
//                coind::data::stream::TransactionType_stream _tx(new_tx);
//                PackStream packed_tx;
//                packed_tx << _tx;
//
//                all_new_txs[coind::data::hash256(packed_tx)] = new_tx;
//            }
//        }
////
////        if (tracker->exists(share->hash))
////        {
//////			#print 'Got duplicate share, ignoring. Hash: %s' % (p2pool_data.format_hash(share.hash),)
//////			continue
////        }
////
////        new_count++;
////        tracker->add(share);
//    }
//
//    known_txs.add(all_new_txs);
//
////    if (new_count)
////    {
////        coind_node->set_best_share();
////    }
////
////    if (shares.size() > 5)
////    {
////        LOG_INFO << "... done processing " << shares.size() << "shares. New: " << new_count << " Have: " << tracker->items.size() << "/~" << 2*net->CHAIN_LENGTH;
////    }
//
//}


TEST_F(SharechainsTest, tracker_one_share)
{
    std::shared_ptr<ShareTracker> tracker = std::make_shared<ShareTracker>(net);

    PackStream stream_share;
//    stream_share.from_hex("11fda501fe02000020707524a64aa0820305612357ae0d2744695c8ba18b8e1402dc4e199b5e1bf8daae2ceb62979e001bc0006d6200000000000000000000000000000000000000000000000000000000000000003d043edaec002cfabe6d6d08d3533a81ca356a7ac1c85c9b0073aebcca7182ad83849b9498377c9a1cd8a701000000000000000a5f5f6332706f6f6c5f5f3e9922fe9ad7bdd0e20eb7f64fa6dd42734dd4f43275cc26fd4d483b0a00000000000021012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d61f2bae86d664294b8850df3f580ec9e4fb2170fe8dbae492b5159af73834eba4012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d60100000000000000000000000000000000000000000000000000000000000000000000ffff0f1effff0f1eae2ceb6201000000010010000000000000000000000000000000000000000000001fcbf0a89045913d394db52949e986b8c6385b0060cbaebf3cf7806ff1df96affd7a01012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d6");
//    stream_share.from_hex("21fd0702fe02000020617dfa46bf73eb96548e0b039a647d35b387ed0cb1a6e51c80092175857d3f5b3ac4ff62f1a9001bc0254dda4d00fe065ba137d8e108ef134db29b7e33f46327f13626975c0c2a190082018f3d04d03aee002cfabe6d6d21102609e852babee96639fbb3b65588bbcc419720fec56da52e47120c4804a501000000000000000a5f5f6332706f6f6c5f5ffc88aa669a2cd3c1310067ae7e47a7869b330d30b691c61b46fb483b0a0000000000002102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203517d2164368b766e6b9d0598510a7bbfc9882940ebfe3f65bb72173c3dbf105802f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5ef1025a29236b072d75cde8637584a3ed2fe0bcd4aadb5824b61cc42b4414e143d020000000195cbb26f405ead27fcd8cf84155cfcfab722a0cfdb3a2c735fce15fb19bc8ae4ffff0f1e8888001e3bc4ff62cc210000df798a25160000000000000000000000000000000001000000986dae33074d8c439a5dc61c2019a86726ebd1cf0eb0240582ccc0b249d12ba7fd9c0102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203");
    stream_share.from_hex("21fd4301fe02000020d015122ac6c9b4ec0b3b0f684dcb88fedc106c22d66b8583d67bcdf7fa2fbe37542188632205011b492009eaa2bfe882e1f6f99596e720c18657a1dde02bdc10dcb3a8725c765625db9c3ea73d04ec59f7002cfabe6d6d9af7e5ceeeb550fe519d93acf6180dfac960ba8de50867804e3e1266e46b954a01000000000000000a5f5f6332706f6f6c5f5f04d213ddbb351fc9fbbd8e1f40942130e77131978df6de416cea4cc8090000000000002100000000000000000000000000000000000000000000000000000000000000000000009678d14ad4c5e2859d7d036b8f69b8211884a6b63711d6c3ee3c633d61610bf45d31041efb45011e552188630cd30300d98b6cb72504000000000000000000000000000000010000007e0fa5ede3dae6732ef68a7447180e26ef694d17a37d2e4c406244004c839722fd7a0100");
    auto share = load_share(stream_share, net, {"0.0.0.0", "0"});

    auto hash = share->hash;

    tracker->add(share);

    std::cout << "Desired version dist = 1" << std::endl;
    auto desired_version1 = tracker->get_desired_version_counts(hash, 1);
    for (auto v : desired_version1)
    {
        std::cout << v.first << ": " << v.second.ToString() << std::endl;
    }

    // Get
    std::cout << "Get" << std::endl;
    auto share2 = tracker->get(hash);
    ASSERT_EQ(share2, share);

    // Remove
    std::cout << "Remove" << std::endl;
    tracker->remove(hash);

}

TEST_F(SharechainsTest, tracker_get_height_and_last)
{
    std::shared_ptr<ShareTracker> tracker = std::make_shared<ShareTracker>(net);

    PackStream stream_share;
//    stream_share.from_hex("11fda501fe02000020707524a64aa0820305612357ae0d2744695c8ba18b8e1402dc4e199b5e1bf8daae2ceb62979e001bc0006d6200000000000000000000000000000000000000000000000000000000000000003d043edaec002cfabe6d6d08d3533a81ca356a7ac1c85c9b0073aebcca7182ad83849b9498377c9a1cd8a701000000000000000a5f5f6332706f6f6c5f5f3e9922fe9ad7bdd0e20eb7f64fa6dd42734dd4f43275cc26fd4d483b0a00000000000021012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d61f2bae86d664294b8850df3f580ec9e4fb2170fe8dbae492b5159af73834eba4012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d60100000000000000000000000000000000000000000000000000000000000000000000ffff0f1effff0f1eae2ceb6201000000010010000000000000000000000000000000000000000000001fcbf0a89045913d394db52949e986b8c6385b0060cbaebf3cf7806ff1df96affd7a01012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d6");
//    stream_share.from_hex(
//            "21fd0702fe02000020617dfa46bf73eb96548e0b039a647d35b387ed0cb1a6e51c80092175857d3f5b3ac4ff62f1a9001bc0254dda4d00fe065ba137d8e108ef134db29b7e33f46327f13626975c0c2a190082018f3d04d03aee002cfabe6d6d21102609e852babee96639fbb3b65588bbcc419720fec56da52e47120c4804a501000000000000000a5f5f6332706f6f6c5f5ffc88aa669a2cd3c1310067ae7e47a7869b330d30b691c61b46fb483b0a0000000000002102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203517d2164368b766e6b9d0598510a7bbfc9882940ebfe3f65bb72173c3dbf105802f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5ef1025a29236b072d75cde8637584a3ed2fe0bcd4aadb5824b61cc42b4414e143d020000000195cbb26f405ead27fcd8cf84155cfcfab722a0cfdb3a2c735fce15fb19bc8ae4ffff0f1e8888001e3bc4ff62cc210000df798a25160000000000000000000000000000000001000000986dae33074d8c439a5dc61c2019a86726ebd1cf0eb0240582ccc0b249d12ba7fd9c0102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203");
    stream_share.from_hex("21fd4b02fe0200002094eca1b013c434b150b042895d59dd357f2f4f661dd132dc83787402c3874a55b34d40635ea0001b00db7fabb0524a1171d7f71d84285e76f4f2fb742e29e1b29c8a997331fb3cdab0d3cbfa3d04dc8bf2002cfabe6d6d2a19b48958c42722af5c9a4cc7a16ffd895f613d49cabe48b5a44d9190f3eb4301000000000000000a5f5f6332706f6f6c5f5f5bf0ec6fbb351fc9fbbd8e1f40942130e77131978df6de41ad6426010a00000000000021036167652e12a2eac51373cf2690ee05b720ce34955eec05a32164cad6fe122b914bdbaeb18c80e89558a977cfa4fccea584fca11a0fb5a0a3aeebf1c2a0f4a1c1fbbdf2984cfb8e93a8bf30d456cf0018dfbfdb3df9500c81fbee92a9982863d3b6dd2d15fe26c1b07aa9f01db4810417da3e15f56e5c203e23b9390534e9bfef021eb045d04c4a85760929f818acfc0813ec018cdc570a501e609fb2f7bd4b35211f608e1d875036fa74f7cc814d8cd1a28835806b349214e2ca8229be81c539fd040100010100000001ee638ae5af53e60f73915fa1e408b857b9b5b0b6c799cdc969bff98bf1a8746115a0051eb900301db44d406381780100ef389e188f01000000000000000000000000000000010000001abe671960fd58c3c7d0b73b8a8ab38b71ee85f207d38476f3c1fb0b4519d2fffd7a0103e5c017d9d92ae1fd1e3b9a931de8ad6585809be3b27538c93199a5a92b306f6fe42882200a480a47a36db1292ba556517644b70cda40d3a9ceec6e062a36874f3823c7e9921ea9e44106d95759467b629f13cd9dbc847a95fb918aaf18b4306e");
    auto share = load_share(stream_share, net, {"0.0.0.0", "0"});

    auto hash = share->hash;
    tracker->add(share);

    auto height_and_last = tracker->get_height_and_last(hash);
    std::cout << "Height: " << std::get<0>(height_and_last) << std::endl;
    std::cout << "Last: " << std::get<1>(height_and_last) << std::endl;

}

TEST_F(SharechainsTest, tracker_think)
{
    std::shared_ptr<ShareTracker> tracker = std::make_shared<ShareTracker>(net);

    std::vector<std::string> datas {
            "21fd4301fe02000020a7fc88bb060ad0c93111b1e2a2a812a30e66f6e49a4f026eb56850d5bac7aa162f694b631ed3001b899cda89ee0c74ddefbfc86c2f326b947809dc41420cbcfaed0eb6dcb49e3a723a86268e3d04184af3002cfabe6d6d3ad1b6dc5cf06d85b8bf0b91da474a19572cfe6cfe9e2603987dedff8bc9fb6c01000000000000000a5f5f6332706f6f6c5f5ff664235abb351fc9fbbd8e1f40942130e77131978df6de411a7125010a000000000000210000000000000000000000000000000000000000000000000000000000000000000000a15ea9394af3d2ea723b77890b4eb4926ac34a66d2f9305fa8926e9a8bcd6fffd738021e1df6121d2f694b6383d4010003151050f80100000000000000000000000000000001000000f682226e7f28689aa1ee6d0ea025501392a3ea294a4013a09d55f127fadf417dfd7a0100",
            "21fd0702fe020000204848c58a9eecf074ec30bda48523447b7051916099ceb63901000000000000008c684b63fcc5001bd9a5549a7b61579afd4608b8191ca4b26e2da0e50383c5f301ff79caf19ba21ed384799e3d04124af3002cfabe6d6da6280d3c81df1c68efe356c123f7f3bb4d51e3d9671ae0060b70ced54a7f2b2f01000000000000000a5f5f6332706f6f6c5f5f95c5ae73bb351fc9fbbd8e1f40942130e77131978df6de41b00326010a0000000000fe2102f396eb2887df58385886b00b6d40894d57ef19ebc3e7af23235c2d3c37c527afbfb69463abbad2d057c010bf976584f73b5d9220c42f406824fa2404603094c14bf1f4f2799a6c57022b01ac98d4ea6c3a4fac23d97a206b069ab804de130dde02f396eb2887df58385886b00b6d40894d57ef19ebc3e7af23235c2d3c37c527afc410379a6d4b234bf95300942810e64ccd7c7f67986aa546222c6d345e8eff78020000000179946855deb7219d34e858f21ace48d5d0efde210249f16b5f18b73cbb2643412105021edd3c111d91684b6382d4010027cb8f42f801000000000000000000000000000000010000004ba89a690dc44135196be51b09afaaa08e802b22b0b1bb8f04ea8ce44152c931fd7a0102f396eb2887df58385886b00b6d40894d57ef19ebc3e7af23235c2d3c37c527afbfb69463abbad2d057c010bf976584f73b5d9220c42f406824fa2404603094c1",
            "21fd4301fe0200002069a23207be25e7a85c90503b49c3afa2a1f81932d4e849db0000000000000000d25b4b637ecb001b38f9c44cc1f5b414f81799b7a2aea1fe855f6fd45c6cef593b0bac6b29f5a67abfc35a7d3d043c49f3002cfabe6d6d265e57d73d2102c2d426c33c427a5ac70d92d50b018a3ffd2f325c5bb585d01601000000000000000a5f5f6332706f6f6c5f5fe1d4e229bb351fc9fbbd8e1f40942130e77131978df6de411a7125010a0000000000002100000000000000000000000000000000000000000000000000000000000000000000004bb6d4ae0d8da118c8a7ab7d79a7c30e72c42e0d1ca0663e514ff6f47bc888af2b06021e2b06021eda5b4b6381d4010097e7b533f80100000000000000000000000000000001000000d53919c88fe180f62b333d9a57f00b4483ed0cac2793fe3a18f2501c3156f924fd7a0100",
            "21fd4301fe0200002069a23207be25e7a85c90503b49c3afa2a1f81932d4e849db0000000000000000d25b4b637ecb001b58f427e3a583560fc5b700f77901327a5f2a7bc4cc68c044af6e82ab7b7d0699e5f7c9bf3d043c49f3002cfabe6d6d265e57d73d2102c2d426c33c427a5ac70d92d50b018a3ffd2f325c5bb585d01601000000000000000a5f5f6332706f6f6c5f5f421aebd7bb351fc9fbbd8e1f40942130e77131978df6de411a7125010a0000000000002100000000000000000000000000000000000000000000000000000000000000000000005b592aae5b471d7af15a98c71136ff94220e9e8e0c998109e34d0b039f6ed5355307021e5307021ed65b4b6380d40100a56d3733f80100000000000000000000000000000002000000d53919c88fe180f62b333d9a57f00b4483ed0cac2793fe3a18f2501c3156f924fd7a0100",
            "21fd4301fe0200002069a23207be25e7a85c90503b49c3afa2a1f81932d4e849db0000000000000000c35b4b637ecb001b18f7f3ad2c3de4ce481e62689c2785f51848e0c0279655ecbc8636587bf023fc405445db3d043c49f3002cfabe6d6d265e57d73d2102c2d426c33c427a5ac70d92d50b018a3ffd2f325c5bb585d01601000000000000000a5f5f6332706f6f6c5f5f3c6a687dbb351fc9fbbd8e1f40942130e77131978df6de411a7125010a0000000000fe210000000000000000000000000000000000000000000000000000000000000000000000f875eed2d6e8aea3bb4040faeb460422a9663ce8d3684892e7f50bd6b7df9c341009021e1009021ecb5b4b637ed40100a3343b32f80100000000000000000000000000000001000000d53919c88fe180f62b333d9a57f00b4483ed0cac2793fe3a18f2501c3156f924fd7a0100",
            "21fd4301fe0200002069a23207be25e7a85c90503b49c3afa2a1f81932d4e849db0000000000000000c35b4b637ecb001b18f3c4e670b789e2dc2fd0ead0e49f52699176d7a7a96730837024b5c8a5d4a7f5bc2e2c3d043c49f3002cfabe6d6d265e57d73d2102c2d426c33c427a5ac70d92d50b018a3ffd2f325c5bb585d01601000000000000000a5f5f6332706f6f6c5f5f2f6d9d23bb351fc9fbbd8e1f40942130e77131978df6de411a7125010a00000000000021000000000000000000000000000000000000000000000000000000000000000000000055ac137f1b1995004f2fc98705c3ed7f9cc5f8e8551c96ed0316cb4bf764ceea6709021e6709021ec85b4b637dd401008d6ebd31f80100000000000000000000000000000001000000d53919c88fe180f62b333d9a57f00b4483ed0cac2793fe3a18f2501c3156f924fd7a0100"
    };

    for (auto v : datas)
    {
        PackStream stream_share;
        stream_share.from_hex(v);
        auto share = load_share(stream_share, net, {"0.0.0.0", "0"});
        tracker->add(share);
    }


//    stream_share.from_hex("11fda501fe02000020707524a64aa0820305612357ae0d2744695c8ba18b8e1402dc4e199b5e1bf8daae2ceb62979e001bc0006d6200000000000000000000000000000000000000000000000000000000000000003d043edaec002cfabe6d6d08d3533a81ca356a7ac1c85c9b0073aebcca7182ad83849b9498377c9a1cd8a701000000000000000a5f5f6332706f6f6c5f5f3e9922fe9ad7bdd0e20eb7f64fa6dd42734dd4f43275cc26fd4d483b0a00000000000021012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d61f2bae86d664294b8850df3f580ec9e4fb2170fe8dbae492b5159af73834eba4012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d60100000000000000000000000000000000000000000000000000000000000000000000ffff0f1effff0f1eae2ceb6201000000010010000000000000000000000000000000000000000000001fcbf0a89045913d394db52949e986b8c6385b0060cbaebf3cf7806ff1df96affd7a01012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d6");
//    stream_share.from_hex(
//            "21fd0702fe02000020617dfa46bf73eb96548e0b039a647d35b387ed0cb1a6e51c80092175857d3f5b3ac4ff62f1a9001bc0254dda4d00fe065ba137d8e108ef134db29b7e33f46327f13626975c0c2a190082018f3d04d03aee002cfabe6d6d21102609e852babee96639fbb3b65588bbcc419720fec56da52e47120c4804a501000000000000000a5f5f6332706f6f6c5f5ffc88aa669a2cd3c1310067ae7e47a7869b330d30b691c61b46fb483b0a0000000000002102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203517d2164368b766e6b9d0598510a7bbfc9882940ebfe3f65bb72173c3dbf105802f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5ef1025a29236b072d75cde8637584a3ed2fe0bcd4aadb5824b61cc42b4414e143d020000000195cbb26f405ead27fcd8cf84155cfcfab722a0cfdb3a2c735fce15fb19bc8ae4ffff0f1e8888001e3bc4ff62cc210000df798a25160000000000000000000000000000000001000000986dae33074d8c439a5dc61c2019a86726ebd1cf0eb0240582ccc0b249d12ba7fd9c0102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203");
//    auto share = load_share(stream_share, net, {"0.0.0.0", "0"});
//
//    auto hash = share->hash;
//    tracker->add(share);
    //===========================================

    boost::function<int32_t(uint256)> test_block_rel_height_func = [&](uint256 hash){return 0;};

    std::vector<uint8_t> _bytes = {103, 108, 55, 240, 5, 80, 187, 245, 215, 227, 92, 1, 210, 201, 113, 66, 242, 76, 148, 121, 29, 76, 3, 170, 153, 253, 61, 21, 199, 77, 202, 35};
    auto bytes_prev_block = c2pool::dev::bytes_from_uint8(_bytes);
    uint256 previous_block(bytes_prev_block);


    uint32_t bits = 453027171;
    std::map<uint256, coind::data::tx_type> known_txs;

    auto [_best, _desired, _decorated_heads, _bad_peer_addresses] = tracker->think(test_block_rel_height_func, previous_block, bits, known_txs);
    std::cout << "Best = " << _best.GetHex() << std::endl;

}

TEST_F(SharechainsTest, sharestore_only)
{
    std::shared_ptr<ShareTracker> tracker = std::make_shared<ShareTracker>(net);
//    std::cout << "getProjectPath + 'data': " << c2pool::filesystem::getProjectPath() / "data" << std::endl;

    auto share_store = ShareStore(net);
    share_store.legacy_init(c2pool::filesystem::getProjectPath() / "shares.0", [&](auto shares, auto known){tracker->init(shares, known);});

    std::cout << tracker->items.size() << " " << tracker->verified.items.size() << std::endl;
    std::cout << "shares: " << tracker->heads.size() << "/" << tracker->tails.size() << std::endl;
    std::cout << "verified: " << tracker->verified.heads.size() << "/" << tracker->verified.tails.size() << std::endl;

    for (auto v: tracker->verified.tails)
    {
        std::cout << v.first.GetHex() << ": " << std::endl;
        uint256 last_el;
        for (auto vv : v.second)
        {
            std::cout << vv.GetHex() << "; ";
            last_el = vv;
        }
        std::cout << "\b\b\n";

        std::cout << "max: " << last_el.GetHex() << std::endl;
        std::cout << "height: " << tracker->verified.get_height(last_el) << std::endl;

    }

    for (auto v : tracker->sum)
    {
        std::cout << v.second.height << " ";
    }
    std::cout << std::endl;
}

TEST_F(SharechainsTest, weights_test)
{
    std::shared_ptr<ShareTracker> tracker = std::make_shared<ShareTracker>(net);

    auto share_store = ShareStore(net);
    share_store.legacy_init(c2pool::filesystem::getProjectPath() / "shares.0", [&](auto shares, auto known){tracker->init(shares, known);});

    std::cout << tracker->items.size() << " " << tracker->verified.items.size() << std::endl;

    boost::function<int32_t(uint256)> test_block_rel_height_func = [&](uint256 hash){return 0;};

    std::vector<uint8_t> _bytes = {103, 108, 55, 240, 5, 80, 187, 245, 215, 227, 92, 1, 210, 201, 113, 66, 242, 76, 148, 121, 29, 76, 3, 170, 153, 253, 61, 21, 199, 77, 202, 35};
    auto bytes_prev_block = c2pool::dev::bytes_from_uint8(_bytes);
    uint256 previous_block(bytes_prev_block);


    uint32_t bits = 453027171;
    std::map<uint256, coind::data::tx_type> known_txs;

    auto [_best, _desired, _decorated_heads, _bad_peer_addresses] = tracker->think(test_block_rel_height_func, previous_block, bits, known_txs);
    std::cout << "Best = " << _best.GetHex() << std::endl;
    std::cout << "pre for Best = " << tracker->get(_best)->previous_hash->GetHex();

    ShareType previous_share = tracker->get(tracker->get(_best)->hash);
    uint256 prev_share_hash = previous_share ? previous_share->hash : uint256::ZERO;

    //height, last
    auto [height, last] = tracker->get_height_and_last(_best);

    auto _block_target = FloatingInteger(0).target();

    //get_cumulative_weights
    std::map<std::vector<unsigned char>, arith_uint288> weights;
    arith_uint288 total_weight;
    arith_uint288 donation_weight;
    {
        uint256 start_hash = *previous_share->previous_hash;

        int32_t max_shares = max(0, min(height, net->REAL_CHAIN_LENGTH) - 1);

        LOG_TRACE << "block_target: " << _block_target.GetHex();
        auto _block_target_attempts = coind::data::target_to_average_attempts(_block_target);
        LOG_TRACE << "_block_target_attempts: " << _block_target_attempts.GetHex();

        auto desired_weight = _block_target_attempts * 65535 * net->SPREAD;

        LOG_TRACE << "For get_cumulative_weights: " << start_hash.GetHex() << " " << max_shares << " " << desired_weight.GetHex();
        auto weights_result = tracker->get_cumulative_weights(start_hash, max_shares, desired_weight);
        weights = std::get<0>(weights_result);
        total_weight = std::get<1>(weights_result);
        donation_weight = std::get<2>(weights_result);
        LOG_TRACE << "weights.size = " << weights.size() << ", total_weight = " << total_weight.GetHex() << ", donation_weight = " << donation_weight.GetHex();
        LOG_TRACE << "Weights: ";
        for (auto v : weights)
        {
            LOG_TRACE << HexStr(v.first) << " " << v.second.GetHex();
        }
    }
}

TEST_F(SharechainsTest, gentx_test)
{
    std::shared_ptr<ShareTracker> tracker = std::make_shared<ShareTracker>(net);

    auto share_store = ShareStore(net);
    share_store.legacy_init(c2pool::filesystem::getProjectPath() / "shares.0", [&](auto shares, auto known){tracker->init(shares, known);});

    std::cout << tracker->items.size() << " " << tracker->verified.items.size() << std::endl;
    std::cout << "shares: " << tracker->heads.size() << "/" << tracker->tails.size() << std::endl;
    std::cout << "verified: " << tracker->verified.heads.size() << "/" << tracker->verified.tails.size() << std::endl;

    boost::function<int32_t(uint256)> test_block_rel_height_func = [&](uint256 hash){return 0;};

    std::vector<uint8_t> _bytes = {103, 108, 55, 240, 5, 80, 187, 245, 215, 227, 92, 1, 210, 201, 113, 66, 242, 76, 148, 121, 29, 76, 3, 170, 153, 253, 61, 21, 199, 77, 202, 35};
    auto bytes_prev_block = c2pool::dev::bytes_from_uint8(_bytes);
    uint256 previous_block(bytes_prev_block);


    uint32_t bits = 453027171;
    std::map<uint256, coind::data::tx_type> known_txs;

    auto [_best, _desired, _decorated_heads, _bad_peer_addresses] = tracker->think(test_block_rel_height_func, previous_block, bits, known_txs);
    std::cout << "Best = " << _best.GetHex() << std::endl;

    //-------------------------------------------------------------------------------------------

    struct _current_work {
        int32_t height;
        std::vector<unsigned char> coinbaseflags;
        uint64_t subsidy;
        vector<int32_t> transaction_fees;
        int32_t bits;
    };
    _current_work current_work {0, {}, 0, {}, 0};
    double donation_percentage = 0;
    uint160 pubkey_hash;
    pubkey_hash.SetHex("78ecd67a8695aa4adc55b70f87c2fa3279cee6d0");
    uint256 desired_share_target = uint256S("00000000359dc900000000000000000000000000000000000000000000000000");

    struct stale_counts
    {
        std::tuple<int32_t, int32_t> orph_doa; //(orphans; doas)
        int32_t total;
        std::tuple<int32_t, int32_t> recorded_in_chain; // (orphans_recorded_in_chain, doas_recorded_in_chain)
    };
    stale_counts get_stale_counts{{0,0}, 0, {0,0}};

    auto generate_transaction = std::make_shared<GenerateShareTransaction>(tracker);
    generate_transaction->
            set_block_target(FloatingInteger(current_work.bits).target()).
            set_desired_timestamp(c2pool::dev::timestamp()).
            set_desired_target(desired_share_target).
            set_ref_merkle_link(coind::data::MerkleLink({}, 0)).
            set_desired_other_transaction_hashes_and_fees({}).
            set_known_txs({}).
            set_base_subsidy(net->parent->SUBSIDY_FUNC(current_work.height));

    // ShareData
    {
        std::vector<unsigned char> coinbase;
        {
            CScript _coinbase;
            _coinbase << current_work.height;
            // _coinbase << mm_data // TODO: FOR MERGED MINING
            _coinbase << current_work.coinbaseflags;
            coinbase = ToByteVector(_coinbase);
            if (coinbase.size() > 100)
                coinbase.resize(100);

            int pos = 0;
            while (coinbase[pos] == '\0' && pos < coinbase.size())
                pos++;
            coinbase.erase(coinbase.begin(), coinbase.begin()+pos);
        }
        uint16_t donation = 65535 * donation_percentage / 100; //TODO: test for "math.perfect_round"
        StaleInfo stale_info;
        {
            auto v = get_stale_counts;
            std::cout << "get_stale_counts: (" << std::get<0>(v.orph_doa) << ", " << std::get<1>(v.orph_doa) << "); (" << std::get<0>(v.recorded_in_chain) << ", " << std::get<1>(v.recorded_in_chain) << "); " << v.total << std::endl;
            if (std::get<0>(v.orph_doa) > std::get<0>(v.recorded_in_chain))
                stale_info = orphan;
            else if (std::get<1>(v.orph_doa) > std::get<1>(v.recorded_in_chain))
                stale_info = doa;
            else
                stale_info = unk;
        }

        types::ShareData _share_data(
                _best,
                coinbase,
                c2pool::random::randomNonce(),
                pubkey_hash,
                current_work.subsidy,
                donation,
                stale_info,
                17
        );
        generate_transaction->set_share_data(_share_data);
    }

    auto [share_info, share_data, gentx, other_transaction_hashes, get_share] = *(*generate_transaction)(17);
    LOG_TRACE << "other_transaction_hashes size: " << other_transaction_hashes.size();

    // share_info
    LOG_TRACE << "SHARE_INFO:";

    LOG_TRACE << "\tnew_transaction_hashes: ";
    for (auto v : share_info->new_transaction_hashes)
        LOG_TRACE << v.GetHex();
    ASSERT_EQ(share_info->new_transaction_hashes, std::vector<uint256>());

    LOG_TRACE << "\tfar_share_hash:" << share_info->far_share_hash.GetHex();
    ASSERT_EQ(share_info->far_share_hash, uint256S("ba025a80b4be4999c4c42851b395599df3770d66f892b4074698a82200ab4cfe"));

    LOG_TRACE << "\ttransaction_hash_refs: ";
    for (auto [v1, v2] : share_info->transaction_hash_refs)
        LOG_TRACE << v1 << " " << v2;
    ASSERT_EQ(share_info->transaction_hash_refs, (std::vector<std::tuple<uint64_t, uint64_t>>{}));

    LOG_TRACE << "\ttimestamp: " << share_info->timestamp;

    // SEGWIT_DATA
    LOG_TRACE << "\tSegwitData:";
    if (share_info->segwit_data.has_value())
    {
        LOG_TRACE << "\t\twtxid_merkle_root: " << share_info->segwit_data->wtxid_merkle_root;
        LOG_TRACE << "\t\ttxid_merkle_link: ";
        LOG_TRACE << "\t\t\tindex: " << share_info->segwit_data->txid_merkle_link.index;
        LOG_TRACE << "\t\t\tbranch: ";
        for (auto v: share_info->segwit_data->txid_merkle_link.branch)
        {
            LOG_TRACE << "\t\t\t\t" << v.GetHex();
        }
    }
    LOG_TRACE << " ";

    LOG_TRACE << "\tabsheight:" << share_info->absheight;
    ASSERT_EQ(share_info->absheight, 259326);

    LOG_TRACE << "\tabswork:" << share_info->abswork;
    ASSERT_EQ(share_info->abswork.GetHex(), "00000000000000000000044bc54f548a");

    LOG_TRACE << "\tbits:" << share_info->bits;
    ASSERT_EQ(share_info->bits, 487911265);

    LOG_TRACE << "\tmax_bits:" << share_info->max_bits;
    ASSERT_EQ(share_info->max_bits, 503477261);


    // share_data
    LOG_TRACE << "SHARE_DATA:";

    LOG_TRACE << "\tnonce: " << share_data.nonce;

    LOG_TRACE << "\tprevious_share_hash: " << share_data.previous_share_hash.GetHex();
    ASSERT_EQ(share_data.previous_share_hash.GetHex(), "674f2df26d4897932599be06eebb659a5e0737964c9cb0c091f4fffc76aeb24e");

    LOG_TRACE << "\tstale_info: " << share_data.stale_info;
    ASSERT_EQ(share_data.stale_info, StaleInfo::unk);

    LOG_TRACE << "\tpubkey_hash: " << share_data.pubkey_hash;
    ASSERT_EQ(share_data.pubkey_hash.GetHex(), "78ecd67a8695aa4adc55b70f87c2fa3279cee6d0");

    LOG_TRACE << "\tsubsidy: " << share_data.subsidy;
    ASSERT_EQ(share_data.subsidy, 0);

    LOG_TRACE << "\tdonation: " << share_data.donation;
    ASSERT_EQ(share_data.donation, 0);

    LOG_TRACE << "\tcoinbase: ";
    for (auto v : share_data.coinbase)
        LOG_TRACE << (unsigned int) v;
    ASSERT_EQ(share_data.coinbase, std::vector<unsigned char>{});

    LOG_TRACE << "\tdesired_version: " << share_data.desired_version;
    ASSERT_EQ(share_data.desired_version, 17);

    // gentx:
    LOG_TRACE << "GENTX: " << gentx;

    // get_share:
}

TEST_F(SharechainsTest, get_ref_hash_test)
{
    uint160 pubkey_hash;
    pubkey_hash.SetHex("78ecd67a8695aa4adc55b70f87c2fa3279cee6d0");

    types::ShareData share_data {
        uint256S("674f2df26d4897932599be06eebb659a5e0737964c9cb0c091f4fffc76aeb24e"),
        {'\0'},
        1195140249,
        pubkey_hash,
        0,
        0,
        StaleInfo::unk,
        17
    };


    uint128 abswork;
    abswork.SetHex("44bc54f548a");

    types::ShareInfo share_info {
        uint256S("ba025a80b4be4999c4c42851b395599df3770d66f892b4074698a82200ab4cfe"),
        503477261,
        487911265,
        1670107505,
        {},
        {},
        259326,
        abswork
    };

    coind::data::MerkleLink ref_merkle_link{
            {},
            0
    };


    std::optional<types::SegwitData> segwit_data = std::make_optional<types::SegwitData>(coind::data::MerkleLink{}, uint256::ZERO);
    auto res = shares::get_ref_hash(17, net, share_data, share_info, ref_merkle_link, segwit_data);

    LOG_INFO.stream() << res.data;
    LOG_INFO << unpack<IntType(256)>(res.data).GetHex();

    //
    auto script = std::vector<unsigned char>{0x6a, 0x28};

    auto _get_ref_hash = shares::get_ref_hash(17, net, share_data, share_info, ref_merkle_link, segwit_data);
    LOG_TRACE << "nonce = " << share_data.nonce;
    LOG_TRACE << "_get_ref_hash = " << _get_ref_hash;
    script.insert(script.end(), _get_ref_hash.data.begin(), _get_ref_hash.data.end());

    std::vector<unsigned char> packed_last_txout_nonce = pack<IntType(64)>(2270414773);
    LOG_TRACE.stream() << packed_last_txout_nonce;
    script.insert(script.end(), packed_last_txout_nonce.begin(), packed_last_txout_nonce.end());

    LOG_TRACE.stream() << "script: " << script;

    std::vector<unsigned char> true_script {106, 40, 1, 255, 199, 147, 12, 16, 6, 17, 229, 114, 102, 114, 155, 195, 239, 2, 107, 179, 122, 183, 0, 216, 93, 174, 27, 154, 136, 204, 44, 120, 70, 14, 181, 199, 83, 135, 0, 0, 0, 0};

    ASSERT_EQ(script, true_script);
}

TEST_F(SharechainsTest, get_ref_hash_test2)
{
    PackStream stream_share;
    stream_share.from_hex("21fd4301fe0200002069a23207be25e7a85c90503b49c3afa2a1f81932d4e849db0000000000000000c35b4b637ecb001b18f3c4e670b789e2dc2fd0ead0e49f52699176d7a7a96730837024b5c8a5d4a7f5bc2e2c3d043c49f3002cfabe6d6d265e57d73d2102c2d426c33c427a5ac70d92d50b018a3ffd2f325c5bb585d01601000000000000000a5f5f6332706f6f6c5f5f2f6d9d23bb351fc9fbbd8e1f40942130e77131978df6de411a7125010a00000000000021000000000000000000000000000000000000000000000000000000000000000000000055ac137f1b1995004f2fc98705c3ed7f9cc5f8e8551c96ed0316cb4bf764ceea6709021e6709021ec85b4b637dd401008d6ebd31f80100000000000000000000000000000001000000d53919c88fe180f62b333d9a57f00b4483ed0cac2793fe3a18f2501c3156f924fd7a0100");
    LOG_INFO << "stream_share len: " << stream_share.size();

    auto share = load_share(stream_share, net, {"0.0.0.0", "0"});

    auto ref_hash = shares::get_ref_hash(17, net, *(*share->share_data).get(), *(*share->share_info).get(), *(*share->ref_merkle_link).get(), *(*share->segwit_data).get());
    LOG_INFO << "ref_hash = " << uint256(ref_hash.data);
}

TEST_F(SharechainsTest, share_pack_unpack)
{
    PackStream stream_share;
    stream_share.from_hex("21fd4301fe0200002069a23207be25e7a85c90503b49c3afa2a1f81932d4e849db0000000000000000c35b4b637ecb001b18f3c4e670b789e2dc2fd0ead0e49f52699176d7a7a96730837024b5c8a5d4a7f5bc2e2c3d043c49f3002cfabe6d6d265e57d73d2102c2d426c33c427a5ac70d92d50b018a3ffd2f325c5bb585d01601000000000000000a5f5f6332706f6f6c5f5f2f6d9d23bb351fc9fbbd8e1f40942130e77131978df6de411a7125010a00000000000021000000000000000000000000000000000000000000000000000000000000000000000055ac137f1b1995004f2fc98705c3ed7f9cc5f8e8551c96ed0316cb4bf764ceea6709021e6709021ec85b4b637dd401008d6ebd31f80100000000000000000000000000000001000000d53919c88fe180f62b333d9a57f00b4483ed0cac2793fe3a18f2501c3156f924fd7a0100");
    LOG_INFO << "stream_share len: " << stream_share.size();

    auto share = load_share(stream_share, net, {"0.0.0.0", "0"});

    // Pack Share
    auto packed_share = pack_share(share);

    // Unpack Share
    auto stream_packed_share = pack_to_stream<PackedShareData>(packed_share);
    auto loaded_share = load_share(stream_packed_share, net, {"0.0.0.0", "0"});

    ASSERT_EQ(share->hash, loaded_share->hash);
}

TEST_F(SharechainsTest, share_store_test)
{
    std::shared_ptr<ShareTracker> tracker = std::make_shared<ShareTracker>(net);

    tracker->share_store.legacy_init(c2pool::filesystem::getProjectPath() / "shares.0", [&](auto shares, auto known)
    { tracker->init(shares, known); });

    std::cout << tracker->items.size() << " " << tracker->verified.items.size() << std::endl;

    auto [hash, share] = *tracker->items.begin();

    tracker->share_store.add_share(share);
    LOG_INFO << "ADDED SHARE " << hash;

    LOG_INFO << tracker->share_store.get_share(hash)->hash;
}

TEST(GenShareTxTest, get_ref_hash_test)
{

}