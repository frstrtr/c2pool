#include <gtest/gtest.h>

#include <memory>

#include <libdevcore/common.h>
#include <sharechains/tracker.h>
#include <networks/network.h>

class TestNetwork : public c2pool::Network
{
public:
    TestNetwork(std::shared_ptr<coind::ParentNetwork> _par) : c2pool::Network("test_sharechain", _par)
    {
        SOFTFORKS_REQUIRED = {"nversionbips", "csv", "segwit", "reservealgo", "odo"};
        BOOTSTRAP_ADDRS = {
                CREATE_ADDR("0.0.0.0", "5024")
        };
        PREFIX_LENGTH = 8;
        PREFIX = new unsigned char[PREFIX_LENGTH]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x68};
        IDENTIFIER_LENGHT = 8;
        IDENTIFIER = new unsigned char[IDENTIFIER_LENGHT]{0x83, 0xE6, 0x5D, 0x2C, 0x81, 0xBF, 0x6D, 0x66};
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
        std::shared_ptr<coind::DigibyteParentNetwork> parent_net = std::make_shared<coind::DigibyteParentNetwork>();
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

TEST_F(SharechainsTest, tracker_empty)
{
    std::shared_ptr<ShareTracker> tracker = std::make_shared<ShareTracker>(net);

    uint256 hash = uint256S("1");


    // Remove
    std::cout << "Remove" << std::endl;
    tracker->remove(hash);

    // Pool attempts for dist = 1
    std::cout << "Pool attempts for dist = 1" << std::endl;
    ASSERT_DEATH({
                     auto attempts1 = tracker->get_pool_attempts_per_second(hash, 1);
                 }, "get_pool_attempts_per_second: assert for dist >= 2");

    // Pool attempts for dist = 10
    std::cout << "Pool attempts for dist = 10" << std::endl;
    ASSERT_THROW({auto attempts10 = tracker->get_pool_attempts_per_second(hash, 10);}, std::invalid_argument);

    // Desired version dist = 1
    std::cout << "Desired version dist = 1" << std::endl;
    auto desired_version1 = tracker->get_desired_version_counts(hash, 1);
    for (auto v : desired_version1)
    {
        std::cout << v.first << ": " << v.second.ToString() << std::endl;
    }

    // Desired version dist = 10
    std::cout << "Desired version dist = 10" << std::endl;
    auto desired_version10 = tracker->get_desired_version_counts(hash, 10);
    for (auto v : desired_version10)
    {
        std::cout << v.first << ": " << v.second.ToString() << std::endl;
    }

    // Get
    std::cout << "Get" << std::endl;
    auto share = tracker->get(hash);
    ASSERT_EQ(share, nullptr);
}

TEST_F(SharechainsTest, just_share_load)
{
    PackStream stream_share;
//    stream_share.from_hex("21fd0702fe02000020617dfa46bf73eb96548e0b039a647d35b387ed0cb1a6e51c80092175857d3f5b3ac4ff62f1a9001bc0254dda4d00fe065ba137d8e108ef134db29b7e33f46327f13626975c0c2a190082018f3d04d03aee002cfabe6d6d21102609e852babee96639fbb3b65588bbcc419720fec56da52e47120c4804a501000000000000000a5f5f6332706f6f6c5f5ffc88aa669a2cd3c1310067ae7e47a7869b330d30b691c61b46fb483b0a0000000000002102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203517d2164368b766e6b9d0598510a7bbfc9882940ebfe3f65bb72173c3dbf105802f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5ef1025a29236b072d75cde8637584a3ed2fe0bcd4aadb5824b61cc42b4414e143d020000000195cbb26f405ead27fcd8cf84155cfcfab722a0cfdb3a2c735fce15fb19bc8ae4ffff0f1e8888001e3bc4ff62cc210000df798a25160000000000000000000000000000000001000000986dae33074d8c439a5dc61c2019a86726ebd1cf0eb0240582ccc0b249d12ba7fd9c0102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203");
//    stream_share.from_hex("21fd4301fe020000206201af0a6930f520a4e89c2a024731e401b2d9cf976e4d0a82dcf9c206c1370b4ce02763d1f5001b03e0d41cfb866ba9fec6e8c456dd721b850a1b012b923dbbe9aa615a6de390230eebb5f53d04a9e9f0002cfabe6d6d4644c9e477f93b03c5c33cd6d61f16165c57f360325d75630d58dddac2ab635301000000000000000a5f5f6332706f6f6c5f5fd0ba3068bb351fc9fbbd8e1f40942130e77131978df6de41541d0d1e0a0000000000002100000000000000000000000000000000000000000000000000000000000000000000007c943b346fed7bc58a33254406d6a67c55c8b3759f8b87e11de3513cd5e67c12ee83021ee476151d4de02763d4aa0000502cdf03b40000000000000000000000000000000001000000e1a45914351179267e8d373f31778ba4792ef4227f68752459acff124bb965b7fd7a0100");
//    stream_share.from_hex("21fdad02fe0200002039cc52f3e1412ce3e0dcfd3c53ce0f8b62edecdd82b4ac3b45b483dcfa4b71d1351a28638fd2001b335ab26f3626eafdcee83bb1ac57b757a7f73ce919d0690964b361f97171cc32cb2cab983d0474edf0002cfabe6d6ddd5bd8f3360ee89b84a17f0fd30446a5620888d9342d5d49d1255527ed6cbef501000000000000000a5f5f6332706f6f6c5f5f347623c9bb351fc9fbbd8e1f40942130e77131978df6de413288101e0a0000000000fe21031d30c187f67e4d41a4e069f648413865c5d093de552a86d09bd81480c1c4da5169b87cc45a6debf0832392165de663983a5e6dadc6c3c0d789fb68547d1e2b2f0210bea6d2a99698b42cd62a71c2769bcf28a9e176ec3ee7f3e6b1b77785a79357efbc35825402100550ec1ba19cda3f01b25ffc5587acc90f4bcdd2998e1a4405b80c7f452d6d846290ca65b75caf21aa7cfe08672bc20f83d9b55a3ee87fed6c2b58b75c1eb34aee44912beaf81298a6981cd27336c407f530f71a1ec8a40790e19149645601a62beaf9442b76557b8fa48767bb8daf22d3d26a8c922b8bbdadd3a92eba693decb11345556a4915a91f5a0c072960d3b97da275b09a7815a639f2346d24027e63ea93693073b70ac29714f3b6ed8edf6d46db711fb99f249e030500000001000200030004d812db8ae1f908a68bf7072153ca319f247a86d6fd8a9f2218d312544f71b97dc29c071e68f5401d3b1a28639bac000015650778b5000000000000000000000000000000000100000009557e7d9e53aeb227850a55d32310a57c64744f18a2d2c362e83ecc9505102efd7a0103b80c7f452d6d846290ca65b75caf21aa7cfe08672bc20f83d9b55a3ee87fed6c69b87cc45a6debf0832392165de663983a5e6dadc6c3c0d789fb68547d1e2b2f0210bea6d2a99698b42cd62a71c2769bcf28a9e176ec3ee7f3e6b1b77785a793");
    stream_share.from_hex("21fd0702fe02000020462750c8ee349d5cdf644f2f387eae5e83f09c516d80f6b7bff6bb5077f492cf501c286382d0001b336009dfc05bb320693870ee52f31b1a7acdf59fd62a06304c2226ec71372e2dd81038443d04abedf0002cfabe6d6dbb98999c619b01360f5f78fb757361280a0fc6d86e64af39883cd4c32c1bb41f01000000000000000a5f5f6332706f6f6c5f5feafa8b19bb351fc9fbbd8e1f40942130e77131978df6de41c5bc0d1e0a0000000000002102ba60a71143d79b34ce2763688d2dc47431699e946cfba3bc09f0538db16c247603f5fd54628f9524c7816a13bfdcbb294bfbf910c856dd6d2867e3fea75e6ff0fa575b274b856f98e04e2e4e137d1aec6ff73ac3abe10198b9e2a4cacebb32a602ba60a71143d79b34ce2763688d2dc47431699e946cfba3bc09f0538db16c24761f66f6ca39e76964e7c66d2d6ce0c0f53a41c240c21ac01f9f1ca7a88d3a40530200000001e541da22b7db053fbc6cdcd45cf4ebd37b17704c4845fcc9ab41f01ff85e935e78ee081e3b374c1d521c2863a7ac00000ef2e2a1b50000000000000000000000000000000001000000849846b13fc97f2930fda8c079866515eb86fed117a26ec0d91a47406e1caadefd7a0102ba60a71143d79b34ce2763688d2dc47431699e946cfba3bc09f0538db16c247603f5fd54628f9524c7816a13bfdcbb294bfbf910c856dd6d2867e3fea75e6ff0");
    auto share = load_share(stream_share, net, {"0.0.0.0", "0"});
}

TEST_F(SharechainsTest, handle_share_test)
{
    VariableDict<uint256, coind::data::tx_type> known_txs = VariableDict<uint256, coind::data::tx_type>(true);


    PackStream stream_share;
    stream_share.from_hex(
            "21fd0702fe02000020462750c8ee349d5cdf644f2f387eae5e83f09c516d80f6b7bff6bb5077f492cf501c286382d0001b336009dfc05bb320693870ee52f31b1a7acdf59fd62a06304c2226ec71372e2dd81038443d04abedf0002cfabe6d6dbb98999c619b01360f5f78fb757361280a0fc6d86e64af39883cd4c32c1bb41f01000000000000000a5f5f6332706f6f6c5f5feafa8b19bb351fc9fbbd8e1f40942130e77131978df6de41c5bc0d1e0a0000000000002102ba60a71143d79b34ce2763688d2dc47431699e946cfba3bc09f0538db16c247603f5fd54628f9524c7816a13bfdcbb294bfbf910c856dd6d2867e3fea75e6ff0fa575b274b856f98e04e2e4e137d1aec6ff73ac3abe10198b9e2a4cacebb32a602ba60a71143d79b34ce2763688d2dc47431699e946cfba3bc09f0538db16c24761f66f6ca39e76964e7c66d2d6ce0c0f53a41c240c21ac01f9f1ca7a88d3a40530200000001e541da22b7db053fbc6cdcd45cf4ebd37b17704c4845fcc9ab41f01ff85e935e78ee081e3b374c1d521c2863a7ac00000ef2e2a1b50000000000000000000000000000000001000000849846b13fc97f2930fda8c079866515eb86fed117a26ec0d91a47406e1caadefd7a0102ba60a71143d79b34ce2763688d2dc47431699e946cfba3bc09f0538db16c247603f5fd54628f9524c7816a13bfdcbb294bfbf910c856dd6d2867e3fea75e6ff0");
    auto share = load_share(stream_share, net, {"0.0.0.0", "0"});

    //t0
    vector<tuple<ShareType, std::vector<coind::data::tx_type>>> result; //share, txs


    std::vector<coind::data::tx_type> txs;
    if (true)
    {
        for (auto tx_hash: *share->new_transaction_hashes)
        {
            coind::data::tx_type tx;
            if (known_txs.value().find(tx_hash) != known_txs.value().end())
            {
                tx = known_txs.value()[tx_hash];
            }
//            else
//            {
//                for (auto cache: protocol->known_txs_cache)
//                {
//                    if (cache.find(tx_hash) != cache.end())
//                    {
//                        tx = cache[tx_hash];
//                        LOG_INFO
//                            << boost::format("Transaction %0% rescued from peer latency cache!") % tx_hash.GetHex();
//                        break;
//                    }
//                }
//            }
            txs.push_back(tx);
        }
    }
    result.emplace_back(share, txs);

//    handle_shares(result, protocol);
// HANDLE SHARES:

//    int32_t new_count = 0;
    std::map<uint256, coind::data::tx_type> all_new_txs;
    auto [_share, new_txs] = result[0];
    {
        if (!new_txs.empty())
        {
            for (const auto& new_tx : new_txs)
            {
                coind::data::stream::TransactionType_stream _tx(new_tx);
                PackStream packed_tx;
                packed_tx << _tx;

                all_new_txs[coind::data::hash256(packed_tx)] = new_tx;
            }
        }
//
//        if (tracker->exists(share->hash))
//        {
////			#print 'Got duplicate share, ignoring. Hash: %s' % (p2pool_data.format_hash(share.hash),)
////			continue
//        }
//
//        new_count++;
//        tracker->add(share);
    }

    known_txs.add(all_new_txs);

//    if (new_count)
//    {
//        coind_node->set_best_share();
//    }
//
//    if (shares.size() > 5)
//    {
//        LOG_INFO << "... done processing " << shares.size() << "shares. New: " << new_count << " Have: " << tracker->items.size() << "/~" << 2*net->CHAIN_LENGTH;
//    }

}



TEST_F(SharechainsTest, tracker_one_share)
{
    std::shared_ptr<ShareTracker> tracker = std::make_shared<ShareTracker>(net);

    PackStream stream_share;
//    stream_share.from_hex("11fda501fe02000020707524a64aa0820305612357ae0d2744695c8ba18b8e1402dc4e199b5e1bf8daae2ceb62979e001bc0006d6200000000000000000000000000000000000000000000000000000000000000003d043edaec002cfabe6d6d08d3533a81ca356a7ac1c85c9b0073aebcca7182ad83849b9498377c9a1cd8a701000000000000000a5f5f6332706f6f6c5f5f3e9922fe9ad7bdd0e20eb7f64fa6dd42734dd4f43275cc26fd4d483b0a00000000000021012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d61f2bae86d664294b8850df3f580ec9e4fb2170fe8dbae492b5159af73834eba4012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d60100000000000000000000000000000000000000000000000000000000000000000000ffff0f1effff0f1eae2ceb6201000000010010000000000000000000000000000000000000000000001fcbf0a89045913d394db52949e986b8c6385b0060cbaebf3cf7806ff1df96affd7a01012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d6");
    stream_share.from_hex("21fd0702fe02000020617dfa46bf73eb96548e0b039a647d35b387ed0cb1a6e51c80092175857d3f5b3ac4ff62f1a9001bc0254dda4d00fe065ba137d8e108ef134db29b7e33f46327f13626975c0c2a190082018f3d04d03aee002cfabe6d6d21102609e852babee96639fbb3b65588bbcc419720fec56da52e47120c4804a501000000000000000a5f5f6332706f6f6c5f5ffc88aa669a2cd3c1310067ae7e47a7869b330d30b691c61b46fb483b0a0000000000002102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203517d2164368b766e6b9d0598510a7bbfc9882940ebfe3f65bb72173c3dbf105802f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5ef1025a29236b072d75cde8637584a3ed2fe0bcd4aadb5824b61cc42b4414e143d020000000195cbb26f405ead27fcd8cf84155cfcfab722a0cfdb3a2c735fce15fb19bc8ae4ffff0f1e8888001e3bc4ff62cc210000df798a25160000000000000000000000000000000001000000986dae33074d8c439a5dc61c2019a86726ebd1cf0eb0240582ccc0b249d12ba7fd9c0102f24e44938c7bde43245d2a17c7fe424fbebc63f05317dfdace08a95a2f10d5efe4248d9eb63c2de431a93f0c94e857920cb3f70163dba595de7720e6cc014203");
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

    PackStream stream_share;
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
}