#include <gtest/gtest.h>
#include <sharechains/base_share_tracker.h>

TEST(tree_tracker, init)
{
    BaseShareTracker tracker;
}

//TEST(tree_tracker, one_share)
//{
//    BaseShareTracker tracker;
//
//    PackStream stream_share;
//    stream_share.from_hex("21fd4301fe02000020d015122ac6c9b4ec0b3b0f684dcb88fedc106c22d66b8583d67bcdf7fa2fbe37542188632205011b492009eaa2bfe882e1f6f99596e720c18657a1dde02bdc10dcb3a8725c765625db9c3ea73d04ec59f7002cfabe6d6d9af7e5ceeeb550fe519d93acf6180dfac960ba8de50867804e3e1266e46b954a01000000000000000a5f5f6332706f6f6c5f5f04d213ddbb351fc9fbbd8e1f40942130e77131978df6de416cea4cc8090000000000002100000000000000000000000000000000000000000000000000000000000000000000009678d14ad4c5e2859d7d036b8f69b8211884a6b63711d6c3ee3c633d61610bf45d31041efb45011e552188630cd30300d98b6cb72504000000000000000000000000000000010000007e0fa5ede3dae6732ef68a7447180e26ef694d17a37d2e4c406244004c839722fd7a0100");
//    auto share = load_share(stream_share, net, {"0.0.0.0", "0"});
//
//    auto hash = share->hash;
//
//    tracker->add(share);
//
//    std::cout << "Desired version dist = 1" << std::endl;
//    auto desired_version1 = tracker->get_desired_version_counts(hash, 1);
//    for (auto v : desired_version1)
//    {
//        std::cout << v.first << ": " << v.second.ToString() << std::endl;
//    }
//
//    // Get
//    std::cout << "Get" << std::endl;
//    auto share2 = tracker->get(hash);
//    ASSERT_EQ(share2, share);
//}