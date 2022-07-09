#include <gtest/gtest.h>
#include <tuple>
#include <string>
#include <sstream>
#include <iostream>

#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <libcoind/types.h>
#include <libcoind/data.h>

using namespace std;

uint256 CreateUINT256(string _hex){
    uint256 result;
    result.SetHex(_hex);
    return result;
}

TEST(BitcoindDataTest, target_to_averate_attempts_test){
    auto first = CreateUINT256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    uint256 first_res = coind::data::target_to_average_attempts(first);
    cout << first_res.GetHex() << endl;
    ASSERT_EQ(first_res.GetHex(), "0000000000000000000000000000000000000000000000000000000000000001");
    
    auto second = CreateUINT256("1");
    uint256 second_res = coind::data::target_to_average_attempts(second);
    cout << second_res.GetHex() << endl;
    //Note: in Python: '0x8000000000000000000000000000000000000000000000000000000000000000'
    ASSERT_EQ(second_res.GetHex(), "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    auto third = CreateUINT256("100000000000000000000000000000000");
    uint256 third_res = coind::data::target_to_average_attempts(third);
    cout << third_res.GetHex() << endl;
    ASSERT_EQ(third_res.GetHex(), "00000000000000000000000000000000ffffffffffffffffffffffffffffffff");

    auto fourth = CreateUINT256("ffffffffffffffffffffffffffffffff");
    uint256 fourth_res = coind::data::target_to_average_attempts(fourth);
    cout << fourth_res.GetHex() << endl;
    ASSERT_EQ(fourth_res.GetHex(), "00000000000000000000000000000000ffffffffffffffffffffffffffffffff");
}

TEST(BitcoindDataTest, average_attempts_to_target_test){
    auto first = CreateUINT256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    uint256 first_res = coind::data::average_attempts_to_target(first);
    cout << first_res.GetHex() << endl;
    ASSERT_EQ(first_res.GetHex(), "0000000000000000000000000000000000000000000000000000000000000000");
    
    auto second = CreateUINT256("100000000000000000000000000000000");
    uint256 second_res = coind::data::target_to_average_attempts(second);
    cout << second_res.GetHex() << endl;
    //Note: in Python: '0x8000000000000000000000000000000000000000000000000000000000000000'
    ASSERT_EQ(second_res.GetHex(), "0000000000000000000000000000000100000000000000000000000000000000");

    auto third = CreateUINT256("100000000000000000000000000000000");
    uint256 third_res = coind::data::target_to_average_attempts(third);
    cout << third_res.GetHex() << endl;
    ASSERT_EQ(third_res.GetHex(), "00000000000000000000000000000000ffffffffffffffffffffffffffffffff");

    auto fourth = CreateUINT256("ffffffffffffffffffffffffffffffff");
    uint256 fourth_res = coind::data::target_to_average_attempts(fourth);
    cout << fourth_res.GetHex() << endl;
    ASSERT_EQ(fourth_res.GetHex(), "00000000000000000000000000000000ffffffffffffffffffffffffffffffff");
}

TEST(CoindDataTest, hash256_from_hash_link_test)
{
    uint32_t _init[8] {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05644c, 0x1f83d9ab, 0x5be0cd12};
    auto result = coind::data::hash256_from_hash_link(_init, (unsigned char*)"12345678901234ac", (unsigned char*) "12345678901234ac", 128/8);
    std::cout << result.GetHex() << std::endl;
    ASSERT_EQ(result.GetHex(), "209c335d5b5d3f5735d44b33ec1706091969060fddbdb26a080eb3569717fb9e");
}

TEST(CoindDataTest, test_header_hash)
{
	coind::data::BlockHeaderType header;
	header.make_value(1, uint256S("000000000000038a2a86b72387f93c51298298a732079b3b686df3603d2f6282"), 1323752685, 437159528, 3658685446, uint256S("37a43a3b812e4eb665975f46393b4360008824aab180f27d642de8c28073bc44"));
	ASSERT_EQ(header->version, 1);
	ASSERT_EQ(header->previous_block, uint256S("000000000000038a2a86b72387f93c51298298a732079b3b686df3603d2f6282"));
	ASSERT_EQ(header->timestamp, 1323752685);
	ASSERT_EQ(header->bits, 437159528);
	ASSERT_EQ(header->nonce, 3658685446);
	ASSERT_EQ(header->merkle_root, uint256S("37a43a3b812e4eb665975f46393b4360008824aab180f27d642de8c28073bc44"));
	auto stream = header.get_pack();

	for (auto v : stream.data)
	{
		std::cout << (unsigned int) v << " ";
	}
	std::cout << std::endl;

	auto hash_result = coind::data::hash256(stream);
	std::cout << hash_result.ToString() << std::endl;

	ASSERT_EQ(hash_result, uint256S("000000000000003aaaf7638f9f9c0d0c60e8b0eb817dcdb55fd2b1964efc5175"));
}