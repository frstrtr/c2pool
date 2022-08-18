#include <gtest/gtest.h>
#include <tuple>
#include <string>
#include <sstream>
#include <iostream>

#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <libcoind/types.h>
#include <libcoind/data.h>
#include <networks/network.h>

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

TEST(SharechainDataTest, TestCustomSha256)
{
    std::string data("123456789");
    auto sha = CSHA256().Write((unsigned char *)&data[0], data.size());

    vector<unsigned char> out;
    out.resize(CSHA256::OUTPUT_SIZE);

    WriteBE32((unsigned char *)&out[0], sha.s[0]);
    WriteBE32(&out[0+4], sha.s[1]);
    WriteBE32(&out[0+8], sha.s[2]);
    WriteBE32(&out[0+12], sha.s[3]);
    WriteBE32(&out[0+16], sha.s[4]);
    WriteBE32(&out[0+20], sha.s[5]);
    WriteBE32(&out[0+24], sha.s[6]);
    WriteBE32(&out[0+28], sha.s[7]);


    auto hash = HexStr(out);
//    std::cout << hash << std::endl;
    ASSERT_EQ(hash, "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19");
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

	auto hash_result = coind::data::hash256(stream, true);
	std::cout << hash_result.ToString() << std::endl;

	ASSERT_EQ(hash_result, uint256S("000000000000003aaaf7638f9f9c0d0c60e8b0eb817dcdb55fd2b1964efc5175"));
}

TEST(CoindDataTest, PowFuncTest)
{
	std::shared_ptr<coind::DigibyteParentNetwork> parent_net = std::make_shared<coind::DigibyteParentNetwork>();

	coind::data::BlockHeaderType header;
	header.make_value(1, uint256S("d928d3066613d1c9dd424d5810cdd21bfeef3c698977e81ec1640e1084950073"), 1327807194, 0x1d01b56f, 20736, uint256S("03f4b646b58a66594a182b02e425e7b3a93c8a52b600aa468f1bc5549f395f16"));
	ASSERT_EQ(header->version, 1);
	ASSERT_EQ(header->previous_block, uint256S("d928d3066613d1c9dd424d5810cdd21bfeef3c698977e81ec1640e1084950073"));
	ASSERT_EQ(header->timestamp, 1327807194);
	ASSERT_EQ(header->bits, 0x1d01b56f);
	ASSERT_EQ(header->nonce, 20736);
	ASSERT_EQ(header->merkle_root, uint256S("03f4b646b58a66594a182b02e425e7b3a93c8a52b600aa468f1bc5549f395f16"));
	auto stream = header.get_pack();
	for (auto v : stream.data){
		std::cout << (unsigned int) v << " ";
	}
	std::cout << std::endl;

//	parent_net->POW_FUNC(stream);

	coind::data::BlockHeaderType header2;
//	coind::data::stream::BlockHeaderType_stream header2;
	stream >> header2;

	ASSERT_EQ(header->version, header2->version);
	ASSERT_EQ(header->previous_block, header2->previous_block);
	ASSERT_EQ(header->timestamp, header2->timestamp);
	ASSERT_EQ(header->bits, header2->bits);
	ASSERT_EQ(header->nonce, header2->nonce);
	ASSERT_EQ(header->merkle_root, header2->merkle_root);

//	ASSERT_EQ(header->version, header2.version.get());
//	ASSERT_EQ(header->previous_block, header2.previous_block.get());
//	ASSERT_EQ(header->timestamp, header2.timestamp.get());
//	ASSERT_EQ(header->bits, header2.bits.get());
//	ASSERT_EQ(header->nonce, header2.nonce.get());
//	ASSERT_EQ(header->merkle_root, header2.merkle_root.get());

//	parent_net->POW_FUNC(stream);
	PackStream stream2;
	stream2 << header2;

	auto result = parent_net->POW_FUNC(stream2);
	std::cout << result.ToString() << std::endl;
	uint256 for_compare = uint256S("400000000000000000000000000000000000000000000000000000000");
	arith_uint256 for_compare_arith = UintToArith256(for_compare);
	arith_uint256 result_arith = UintToArith256(result);
	std::cout << "for_compare: " << for_compare.GetHex() << std::endl;
	std::cout << (result < uint256S("400000000000000000000000000000000000000000000000000000000")) << std::endl;
	std::cout << "arith: " << (result_arith < for_compare_arith) << std::endl;
	std::cout << (result == uint256S("1312dc20ce5aa3ee622f5562dfb2593ec51436aab739ef0d02189e18f")) << std::endl;

	std::cout << header2->bits << " " << header2.stream()->bits.bits.target() << std::endl;
	ASSERT_EQ(header2->bits, 486651247);
	ASSERT_EQ(header2.stream()->bits.bits.target(), uint256S("1b56f0000000000000000000000000000000000000000000000000000"));
}