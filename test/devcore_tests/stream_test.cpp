#include <gtest/gtest.h>
#include <btclibs/uint256.h>
#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>
#include <libdevcore/types.h>
#include <iostream>

//const char* hex_num = "21c9716491c93e9a531f6ea06051bf16311dce9ac8c6d4fb606eedcc0e52106a";
const char* hex_num = "00032a417a23fcd43a983a44b35da54becf63e847231b8ec8518e25c1fcd31a0";

TEST(Devcore_stream, type_uint256)
{
	uint256 num;
	num.SetHex(hex_num);

	IntType(256) packed_num(num);
	PackStream stream;
	stream << packed_num;

	int i = 0;
	for (auto v = num.begin(); v != num.end(); v++)
	{
		ASSERT_EQ(*v, stream.data[i]);
		i++;
	}
	IntType(256) unpacked_num;
	stream >> unpacked_num;

	auto v2 = unpacked_num.get().begin();
	for (auto v = num.begin(); v != num.end(); v++)
	{
		ASSERT_EQ(*v, *v2);
		v2++;
	}

	ASSERT_EQ(unpacked_num.get().GetHex(), hex_num);
	ASSERT_EQ(num.GetHex(), unpacked_num.get().GetHex());
}

TEST(Devcore_stream, list_type_uint256)
{
	// Init hex for nums
	std::vector<std::string> hexs = {{"21c9716491c93e9a531f6ea06051bf16311dce9ac8c6d4fb606eedcc0e52106a"},
									 {"21c9716491c93e9a531f6ea06051bf8301edce9ac8c6d4fb606eedcc0e52106a"},
									 {"d84154f18eb9e1941613af312539c298181ecdcf6c6767b7ae4b3f8bfc8fa8c8"},
									 {"56831d65ca78d27803c2f0dd19f3b47051ce854ab398d7afba25db61ca32ecfc"},
									 {"4fa98884f7d4e3a2545b4910792fe9970d9c0d9fe05b1ebef75592f6cffd378f"}};

	// Init nums
	std::vector<uint256> nums;
	for (auto v : hexs)
	{
		uint256 num;
		num.SetHex(v);
		nums.push_back(num);
	}

	// Init List PackType
	PackStream stream;
	ListType<IntType(256)> packed_nums(ListType<IntType(256)>::make_type(nums));

	// Pack packed_nums in stream
	stream << packed_nums;

	// Unpack stream to unpacked_nums
	ListType<IntType(256)> unpacked_nums;
	stream >> unpacked_nums;
}

TEST(Devcore_stream, type_IPV6AddressType){
    std::string ip1 = "192.168.50.31";
    c2pool::messages::stream::IPV6AddressType pack_ip(ip1);

    PackStream stream;
    stream << pack_ip;

    c2pool::messages::stream::IPV6AddressType unpack_ip;
    stream >> unpack_ip;

    ASSERT_EQ(ip1, unpack_ip.value);
}

TEST(Devcore_stream, type_const_char)
{
    vector<unsigned char> chrs1 = {0x84, 0x76, 0xA9, 0xA9, 0xA9};
    vector<unsigned char> chrs2 = {0x76, 0xa9, 0x14, 0xF1};

    vector<unsigned char> check_res(chrs1);
    check_res.insert(check_res.end(), chrs2.begin(), chrs2.end());

    PackStream stream;

    stream << chrs1;
    stream << vector<unsigned char>({0x76, 0xa9, 0x14, 0xF1});

    std::cout << "check_res.size(): " << check_res.size() << std::endl;
    for (int i = 0; i < check_res.size(); i++)
    {
        ASSERT_EQ(check_res[i], stream.data[i]);
    }

}