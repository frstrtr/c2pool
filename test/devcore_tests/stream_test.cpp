#include <gtest/gtest.h>
#include <btclibs/uint256.h>
#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>

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