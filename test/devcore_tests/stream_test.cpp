#include <gtest/gtest.h>
#include <btclibs/uint256.h>
#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>

TEST(DEVCORE_TEST, pack_uint256)
{
	uint256 num;
	num.SetHex("21c9716491c93e9a531f6ea06051bf16311dce9ac8c6d4fb606eedcc0e52106a");

	int ii = 0;
	for (auto v = num.begin(); v != num.end(); v++){
		ii++;
	}
	std::cout << ii << std::endl;

	INT256 packed_num(num);
	PackStream stream;
	std::cout << stream.data.size() << std::endl;
	stream << packed_num;
	std::cout << stream.data.size() << std::endl;

	int i = 0;
	for (auto v = num.begin(); v != num.end(); v++)
	{
		ASSERT_EQ(*v, stream.data[i]);
		i++;
	}
	std::cout << stream.data.size() << std::endl;
//	stream.data.erase(stream.data.begin()+stream.data.size()/2, stream.data.end());
	std::cout << stream.data.size() << std::endl;
	INT256 unpacked_num;
	stream >> unpacked_num;

	auto v2 = unpacked_num.get().begin();
	for (auto v = num.begin(); v != num.end(); v++)
	{
		ASSERT_EQ(*v, *v2);
		v2++;
	}

	std::cout << num.GetHex() << std::endl;
	std::cout << unpacked_num.get().GetHex() << std::endl;
	ASSERT_EQ(num.GetHex(), unpacked_num.get().GetHex());
}