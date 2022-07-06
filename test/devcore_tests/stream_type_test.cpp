#include <gtest/gtest.h>
#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>

TEST(stream_types_test, int_type)
{
    IntType(64) num(1231);

    PackStream stream;
    stream << num;

    IntType(32) num_res;
    int32_t res = num_res.get();

    ASSERT_EQ(12312312, res);
}

TEST(stream_types_test, floating_integer)
{
	PackStream stream;
	int i = 0x1a107121;
	ASSERT_EQ(437285153, i);

	stream << i;
	FloatingIntegerType data;
	stream >> data;

	ASSERT_EQ(data.get(), 437285153);
	std::cout << data.bits.target() << std::endl;
}

TEST(stream_types_test, inttype)
{
	IntType(32) _int32;
	PackStream stream;
	int32_t i = 12;
	stream << i;
	stream >> _int32;

	ASSERT_EQ(i, _int32.get());
}
