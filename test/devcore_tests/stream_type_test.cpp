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

TEST(stream_types_test, floating_integer2)
{
	PackStream stream;
	int i = 0x1a107121;
	ASSERT_EQ(437285153, i);

	IntType(32) i_stream(i);
	stream << i_stream;
	FloatingIntegerType data;
	stream >> data;

	ASSERT_EQ(data.get(), 437285153);
	std::cout << data.bits.target() << std::endl;
}

TEST(stream_types_test, floating_integer3)
{
	IntType(32) value1(12345);

	PackStream stream;
	stream << value1;

	FloatingIntegerType value2;
	stream >> value2;

	ASSERT_EQ(value2.get(), value1.get());

	PackStream stream2;
	stream2 << value2;

	IntType(32) value3;
	stream2 >> value3;

	ASSERT_EQ(value3.get(), value1.get());
	ASSERT_EQ(value3.get(), value2.get());

	FloatingIntegerType value4;
	value4 = 12345;

	ASSERT_EQ(value4.get(), value1.get());
}

TEST(stream_types_test, floating_integer_target)
{
	FloatingIntegerType v;
	v = 123456789;
	ASSERT_EQ(v.get(), 123456789);
	ASSERT_EQ(v.bits.get(), 123456789);

	std::cout << v.bits.target() << std::endl;
}

TEST(stream_types_test, inttype)
{
	IntType(32) setter_int32(17);

	IntType(32) _int32;
	PackStream stream;
	int32_t i = 17;
//	stream << i;
	stream << setter_int32;
//	stream << PackStream("\0\0\0", 3);
	stream >> _int32;

	std::cout << _int32.get();
	ASSERT_EQ(i, _int32.get());
}
