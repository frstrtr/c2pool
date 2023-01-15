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

TEST(stream_types_test, from_target_upper_bound_test)
{
    // 000002740d65d4ca83388eeaf63b94010c1a58203e12d3fcc23cec9ec612729d
    auto target = uint256S("2740d65d4ca83388eeaf63b94010c1a58203e12d3fcc23cec9ec612729d");

    //--Manual
    auto n = math::natural_to_string(target);
    std::vector<unsigned char> true_n {2, 116, 13, 101, 212, 202, 131, 56, 142, 234, 246, 59, 148, 1, 12, 26, 88, 32, 62, 18, 211, 252, 194, 60, 236, 158, 198, 18, 114, 157};
    ASSERT_EQ(n, true_n);

    std::cout << "n: ";
    for (auto v : n)
    {
        std::cout << v << " ";
    }
    std::cout << std::endl;

    std::cout << "n(ord): ";
    for (auto v : n)
    {
        std::cout << (unsigned int)v << " ";
    }
    std::cout << std::endl;

    if (!n.empty() && *n.begin() >= 128)
    {
        std::cout << "pushed zero to n.begin" << std::endl;
        n.insert(n.begin(), '\0');
//        n.push_front('\0');
    }

    std::vector<unsigned char> bits2;
//    std::cout << "(unsigned char)n.size() = " << (unsigned char)n.size() << std::endl;
    bits2.push_back((unsigned char)n.size());
    ASSERT_EQ(bits2, std::vector<unsigned char>{(unsigned char)30});

    bits2.insert(bits2.end(), n.begin(), n.end());
    bits2.insert(bits2.end(), {0,0,0});
    bits2.resize(4);
    std::reverse(bits2.begin(), bits2.end());
    std::cout << "bits2(ord): ";
    for (auto v : bits2)
    {
        std::cout << (unsigned int)v << " ";
    }
    std::cout << std::endl;
    std::vector<unsigned char> true_bits2{13, 116, 2, 30};
    ASSERT_EQ(bits2, true_bits2);

    IntType(32) unpacked_bits;
    PackStream stream_bits(bits2);
    stream_bits >> unpacked_bits;
    std::cout << "bits: " << unpacked_bits.get() << std::endl;
    ASSERT_EQ(unpacked_bits.get(), 503477261);

    FloatingInteger from_target1(unpacked_bits);
    cout << "from target2: target = " << from_target1.target() << ", value = " << from_target1.get() << std::endl;
    ASSERT_EQ(from_target1.get(), 503477261);
    ASSERT_EQ(from_target1.target(), uint256S("2740d000000000000000000000000000000000000000000000000000000"));


    //--FROM FloatingInteget::from_target_upper_bound
    auto from_target2 = FloatingInteger::from_target_upper_bound(target);
    cout << "from target2: target = " << from_target2.target() << ", value = " << from_target2.get() << std::endl;

    ASSERT_EQ(from_target1.get(), from_target2.get());
    ASSERT_EQ(from_target1.target(), from_target2.target());
}
