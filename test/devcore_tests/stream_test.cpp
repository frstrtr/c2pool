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
    ::stream::IPV6AddressType pack_ip(ip1);

    PackStream stream;
    stream << pack_ip;

    ::stream::IPV6AddressType unpack_ip;
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

TEST(Devcore_stream, type_str)
{
	StrType str1("asd123");
	ASSERT_EQ(str1.get(), "asd123");

	PackStream stream;
	stream << str1;

	StrType str2;
	stream >> str2;
	ASSERT_EQ(str2.get(), "asd123");
}

struct TestType
{
    int64_t i1;
    int32_t i2;

    TestType() = default;

    TestType(int64_t _i1, int32_t _i2)
    {
        i1 = _i1;
        i2 = _i2;
    }
};

struct TestType_stream
{
    IntType(64) i1;
    IntType(32) i2;

    TestType_stream() = default;

    TestType_stream(IntType(64) _i1, IntType(32) _i2)
    {
        i1 = _i1;
        i2 = _i2;
    }

    TestType_stream(int64_t _i1, int32_t _i2)
    {
        i1 = _i1;
        i2 = _i2;
    }

};

struct TestTypeAdapter : public
        StreamTypeAdapter<TestType, TestType_stream>
{
    void _to_stream() override
    {

    }

    void _to_value() override
    {
        make_value(_stream->i1.get(), _stream->i2.get());
    }
};

TEST(Devcore_stream, adapter)
{
    TestTypeAdapter adapter1;
    adapter1.make_value(123,232);

    ASSERT_EQ(adapter1->i1, 123);
    ASSERT_EQ(adapter1->i2, 232);

    TestTypeAdapter adapter2;
    adapter2.make_stream(123,232);
    ASSERT_EQ(adapter2->i1, 123);
    ASSERT_EQ(adapter2->i2, 232);
}

TEST(Devcore_stream, getter_test_class)
{
	class TestInt : public Getter<int>
	{

	};

	TestInt t_int;
	t_int.value = 100;
	ASSERT_EQ(t_int.get(), 100);

	class TestSubInt : public Getter<TestInt>{

	};

	TestSubInt t_sub_int;
	t_sub_int.value = t_int;
	t_sub_int.value.value = 1337;
	ASSERT_EQ(t_sub_int.get(), 1337);
}

template <typename T>
class TestTemplateObj : public Getter<T>
{
public:
	TestTemplateObj() = default;

	TestTemplateObj(T _value)
	{
		Getter<T>::value = _value;
	}
};

TEST(Devcore_stream, getter_template_test_class)
{
	TestTemplateObj<int> t_int;
	t_int.value = 1234;
	ASSERT_EQ(t_int.get(), 1234);

	TestTemplateObj<TestTemplateObj<int>> t_sub_int;
	t_sub_int.value.value = 4321;
	ASSERT_EQ(t_sub_int.get(), 4321);
}

template <typename T>
class TestListType : public GetterList<T>
{

};

TEST(Devcore_stream, getter_vector_test_class)
{
	TestListType<int> l1;
	l1.value.push_back(1);
	l1.value.push_back(2);
	l1.value.push_back(3);
	ASSERT_EQ(l1.get(), (vector<int>{1, 2, 3}));

	TestListType<TestTemplateObj<int>> l2;
	l2.value.push_back(TestTemplateObj<int>(10));
	l2.value.push_back(TestTemplateObj<int>(25));
	l2.value.push_back(TestTemplateObj<int>(17));
	ASSERT_EQ(l2.get(), (vector<int>{10, 25, 17}));
}

TEST(Devcore_stream, getter_basic_types)
{
	IntType(32) _int32_type;
	_int32_type = 123;

	ASSERT_EQ(_int32_type.get(), 123);
}

TEST(Devcore_stream, getter_list_type)
{
	ListType<IntType(32)> l;
	std::vector<uint32_t> test_data{1,2,3,4};
	l = l.make_type(test_data);
	ASSERT_EQ(l.value.size(), 4);

	ASSERT_EQ(l.get(), (std::vector<uint32_t>{1,2,3,4}));
}

TEST(Devcore_stream, getter_possible_nonetype)
{
	PossibleNoneType<IntType(32)> v(-1);
	ASSERT_EQ(v.get(), -1);

	v = 123;
	ASSERT_EQ(v.get(), 123);
}

TEST(Devcore_stream, pack_stream_bytes)
{
    IntType(32) i(1000005252);
    PackStream s;

    s << i;

    auto bytes = s.bytes();
    std::cout << bytes;
}