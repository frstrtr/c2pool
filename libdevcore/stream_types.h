#pragma once

#include <cstring>
#include <string>
#include <vector>
#include <list>
#include <optional>

#include <btclibs/util/strencodings.h>
#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>

#include "stream.h"
#include "math.h"
#include "logger.h"
using namespace std;

struct VarIntType : public Maker<VarIntType, uint64_t>, public Getter<uint64_t>
{
    typedef uint64_t value_type;

    VarIntType() {}

    VarIntType(uint64_t _v)
    {
        value = _v;
    }

    PackStream &write(PackStream &stream)
    {
        stream << value;

        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        stream >> value;

        return stream;
    }
};

template <typename T>
struct ListType : public MakerListType<T>, public GetterList<T>
{
    ListType() {}

    ListType(T arr[], size_t len)
    {
		GetterList<T>::value.insert(GetterList<T>::value.end(), arr, arr + len);
    }

    ListType(vector<T> arr)
    {
		GetterList<T>::value = vector<T>(arr);
    }

    auto &operator=(vector<T> _value)
    {
		GetterList<T>::value = _value;
        return *this;
    }

    PackStream &write(PackStream &stream) const
    {
        auto len = GetterList<T>::value.size();
        stream << len;
        for (auto v : GetterList<T>::value)
        {
            stream << v;
        }

        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        VarIntType _len;
        stream >> _len;

        auto len = _len.get();
        for (int i = 0; i < len; i++)
        {
            T temp;
            stream >> temp;
			GetterList<T>::value.push_back(temp);
        }
        return stream;
    }
};

//In p2pool - VarStrType
struct StrType : public Maker<StrType, string>, public CustomGetter<std::string>
{
    vector<unsigned char> value;

	//TODO: c_str()?

    StrType() = default;

    StrType(string _str)
    {
        value.insert(value.begin(), _str.begin(), _str.end());
    }

    StrType(vector<unsigned char> _c_str)
    {
        value = _c_str;
    }

    StrType &fromHex(const std::string &hexData)
    {
        value.clear();
        auto parsedHexData = ParseHex(hexData);
        value.insert(value.end(), parsedHexData.begin(), parsedHexData.end());

        return *this;
    }

    StrType &fromHex(PackStream &hexData)
    {
        value.clear();
        value.insert(value.end(), hexData.data.begin(), hexData.data.end());

        return *this;
    }

    auto &operator=(std::string _str)
    {
		value.clear();
        value.insert(value.begin(), _str.begin(), _str.end());
        return *this;
    }

    PackStream &write(PackStream &stream) const
    {
        VarIntType _len = value.size();
        stream << _len << PackStream(value);
        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        VarIntType _len;
        stream >> _len;

        auto len = _len.get();

        if (stream.size() < len)
            throw std::invalid_argument("StrType: stream size < len");

        value.insert(value.end(), stream.data.begin(), stream.data.begin()+len);
        stream.data.erase(stream.data.begin(), stream.data.begin()+len);
        return stream;
    }

    std::string get() const override
    {
		return string(value.begin(), value.end());
    }
};

template <int SIZE>
struct FixedStrType : public Maker<FixedStrType<SIZE>, string>, public CustomGetter<std::string>
{
    vector<unsigned char> value;

    FixedStrType() = default;

    FixedStrType(string _str)
    {
        if (_str.length() != SIZE)
        {
            throw std::invalid_argument("Incorrect length str in FixedStrType");
        }
        value.insert(value.begin(), _str.begin(), _str.end());
    }

    FixedStrType(vector<unsigned char> _c_str)
    {
        if (_c_str.size() != SIZE)
        {
            throw std::invalid_argument("Incorrect length str in FixedStrType");
        }
        value = _c_str;
    }

    StrType &fromHex(const std::string &hexData)
    {
        value.clear();
        auto parsedHexData = ParseHex(hexData);

        if (parsedHexData.size() != SIZE)
        {
            throw std::invalid_argument("Incorrect length str in FixedStrType");
        }

        value.insert(value.end(), parsedHexData.begin(), parsedHexData.end());

        return *this;
    }

    PackStream &write(PackStream &stream) const
    {
//        LOG_TRACE << "FixedStrType Worked!";
        ListType<unsigned char> list_s(value);

//        auto _len = value.size();
        stream << PackStream(value);
        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        if (SIZE != 0)
        {
            auto len = SIZE;
            if (stream.size() < len)
                throw std::invalid_argument("FixedStr: stream size < len");

            value.insert(value.begin(), stream.data.begin(), stream.data.begin()+len);
            stream.data.erase(stream.data.begin(), stream.data.begin()+len);

            //            std::remove_copy(stream.data.begin(), stream.data.end(), value.begin(), len);

//            ListType<unsigned char> list_s;
//            stream >> list_s;
//            if (SIZE < list_s.value.size())
//                list_s.value.resize(SIZE);
//            value = std::move(list_s.value);
        }
        return stream;
    }

    std::string get() const override
    {
        return string(value.begin(), value.end());
    }
};

template <typename INT_T, bool BIG_ENDIAN = false>
struct IntType : public Maker<IntType<INT_T, BIG_ENDIAN>, INT_T>, public Getter<INT_T>
{
    typedef INT_T value_type;

    IntType() {}

    IntType(INT_T _value)
    {
        Getter<INT_T>::value = _value;
    }

    IntType<INT_T> &set(const INT_T &_value)
    {
		Getter<INT_T>::value = _value;
        return *this;
    }

    auto &operator=(INT_T _value)
    {
		Getter<INT_T>::value = _value;
        return *this;
    }

    PackStream &write(PackStream &stream)
    {
        INT_T value2 = Getter<INT_T>::value;
        unsigned char *packed = reinterpret_cast<unsigned char *>(&value2);
        int32_t len = sizeof(value2) / sizeof(*packed);

        if (BIG_ENDIAN)
            std::reverse(packed, packed+len);
        PackStream s(packed, len);
        stream << s;

        return stream;
    }

    virtual PackStream &read(PackStream &stream)
    {
        size_t _len = CALC_SIZE(INT_T);
        if (stream.size() < _len)
            throw std::invalid_argument("IntType: stream size < _len");

        unsigned char *packed = new unsigned char[_len];
        //int32_t len = sizeof(value2) / sizeof(*packed);

        for (int i = 0; i < _len; i++)
        {
            packed[i] = stream.data[i];
        }
        stream.data.erase(stream.data.begin(), stream.data.begin() + _len);
        if (BIG_ENDIAN)
            std::reverse(packed, packed+_len);
        auto *_value = reinterpret_cast<INT_T *>(packed);
		Getter<INT_T>::value = *_value;

        return stream;
    }
};

template <typename INT_T>
struct ULongIntType : public Maker<ULongIntType<INT_T>, INT_T>, public Getter<INT_T>
{
    typedef INT_T value_type;

    ULongIntType() {}

    ULongIntType(INT_T _value)
    {
		Getter<INT_T>::value = _value;
    }

    ULongIntType<INT_T> &set(const INT_T &_value)
    {
		Getter<INT_T>::value = _value;
        return *this;
    }

    INT_T get() const
    {
        return Getter<INT_T>::value;
    }

    auto &operator=(INT_T _value)
    {
		Getter<INT_T>::value = _value;
        return *this;
    }

    virtual PackStream &write(PackStream &stream)
    {
//        LOG_TRACE << "ULongIntType Worked!";

        INT_T value2 = Getter<INT_T>::value;
        unsigned char *packed = reinterpret_cast<unsigned char *>(&value2);
        int32_t len = std::distance(value2.begin(), value2.end());

        PackStream s(packed, len);
        stream << s;

        return stream;
    }

    virtual PackStream &read(PackStream &stream)
	{
        if (stream.size() < value_type::WIDTH)
            throw std::invalid_argument("ULongIntType: stream size < value_type::WIDTH");

		unsigned char *packed = new unsigned char[value_type::WIDTH];
		//int32_t len = sizeof(value2) / sizeof(*packed);

		for (int i = 0; i < value_type::WIDTH; i++)
		{
			packed[i] = stream.data[i];
		}
		stream.data.erase(stream.data.begin(), stream.data.begin() + value_type::WIDTH);
		auto *_value = reinterpret_cast<INT_T *>(packed);
		Getter<INT_T>::value = *_value;

		return stream;
	}
};

#define INT8 IntType<uint8_t>
#define INT16 IntType<uint16_t>
#define INT32 IntType<uint32_t>
#define INT64 IntType<uint64_t>
#define INT160 ULongIntType<uint160>
#define INT128 ULongIntType<uint128>
#define INT256 ULongIntType<uint256>

#define IntType(bytes) INT##bytes

//PACK_TYPE = StreamObjType
template <StreamEnumType ENUM_T, typename PACK_TYPE = IntType(32)>
struct EnumType : public Maker<EnumType<ENUM_T, PACK_TYPE>, ENUM_T>, public Getter<ENUM_T>
{
	typedef typename PACK_TYPE::value_type value_type;

    EnumType() {}

    EnumType(ENUM_T _value)
    {
		Getter<ENUM_T>::value = _value;
    }

    void set(ENUM_T _value)
    {
		Getter<ENUM_T>::value = _value;
    }

	ENUM_T get()
	{
		return Getter<ENUM_T>::value;
	}

    PackStream &write(PackStream &stream)
    {
        PACK_TYPE v((typename PACK_TYPE::value_type)Getter<ENUM_T>::value);
        stream << v;

        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        PACK_TYPE v;
        stream >> v;

		Getter<ENUM_T>::value = (ENUM_T)v.value;

        return stream;
    }
};

//template <StreamObjType ObjType>
template <typename ObjType>
class PossibleNoneType : public Maker<PossibleNoneType<ObjType>, ObjType>, public CustomGetter<ObjType>
{
private:
    ObjType none_value;

public:
    typedef ObjType TYPE;

    optional<ObjType> value;

    PossibleNoneType(ObjType _none_value)
    {
        none_value = _none_value;
    }

    PossibleNoneType(const ObjType &_none_value, const ObjType &_value)
    {
        none_value = _none_value;
        value = _value;
    }

    ObjType get() const override
    {
        if (value.has_value())
        {
            return value.value();
        }
        else
        {
            return none_value;
        }
    }

    auto &operator=(ObjType obj)
    {
        value = obj;
        return *this;
    }

    PackStream &write(PackStream &stream)
    {
        if (value.has_value())
        {
            value.value().write(stream);
        }
        else
        {
            none_value.write(stream);
        }
        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        ObjType *_value = new ObjType();
        stream >> *_value;

        value = make_optional(*_value);
		delete _value;
        return stream;
    }
};

template <GetterType ObjType>
class PossibleNoneType<ObjType> : public Maker<PossibleNoneType<ObjType>, ObjType>, public CustomGetter<typename ObjType::get_type>
{
private:
	ObjType none_value;

public:
	typedef ObjType TYPE;

	optional<ObjType> value;

	PossibleNoneType(ObjType _none_value)
	{
		none_value = _none_value;
	}

	PossibleNoneType(const ObjType &_none_value, const ObjType &_value)
	{
		none_value = _none_value;
		value = _value;
	}

	typename ObjType::get_type get() const override
	{
		if (value.has_value())
		{
			return value.value().get();
		}
		else
		{
			return none_value.get();
		}
	}

	auto &operator=(ObjType obj)
	{
		value = obj;
		return *this;
	}

	PackStream &write(PackStream &stream)
	{
		if (value.has_value())
		{
			value.value().write(stream);
		}
		else
		{
			none_value.write(stream);
		}
		return stream;
	}

	PackStream &read(PackStream &stream)
	{
		ObjType *_value = new ObjType();
		stream >> *_value;

		value = make_optional(*_value);
		delete _value;
		return stream;
	}
};

struct FloatingInteger : public Getter<IntType(32)>
{
	///now: Getter<IntType(32)>::value = bits
	///legacy: IntType(32) bits;

    FloatingInteger()
    {
    }

    FloatingInteger(IntType(32) _bits)
    {
        value = _bits;
    }

    FloatingInteger(int32_t _bits)
    {
        value = _bits;
    }

    uint256 target()
    {
		auto shift_left = [&](int32_t _n, int32_t _m)
		{
			arith_uint256 n(_n);
			if (_m >= 0)
			{
				n <<= _m;
			} else
			{
				_m = -_m;
				n >>= _m;
			}
			return ArithToUint256(n);
		};
//        arith_uint256 res(value.value & 0x00ffffff);
//
//        res << (8 * ((value.value >> 24) - 3));

//		auto res = shift_left(value.get() & 0x00ffffff, 8 * ((value.get() >> 24) - 3));
//
//        return ArithToUint256(res);
		auto res = shift_left(value.get() & 0x00ffffff, 8 * ((value.get() >> 24) - 3));
		return res;
    }

    //TODO: test
    static FloatingInteger from_target_upper_bound(uint256 target)
    {
        std::string str_n = math::natural_to_string(target);
        list<unsigned char> n;
        n.insert(n.end(), str_n.begin(), str_n.end());

        if (n.size() > 0 && *n.begin() >= 128)
        {
            n.push_front('\0');
        }

        list<unsigned char> bits2;
        bits2.push_back((unsigned char)n.size());
        {
            list<unsigned char> temp_bits(n);
            for (int i = 0; i < 3; i++)
                temp_bits.push_back('\0');
            auto vi = temp_bits.begin();
            std::advance(vi, 3);
            bits2.insert(bits2.end(), temp_bits.begin(), vi);
        }
        bits2.reverse();

        IntType(32) unpacked_bits;

        unsigned char *bits = new unsigned char[bits2.size()];
        std::copy(bits2.begin(), bits2.end(), bits);
        PackStream stream(bits, bits2.size());
        stream >> unpacked_bits;

        return FloatingInteger(unpacked_bits);
    }
};

struct FloatingIntegerType : public CustomGetter<typename FloatingInteger::get_type>
{
    FloatingInteger bits;

    PackStream &write(PackStream &stream)
    {
        stream << bits.value;

        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        IntType(32) _bits;
        stream >> _bits;
        bits = FloatingInteger(_bits);

        return stream;
    }

    auto &operator=(int32_t v)
    {
        bits.value = v;
        return *this;
    }

    uint32_t get() const override
    {
        return bits.get();
    }
};