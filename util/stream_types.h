#include <devcore/logger.h>
#include <cstring>
#include <vector>
#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <optional>
#include "stream.h"
using namespace std;

template <typename T>
struct ListType
{
    vector<T> l;

    ListType() {}

    ListType(T arr[], size_t len)
    {
        l.insert(l.end(), arr, arr + len);
    }

    ListType(vector<T> arr)
    {
        l = vector<T>(arr);
    }

    PackStream &write(PackStream &stream) const
    {
        LOG_TRACE << "ListType Worked!";
        auto len = l.size();
        stream << len;
        for (auto v : l)
        {
            stream << v;
        }

        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        auto len = 0;
        stream >> len;
        for (int i = 0; i < len; i++)
        {
            T temp;
            stream >> temp;
            l.push_back(temp);
        }
        return stream;
    }
};

struct StrType
{
    string str;

    PackStream &write(PackStream &stream) const
    {
        LOG_TRACE << "StrType Worked!";

        char s[str.length() + 1];
        strcpy(s, str.c_str());

        ListType<char> list_s(s, str.length());

        stream << list_s;

        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        ListType<char> list_s;
        stream >> list_s;

        str = string(list_s.l.begin(), list_s.l.end());
        return stream;
    }
};

//TODO: TEST
template <int SIZE>
struct FixedStrType
{
    string str;

    FixedStrType()
    {
    }

    FixedStrType(string _str)
    {
        if (_str.length() != SIZE)
        {
            throw std::invalid_argument("Incorrect length str in FixedStrType");
        }
        str = _str;
    }

    PackStream &write(PackStream &stream) const
    {
        LOG_TRACE << "FixedStrType Worked!";

        for (auto c : str)
        {
            stream << c;
        }

        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        char *c_str = new char[SIZE];
        for (int i = 0; i < SIZE; i++)
        {
            stream >> c_str[i];
        }

        str = string(c_str, c_str + SIZE);
        return stream;
    }
};

template <typename INT_T>
struct IntType
{
    typedef INT_T value_type;
    INT_T value;

    IntType() {}

    IntType(INT_T _value)
    {
        value = _value;
    }

    IntType<INT_T> &set(const INT_T &_value)
    {
        value = _value;
        return *this;
    }

    INT_T get() const
    {
        return value;
    }

    PackStream &write(PackStream &stream) const
    {
        LOG_TRACE << "IntType Worked!";

        INT_T value2 = value;
        unsigned char *packed = reinterpret_cast<unsigned char *>(&value2);
        int32_t len = sizeof(value2) / sizeof(*packed);

        PackStream s(packed, len);
        stream << s;

        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        unsigned char *packed = new unsigned char[CALC_SIZE(INT_T)];
        //int32_t len = sizeof(value2) / sizeof(*packed);

        for (int i = 0; i < CALC_SIZE(INT_T); i++)
        {
            packed[i] = stream.data[i];
            stream.data.erase(stream.data.begin(), stream.data.begin() + 1);
        }
        auto *_value = reinterpret_cast<INT_T *>(packed);
        value = *_value;

        return stream;
    }
};

#define INT8 uint8_t
#define INT16 uint16_t
#define INT32 uint32_t
#define INT64 uint64_t
#define INT160 uint160
#define INT256 uint256

#define IntType(bytes) IntType<INT##bytes>

struct VarIntType
{
    uint64_t value;

    VarIntType(uint64_t _v)
    {
        value = _v;
    }

    PackStream &write(PackStream &stream) const
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

template <StreamEnumType ENUM_T, StreamObjType PACK_TYPE = IntType(32)>
struct EnumType
{
    ENUM_T value;

    EnumType() {}

    EnumType(ENUM_T _value)
    {
        value = _value;
    }

    void set(ENUM_T _value)
    {
        value = _value;
    }

    PackStream &write(PackStream &stream) const
    {
        LOG_TRACE << "EnumType Worked!";

        PACK_TYPE v((typename PACK_TYPE::value_type)value);
        stream << v;

        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        PACK_TYPE v;
        stream >> v;

        value = (ENUM_T)v.value;

        return stream;
    }
};

template <StreamObjType ObjType>
class PossibleNoneType
{
private:
    ObjType none_value;

public:
    optional<ObjType> value;

    ObjType get() const
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

    PackStream &write(PackStream &stream) const
    {
        cout << "NonValueType Worked!" << endl;

        if (value.has_value())
        {
            value.value.write(stream);
        }
        else
        {
            none_value.write(stream);
        }
        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        ObjType *_value;
        stream >> *_value;

        if (*_value != none_value)
        {
            value.make_optional(*_value);
        }
        return stream;
    }
};

//TODO: test

struct FloatingInteger
{

    IntType(32) bits;

    FloatingInteger()
    {
    }

    FloatingInteger(IntType(32) _bits)
    {
        bits = _bits;
    }

    uint256 target(){
        arith_uint256 res(bits.value && 0x00ffffff);
        
        res << (8 * ((bits.value >> 24) - 3));

        return ArithToUint256(res);
    }
};

//TODO: test
struct FloatingIntegerType
{

    FloatingInteger bits;

    PackStream &write(PackStream &stream) const
    {
        stream << bits.bits;

        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        IntType(32) _bits;
        stream >> _bits;
        bits = FloatingInteger(_bits);

        return stream;
    }
};