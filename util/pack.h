#pragma once
#include <stdint.h>
#include <btclibs/uint256.h>

/*
template T for pack:

#pragma pack(push, 1)
struct A
{
    int a;
    int b;
    int c;
    char str[9]; // = "hello";
};
#pragma pack(pop)
*/

namespace c2pool
{
    class SerializedData
    {
    public:
        unsigned char *data;
        int32_t length;

    public:
        SerializedData()
        {
            data = nullptr;
            length = 0;
        }

        SerializedData(unsigned char *_data, int32_t _length)
        {
            data = _data;
            length = _length;
        }

    public:
        template <typename T>
        static SerializedData pack(T &obj)
        {
            unsigned char *bytes_temp = reinterpret_cast<unsigned char *>(&obj);
            int32_t _length = (sizeof(obj) / sizeof(*bytes_temp));
            return SerializedData(bytes_temp, _length);
        }

        template <typename T>
        static T *unpack(unsigned char *_data)
        {
            T *unpacked_data;
            unpacked_data = (T *)_data;
            return unpacked_data;
        }

        template <typename T>
        static T *unpack(SerializedData &_data)
        {
            return SerializedData::unpack<T>(_data.data);
        }
    };

    template<>
    SerializedData SerializedData::pack(uint256 &_data){
        unsigned char* bytes_temp = reinterpret_cast<unsigned char*>(&_data);
        int32_t _length = std::distance(_data.begin(), _data.end());
        return SerializedData(bytes_temp, _length);
    }
}