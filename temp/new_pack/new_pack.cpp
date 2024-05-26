#include <iostream>
#include <span>
#include <vector>
#include <memory>
#include <cstring>
#include <iomanip>
#include <string>

struct PackStream
{
    std::vector<std::byte> bytes;

    void write(std::span<const std::byte> data)
    {
        bytes.insert(bytes.end(), data.begin(), data.end());
    }

    void print() const
    {
        std::cout << "{ ";
        for (auto const b : bytes)
            std::cout << std::setw(2) << std::to_integer<int>(b) << ' ';
        std::cout << std::dec << "}\n";
    }

    void read(const std::span<std::byte>& data)
    {
        memcpy(data.data(), &bytes[0], data.size());
    }
};

template <typename int_type>
struct _IntType
{
    static void serialize(PackStream& os, int_type& value)
    {
        os.write(std::as_bytes(std::span{&value, 1}));
    }

    static void unserialize(PackStream& is, int_type& value)
    {

        is.read(std::as_writable_bytes(std::span{&value, 1}));
    }
};

template <int N>
struct IntTypeSpecificator;

#define INT_TYPE_SPEC(N, TYPE)\
    template<> struct IntTypeSpecificator<N> { using type = TYPE; }

INT_TYPE_SPEC(16, int16_t);
INT_TYPE_SPEC(32, int32_t);
INT_TYPE_SPEC(64, int64_t);

template <int N>
using IntType = _IntType<typename IntTypeSpecificator<N>::type>;

struct StrType
{
    static void serialize(PackStream& os, std::string& value)
    {
        os.write(std::as_bytes(std::span{&value, 1}));
    }

    static void unserialize(PackStream& is, std::string& value)
    {

        is.read(std::as_writable_bytes(std::span{&value, 1}));
    }
};

int main()
{
    int32_t old_value = 322;

    PackStream stream;
    IntType<32>::serialize(stream, old_value);

    stream.print();
    int32_t new_value;
    IntType<32>::unserialize(stream, new_value);

    std::cout << "Old value: " << old_value << std::endl;
    std::cout << "New value: " << new_value << std::endl;

    int64_t v1;
    IntType<64>::unserialize(stream, v1);
    std::cout << v1 << std::endl;

    // string
    PackStream str_stream;

    std::string str1("Hello world!");
    StrType::serialize(str_stream, str1);

    std::string str2;
    StrType::unserialize(str_stream, str2);

    std::cout << str2 << std::endl;

    return 0;
}