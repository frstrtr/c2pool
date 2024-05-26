#include <iostream>
#include <span>
#include <vector>
#include <memory>
#include <cstring>
#include <iomanip>

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

    void read(std::span<std::byte>& data)
    {
        memcpy(data.data(), &bytes[0], data.size());
    }
};

template <typename int_type>
struct IntType
{
    static void serialize(PackStream& os, int_type& value)
    {
        os.write(std::as_bytes(std::span{&value, 1}));
    }

    static void unserialize(PackStream& is, int_type& value)
    {
        auto _span = std::as_writable_bytes(std::span{&value, 1});
        std::cout << _span.size() << std::endl;
        is.read(_span);
        // value = *reinterpret_cast<const int32_t*>(dataSpan.data());
    }
};

struct IntType32
{
    static void serialize(PackStream& os, int32_t& value)
    {
        os.write(std::as_bytes(std::span{&value, 1}));
    }

    static void unserialize(PackStream& is, int32_t& value)
    {
        auto _span = std::as_writable_bytes(std::span{&value, 1});
        std::cout << _span.size() << std::endl;
        is.read(_span);
        // value = *reinterpret_cast<const int32_t*>(dataSpan.data());
    }
};

int main()
{
    int32_t old_value = 322;

    PackStream stream;
    IntType32::serialize(stream, old_value);

    stream.print();
    int32_t new_value;
    IntType32::unserialize(stream, new_value);

    std::cout << "Old value: " << old_value << std::endl;
    std::cout << "New value: " << new_value << std::endl;

    int64_t v1;
    IntType<int64_t>::unserialize(stream, v1);

    return 0;
}