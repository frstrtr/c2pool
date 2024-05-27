#pragma once

#include <iostream>
#include <span>
#include <vector>
#include <memory>
#include <cstring>
#include <iomanip>
#include <string>
#include <limits>

/**
 * The maximum size of a serialized object in bytes or number of elements
 * (for eg vectors) when the size is encoded as CompactSize.
 */
static constexpr uint64_t MAX_SIZE = 0x02000000;

template <typename RealType>
struct PackType
{
    using type = RealType;
};

struct PackStream
{
protected:
    std::vector<std::byte> m_vch;
    std::vector<std::byte>::size_type m_cursor{0};
public:

    void write(std::span<const std::byte> value)
    {
        m_vch.insert(m_vch.end(), value.begin(), value.end());
    }

    void print() const
    {
        std::cout << "{ ";
        for (auto const b : m_vch)
            std::cout << std::setw(2) << std::to_integer<int>(b) << ' ';
        std::cout << std::dec << "}\n";
    }

    void read(const std::span<std::byte>& data)
    {
        if (data.empty()) return;

        auto new_cursor_pos = m_cursor + data.size();
        if (new_cursor_pos > m_vch.size())
            throw std::ios_base::failure("PackStream::read(): end of data!");

        memcpy(data.data(), &m_vch[m_cursor], data.size());
        if (new_cursor_pos == m_vch.size()) 
        {
            m_cursor = 0;
            m_vch.clear();
            return;
        }

        m_cursor = new_cursor_pos;
    }
};

// serialize int data
template<typename Stream> inline void ser_writedata8(Stream &s, uint8_t obj)
{
    s.write(std::as_bytes(std::span<uint8_t>{&obj, 1}));
}

template<typename Stream> inline void ser_writedata16(Stream &s, uint16_t obj)
{
    obj = htole16(obj);
    s.write(std::as_bytes(std::span{&obj, 1}));
}

template<typename Stream> inline void ser_writedata16be(Stream &s, uint16_t obj)
{
    obj = htobe16(obj);
    s.write(std::as_bytes(std::span{&obj, 1}));
}

template<typename Stream> inline void ser_writedata32(Stream &s, uint32_t obj)
{
    obj = htole32(obj);
    s.write(std::as_bytes(std::span{&obj, 1}));
}

template<typename Stream> inline void ser_writedata32be(Stream &s, uint32_t obj)
{
    obj = htobe32(obj);
    s.write(std::as_bytes(std::span{&obj, 1}));
}

template<typename Stream> inline void ser_writedata64(Stream &s, uint64_t obj)
{
    obj = htole64(obj);
    s.write(std::as_bytes(std::span{&obj, 1}));
}

template<typename Stream> inline uint8_t ser_readdata8(Stream &s)
{
    uint8_t obj;
    s.read(std::as_writable_bytes(std::span{&obj, 1}));
    return obj;
}

template<typename Stream> inline uint16_t ser_readdata16(Stream &s)
{
    uint16_t obj;
    s.read(std::as_writable_bytes(std::span{&obj, 1}));
    return le16toh(obj);
}

template<typename Stream> inline uint16_t ser_readdata16be(Stream &s)
{
    uint16_t obj;
    s.read(std::as_writable_bytes(std::span{&obj, 1}));
    return be16toh(obj);
}

template<typename Stream> inline uint32_t ser_readdata32(Stream &s)
{
    uint32_t obj;
    s.read(std::as_writable_bytes(std::span{&obj, 1}));
    return le32toh(obj);
}

template<typename Stream> inline uint32_t ser_readdata32be(Stream &s)
{
    uint32_t obj;
    s.read(std::as_writable_bytes(std::span{&obj, 1}));
    return be32toh(obj);
}

template<typename Stream> inline uint64_t ser_readdata64(Stream &s)
{
    uint64_t obj;
    s.read(std::as_writable_bytes(std::span{&obj, 1}));
    return le64toh(obj);
}

void WriteCompactSize(PackStream& os, uint64_t nSize)
{
    if (nSize < 253)
    {
        ser_writedata8(os, nSize);
    }
    else if (nSize <= std::numeric_limits<uint16_t>::max())
    {
        ser_writedata8(os, 253);
        ser_writedata16(os, nSize);
    }
    else if (nSize <= std::numeric_limits<unsigned int>::max())
    {
        ser_writedata8(os, 254);
        ser_writedata32(os, nSize);
    }
    else
    {
        ser_writedata8(os, 255);
        ser_writedata64(os, nSize);
    }
    return;
}

uint64_t ReadCompactSize(PackStream& is, bool range_check = true)
{
    uint8_t chSize = ser_readdata8(is);
    uint64_t nSizeRet = 0;
    if (chSize < 253)
    {
        nSizeRet = chSize;
    }
    else if (chSize == 253)
    {
        nSizeRet = ser_readdata16(is);
        if (nSizeRet < 253)
            throw std::ios_base::failure("non-canonical ReadCompactSize()");
    }
    else if (chSize == 254)
    {
        nSizeRet = ser_readdata32(is);
        if (nSizeRet < 0x10000u)
            throw std::ios_base::failure("non-canonical ReadCompactSize()");
    }
    else
    {
        nSizeRet = ser_readdata64(is);
        if (nSizeRet < 0x100000000ULL)
            throw std::ios_base::failure("non-canonical ReadCompactSize()");
    }
    if (range_check && nSizeRet > MAX_SIZE) {
        throw std::ios_base::failure("ReadCompactSize(): size too large");
    }
    return nSizeRet;
}