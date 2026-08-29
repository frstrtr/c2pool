// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_STREAMS_H
#define BITCOIN_STREAMS_H

#include "serialize.h"
#include "span.h"
// #include <support/allocators/zeroafterfree.h>
// #include <util/overflow.h>

#include <algorithm>
#include <assert.h>
#include <cstddef>
#include <cstdio>
#include <ios>
#include <limits>
#include <optional>
#include <stdint.h>
#include <string.h>
#include <string>
#include <utility>
#include <vector>

namespace legacy::util {
inline void Xor(Span<std::byte> write, Span<const std::byte> key, size_t key_offset = 0)
{
    if (key.size() == 0) {
        return;
    }
    key_offset %= key.size();

    for (size_t i = 0, j = key_offset; i != write.size(); i++) {
        write[i] ^= key[j++];

        // This potentially acts on very many bytes of data, so it's
        // important that we calculate `j`, i.e. the `key` index in this
        // way instead of doing a %, which would effectively be a division
        // for each byte Xor'd -- much slower than need be.
        if (j == key.size())
            j = 0;
    }
}
} // namespace util

/* Minimal stream for overwriting and/or appending to an existing byte vector
 *
 * The referenced vector will grow as necessary
 */
class VectorWriter
{
public:
/*
 * @param[in]  vchDataIn  Referenced byte vector to overwrite/append
 * @param[in]  nPosIn Starting position. Vector index where writes should start. The vector will initially
 *                    grow as necessary to max(nPosIn, vec.size()). So to append, use vec.size().
*/
    VectorWriter(std::vector<unsigned char>& vchDataIn, size_t nPosIn) : vchData{vchDataIn}, nPos{nPosIn}
    {
        if(nPos > vchData.size())
            vchData.resize(nPos);
    }
/*
 * (other params same as above)
 * @param[in]  args  A list of items to serialize starting at nPosIn.
*/
    template <typename... Args>
    VectorWriter(std::vector<unsigned char>& vchDataIn, size_t nPosIn, Args&&... args) : VectorWriter{vchDataIn, nPosIn}
    {
        ::legacy::SerializeMany(*this, std::forward<Args>(args)...);
    }
    void write(Span<const std::byte> src)
    {
        assert(nPos <= vchData.size());
        size_t nOverwrite = std::min(src.size(), vchData.size() - nPos);
        if (nOverwrite) {
            memcpy(vchData.data() + nPos, src.data(), nOverwrite);
        }
        if (nOverwrite < src.size()) {
            vchData.insert(vchData.end(), UCharCast(src.data()) + nOverwrite, UCharCast(src.end()));
        }
        nPos += src.size();
    }
    template <typename T>
    VectorWriter& operator<<(const T& obj)
    {
        ::legacy::Serialize(*this, obj);
        return (*this);
    }

private:
    std::vector<unsigned char>& vchData;
    size_t nPos;
};

/** Minimal stream for reading from an existing byte array by Span.
 */
class SpanReader
{
private:
    Span<const unsigned char> m_data;

public:
    /**
     * @param[in]  data Referenced byte vector to overwrite/append
     */
    explicit SpanReader(Span<const unsigned char> data) : m_data{data} {}

    template<typename T>
    SpanReader& operator>>(T&& obj)
    {
        ::legacy::Unserialize(*this, obj);
        return (*this);
    }

    size_t size() const { return m_data.size(); }
    bool empty() const { return m_data.empty(); }

    void read(Span<std::byte> dst)
    {
        if (dst.size() == 0) {
            return;
        }

        // Read from the beginning of the buffer
        if (dst.size() > m_data.size()) {
            throw std::ios_base::failure("SpanReader::read(): end of data");
        }
        memcpy(dst.data(), m_data.data(), dst.size());
        m_data = m_data.subspan(dst.size());
    }

    void ignore(size_t n)
    {
        m_data = m_data.subspan(n);
    }
};

template <class T>
[[nodiscard]] bool AdditionOverflow(const T i, const T j) noexcept
{
    static_assert(std::is_integral<T>::value, "Integral required.");
    if constexpr (std::numeric_limits<T>::is_signed) {
        return (i > 0 && j > std::numeric_limits<T>::max() - i) ||
               (i < 0 && j < std::numeric_limits<T>::min() - i);
    }
    return std::numeric_limits<T>::max() - i < j;
}

template <class T>
[[nodiscard]] std::optional<T> CheckedAdd(const T i, const T j) noexcept
{
    if (AdditionOverflow(i, j)) {
        return std::nullopt;
    }
    return i + j;
}

/** Double ended buffer combining vector and stream-like interfaces.
 *
 * >> and << read and write unformatted data using the above serialization templates.
 * Fills with data in linear time; some stringstream implementations take N^2 time.
 */
class DataStream
{
protected:
    using vector_type = std::vector<std::byte>;
    vector_type vch;
    vector_type::size_type m_read_pos{0};

public:
    typedef vector_type::allocator_type   allocator_type;
    typedef vector_type::size_type        size_type;
    typedef vector_type::difference_type  difference_type;
    typedef vector_type::reference        reference;
    typedef vector_type::const_reference  const_reference;
    typedef vector_type::value_type       value_type;
    typedef vector_type::iterator         iterator;
    typedef vector_type::const_iterator   const_iterator;
    typedef vector_type::reverse_iterator reverse_iterator;

    explicit DataStream() {}
    explicit DataStream(Span<const uint8_t> sp) : DataStream{AsBytes(sp)} {}
    explicit DataStream(Span<const value_type> sp) : vch(sp.data(), sp.data() + sp.size()) {}

    std::string str() const
    {
        return std::string{UCharCast(data()), UCharCast(data() + size())};
    }


    //
    // Vector subset
    //
    const_iterator begin() const                     { return vch.begin() + m_read_pos; }
    iterator begin()                                 { return vch.begin() + m_read_pos; }
    const_iterator end() const                       { return vch.end(); }
    iterator end()                                   { return vch.end(); }
    size_type size() const                           { return vch.size() - m_read_pos; }
    bool empty() const                               { return vch.size() == m_read_pos; }
    void resize(size_type n, value_type c = value_type{}) { vch.resize(n + m_read_pos, c); }
    void reserve(size_type n)                        { vch.reserve(n + m_read_pos); }
    const_reference operator[](size_type pos) const  { return vch[pos + m_read_pos]; }
    reference operator[](size_type pos)              { return vch[pos + m_read_pos]; }
    void clear()                                     { vch.clear(); m_read_pos = 0; }
    value_type* data()                               { return vch.data() + m_read_pos; }
    const value_type* data() const                   { return vch.data() + m_read_pos; }

    // inline void Compact()
    // {
    //     vch.erase(vch.begin(), vch.begin() + m_read_pos);
    //     m_read_pos = 0;
    // }

    // bool Rewind(std::optional<size_type> n = std::nullopt)
    // {
    //     // Total rewind if no size is passed
    //     if (!n) {
    //         m_read_pos = 0;
    //         return true;
    //     }
    //     // Rewind by n characters if the buffer hasn't been compacted yet
    //     if (*n > m_read_pos)
    //         return false;
    //     m_read_pos -= *n;
    //     return true;
    // }


    //
    // Stream subset
    //
    bool eof() const             { return size() == 0; }
    int in_avail() const         { return size(); }

    void read(Span<value_type> dst)
    {
        if (dst.size() == 0) return;

        // Read from the beginning of the buffer
        auto next_read_pos{CheckedAdd(m_read_pos, dst.size())};
        if (!next_read_pos.has_value() || next_read_pos.value() > vch.size()) {
            throw std::ios_base::failure("DataStream::read(): end of data");
        }
        memcpy(dst.data(), &vch[m_read_pos], dst.size());
        if (next_read_pos.value() == vch.size()) {
            m_read_pos = 0;
            vch.clear();
            return;
        }
        m_read_pos = next_read_pos.value();
    }

    void ignore(size_t num_ignore)
    {
        // Ignore from the beginning of the buffer
        auto next_read_pos{CheckedAdd(m_read_pos, num_ignore)};
        if (!next_read_pos.has_value() || next_read_pos.value() > vch.size()) {
            throw std::ios_base::failure("DataStream::ignore(): end of data");
        }
        if (next_read_pos.value() == vch.size()) {
            m_read_pos = 0;
            vch.clear();
            return;
        }
        m_read_pos = next_read_pos.value();
    }

    void write(Span<const value_type> src)
    {
        // Write to the end of the buffer
        vch.insert(vch.end(), src.begin(), src.end());
    }

    template<typename T>
    DataStream& operator<<(const T& obj)
    {
        ::legacy::Serialize(*this, obj);
        return (*this);
    }

    template<typename T>
    DataStream& operator>>(T&& obj)
    {
        ::legacy::Unserialize(*this, obj);
        return (*this);
    }

    // /**
    //  * XOR the contents of this stream with a certain key.
    //  *
    //  * @param[in] key    The key used to XOR the data in this stream.
    //  */
    // void Xor(const std::vector<unsigned char>& key)
    // {
    //     util::Xor(MakeWritableByteSpan(*this), MakeByteSpan(key));
    // }
};

#endif // BITCOIN_STREAMS_H
