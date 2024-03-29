#pragma once

#ifdef _WIN32
#include <concepts>
#endif

#include <iostream>
#include <sstream>
#include <vector>
#include <numeric>
#include <memory>

#include <btclibs/util/strencodings.h>
#include "logger.h"

using namespace std;

class PackStream;

template <typename T>
concept StreamObjType = requires(T a)
{
	a.write;
	a.read;
};

template <typename T>
concept C_STRING = std::is_same_v<T, const char *> || std::is_same_v<T, char *> || std::is_same_v<T, unsigned char *> || std::is_same_v<T, const unsigned char *> || std::is_same_v<T, char>;

template <typename T>
concept StreamIntType = !C_STRING<T> && std::numeric_limits<T>::is_integer;

template <typename T>
concept StreamEnumType = std::is_enum_v<T>;

/// MAKER

struct BaseMaker //TIP, HACK, КОСТЫЛЬ
{
};

template <typename T>
concept MakerType = std::is_base_of_v<BaseMaker, T>;

template <typename T, typename SUB_T>
struct Maker : BaseMaker
{
    typedef T to;
    typedef SUB_T from;

    template <typename LAST_T>
    static T make_type(LAST_T v)
    {
        return T(v);
    }

    template <typename LAST_T>
    static vector<T> make_list_type(vector<LAST_T> v_arr)
    {
        vector<T> res;
        for (auto v : v_arr)
        {
            res.push_back(make_type(v));
        }
        return res;
    }
};

template <typename T, MakerType SUB_T>
struct Maker<T, SUB_T> : BaseMaker
{
    typedef T to;
    typedef SUB_T from;

    template <typename LAST_T>
    static T make_type(LAST_T v)
    {
        return SUB_T::make_type(v);
    }

    template <typename LAST_T>
    static vector<T> make_list_type(vector<LAST_T> v_arr)
    {
        vector<T> res;
        for (auto v : v_arr)
        {
            res.push_back(make_type(v));
        }
        return res;
    }
};

template <typename LIST_TYPE>
struct MakerListType : BaseMaker
{
    static vector<LIST_TYPE> make_type(vector<LIST_TYPE> values)
    {
        return values;
    }
};

template <MakerType LIST_TYPE>
struct MakerListType<LIST_TYPE> : BaseMaker
{
    template <typename SUB_EL_TYPE>
    static vector<LIST_TYPE> make_type(vector<SUB_EL_TYPE> values)
    {
        return LIST_TYPE::make_list_type(values);
    }
};

/// GETTER

struct BaseGetter{};

template <typename T>
concept GetterType = std::is_base_of_v<BaseGetter, T>;

template <typename GET_TYPE>
struct Getter : BaseGetter
{
	typedef GET_TYPE get_type;
	get_type value;

	virtual get_type get() const
	{
		return value;
	}
};

template <GetterType GET_TYPE>
struct Getter <GET_TYPE> : BaseGetter
{
	typedef typename GET_TYPE::get_type get_type;
	GET_TYPE value;

	virtual get_type get() const
	{
		return value.get();
	}
};

template <typename GET_TYPE>
struct GetterList : BaseGetter
{
	typedef std::vector<GET_TYPE> get_type;
	get_type value;

	virtual get_type get() const
	{
		return value;
	}
};

template <GetterType GET_TYPE>
struct GetterList<GET_TYPE> : BaseGetter
{
	typedef std::vector<typename GET_TYPE::get_type> get_type;
	std::vector<GET_TYPE> value;

	/// Return copy, don't use (get().begin, get().end())
	virtual get_type get() const
	{
		get_type result;
		for (auto v: value)
		{
			result.push_back(v.get());
		}
		return result;
	}
};

template <typename T>
struct CustomGetter : BaseGetter
{
	typedef T get_type;

	virtual T get() const = 0;
};

class packstream_exception : public std::exception
{
private:
    std::string err;
public:
    packstream_exception(std::string _err) : err(_err) {}
    packstream_exception(const char* _err) : err(_err) {}

    virtual const char *what() const throw()
    {
        return err.c_str();
    }
};

/// PackStream

struct PackStream
{
    vector<unsigned char> data;

    PackStream() {}

    PackStream(vector<unsigned char> value)
    {
        data = value;
    }

    PackStream(unsigned char *value, int32_t len)
    {
        data = vector<unsigned char>(value, value + len);
    }

    PackStream(const unsigned char *value, int32_t len)
    {
        data = vector<unsigned char>(value, value + len);
    }

    PackStream(char *value, int32_t len)
    {
        auto temp = (unsigned char *)value;
        data = vector<unsigned char>(temp, temp + len);
    }

    PackStream(const char *value, int32_t len)
    {
        auto temp = (unsigned char *)value;
        data = vector<unsigned char>(temp, temp + len);
    }

    PackStream &operator<<(PackStream &val)
    {
        data.insert(data.end(), val.data.begin(), val.data.end());
        return *this;
    }

    PackStream &operator<<(const PackStream &val)
    {
        data.insert(data.end(), val.data.begin(), val.data.end());
        return *this;
    }

    PackStream &operator<<(const std::vector<unsigned char> &val)
    {
        data.insert(data.end(), val.begin(), val.end());
        return *this;
    }

    PackStream &operator<<(std::vector<unsigned char> &val)
    {
        data.insert(data.end(), val.begin(), val.end());
        return *this;
    }

    template <typename T>
    PackStream &operator<<(T &val)
    {
        unsigned char *packed = reinterpret_cast<unsigned char *>(&val);
        int32_t len = sizeof(val) / sizeof(*packed);

        data.insert(data.end(), packed, packed + len);
        return *this;
    }

    template <typename T>
    PackStream &operator<<(T val[])
    {
        unsigned char *packed = reinterpret_cast<unsigned char *>(&val);
        int32_t len = sizeof(val) / sizeof(*packed);
        data.insert(data.end(), packed, packed + len);
        return *this;
    }

    template <StreamObjType T>
    PackStream &operator<<(T &val)
    {
        val.write(*this);
        return *this;
    }

#define ADDING_INT(num_type, _code)                                   \
    unsigned char code = _code;                                       \
    data.push_back(code);                                             \
    num_type val2 = (num_type)val;                                    \
    unsigned char *packed = reinterpret_cast<unsigned char *>(&val2); \
    int32_t len = sizeof(val2) / sizeof(*packed);                     \
    data.insert(data.end(), packed, packed + len);                    \
    return *this;

    template <StreamIntType T>
    PackStream &operator<<(T &val)
    {
        if (val < 0xfd)
        {
            unsigned char packed = (unsigned char)val;
            data.push_back(packed);
            return *this;
        }
        if (val < 0xffff)
        {
            ADDING_INT(uint16_t, 0xfd)
        }
        if (val < 0xffffffff)
        {
            ADDING_INT(uint32_t, 0xfe)
        }
        if (val < 0xffffffffffffffff)
        {
            ADDING_INT(uint64_t, 0xff)
        }

        throw packstream_exception("int too large for varint");
    }
#undef ADDING_INT

#define CALC_SIZE(T) (sizeof(T))

    PackStream &operator>>(PackStream &val)
    {
        val.data.insert(val.data.end(), data.begin(), data.end());
        return *this;
    }

    template <typename T>
    PackStream &operator>>(T &val)
    {
		auto _size = CALC_SIZE(T);
        if (data.size() < _size)
            throw packstream_exception("PackStream >> T: data.size < CALC_SIZE(T)!");
        auto *packed = new unsigned char[_size];
        for (int i = 0; i < _size; i++)
        {
            packed[i] = data[i];
        }
		data.erase(data.begin(), data.begin() + _size);
        auto *res = reinterpret_cast<T *>(packed);
        val = *res;
		delete[] packed;
        return *this;
    }

    template <StreamObjType T>
    PackStream &operator>>(T &val)
    {
        val.read(*this);
        return *this;
    }

    template <typename NUM_TYPE, StreamIntType T>
    PackStream& GET_INT(T &val)
    {
        auto _size = CALC_SIZE(NUM_TYPE);
        if (data.size() < _size)
            throw packstream_exception("GET_INT: data.size < CALC_SIZE(NUM_TYPE)!");
        auto *packed = new unsigned char[_size];
        for (int i = 0; i < _size; i++)
        {
            packed[i] = data[i];
        }
        auto *val2 = reinterpret_cast<NUM_TYPE *>(packed);
        val = *val2;
        data.erase(data.begin(), data.begin() + _size);
        delete[] packed;

        return *this;
    }

    template <StreamIntType T>
    PackStream &operator>>(T &val)
    {
        if (data.empty())
            throw packstream_exception("PackStream >> StreamIntType: empty data!");
        unsigned char code = data.front();
        data.erase(data.begin(), data.begin() + 1);
        if (code < 0xfd)
        {
            val = code;
        }
        else if (code == 0xfd)
        {
            return GET_INT<uint16_t>(val);
        }
        else if (code == 0xfe)
        {
            return GET_INT<uint32_t>(val);
        }
        else if (code == 0xff)
        {
            return GET_INT<uint64_t>(val);
        } else
		{
			throw packstream_exception("error in code StreamIntType");
		}
        return *this;
    }

    unsigned char *bytes() const
    {
        unsigned char *result = new unsigned char[data.size()];
        std::copy(data.begin(), data.end(), result);
        return result;
    }

    const char* c_str() const
    {
        const char* result = reinterpret_cast<const char*>(data.data());
        return result;
    }

    size_t size() const
    {
        return data.size();
    }

    bool isNull() const
    {
        return data.size() <= 0;
    }

	auto begin()
	{
		return data.begin();
	}

	auto end()
	{
		return data.end();
	}

    void from_hex(const std::string &hexData)
    {
        PackStream _stream;

        auto parsedHexData = ParseHex(hexData);
        auto lenData = parsedHexData.size();

        data.insert(data.end(), parsedHexData.begin(), parsedHexData.end());
    }

    friend std::ostream &operator<<(std::ostream &stream, const PackStream &packstream)
    {
        stream << packstream.data;
        return stream;
    }

    friend bool operator==(const PackStream& left, const PackStream& right)
    {
        return left.data == right.data;
    }

    friend bool operator!=(const PackStream& left, const PackStream& right)
    {
        return !(left == right);
    }
};

template<typename ValueType, typename StreamType>
class StreamTypeAdapter
{
public:
    typedef ValueType value_type;
    typedef StreamType stream_type;
protected:
    std::shared_ptr<ValueType> _value;
    std::shared_ptr<StreamType> _stream;

public:
    StreamTypeAdapter() = default;

    virtual std::shared_ptr<value_type> make_empty_value()
    {
        auto result = std::make_shared<ValueType>();
        return result;
    }

    std::shared_ptr<ValueType> operator->()
    {
        if (!_value)
        {
            if (_stream)
            {
                to_value();
            } else
            {
                _value = make_empty_value();
            }
        }
        return _value;
    }

    PackStream &write(PackStream &stream)
    {
        stream << *_stream;
        return stream;
    }

    PackStream &read(PackStream &stream)
    {
		if (!_stream)
			_stream = std::make_shared<StreamType>();
        stream >> *_stream;
        return stream;
    }

    std::shared_ptr<ValueType> get()
    {
        if (!_value)
        {
            if (_stream)
            {
                to_value();
            } else
            {
                LOG_DEBUG_OTHER << "StreamTypeAdapter operator -> warning: _value and _stream - nullptr!";
            }
        }
        return _value;
    }

    std::shared_ptr<StreamType> stream()
    {
		if (!_stream)
			to_stream();
        return _stream;
    }

//    template <class T, >
//    shared_ptr<T> make_shared (Args&&... args);

    template<class... Args>
    void make_value(Args &&... args)
    {
        _value = std::make_shared<value_type>(args...);
    }

    template<class... Args>
    void make_stream(Args &&... args)
    {
        _stream = std::make_shared<stream_type>(args...);
    }

    bool is_none()
    {
        return _value || _stream;

    }

	void set_value(const ValueType& __value)
	{
		_value = std::make_shared<ValueType>(__value);
	}

	void set_stream(const StreamType& __stream)
	{
		_stream = std::make_shared<StreamType>(__stream);
	}

    PackStream get_pack()
    {
        PackStream __stream;
        __stream << *stream();
        return __stream;
    }

//    bool operator==(StreamTypeAdapter<ValueType, StreamType> &b)
//    {
//        auto _a = this->get();
//        auto _b = b.get();
//
//        if (_a && _b)
//            return *_a == *_b;
//        else
//            false;
//    }
//
//    bool operator!=(StreamTypeAdapter<ValueType, StreamType> &b)
//    {
//        { return !(*this == b); }
//    }

    friend inline bool operator==(StreamTypeAdapter &a, StreamTypeAdapter &b)
    {
        auto _a = a.get();
        auto _b = b.get();

        if (_a && _b)
            return *a._value == *b._value;
        else
            return false;

    }
    friend inline bool operator!=(StreamTypeAdapter &a, StreamTypeAdapter &b) { return !(a == b); }
protected:
    virtual void _to_stream() = 0;

    virtual void _to_value() = 0;

private:
    virtual void to_stream()
    {
        if (_value)
        {
            _to_stream();
        } else
        {
            throw packstream_exception("StreamTypeAdapter.to_stream error: _value - nullptr!");
        }
    }

    size_t size() const
    {
        PackStream _buffer;
        _buffer << *stream();
        return _buffer.size();
    }

    virtual void to_value()
    {
        if (_stream)
        {
            _to_value();
        } else
        {
            throw packstream_exception("StreamTypeAdapter.to_value error: _stream - nullptr!");
        }
    }
};

template <typename StreamType, typename T>
std::vector<unsigned char> pack(T value)
{
    PackStream stream;
    StreamType stream_value(value);

    stream << stream_value;
    return stream.data;
}

template <typename StreamType, typename T>
PackStream pack_to_stream(T value)
{
    PackStream stream;
    StreamType stream_value(value);

    stream << stream_value;
    return stream;
}

template <typename StreamType>
typename StreamType::get_type unpack(PackStream stream)
{
    StreamType stream_value;
    stream >> stream_value;
    return stream_value.get();
}

template <typename StreamType>
typename StreamType::get_type unpack(std::vector<unsigned char> data)
{
    PackStream stream(std::move(data));
    return unpack<StreamType>(stream);
}