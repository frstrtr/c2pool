#pragma once
#include <string>
#include <stdexcept>

namespace c2pool
{
    enum ExceptionCode
    {
        node_errc,
        net_errc
    };

    struct C2PoolExceptData
    {
       const ExceptionCode code;

        C2PoolExceptData(const ExceptionCode& _code) : code(_code)
        {

        }
    };

    class base_c2pool_exception : public std::runtime_error
    {
        C2PoolExceptData* data;
    public:
        base_c2pool_exception(std::string reason, C2PoolExceptData* _data) : std::runtime_error(reason), data(_data) {}

        ExceptionCode where() const
        {
            return data->code;
        }

        C2PoolExceptData* get_data() const
        { 
            return data; 
        }

        ~base_c2pool_exception()
        {
            if (data)
                delete data;
        }
    };
}

struct NodeExcept : public c2pool::C2PoolExceptData
{
    NodeExcept() : c2pool::C2PoolExceptData(c2pool::node_errc)
    {

    }
};

struct NetExcept : public c2pool::C2PoolExceptData
{
    std::string ip;

    NetExcept(std::string _ip) : c2pool::C2PoolExceptData(c2pool::net_errc), ip(_ip)
    {

    }
};
class coind_exception : public c2pool::base_c2pool_exception
{
public:
    coind_exception(std::string reason, c2pool::C2PoolExceptData* data) : c2pool::base_c2pool_exception(reason, data)
    {

    }
};

class pool_exception : public c2pool::base_c2pool_exception
{
public:
    pool_exception(std::string reason, c2pool::C2PoolExceptData* data) : c2pool::base_c2pool_exception(reason, data)
    {

    }
};

template <typename ExceptT, typename DataT, typename... Args>
ExceptT make_except(std::string reason, Args... args)
{
    return ExceptT(reason, new DataT(args...));
}

class NodeExceptionHandler 
{
public:
    void HandleException(const c2pool::C2PoolExceptData* data)
    {
        switch (data->code)
        {
        case c2pool::node_errc:
            HandleNodeException();
            break;
        case c2pool::net_errc:
            HandleNetException((NetExcept*)data);
            break;
        default:
            break;
        }
    }

protected:
    virtual void HandleNodeException() = 0;
    virtual void HandleNetException(NetExcept* data) = 0;
};