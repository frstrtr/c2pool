#pragma once
#include <string>
#include <stdexcept>

enum ExceptionCode
{
    node_errc,
    net_errc
};

struct c2pool_except_data
{
   const ExceptionCode code;
    
    c2pool_except_data(const ExceptionCode& _code) : code(_code)       {

   }
};

struct node_exception : public c2pool_except_data
{
    node_exception() : c2pool_except_data(node_errc)
    {

    }
};

struct net_exception : public c2pool_except_data
{
    std::string ip;

    net_exception(std::string _ip) : c2pool_except_data(net_errc), ip(_ip)
    {

    }
};

namespace c2pool
{
    class NodeExceptionHandler 
    {
    public:
        void HandleException(const c2pool_except_data* data)
        {
            switch (data->code)
            {
            case node_errc:
                HandleNodeException();
                break;
            case net_errc:
                HandleNetException((net_exception*)data);
                break;
            default:
                break;
            }
        }

    protected:
        virtual void HandleNodeException() = 0;
        virtual void HandleNetException(net_exception* data) = 0;
    };

    class base_c2pool_exception : public std::runtime_error
    {
        c2pool_except_data* data;
    public:
        base_c2pool_exception(std::string reason, c2pool_except_data* _data) : std::runtime_error(reason), data(_data) {}

        ExceptionCode where() const
        {
            return data->code;
        }

        c2pool_except_data* get_data() const
        { 
            return data; 
        }

        ~base_c2pool_exception()
        {
            if (data)
                delete data;
        }
    };

    class CoindExcept : public base_c2pool_exception
    {
    public:
        CoindExcept(std::string reason, c2pool_except_data* data) : base_c2pool_exception(reason, data)
        {

        }
    };

    class PoolExcept : public base_c2pool_exception
    {
    public:
        PoolExcept(std::string reason, c2pool_except_data* data) : base_c2pool_exception(reason, data)
        {

        }
    };
}

template <typename ExceptT, typename DataT, typename... Args>
ExceptT make_except(std::string reason, Args... args)
{
    return ExceptT(reason, new DataT(args...));
}