#include "config.h"

#include <istream>
#include <string>


namespace c2pool::dev
{
    c2pool_config *c2pool_config::_instance = nullptr;

    std::istream &operator>>(std::istream &in, c2pool::dev::DebugState &value)
    {
        int token;
        try
        {
            in >> token;
            value = (c2pool::dev::DebugState) token;
        } catch (...)
        {
            throw std::invalid_argument("Invalid DebugState!");
        }
        return in;
    }

    void c2pool_config::INIT()
    {
        if (_instance == nullptr)
        {
            _instance = new c2pool_config();
        }
        else
        {
            //TODO: [LOG] instance already exists
        }
    }

    c2pool_config *c2pool_config::get()
    {
        //TODO: check for exist _instance
        return _instance;
    }
} // namespace c2pool::dev