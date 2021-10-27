#include "config.h"

#include <istream>
#include <string>

std::istream &operator>>(std::istream &in, c2pool::dev::DebugState &value)
{
    std::string token;
    in >> token;
    //cout << token << endl;
    if (token == "0")
        value = c2pool::dev::DebugState::trace;
    else if (token == "1")
        value = c2pool::dev::DebugState::debug;
    else if (token == "2")
        value = c2pool::dev::DebugState::normal;
    return in;
}

namespace c2pool::dev
{
    c2pool_config *c2pool_config::_instance = nullptr;

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