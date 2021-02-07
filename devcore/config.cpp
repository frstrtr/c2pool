#include "config.h"

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