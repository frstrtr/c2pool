#include "data.h"
#include "shareTypes.h"
#include <networks/network.h>

namespace c2pool::shares
{
    bool is_segwit_activated(int version, shared_ptr<Network> net)
    {
        return version >= net->SEGWIT_ACTIVATION_VERSION;
    }
}