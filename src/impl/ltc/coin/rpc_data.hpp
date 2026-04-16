#pragma once
// Forwarding header: types moved to bitcoin_family
#include <impl/bitcoin_family/coin/rpc_data.hpp>
namespace ltc { namespace coin {
    using namespace bitcoin_family::coin;
    namespace rpc { using namespace bitcoin_family::coin::rpc; }
}}
