#pragma once
// Forwarding header: generic softfork check moved to bitcoin_family
#include <impl/bitcoin_family/coin/softfork_check.hpp>
namespace ltc { namespace coin {
    using bitcoin_family::coin::collect_softfork_names;
}}
