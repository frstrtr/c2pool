#ifndef CORE_ADDRESS_UTILS_H
#define CORE_ADDRESS_UTILS_H

#include <cstdint>
#include <string>
#include <vector>
#include "core/coin_params.h"

namespace core {

uint160 address_to_hash160(const std::string& address, const CoinParams& params);

} // namespace core

#endif // CORE_ADDRESS_UTILS_H
