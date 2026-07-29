#include <cstdint>
#include <string>
#include <vector>
#include "core/coin_params.h"
#include "core/address_utils.h"

uint160 core::address_to_hash160(const std::string& address, const CoinParams& params) {
    std::vector<unsigned char> decoded;
    if (!DecodeBase58(address, decoded)) {
        throw std::invalid_argument("Invalid address");
    }
    if (decoded.size() < 1) {
        throw std::invalid_argument("Address too short");
    }
    uint8_t version = decoded[0];
    if (version != params.address_version && version != params.address_p2sh_version) {
        throw std::invalid_argument("Address version mismatch. Expected network: " + params.name);
    }
    uint160 h160;
    std::copy(decoded.begin() + 1, decoded.begin() + 21, h160.begin());
    return h160;
}
