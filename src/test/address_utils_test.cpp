#include <gtest/gtest.h>
#include "core/address_utils.h"
#include "core/coin_params.h"

TEST(AddressUtilsTest, ValidAddress) {
    CoinParams params;
    params.address_version = 76;
    params.address_p2sh_version = 16;
    params.name = "DASH";
    std::string address = "XyJjFjS3g8Q6c9T7B8uVwXzY1A2sD3fG4hJ5kL6mN7oP8qR9";
    uint160 h160 = core::address_to_hash160(address, params);
    EXPECT_NE(h160, uint160());
}

TEST(AddressUtilsTest, InvalidAddress) {
    CoinParams params;
    params.address_version = 76;
    params.address_p2sh_version = 16;
    params.name = "DASH";
    std::string address = "InvalidAddress";
    EXPECT_THROW(core::address_to_hash160(address, params), std::invalid_argument);
}

TEST(AddressUtilsTest, WrongNetworkAddress) {
    CoinParams params;
    params.address_version = 76;
    params.address_p2sh_version = 16;
    params.name = "DASH";
    std::string address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    EXPECT_THROW(core::address_to_hash160(address, params), std::invalid_argument);
}
