# bitcoin_family: shared header-only library for Bitcoin-derived coins.
# Contains generic base types (headers, softfork check, txid cache).
# Coin modules (ltc/, dash/) include these and extend with coin-specific features.

add_library(bitcoin_family INTERFACE)
target_include_directories(bitcoin_family INTERFACE
    ${CMAKE_SOURCE_DIR}/src
)
