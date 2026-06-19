# NMC (embedded merge-mined Namecoin) — P0 structural leaf.
# Only the coin tree exists at P0. node/stratum/share layers come later.
add_subdirectory(coin)

# P1: NMC module tests (AuxPow merkle-walk KAT). Gated on BUILD_TESTING.
if (BUILD_TESTING)
    add_subdirectory(test)
endif()
