# BIP-110 (Bitcoin Knots BLAKE2b hard fork) lane. M1 = daemonless SPV header
# follower (coin/, cloned from btc/coin). M3 = the v36 sharechain lane (pool/).
# The lane-local BLAKE2b primitive (crypto/blake2b.c) is compiled into the
# c2pool-bip110 exe + the KAT targets directly (see src/c2pool/CMakeLists.txt and
# pool/CMakeLists.txt), so it is not built into a library here.
add_subdirectory(coin)
add_subdirectory(pool)   # M3 PR-A: v36 sharechain lane foundation + identity KAT
