# BIP-110 (Bitcoin Knots BLAKE2b hard fork) lane. M1 = daemonless SPV header
# follower. Only the coin-network SPV layer is built here (cloned from btc/coin);
# the pool-side sharechain/stratum runtime lands in a later slice. The lane-local
# BLAKE2b primitive (crypto/blake2b.c) is compiled into the c2pool-bip110 exe +
# the KAT targets directly (see src/c2pool/CMakeLists.txt), so it is not built
# into a library here.
add_subdirectory(coin)
