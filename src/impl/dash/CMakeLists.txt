# c2pool-dash coin module (V36 / PR-0 foundation decomposition).
#
# S2 scope (project_v36 consensus stage): X11 PoW hashing primitive ONLY.
# DGW v3 retarget is DEFERRED to S3 (header-chain slice); pay/replay to S4/S5.
# No coin binary or daemon slice is wired here yet -- this registers the single
# additive dash_x11 target so its KAT ctest runs on every Linux build. The diff
# is confined to src/impl/dash/* and is SAFE-ADDITIVE: no existing target links
# dash_x11, so ltc/btc/doge/dgb build + ctest surfaces are untouched.
add_subdirectory(crypto)
