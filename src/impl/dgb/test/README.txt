DGB module tests (M3). Mirror src/impl/btc/test: template_parity_test (vs
p2pool-merged-v36 reference fixtures), share_test (Scrypt shares == LTC format).
Adds: Scrypt block-validation fixtures; multi-algo handling test (non-Scrypt
headers accepted-by-continuity, never PoW-validated, never rejected on algo);
DigiShield per-algo retarget vectors (Scrypt lane). DOGE-aux integration tests
under -DAUX_DOGE=ON are STRETCH (§X), deferred behind Phase 5.8. Stub at M2.
