// c2pool-btc: PR-B0 scaffold stub.
//
// The real entry point — header sync, mempool, template builder, stratum,
// embedded SPV against bitcoind P2P, sharechain at v35 + protocol 3502
// (jtoomim/SPB BTC p2pool live network) — lands in subsequent phases per
// frstrtr/the/docs/c2pool-btc-embedded-impl-plan.md.
//
// For B0 the goal is compile-clean + linkage verified against the btc
// library (cloned from src/impl/ltc with namespace rename + MWEB still
// dead-code present, swept out in B3).

int main(int /*argc*/, char* /*argv*/[])
{
    return 0;
}
