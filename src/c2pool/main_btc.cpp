// c2pool-btc — Bitcoin embedded SPV p2pool node.
//
// PR-B0/B1/B2 SCAFFOLD: this is still a stub entry point. The real wiring —
// arg parsing, io_context, header chain, UTXO bootstrap, mempool, template
// builder, stratum server, web dashboard — lands in subsequent B-phases per
// frstrtr/the/docs/c2pool-btc-embedded-impl-plan.md. The full LTC entry
// point at src/c2pool/c2pool_refactored.cpp (~90 KB) is the porting source.
//
// What's done so far:
//   B0  scaffold src/impl/btc/ from LTC template (e107b10d)
//   B1  constants + PoW swap to SHA256d, jtoomim/SPB v35 + protocol 3502
//       BTC chain params (PoolConfig identifier fc70035c7a81bc6f, prefix
//       2472ef181efcd37b, port 9333), bitcoind protocol 70016
//   B2  header_chain.hpp: BTCChainParams with mainnet/testnet/testnet4
//       factories, BTC genesis + DAA constants (1209600s/600s, 2016 blocks),
//       SHA256d PoW. Log prefixes [LTC] -> [BTC].
//
// What's still owed for a usable c2pool-btc:
//   B2-net  smoke-test header sync against testnet4 bitcoind (port 48333,
//           genesis 00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043)
//   B3      mempool + template builder, surgical MWEB strip (transaction.hpp
//           m_hogEx, block.hpp m_mweb_raw, template_builder.hpp MWEBBuilder,
//           rpc.cpp "mweb" rule)
//   B4      sharechain + stratum (port LTC's path; v35 share format)
//   B5      P2P block submit + roundtrip
//   B6      parity validation harness vs bitcoind RPC
//
// Reference wiring (commented; see c2pool_refactored.cpp:1700-1800 for the
// actual LTC equivalent that this needs to mirror):
//
//   #include <impl/btc/coin/header_chain.hpp>
//   #include <impl/btc/coin/node.hpp>
//   #include <impl/btc/config_pool.hpp>
//   #include <boost/asio.hpp>
//
//   int main(int argc, char* argv[]) {
//       // 1. Parse args: --testnet, --testnet4, --bootstrap host:port,
//       //    --bitcoind-p2p host:port
//       // 2. boost::asio::io_context ioc;
//       // 3. Build BTCChainParams (mainnet/testnet/testnet4 factory)
//       // 4. Construct btc::coin::HeaderChain<...>
//       // 5. Construct btc::PoolConfig (loaded from pool.yaml)
//       // 6. Construct btc::coin::Node<btc::PoolConfig> coin_node(&ioc, &config)
//       // 7. coin_node.start_p2p(NetService(host, 8333|18333|48333))
//       // 8. Wire HeaderChain to coin_node->new_headers event
//       // 9. ioc.run()
//   }

int main(int /*argc*/, char* /*argv*/[])
{
    return 0;
}
