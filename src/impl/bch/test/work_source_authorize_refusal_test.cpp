// SPDX-License-Identifier: AGPL-3.0-or-later
//
// BCHWorkSource::authorize_refusal KAT. While the chain mints v34/v35 shares
// (author version < 36) a share can carry only a legacy P2PKH or 20-byte P2SH
// address, so a login whose payout script has neither form (a 32-byte P2SH
// CashAddr) is refused at mining.authorize with a reason, instead of hashing
// for shares create_local_share_v35 never mints.
//
//   P2sh32RefusedWhileV35        FAILS before the fix (no refusal hook)
//   LegacyFormsAccepted          passes both
//   V36AuthorAcceptsEverything   passes both
//
// Runs last from the already-allowlisted bch_g2_block_assembly_roundtrip_test
// (it registers the CashAddr decoder, a process-wide hook, so it must not run
// before checks that expect it unregistered).

#include <impl/bch/coin/cashaddr.hpp>
#include <impl/bch/coin/header_chain.hpp>
#include <impl/bch/coin/mempool.hpp>
#include <impl/bch/stratum/work_source.hpp>

#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {

int g_failures = 0;

#define CHECK(cond, what) do { if (!(cond)) { \
    std::cerr << "  FAIL: " #cond " @ line " << __LINE__ << ": " << what << "\n"; \
    ++g_failures; } } while (0)

struct Rig
{
    bch::coin::BCHChainParams params = bch::coin::BCHChainParams::mainnet();
    bch::coin::HeaderChain    chain{params};
    bch::coin::Mempool        mempool;
    std::unique_ptr<bch::stratum::BCHWorkSource> ws;

    explicit Rig(int64_t author_version)
    {
        ws = std::make_unique<bch::stratum::BCHWorkSource>(
            chain, mempool, /*is_testnet=*/false,
            [](const std::vector<unsigned char>&, uint32_t) { return true; });
        ws->set_author_version_fn([author_version] { return author_version; });
    }
};

// type 1 (P2SH), 32-byte hash: the CashAddr P2SH32 form.
const char* kP2sh32 = "bitcoincash:pwsjyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg246e7p7";

} // namespace

int run_work_source_authorize_refusal_checks()
{
    g_failures = 0;
    bch::coin::cashaddr::register_cashaddr_decoder(false, false);
    try {
        Rig v35(35);
        const std::string why = v35.ws->authorize_refusal(kP2sh32);
        CHECK(!why.empty(), "a P2SH32 login must be refused while the chain mints v35 shares");
        CHECK(why.find("P2PKH") != std::string::npos, "the reason names what to use: " << why);
        std::cout << "[" << (g_failures == 0 ? "PASS" : "FAIL") << "] BchAuthorizeRefusal.P2sh32RefusedWhileV35\n";

        const int before = g_failures;
        for (const char* a : {"1HB1xyKKD2VNd6jU7nz76mP67JpwhvSTGC",
                              "3GKp5kSFoNF5pNtbtFg9HCYUMoW1LM8uJA",
                              "qqkhp32tj4w28ytwy5d3nqylnjznpnn9xgfntddexd",
                              "bitcoincash:pzckd7jtwpgfvt3pznjr2v2lzel3vsn95v6xgypwr3"})
            CHECK(v35.ws->authorize_refusal(a).empty(), a << " has a v35 form and must be accepted");
        std::cout << "[" << (g_failures == before ? "PASS" : "FAIL") << "] BchAuthorizeRefusal.LegacyFormsAccepted\n";

        // The stratum server also asks about an EMPTY login now (core
        // stratum_server.cpp mining.authorize): BCH has no reason to refuse
        // one, so an empty login keeps today's outcome on BCH.
        const int before_empty = g_failures;
        CHECK(v35.ws->authorize_refusal("").empty(), "an empty login must keep today's outcome on BCH");
        std::cout << "[" << (g_failures == before_empty ? "PASS" : "FAIL") << "] BchAuthorizeRefusal.EmptyLoginNotRefused\n";

        const int before36 = g_failures;
        Rig v36(36);
        CHECK(v36.ws->authorize_refusal(kP2sh32).empty(), "v36 shares carry the script: no refusal");
        CHECK(v36.ws->authorize_refusal("").empty(), "an empty login must keep today's outcome on BCH");
        std::cout << "[" << (g_failures == before36 ? "PASS" : "FAIL") << "] BchAuthorizeRefusal.V36AuthorAcceptsEverything\n";
    } catch (const std::exception& e) {
        std::cerr << "  FAIL: threw: " << e.what() << "\n";
        ++g_failures;
    }
    return g_failures;
}
