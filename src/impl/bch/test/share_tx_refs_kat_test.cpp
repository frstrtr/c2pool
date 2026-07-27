// ---------------------------------------------------------------------------
// bch::new_tx_hashes accessor KAT -- the guard for the #905 send-side fix.
//
// #905: BCH's tx-forwarding SEND path (node.cpp send_shares) probed
// `requires { obj->m_new_transaction_hashes; }` directly on the share object.
// That FLAT probe is false for EVERY BCH share variant -- v17/v33 nest the list
// inside m_tx_info, v34/v35/v36 carry no list at all -- so the whole needed_txs
// forwarding block was dead code and BCH forwarded no tx bytes. share_tx_refs.hpp
// replaces the flat probe with bch::new_tx_hashes(), which returns the nested
// list for v17/v33 and nullptr for v34+.
//
// This test pins two things so the regression cannot silently return:
//   A. Compile-time topology (static_assert): the FLAT spelling is absent on
//      every variant (== the old probe was dead), the NESTED spelling is present
//      exactly on v17/v33, and new_tx_hashes() selects the right branch.
//   B. Runtime behaviour: the accessor delivers the v17/v33 list by reference
//      (send loop sees every referenced hash) and returns nullptr for v34+.
//
// Build-INERT wrt consensus surface: pure header-only over share.hpp +
// share_tx_refs.hpp, no node/RPC. p2pool-merged-v36 surface: NONE (this is a
// LOCAL relay-plumbing accessor; the share wire-format is unchanged).
// ---------------------------------------------------------------------------

#include <iostream>
#include <type_traits>
#include <vector>

#include <core/uint256.hpp>

#include "../share.hpp"
#include "../share_tx_refs.hpp"

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

// ---- A. Compile-time topology --------------------------------------------
// The FLAT spelling the old probe assumed is absent on EVERY variant: that is
// precisely why the old send path was dead. Held here so it stays absent.
static_assert(!bch::has_flat_new_tx_hashes<bch::Share>,              "v17 must NOT expose the flat list");
static_assert(!bch::has_flat_new_tx_hashes<bch::NewShare>,          "v33 must NOT expose the flat list");
static_assert(!bch::has_flat_new_tx_hashes<bch::SegwitMiningShare>,  "v34 must NOT expose the flat list");
static_assert(!bch::has_flat_new_tx_hashes<bch::PaddingBugfixShare>, "v35 must NOT expose the flat list");
static_assert(!bch::has_flat_new_tx_hashes<bch::MergedMiningShare>,  "v36 must NOT expose the flat list");

// The NESTED spelling is present exactly on v17/v33 (which carry m_tx_info) and
// absent on v34+ (SegWit-less variants carry no new-tx list).
static_assert(bch::has_nested_new_tx_hashes<bch::Share>,              "v17 must nest the list in m_tx_info");
static_assert(bch::has_nested_new_tx_hashes<bch::NewShare>,          "v33 must nest the list in m_tx_info");
static_assert(!bch::has_nested_new_tx_hashes<bch::SegwitMiningShare>,  "v34 carries no new-tx list");
static_assert(!bch::has_nested_new_tx_hashes<bch::PaddingBugfixShare>, "v35 carries no new-tx list");
static_assert(!bch::has_nested_new_tx_hashes<bch::MergedMiningShare>,  "v36 carries no new-tx list");

// new_tx_hashes() selects a non-null pointer branch for v17/v33 and the null
// pointer branch for v34+ -- checked at compile time on the return type / at run
// time on the value below.
template <typename S>
constexpr bool returns_null_branch =
    std::is_same_v<decltype(bch::new_tx_hashes(std::declval<S*>())),
                   const std::vector<uint256>*>;
static_assert(returns_null_branch<bch::SegwitMiningShare>,  "v34 accessor must be the null branch");
static_assert(returns_null_branch<bch::PaddingBugfixShare>, "v35 accessor must be the null branch");
static_assert(returns_null_branch<bch::MergedMiningShare>,  "v36 accessor must be the null branch");

// ---- B. Runtime behaviour -------------------------------------------------

// Reproduce the send-side loop over the accessor result and count the hashes it
// would forward -- this is exactly what node.cpp send_shares now does.
template <typename ShareVariant>
std::size_t forwardable_count(ShareVariant& s)
{
    std::size_t n = 0;
    const auto* new_txs = bch::new_tx_hashes(&s);
    if (!new_txs)
        return 0;
    for (const auto& th : *new_txs)
    {
        (void)th;
        ++n;
    }
    return n;
}

void test_v17_v33_deliver_nested_list()
{
    bch::Share s17;
    s17.m_tx_info.m_new_transaction_hashes = {uint256(1), uint256(2), uint256(3)};

    const auto* p = bch::new_tx_hashes(&s17);
    CHECK(p != nullptr);
    // Same object, by reference -- no copy: the send path reads the live list.
    CHECK(p == &s17.m_tx_info.m_new_transaction_hashes);
    CHECK(p->size() == 3);
    CHECK(forwardable_count(s17) == 3);

    bch::NewShare s33;
    s33.m_tx_info.m_new_transaction_hashes = {uint256(7)};
    CHECK(bch::new_tx_hashes(&s33) != nullptr);
    CHECK(forwardable_count(s33) == 1);

    // Empty nested list: accessor non-null, nothing to forward (not the same as
    // "no list" -- a v17 share with no new txs still probes cleanly).
    bch::Share s17_empty;
    CHECK(bch::new_tx_hashes(&s17_empty) != nullptr);
    CHECK(forwardable_count(s17_empty) == 0);
}

void test_v34plus_have_no_list()
{
    bch::SegwitMiningShare s34;
    bch::PaddingBugfixShare s35;
    bch::MergedMiningShare  s36;
    CHECK(bch::new_tx_hashes(&s34) == nullptr);
    CHECK(bch::new_tx_hashes(&s35) == nullptr);
    CHECK(bch::new_tx_hashes(&s36) == nullptr);
    CHECK(forwardable_count(s34) == 0);
    CHECK(forwardable_count(s35) == 0);
    CHECK(forwardable_count(s36) == 0);
}

} // namespace

int main()
{
    test_v17_v33_deliver_nested_list();
    test_v34plus_have_no_list();

    if (failures)
    {
        std::cerr << failures << " CHECK(s) failed\n";
        return 1;
    }
    std::cout << "bch_share_tx_refs_kat_test: OK\n";
    return 0;
}
