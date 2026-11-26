// SPDX-License-Identifier: AGPL-3.0-or-later
//
// v35 gentx KATs on the REAL bch::ShareTracker / generate_share_transaction /
// verify_share / create_local_share_v35 code paths.
//
//   RealShareGentxMatchesPublicNode   public share 00000000000000024caa7c33...
//       (absheight 4666976) with its full 4,319-share PPLNS window. The rebuilt
//       gentx is txid 15ef67f0... and byte-identical to the public node's
//       /web/share gentx.raw, and verify_share() accepts the share. Negative
//       witness: the deployed build's rule (registry without a CashAddr decoder,
//       raw-bytes fallback) gives 70ea74de..., the txid it logged as expected.
//                                                   FAILS before the fix
//   TwoAddressesOneScriptStaySeparate one script under three strings (q...,
//       bitcoincash:q..., 1...), an amount tie whose string order is not its
//       script order, and a miner using python's donation_address. Python pays
//       the three strings as three outputs and sorts the tie by string; expected
//       bytes from the python rule (tools/verify_gentx.py PY mode).
//                                                   FAILS before the fix
//   LocalShareIsVerifiable  our own v35 share (create_local_share_v35) carries
//       the python address form for its script and passes verify_share(); a
//       script with no v35 address form is refused.  FAILS before the fix
//
// HARNESS: plain int main()/CHECK. Runs from the already-allowlisted
// bch_embedded_block_broadcast_test executable (run_v35_gentx_kat_checks()).
// Fixture: test/fixtures/v35_real_share (raw share contents as in the store,
// the window as "bits donation address-index" rows, the public gentx.raw).

#include <impl/bch/share.hpp>
#include <impl/bch/share_tracker.hpp>

#include <core/address_utils.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <exception>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#ifndef BCH_V35_KAT_DIR
#error "BCH_V35_KAT_DIR must point at src/impl/bch/test/fixtures/v35_real_share"
#endif

namespace {

int g_failures = 0;
int g_case_failures = 0;

#define CHECK(cond, what) do { if (!(cond)) { \
    std::cerr << "  FAIL: " #cond " @ line " << __LINE__ << ": " << what << "\n"; \
    ++g_case_failures; } } while (0)
#define REQUIRE(cond, what) do { if (!(cond)) { \
    std::cerr << "  FAIL: " #cond " @ line " << __LINE__ << ": " << what << "\n"; \
    ++g_case_failures; return; } } while (0)

std::string hex(const std::vector<unsigned char>& v)
{
    static const char* H = "0123456789abcdef";
    std::string s;
    for (unsigned char b : v) { s += H[b >> 4]; s += H[b & 15]; }
    return s;
}

std::vector<unsigned char> unhex(const std::string& s)
{
    std::vector<unsigned char> out;
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<unsigned char>(std::stoul(s.substr(i, 2), nullptr, 16)));
    return out;
}

std::string read_file(const std::string& name)
{
    std::ifstream f(std::string(BCH_V35_KAT_DIR) + "/" + name);
    std::stringstream ss;
    ss << f.rdbuf();
    std::string s = ss.str();
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
        s.pop_back();
    return s;
}

uint256 u256(const std::string& display_hex)
{
    uint256 v;
    v.SetHex(display_hex);
    return v;
}

// A synthetic, unique share hash for window row i.
uint256 row_hash(uint32_t i)
{
    // uint256::begin() yields the eight 32-bit limbs (little-endian), not
    // bytes: limb 0 carries i, the top limb carries the 0x5a35 tag.
    uint256 h;
    h.SetNull();
    h.begin()[0] = i;
    h.begin()[7] = 0x5a350000u;
    return h;
}

struct Row { uint32_t bits; uint16_t donation; std::string address; };

// The public share and its parent, restored as node.cpp loads the store:
// load_share(35, contents), then m_hash from the store key.
const char* kTipHash    = "00000000000000024caa7c331324405ca75f1bc4363bc84f62780505a7f7988b";
const char* kParentHash = "00000000000000258a55e7f8d1962cba7117091a90fc0b562166392e85a9fe4a";
constexpr uint64_t kSubsidy   = 312633082;
constexpr uint32_t kBlockBits = 0x18023173;

bch::ShareType load_fixture_share(const std::string& file, const char* hash)
{
    auto bytes = unhex(read_file(file));
    PackStream ps(bytes);
    auto share = bch::load_share(35, ps, NetService{"kat", 0});
    const uint256 h = u256(hash);
    share.ACTION({ obj->m_hash = h; });
    return share;
}

// tracker := rows (deepest first, row 0 is the parent's parent and gets the
// real hash parent.m_prev_hash), then the parent, then the tip.
void build(bch::ShareTracker& tracker, const std::vector<Row>& rows, bool with_tip = true)
{
    auto parent = load_fixture_share("parent_share.hex", kParentHash);
    uint256 grandparent;
    parent.ACTION({ grandparent = obj->m_prev_hash; });
    for (size_t k = rows.size(); k-- > 0;)
    {
        const uint256 h = (k == 0) ? grandparent : row_hash(static_cast<uint32_t>(k));
        const uint256 prev = (k + 1 < rows.size()) ? row_hash(static_cast<uint32_t>(k + 1)) : uint256();
        auto* s = new bch::PaddingBugfixShare(h, prev);
        s->m_bits = rows[k].bits;
        s->m_max_bits = rows[k].bits;
        s->m_donation = rows[k].donation;
        s->m_desired_version = 35;
        s->m_address.m_data.assign(rows[k].address.begin(), rows[k].address.end());
        s->m_min_header.m_bits = kBlockBits;
        tracker.add(s);
    }
    tracker.add(parent);
    if (with_tip)
        tracker.add(load_fixture_share("tip_share.hex", kTipHash));
}

std::vector<Row> load_window()
{
    std::ifstream f(std::string(BCH_V35_KAT_DIR) + "/window_compact.txt");
    std::vector<std::string> table;
    std::vector<Row> rows;
    std::string line;
    while (std::getline(f, line))
    {
        if (line.empty() || line[0] == '#')
            continue;
        std::istringstream ls(line);
        if (line[0] == 'A')
        {
            std::string tag, addr;
            size_t idx = 0;
            ls >> tag >> idx >> addr;
            if (table.size() <= idx) table.resize(idx + 1);
            table[idx] = addr;
            continue;
        }
        std::string bits_hex;
        unsigned don = 0;
        size_t idx = 0;
        ls >> bits_hex >> don >> idx;
        rows.push_back({static_cast<uint32_t>(std::stoul(bits_hex, nullptr, 16)),
                        static_cast<uint16_t>(don), table.at(idx)});
    }
    return rows;
}

template <typename Fn>
void with_tip(bch::ShareTracker& tracker, Fn&& fn)
{
    tracker.chain.get_share(u256(kTipHash)).invoke([&](auto* obj) {
        using ST = std::remove_pointer_t<decltype(obj)>;
        if constexpr (std::is_same_v<ST, bch::PaddingBugfixShare>)
            fn(*obj);
    });
}

void RealShareGentxMatchesPublicNode()
{
    const auto rows = load_window();
    REQUIRE(rows.size() == 4319, "window rows: " << rows.size());
    bch::ShareTracker tracker;
    build(tracker, rows);

    const std::string expected_raw = read_file("expected_gentx.hex");
    bool ran = false;
    with_tip(tracker, [&](const bch::PaddingBugfixShare& tip) {
        ran = true;
        std::vector<unsigned char> bytes;
        const uint256 txid = bch::generate_share_transaction(tip, tracker, false, false, &bytes);
        CHECK(txid.GetHex() == "15ef67f0eb32e97e7d99f7035cfbf68f4592c3c7fe61baffd24a28d745d66d0b",
              "committed gentx txid, got " << txid.GetHex());
        CHECK(hex(bytes) == expected_raw, "gentx bytes differ from the public /web/share gentx.raw");

        // The whole check: init (ref_hash, hash_link, merkle, header) + the
        // gentx rebuild against the hash the share commits to.
        uint256 verified;
        try {
            verified = bch::verify_share(tip, tracker);
        } catch (const std::exception& e) {
            CHECK(false, "verify_share threw: " << e.what());
        }
        CHECK(verified.GetHex() == kTipHash, "verify_share hash " << verified.GetHex());

        // Negative witness: the deployed build's rule. core::address_to_script
        // with no CashAddr decoder registered (as in this executable), else the
        // raw address bytes; sorted by (amount, script).
        auto v35 = bch::compute_v35_gentx_outputs(
            tracker, tip.m_prev_hash, chain::bits_to_target(tip.m_min_header.m_bits),
            tip.m_subsidy, tip.m_address.m_data);
        std::vector<std::pair<std::vector<unsigned char>, uint64_t>> old_outs;
        for (size_t i = 0; i < v35.payouts.size(); ++i)
        {
            const auto& key = v35.payout_keys[i];
            auto s = core::address_to_script(std::string(key.begin(), key.end()));
            if (s.empty())
                s = key;
            old_outs.emplace_back(s, v35.payouts[i].second);
        }
        std::sort(old_outs.begin(), old_outs.end(), [](const auto& a, const auto& b) {
            if (a.second != b.second) return a.second < b.second;
            return a.first < b.first;
        });
        // prefix (version, input, coinbase: 50 bytes) | count | payouts |
        // donation (76 bytes) + OP_RETURN (55 bytes incl. locktime) from the real gentx.
        const auto real = unhex(expected_raw);
        std::vector<unsigned char> old_tx(real.begin(), real.begin() + 50);
        old_tx.push_back(static_cast<unsigned char>(old_outs.size() + 2));
        for (const auto& [s, a] : old_outs)
        {
            for (int b = 0; b < 8; ++b) old_tx.push_back(static_cast<unsigned char>((a >> (8 * b)) & 0xff));
            old_tx.push_back(static_cast<unsigned char>(s.size()));
            old_tx.insert(old_tx.end(), s.begin(), s.end());
        }
        old_tx.insert(old_tx.end(), real.end() - (76 + 55), real.end());
        const uint256 old_txid = Hash(std::span<const unsigned char>(old_tx.data(), old_tx.size()));
        CHECK(old_txid.GetHex() == "70ea74deb796fbcc7e5e3b9650b6193d3387cda72c6c9f9d18749ebd6040ad68",
              "the deployed rule's txid (what the live node expected), got " << old_txid.GetHex());
    });
    CHECK(ran, "tip share not found in the tracker");
}

const std::string X_Q = "qzkudacn5t5uye5suyrrnvdxt3x6pthfgcqexjz6t6";
const std::string X_P = "bitcoincash:qzkudacn5t5uye5suyrrnvdxt3x6pthfgcqexjz6t6";
const std::string X_L = "1GqrFXaSRVxc8SnWag1teZ7yvXTMZvsmTB";
const std::string X_SCRIPT = "76a914adc6f713a2e9c26690e10639b1a65c4da0aee94688ac";
constexpr uint32_t B1 = 0x197d7a24, B2 = 0x1a0e88af;

std::vector<Row> dup_rows()
{
    return {
        {B1, 0, X_Q}, {B1, 0, X_L}, {B1, 50, X_P}, {B2, 0, X_L},
        {B1, 0, "3GKp5kSFoNF5pNtbtFg9HCYUMoW1LM8uJA"},          // tie with the next row
        {B1, 0, "qqkhp32tj4w28ytwy5d3nqylnjznpnn9xgfntddexd"},  //   (string order != script order)
        {B1, 0, "1Kz5QaUPDtKrj5SqW5tFkn7WZh8LmQaQi4"},          // python donation_address
        {B1, 0, "qr4zpqdj3jnzpth8ph28wqnd89hqrfkeaux7p8hyw5"},  // the tip's own address
        {B1, 0, X_L}, {B2, 0, X_Q},
        {B1, 25, "16mN1NkJNE9dL2JyFsBRwGuyRYo4zFiEd5"},
        {B1, 0, X_P},
    };
}

void TwoAddressesOneScriptStaySeparate()
{
    bch::ShareTracker tracker;
    build(tracker, dup_rows());   // 12 rows, the last with no parent (chain start)

    // python rule (tools/verify_gentx.py PY mode, donation_address = the real string)
    const std::string python_raw =
        "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff04036df00effffffff09"
        "8e4bd701000000001976a9143f3c776fe4917f71940f6f43bca9811c64cf0df388ac"
        "9979d7010000000017a914a08744576dd18836ef25929eeaf29a511817425587"
        "9979d701000000001976a9142d70c54b955ca3916e251b19809f9c8530ce653288ac"
        "0760e701000000001976a914adc6f713a2e9c26690e10639b1a65c4da0aee94688ac"
        "b653ef01000000001976a914ea2081b28ca620aee70dd477026d396e01a6d9ef88ac"
        "1d97ae03000000001976a914adc6f713a2e9c26690e10639b1a65c4da0aee94688ac"
        "a1d9be03000000001976a914adc6f713a2e9c26690e10639b1a65c4da0aee94688ac"
        "bf03d80100000000434104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac"
        "00000000000000002a6a28c1f40c506a15b288006ff8af4d91c16ec31cd039cfdb588193506e100598e21b000000001f000000"
        "00000000";
    bool ran = false;
    with_tip(tracker, [&](const bch::PaddingBugfixShare& tip) {
        ran = true;
        std::vector<unsigned char> bytes;
        const uint256 txid = bch::generate_share_transaction(tip, tracker, false, false, &bytes);
        CHECK(txid.GetHex() == "ffddab278a24f2d0402f5a49bcaa3b65254bf47309a0eeedcbb3719d75d18934",
              "python txid, got " << txid.GetHex());
        CHECK(hex(bytes) == python_raw, "gentx bytes differ from the python rule:\n  got " << hex(bytes));

        auto v35 = bch::compute_v35_gentx_outputs(
            tracker, tip.m_prev_hash, chain::bits_to_target(tip.m_min_header.m_bits),
            tip.m_subsidy, tip.m_address.m_data);
        size_t x_outputs = 0;
        std::map<std::string, uint64_t> by_key;
        for (size_t i = 0; i < v35.payouts.size(); ++i)
        {
            if (hex(v35.payouts[i].first) == X_SCRIPT) ++x_outputs;
            by_key[std::string(v35.payout_keys[i].begin(), v35.payout_keys[i].end())] = v35.payouts[i].second;
        }
        CHECK(x_outputs == 3, "one script under three strings must be three outputs, got " << x_outputs);
        CHECK(by_key.count(X_Q) && by_key.count(X_P) && by_key.count(X_L), "each string has its own output");
        CHECK(!by_key.count("1Kz5QaUPDtKrj5SqW5tFkn7WZh8LmQaQi4"),
              "python's donation_address is paid inside the donation output");
        CHECK(v35.donation_amount == 30933951, "donation " << v35.donation_amount);

        // The script-keyed read model (dashboard / generic stratum map) sums the
        // three strings' python amounts for script X; no finder fee there.
        auto payouts = tracker.get_v35_expected_payouts(
            tip.m_prev_hash, chain::bits_to_target(tip.m_min_header.m_bits), tip.m_subsidy,
            bch::PoolConfig::get_donation_script(35));
        const uint64_t x_sum = by_key[X_Q] + by_key[X_P] + by_key[X_L];
        CHECK(static_cast<uint64_t>(payouts[unhex(X_SCRIPT)]) == x_sum,
              "script X total " << static_cast<uint64_t>(payouts[unhex(X_SCRIPT)]) << " != " << x_sum);
        CHECK(!payouts.count(unhex("76a914d03da6fca390166d020be0e7c28ac8cc70f5840388ac")),
              "no P2PKH output for the donation_address string");
    });
    CHECK(ran, "tip share not found in the tracker");
}

void LocalShareIsVerifiable()
{
    bch::ShareTracker tracker;
    const auto rows = dup_rows();
    build(tracker, rows, /*with_tip=*/false);
    const uint256 prev = u256(kParentHash);

    bch::coin::SmallBlockHeaderType hdr;
    hdr.m_version = 0x20000000;
    hdr.m_previous_block = u256("000000000000000001a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708");
    hdr.m_timestamp = static_cast<uint32_t>(std::time(nullptr));
    hdr.m_bits = kBlockBits;
    const BaseScript coinbase(std::vector<unsigned char>{0x03, 0x6e, 0xf0, 0x0e, 0x04, 'k', 'a', 't', '!'});
    constexpr uint32_t kEasyBits = 0x207fffff;   // share target ~2^255: about half the nonces pass

    // Script X: our own share writes its legacy form, which python keys
    // together with the window's 1Gqr... string and apart from the q... ones.
    const auto script = unhex(X_SCRIPT);
    uint256 created;
    for (uint32_t nonce = 0; nonce < 128 && created.IsNull(); ++nonce)
    {
        hdr.m_nonce = nonce;
        created = bch::create_local_share_v35(
            tracker, hdr, coinbase, kSubsidy, prev, {}, script, /*donation*/ 66,
            bch::StaleInfo::none, false, {}, {}, uint256(), kEasyBits, kEasyBits);
    }
    REQUIRE(!created.IsNull(), "create_local_share_v35 produced no share in 128 nonces");

    bool ran = false;
    tracker.chain.get_share(created).invoke([&](auto* obj) {
        using ST = std::remove_pointer_t<decltype(obj)>;
        if constexpr (std::is_same_v<ST, bch::PaddingBugfixShare>)
        {
            ran = true;
            const std::string addr(obj->m_address.m_data.begin(), obj->m_address.m_data.end());
            CHECK(addr == X_L, "own share address: python script2_to_address form " << X_L << ", got " << addr);
            CHECK(hex(bch::get_share_script(obj)) == X_SCRIPT, "own share address round-trips to its script");
            uint256 verified;
            try {
                verified = bch::verify_share(*obj, tracker);
            } catch (const std::exception& e) {
                CHECK(false, "verify_share of our own share threw: " << e.what());
            }
            CHECK(verified == created, "recomputed share hash " << verified.GetHex()
                                       << " != created " << created.GetHex());
        }
    });
    CHECK(ran, "created share is not a v35 share");

    // P2WPKH has no v35 address form: refuse to mint.
    std::vector<unsigned char> p2wpkh = {0x00, 0x14};
    p2wpkh.insert(p2wpkh.end(), 20, 0x42);
    // The refusal comes before the PoW check, so one call settles it.
    hdr.m_nonce = 1000;
    const uint256 refused = bch::create_local_share_v35(
        tracker, hdr, coinbase, kSubsidy, prev, {}, p2wpkh, 66,
        bch::StaleInfo::none, false, {}, {}, uint256(), kEasyBits, kEasyBits);
    CHECK(refused.IsNull(), "a P2WPKH payout must not be minted into a v35 share");
}

void run_case(const char* name, void (*fn)())
{
    g_case_failures = 0;
    try {
        fn();
    } catch (const std::exception& e) {
        std::cerr << "  FAIL: threw: " << e.what() << "\n";
        ++g_case_failures;
    }
    std::cout << "[" << (g_case_failures == 0 ? "PASS" : "FAIL") << "] BchV35Gentx."
              << name << "\n";
    g_failures += g_case_failures;
}

} // namespace

int run_v35_gentx_kat_checks()
{
    g_failures = 0;
    run_case("RealShareGentxMatchesPublicNode", RealShareGentxMatchesPublicNode);
    run_case("TwoAddressesOneScriptStaySeparate", TwoAddressesOneScriptStaySeparate);
    run_case("LocalShareIsVerifiable", LocalShareIsVerifiable);
    return g_failures;
}
