// SPDX-License-Identifier: AGPL-3.0-or-later
//
// v34/v35 share address -> script KAT (bch::v35_address_to_script) and the
// address our own v35 shares carry (bch::v35_script_to_address).
//
// The deployed c2pool-bch decoded a v35 share's payout address through the
// process-wide core address registry and, when that failed, used the address
// STRING BYTES as the scriptPubKey. The CashAddr decoder was never registered
// in that build, so every CashAddr payout became ASCII and no gentx matched.
// These vectors run with no decoder registered: the rule is self-contained.
//
// Expected values come from the python rule itself: a py3 transliteration of
// kr1z1sBCH c198121 bitcoin/data.py address_to_script2 (padding_bugfix=True)
// that runs util/cash_addr.py and util/math.py convertbits verbatim. "ERR"
// means python raises, so the share is invalid.
//
//   RealChainAndEdgeVectors           FAILS before the fix (raw-bytes fallback,
//                                     BCHN codec for 32-byte / token types,
//                                     core base58 skipping spaces)
//   RuleNeedsNoRegisteredDecoder      FAILS before the fix
//   OwnShareAddressRoundTrips         FAILS before the fix (Litecoin version bytes)
//   DonationAddressIsTheP2pkForm      pins the python donation_script_to_address
//
// HARNESS: plain int main()/CHECK (no GTest in the bch tree). This TU exposes
// run_v35_address_kat_checks() and rides the already-allowlisted
// bch_embedded_block_broadcast_test executable.

#include <impl/bch/v35_address.hpp>

#include <core/address_utils.hpp>
#include <btclibs/crypto/ripemd160.h>
#include <btclibs/crypto/sha256.h>

#include <cstdint>
#include <exception>
#include <iostream>
#include <string>
#include <vector>

namespace {

int g_failures = 0;
int g_case_failures = 0;

#define CHECK(cond, what) do { if (!(cond)) { \
    std::cerr << "  FAIL: " #cond " @ line " << __LINE__ << ": " << what << "\n"; \
    ++g_case_failures; } } while (0)

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

// What v35_address_to_script returns: the script hex, or "ERR".
std::string rule(const std::string& addr, bool testnet)
{
    try {
        return hex(bch::v35_address_to_script(addr, bch::v35_net(testnet)));
    } catch (const bch::V35AddressError&) {
        return "ERR";
    }
}

struct Vector { const char* addr; bool testnet; const char* python; };

// {address, testnet, python result}. "ERR:<exception>" = python raises.
const Vector kVectors[] = {
    // Every address string in the PPLNS window of public share 0000...24caa7c3.
    {"16mN1NkJNE9dL2JyFsBRwGuyRYo4zFiEd5", false, "76a9143f3c776fe4917f71940f6f43bca9811c64cf0df388ac"},
    {"18hpvfv1pJTocxr7PqVWbAQmioHH8xULoE", false, "76a91454818668aac8b65ef3795e3eec45f22dbba2b81888ac"},
    {"1HB1xyKKD2VNd6jU7nz76mP67JpwhvSTGC", false, "76a914b166fa4b7050962e2114e435315f167f164265a388ac"},
    {"3CUjhj778GuxdjszSvsCSLvk5FqatMZNSg", false, "a9147656d9faf93a415e4cc81db00c9c507e88eefc7e87"},
    {"3GKp5kSFoNF5pNtbtFg9HCYUMoW1LM8uJA", false, "a914a08744576dd18836ef25929eeaf29a511817425587"},
    {"bitcoincash:qpkkfys874f5vjcphqwlhn54jaqaccxqkguta6zzru", false, "76a9146d649207f553464b01b81dfbce959741dc60c0b288ac"},
    {"bitcoincash:qpwehj6evdqlsujt45jzdzqmw2y8ahylugpxvfjkfr", false, "76a9145d9bcb596341f8724bad2426881b72887edc9fe288ac"},
    {"bitcoincash:qz20h6v68vzm4hu2lal4p68taqer5eeqnywgmrf7me", false, "76a91494fbe99a3b05badf8aff7f50e8ebe8323a67209988ac"},
    {"qpjmf2qg2tnmks3k34qse7srwlq99fdgcu42plm92f", false, "76a91465b4a80852e7bb42368d410cfa0377c052a5a8c788ac"},
    {"qpwmwln8yfpkkvjl8kqnw20qk655a73utuhevrsu9d", false, "76a9145db77e6722436b325f3d813729e0b6a94efa3c5f88ac"},
    {"qq32xew5ne504zr5ypkypxrk7vus8mqplcp2c6e3t2", false, "76a91422a365d49e68fa8874206c409876f33903ec01fe88ac"},
    {"qqkhp32tj4w28ytwy5d3nqylnjznpnn9xgfntddexd", false, "76a9142d70c54b955ca3916e251b19809f9c8530ce653288ac"},
    {"qqmzqyv52x2hhz6lchnhmlrkmvgy6nd3uqsm4ur4g3", false, "76a9143620119451957b8b5fc5e77dfc76db104d4db1e088ac"},
    {"qqtuua44d9mrmnawh0hg5mzp7r8apqw9rvqlxzg9c6", false, "76a91417ce76b569763dcfaebbee8a6c41f0cfd081c51b88ac"},
    {"qr4zpqdj3jnzpth8ph28wqnd89hqrfkeaux7p8hyw5", false, "76a914ea2081b28ca620aee70dd477026d396e01a6d9ef88ac"},
    {"qrhx22sej50hnvtdm5celd9q537qj9wt7uayhl46fq", false, "76a914ee652a19951f79b16ddd319fb4a0a47c0915cbf788ac"},
    {"qrkmy0tgs4t9646m7vp0pt4v2mmmmjcpm5dzjna0e7", false, "76a914edb23d6885565d575bf302f0aeac56f7bdcb01dd88ac"},
    {"qzkudacn5t5uye5suyrrnvdxt3x6pthfgcqexjz6t6", false, "76a914adc6f713a2e9c26690e10639b1a65c4da0aee94688ac"},
    // The same miner's script under its legacy string (chain history, abs 4656602-4657744).
    {"1GqrFXaSRVxc8SnWag1teZ7yvXTMZvsmTB", false, "76a914adc6f713a2e9c26690e10639b1a65c4da0aee94688ac"},
    // With and without the prefix, upper case, mixed case.
    {"bitcoincash:qqkhp32tj4w28ytwy5d3nqylnjznpnn9xgfntddexd", false, "76a9142d70c54b955ca3916e251b19809f9c8530ce653288ac"},
    {"qpwehj6evdqlsujt45jzdzqmw2y8ahylugpxvfjkfr", false, "76a9145d9bcb596341f8724bad2426881b72887edc9fe288ac"},
    {"QQKHP32TJ4W28YTWY5D3NQYLNJZNPNN9XGFNTDDEXD", false, "76a9142d70c54b955ca3916e251b19809f9c8530ce653288ac"},
    {"BITCOINCASH:QPWEHJ6EVDQLSUJT45JZDZQMW2Y8AHYLUGPXVFJKFR", false, "76a9145d9bcb596341f8724bad2426881b72887edc9fe288ac"},
    {"bitcoincash:QPWEHJ6EVDQLSUJT45JZDZQMW2Y8AHYLUGPXVFJKFR", false, "ERR:ValueError"},
    {"qqkhp32tj4w28ytwy5d3nqylnjznpnn9xgfntddExd", false, "ERR:ValueError"},
    {"bchtest:qqkhp32tj4w28ytwy5d3nqylnjznpnn9xgfntddexd", false, "ERR:ValueError"},
    {"qqkhp32tj4w28ytwy5d3nqylnjznpnn9xgfntddexe", false, "ERR:ValueError"},
    // python's base58 does not skip whitespace (Bitcoin Core's DecodeBase58 does).
    {" 1HB1xyKKD2VNd6jU7nz76mP67JpwhvSTGC", false, "ERR:ValueError"},
    {"1HB1xyKKD2VNd6jU7nz76mP67JpwhvSTGC ", false, "ERR:ValueError"},
    {"xyz", false, "ERR:ValueError"},
    {"", false, "ERR:ValueError"},
    {"bitcoincash:", false, "ERR:ValueError"},
    {":qqkhp32tj4w28ytwy5d3nqylnjznpnn9xgfntddexd", false, "ERR:ValueError"},
    // Litecoin version bytes (what the old own-share path wrote), other nets, bech32.
    {"LbPyEBd9HgjRsuRdHvyQNnSrKXCDp3ufwq", false, "ERR:ValueError"},
    {"MQ5BCQDii3fBWmhoLme3M2zRaXi7CnCQ2s", false, "ERR:ValueError"},
    {"mwgyG2QJ23vdQDD5qMxUvgbQyJRecGZ1MX", false, "ERR:ValueError"},
    {"mwgyG2QJ23vdQDD5qMxUvgbQyJRecGZ1MX", true, "76a914b166fa4b7050962e2114e435315f167f164265a388ac"},
    {"2N9RExFjnNPK6v44Sv2Ga9LjHUBKq2w1wXm", true, "a914b166fa4b7050962e2114e435315f167f164265a387"},
    {"1HB1xyKKD2VNd6jU7nz76mP67JpwhvSTGC", true, "ERR:ValueError"},
    {"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", false, "ERR:ValueError"},
    // CashAddr version-byte edges. python does not check the reserved bit, takes
    // the push length from the hash, and refuses types other than 0 and 1.
    {"bitcoincash:szckd7jtwpgfvt3pznjr2v2lzel3vsn95vupqdd5ke", false, "76a914b166fa4b7050962e2114e435315f167f164265a388ac"},
    {"bitcoincash:zzckd7jtwpgfvt3pznjr2v2lzel3vsn95v2fx4gt8l", false, "ERR:NotImplementedError"},
    {"bitcoincash:rzckd7jtwpgfvt3pznjr2v2lzel3vsn95vavm60guz", false, "ERR:NotImplementedError"},
    {"bitcoincash:0zckd7jtwpgfvt3pznjr2v2lzel3vsn95v0e2vzuvn", false, "ERR:NotImplementedError"},
    {"bitcoincash:qxckd7jtwpgfvt3pznjr2v2lzel3vsn95vz6swpm9v", false, "ERR:ValueError"},
    {"bitcoincash:pwsjyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg246e7p7", false, "a920a12222222222222222222222222222222222222222222222222222222222222287"},
    {"bitcoincash:qwsjyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyphmwp2e0", false, "76a920a12222222222222222222222222222222222222222222222222222222222222288ac"},
    {"bitcoincash:qvzjyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyhk855juw", false, "ERR:Error"},
    {"bitcoincash:qvqzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyfh972w7e", false, "76a91f2222222222222222222222222222222222222222222222222222222222222288ac"},
    {"bitcoincash:qqqqqvenxvenxvenxvenxvenxvenxvenxv5evru6um", false, "76a914000033333333333333333333333333333333333388ac"},
    {"bitcoincash:qyqqqqqqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zy98s5cdsd", false, "76a914444444444444444444444444444444444444444488ac"},
    {"bitcoincash:pzckd7jtwpgfvt3pznjr2v2lzel3vsn95v6xgypwr3", false, "a914b166fa4b7050962e2114e435315f167f164265a387"},
    {"bchtest:qzckd7jtwpgfvt3pznjr2v2lzel3vsn95vf33vy6ls", true, "76a914b166fa4b7050962e2114e435315f167f164265a388ac"},
    {"qzckd7jtwpgfvt3pznjr2v2lzel3vsn95vf33vy6ls", true, "76a914b166fa4b7050962e2114e435315f167f164265a388ac"},
    {"qzckd7jtwpgfvt3pznjr2v2lzel3vsn95vdr4txdcv", true, "ERR:ValueError"},
    {"bitcoincash:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", false, "ERR:ValueError"},
};

void RealChainAndEdgeVectors()
{
    for (const auto& v : kVectors)
    {
        const std::string want = std::string(v.python).rfind("ERR", 0) == 0 ? "ERR" : v.python;
        const std::string got = rule(v.addr, v.testnet);
        CHECK(got == want, "'" << v.addr << "' (" << (v.testnet ? "testnet" : "mainnet")
                               << "): python " << v.python << ", got " << got);
    }
    // A byte outside printable ASCII is refused (cash_addr.disassemble).
    CHECK(rule(std::string("qqkhp32tj4w28ytwy5d3nqylnjznpnn9xgfntdde\xff" "d"), false) == "ERR", "non-ASCII byte");
    // Never the string bytes as a script.
    const std::string garbage = "qqkhp32tj4w28ytwy5d3nqylnjznpnn9xgfntddexe";
    CHECK(rule(garbage, false) != hex(std::vector<unsigned char>(garbage.begin(), garbage.end())),
          "an undecodable address must never become its own bytes");
}

void RuleNeedsNoRegisteredDecoder()
{
    // This executable never calls coin::cashaddr::register_cashaddr_decoder().
    // The core registry therefore cannot decode CashAddr here (the live
    // build's state), while the v35 rule decodes it all the same.
    const std::string ca = "qqkhp32tj4w28ytwy5d3nqylnjznpnn9xgfntddexd";
    CHECK(core::address_to_script(ca).empty(),
          "precondition: no CashAddr decoder is registered in this executable");
    CHECK(rule(ca, false) == "76a9142d70c54b955ca3916e251b19809f9c8530ce653288ac",
          "v35_address_to_script must not depend on the registry");
}

void OwnShareAddressRoundTrips()
{
    const auto h = unhex("b166fa4b7050962e2114e435315f167f164265a3");
    std::vector<unsigned char> p2pkh = {0x76, 0xa9, 0x14};
    p2pkh.insert(p2pkh.end(), h.begin(), h.end());
    p2pkh.push_back(0x88); p2pkh.push_back(0xac);
    std::vector<unsigned char> p2sh = {0xa9, 0x14};
    p2sh.insert(p2sh.end(), h.begin(), h.end());
    p2sh.push_back(0x87);

    // python script2_to_address(script, ADDRESS_VERSION / ADDRESS_P2SH_VERSION, -1, net)
    struct Own { const std::vector<unsigned char>* script; bool testnet; const char* python; };
    const Own own[] = {
        {&p2pkh, false, "1HB1xyKKD2VNd6jU7nz76mP67JpwhvSTGC"},
        {&p2sh,  false, "3Hs2tWokkvokiGRuEtehXPk2Fq7fFHuvBM"},
        {&p2pkh, true,  "mwgyG2QJ23vdQDD5qMxUvgbQyJRecGZ1MX"},
        {&p2sh,  true,  "2N9RExFjnNPK6v44Sv2Ga9LjHUBKq2w1wXm"},
    };
    for (const auto& o : own)
    {
        const auto& net = bch::v35_net(o.testnet);
        const std::string addr = bch::v35_script_to_address(*o.script, net);
        CHECK(addr == o.python, "own-share address for " << hex(*o.script) << ": python "
                                << o.python << ", got " << addr);
        CHECK(rule(addr, o.testnet) == hex(*o.script),
              "own-share address " << addr << " must round-trip through the python rule");
    }
    // What the old create_local_share_v35 wrote for the same script (Litecoin
    // 0x30 / 0x32): python raises "address not for this net!".
    CHECK(rule("LbPyEBd9HgjRsuRdHvyQNnSrKXCDp3ufwq", false) == "ERR", "old P2PKH form");
    CHECK(rule("MQ5BCQDii3fBWmhoLme3M2zRaXi7CnCQ2s", false) == "ERR", "old P2SH form");

    // Scripts with no v35 address form: nothing to mint.
    std::vector<unsigned char> p2wpkh = {0x00, 0x14};
    p2wpkh.insert(p2wpkh.end(), h.begin(), h.end());
    CHECK(bch::v35_script_to_address(p2wpkh, bch::V35_MAINNET).empty(), "P2WPKH has no v35 form");
    CHECK(bch::v35_script_to_address({}, bch::V35_MAINNET).empty(), "empty script has no v35 form");
    std::vector<unsigned char> p2sh32 = {0xaa, 0x20};
    p2sh32.insert(p2sh32.end(), 32, 0x22);
    p2sh32.push_back(0x87);
    CHECK(bch::v35_script_to_address(p2sh32, bch::V35_MAINNET).empty(), "P2SH32 has no v35 form");

    // python cash_addr.encode for the same hash (used for the v36 P2WPKH key).
    const std::string enc = bch::v35_cashaddr_encode("bitcoincash", 0, h);
    CHECK(enc == "bitcoincash:qzckd7jtwpgfvt3pznjr2v2lzel3vsn95vdr4txdcv", "python cash_addr.encode, got " << enc);
    CHECK(rule(enc, false) == hex(p2pkh), "cashaddr_encode -> decode round trip, got " << enc);
    CHECK(bch::v35_cashaddr_encode("bitcoincash", 2, h).empty(), "python encode refuses type 2");
    CHECK(bch::v35_cashaddr_encode("bitcoincash", 0, std::vector<uint8_t>(21, 1)).empty(),
          "python encode refuses a 21-byte hash");
}

void DonationAddressIsTheP2pkForm()
{
    // donation_script_to_address(net) = legacy P2PKH of hash160(pubkey of the
    // v35 P2PK DONATION_SCRIPT). A miner using this string is paid inside the
    // donation output, so the constant must be exactly python's.
    const auto pubkey = unhex(
        "04ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664b");
    unsigned char sha[32];
    unsigned char h160[20];
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(sha);
    CRIPEMD160().Write(sha, 32).Finalize(h160);
    CHECK(bch::v35_legacy_address(0x00, h160) == bch::V35_MAINNET.donation_address, "mainnet donation address");
    CHECK(bch::v35_legacy_address(0x6f, h160) == bch::V35_TESTNET.donation_address, "testnet donation address");
    CHECK(bch::V35_MAINNET.donation_address == "1Kz5QaUPDtKrj5SqW5tFkn7WZh8LmQaQi4", "python value");
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
    std::cout << "[" << (g_case_failures == 0 ? "PASS" : "FAIL") << "] BchV35Address."
              << name << "\n";
    g_failures += g_case_failures;
}

} // namespace

int run_v35_address_kat_checks()
{
    g_failures = 0;
    run_case("RealChainAndEdgeVectors", RealChainAndEdgeVectors);
    run_case("RuleNeedsNoRegisteredDecoder", RuleNeedsNoRegisteredDecoder);
    run_case("OwnShareAddressRoundTrips", OwnShareAddressRoundTrips);
    run_case("DonationAddressIsTheP2pkForm", DonationAddressIsTheP2pkForm);
    return g_failures;
}
