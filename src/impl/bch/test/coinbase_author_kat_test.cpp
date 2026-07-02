// ---------------------------------------------------------------------------
// bch G2 coinbase-AUTHOR KAT -- v36 output-assembly byte-parity vs oracle
//
// Pins BCHWorkSource::build_connection_coinbase's output-assembly (extracted to
// the pure header bch/stratum/coinbase_outputs.hpp) against ground-truth emitted
// by the p2pool-merged-v36 oracle (p2pool/data.py generate_transaction,
// v36_active branch ~920-1085). This is the byte-diff bar that caught the DASH
// dust-payout false-positive: the expected vectors below were produced by the
// ORACLE packer (scripts/gen_g2_oracle.py, a verbatim transcription of the
// data.py v36 amounts/dests/payouts block), NOT authored against this builder.
//
// Three cases:
//   CASE 1 -- ORDERING: four PPLNS dests with an amount TIE (B==C) exercises the
//             (amount asc, THEN script asc) sort; donation marker forced LAST;
//             the marker <1-sat rule decrements the largest (D) by one satoshi.
//   CASE 2 -- DONATION FORCED LAST regardless of amount: the donation output
//             (400000000) ties the largest PPLNS payout yet must still appear
//             LAST, after B and A, NOT sorted into amount order.
//   CASE 3 -- FINDER-FEE REMOVAL byte-diff: the v36 builder pays NO finder fee.
//             The positive vector is the oracle v36 gentx; the NEGATIVE control
//             is the same inputs run through the pre-v36 199/200-haircut +
//             subsidy/200 finder-fee path. The assembled bytes MUST equal the
//             v36 vector and MUST DIFFER from the finder-fee vector -- proving
//             the fee was removed rather than asserting self-authored output.
//
// p2pool-merged-v36 surface: NONE (pins an assembly invariant). per-coin
// isolation: src/impl/bch/ only. Over coinbase_outputs.hpp -- no peer/socket/
// live coin lib, no work-source construction.
// ---------------------------------------------------------------------------

#include <cassert>
#include <cstdint>
#include <iostream>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include <impl/bch/stratum/coinbase_outputs.hpp>

using Script  = std::vector<unsigned char>;
using Outputs = std::vector<std::pair<Script, uint64_t>>;
using bch::stratum::assemble_v36_coinbase_outputs;

static const uint64_t SUBSIDY = 1000000000ULL;

// Fixed deterministic scripts (match scripts/gen_g2_oracle.py).
static Script p2pkh(unsigned char b) {
    Script s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, b);
    s.push_back(0x88); s.push_back(0xac);
    return s;
}
static Script from_hex(const std::string& h) {
    Script out; out.reserve(h.size()/2);
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<unsigned char>(std::stoul(h.substr(i,2), nullptr, 16)));
    return out;
}

static const Script A = p2pkh(0xaa);
static const Script B = p2pkh(0xbb);
static const Script C = p2pkh(0xcc);
static const Script D = p2pkh(0xdd);
// Real V36 COMBINED_DONATION_SCRIPT (P2SH) from data.py:131.
static const Script DON = from_hex("a9148c6272621d89e8fa526dd86acff60c7136be8e8587");

// Serialize the output section exactly as the coinbase author does:
//   value (LE64) || varint(script_len) || script
static void push_varint(Script& v, uint64_t n) {
    if (n < 0xfd) { v.push_back(static_cast<unsigned char>(n)); }
    else if (n <= 0xffff) { v.push_back(0xfd); v.push_back(n & 0xff); v.push_back((n>>8)&0xff); }
    else if (n <= 0xffffffff) {
        v.push_back(0xfe);
        for (int i=0;i<4;++i) v.push_back((n>>(i*8))&0xff);
    } else {
        v.push_back(0xff);
        for (int i=0;i<8;++i) v.push_back((n>>(i*8))&0xff);
    }
}
static std::string to_hex(const Script& b) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(b.size()*2);
    for (unsigned char c : b) { s.push_back(d[c>>4]); s.push_back(d[c&0xf]); }
    return s;
}
static std::string serialize_outsection(const Outputs& outs) {
    Script v;
    for (const auto& [script, value] : outs) {
        for (int i=0;i<8;++i) v.push_back((value>>(i*8))&0xff);  // LE64
        push_varint(v, script.size());
        v.insert(v.end(), script.begin(), script.end());
    }
    return to_hex(v);
}

// Pre-marker PPLNS amounts = subsidy*weight//total_weight, plus the donation
// entry keyed by DON = subsidy - sum(pplns) (what the PPLNS callback hands the
// builder). The marker <1-sat rule + ordering happen INSIDE the function.
static std::map<Script,double> pplns(std::vector<std::pair<Script,uint64_t>> weights,
                                     uint64_t donation_weight) {
    uint64_t total_weight = donation_weight;
    for (auto& [s,w] : weights) total_weight += w;
    std::map<Script,double> amounts;
    uint64_t sum = 0;
    for (auto& [s,w] : weights) {
        uint64_t a = SUBSIDY * w / total_weight;
        amounts[s] = static_cast<double>(a);
        sum += a;
    }
    amounts[DON] = static_cast<double>(SUBSIDY - sum);   // pre-marker donation
    return amounts;
}

int main() {
    // ----- CASE 1: ordering + amount-tie script tiebreak + marker decrement ---
    {
        auto outs = assemble_v36_coinbase_outputs(
            pplns({{A,10},{B,20},{C,20},{D,50}}, 0), DON, SUBSIDY);
        // Order: A(1e8) < B==C(2e8, script-asc bb<cc) < D(5e8-1), DON last(1).
        assert(outs.size() == 5);
        assert(outs[0].first == A && outs[0].second == 100000000ULL);
        assert(outs[1].first == B && outs[1].second == 200000000ULL);
        assert(outs[2].first == C && outs[2].second == 200000000ULL);  // tie -> script asc
        assert(outs[3].first == D && outs[3].second == 499999999ULL);  // marker -1 sat
        assert(outs[4].first == DON && outs[4].second == 1ULL);        // donation LAST
        const std::string ORACLE =
            "00e1f505000000001976a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88ac"
            "00c2eb0b000000001976a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac"
            "00c2eb0b000000001976a914cccccccccccccccccccccccccccccccccccccccc88ac"
            "ff64cd1d000000001976a914dddddddddddddddddddddddddddddddddddddddd88ac"
            "010000000000000017a9148c6272621d89e8fa526dd86acff60c7136be8e8587";
        assert(serialize_outsection(outs) == ORACLE);
        std::cout << "[KAT] case1 ordering/tie/marker -- PASS\n";
    }

    // ----- CASE 2: donation forced LAST even when its amount ties the largest --
    {
        auto outs = assemble_v36_coinbase_outputs(
            pplns({{A,40},{B,20}}, 40), DON, SUBSIDY);
        // PPLNS: B(2e8) < A(4e8); donation(4e8) ties A yet must be LAST.
        assert(outs.size() == 3);
        assert(outs[0].first == B && outs[0].second == 200000000ULL);
        assert(outs[1].first == A && outs[1].second == 400000000ULL);
        assert(outs[2].first == DON && outs[2].second == 400000000ULL);  // forced last
        const std::string ORACLE =
            "00c2eb0b000000001976a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac"
            "0084d717000000001976a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88ac"
            "0084d7170000000017a9148c6272621d89e8fa526dd86acff60c7136be8e8587";
        assert(serialize_outsection(outs) == ORACLE);
        std::cout << "[KAT] case2 donation-forced-last -- PASS\n";
    }

    // ----- CASE 3: finder-fee REMOVAL -- byte-diff vs the fee-bearing control --
    {
        auto outs = assemble_v36_coinbase_outputs(
            pplns({{A,60},{B,40}}, 0), DON, SUBSIDY);
        assert(outs.size() == 3);
        assert(outs[0].first == B && outs[0].second == 400000000ULL);
        assert(outs[1].first == A && outs[1].second == 599999999ULL);  // full weight, NO -fee
        assert(outs[2].first == DON && outs[2].second == 1ULL);
        const std::string ORACLE_V36 =
            "0084d717000000001976a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac"
            "ff45c323000000001976a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88ac"
            "010000000000000017a9148c6272621d89e8fa526dd86acff60c7136be8e8587";
        // NEGATIVE control: oracle pre-v36 (199/200 haircut + subsidy/200 finder
        // fee to A). A v36 builder that still paid the finder fee would emit this.
        const std::string ORACLE_WITH_FINDERFEE =
            "80ffb817000000001976a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac"
            "7fcae123000000001976a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88ac"
            "010000000000000017a9148c6272621d89e8fa526dd86acff60c7136be8e8587";
        const std::string got = serialize_outsection(outs);
        assert(got == ORACLE_V36);                 // matches oracle v36 gentx
        assert(got != ORACLE_WITH_FINDERFEE);      // PROVES finder fee removed
        assert(ORACLE_V36 != ORACLE_WITH_FINDERFEE);
        std::cout << "[KAT] case3 finder-fee-removal byte-diff -- PASS\n";
    }

    std::cout << "[KAT] bch G2 coinbase-author KAT -- ALL CASES PASS\n";
    return 0;
}
