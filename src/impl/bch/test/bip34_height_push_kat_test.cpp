// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::consensus::build_bip34_height_push KAT -- pins the coinbase scriptSig
// height prefix byte-for-byte against BCHN `CScript() << nHeight`
// (CScript::push_int64: OP_0 for 0, OP_1..OP_16 for 1..16, minimal CScriptNum
// data push otherwise), which ContextualCheckBlock prefix-matches for
// bad-cb-height. Same rule as p2pool-merged-v36 script.create_push_script.
//
// Regression: heights 1..16 used to be written as a 1-byte data push (`01 01`
// for height 1), and the stratum work source wrote `01 00` for height 0, so a
// block won at height 0..16 on a fresh regtest chain was bad-cb-height.
// Mainnet heights (>=17) were already correct and are pinned unchanged here.
//
// Pins:
//   1) encoder vectors: 0, 1, 16, 17, 0x7f, 0x80, 0xff, 0x8000, 955808, 21M
//   2) validator round-trip: every canonical prefix parses back to its height
//   3) validator rejects the old low-height encodings + non-minimal pushes
//   4) the stratum work source has no private encoder -- it calls the
//      consensus helper (one BCH encoder)
//
// Harness: plain int main() + CHECK (CTest treats exit 0 as PASS). Header-only
// over coinbase_commitment.hpp; the source check reads work_source.cpp via the
// BCH_WORK_SOURCE_SRC path CMake defines. No coin lib link.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "../coinbase_commitment.hpp"

#ifndef BCH_WORK_SOURCE_SRC
#error "BCH_WORK_SOURCE_SRC must be defined by CMake to the path of src/impl/bch/stratum/work_source.cpp"
#endif

namespace {
int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

using bytes = std::vector<unsigned char>;
using bch::consensus::build_bip34_height_push;
using bch::consensus::validate_coinbase_commitment;
using bch::consensus::COINBASE_TAG;
using bch::consensus::COINBASE_TAG_LEN;
using bch::consensus::STATE_ROOT_LEN;

// [height prefix] || "/c2pool/" || state_root(32B)
bytes script_sig_with(const bytes& prefix)
{
    bytes s = prefix;
    s.insert(s.end(), COINBASE_TAG, COINBASE_TAG + COINBASE_TAG_LEN);
    s.insert(s.end(), STATE_ROOT_LEN, 0x11);
    return s;
}

std::string read_text(const char* path)
{
    std::ifstream in(path);
    CHECK(in.good());
    std::stringstream ss; ss << in.rdbuf();
    return ss.str();
}
} // namespace

int main()
{
    // 1) Encoder vectors (BCHN CScript() << h).
    struct Vec { int64_t h; bytes want; };
    const Vec vecs[] = {
        {0,          {0x00}},                          // OP_0
        {1,          {0x51}},                          // OP_1
        {2,          {0x52}},                          // OP_2
        {16,         {0x60}},                          // OP_16
        {17,         {0x01, 0x11}},                    // first data-push height
        {0x7f,       {0x01, 0x7f}},
        {0x80,       {0x02, 0x80, 0x00}},              // sign byte
        {0xff,       {0x02, 0xff, 0x00}},
        {0x100,      {0x02, 0x00, 0x01}},
        {0x8000,     {0x03, 0x00, 0x80, 0x00}},
        {955808,     {0x03, 0xa0, 0x95, 0x0e}},        // mainnet anchor (matches coinbase_kat_bytevector_test)
        {21000000,   {0x04, 0x40, 0x6f, 0x40, 0x01}},  // 21M
    };
    for (const auto& v : vecs) {
        const bytes got = build_bip34_height_push(v.h);
        if (got != v.want) std::cerr << "  height " << v.h << " mismatch\n";
        CHECK(got == v.want);
    }

    // Every 1..16 is exactly one small-int opcode byte.
    for (int64_t h = 1; h <= 16; ++h) {
        const bytes got = build_bip34_height_push(h);
        CHECK(got.size() == 1 && got[0] == static_cast<unsigned char>(0x50 + h));
    }

    // Negative heights are refused.
    bool threw = false;
    try { (void)build_bip34_height_push(-1); } catch (const std::invalid_argument&) { threw = true; }
    CHECK(threw);

    // 2) Validator round-trip: canonical prefix parses back to its height and
    //    the tag/state_root that follow are still found.
    for (const auto& v : vecs) {
        const auto r = validate_coinbase_commitment(script_sig_with(v.want), v.h);
        if (!r.ok) std::cerr << "  height " << v.h << ": " << r.error << "\n";
        CHECK(r.ok);
        CHECK(r.height == v.h);
        CHECK(r.state_root == bytes(STATE_ROOT_LEN, 0x11));
    }
    for (int64_t h = 0; h <= 300; ++h) {
        const auto r = validate_coinbase_commitment(script_sig_with(build_bip34_height_push(h)), h);
        CHECK(r.ok && r.height == h);
    }
    // expected_height < 0 still parses the small-int form.
    {
        const auto r = validate_coinbase_commitment(script_sig_with({0x5a}), -1);
        CHECK(r.ok && r.height == 10);
    }

    // 3) Rejections.
    {
        // Old encodings: data push for 1 and 16, `01 00` for 0 (stratum pre-fix).
        CHECK(!validate_coinbase_commitment(script_sig_with({0x01, 0x01}), 1).ok);
        CHECK(!validate_coinbase_commitment(script_sig_with({0x01, 0x10}), 16).ok);
        CHECK(!validate_coinbase_commitment(script_sig_with({0x01, 0x00}), 0).ok);
        CHECK(!validate_coinbase_commitment(script_sig_with({0x01, 0x01}), -1).ok);
        // Non-minimal data push of a big height (padded zero byte).
        CHECK(!validate_coinbase_commitment(script_sig_with({0x02, 0x11, 0x00}), 17).ok);
        // Right encoding, wrong expected height.
        const auto r = validate_coinbase_commitment(script_sig_with({0x51}), 2);
        CHECK(!r.ok);
        CHECK(r.error.find("bad-cb-height") != std::string::npos);
        // Push opcodes that cannot carry a height, and truncation.
        CHECK(!validate_coinbase_commitment(script_sig_with({0x4f}), -1).ok);    // OP_1NEGATE
        CHECK(!validate_coinbase_commitment(script_sig_with({0x61}), -1).ok);    // OP_NOP
        CHECK(!validate_coinbase_commitment(bytes{0x03, 0xa0}, -1).ok);          // short push
        CHECK(!validate_coinbase_commitment(bytes{}, -1).ok);
    }

    // 4) One encoder: the stratum work source must call the consensus helper,
    //    not carry its own copy.
    {
        const std::string src = read_text(BCH_WORK_SOURCE_SRC);
        CHECK(src.find("bch::consensus::build_bip34_height_push(") != std::string::npos);
        CHECK(src.find("bip34_height_push(uint32_t") == std::string::npos);
    }

    if (failures) {
        std::cerr << failures << " CHECK(s) failed\n";
        return 1;
    }
    std::cout << "bch_bip34_height_push_kat_test: all BIP34 height-push KATs passed\n";
    return 0;
}
