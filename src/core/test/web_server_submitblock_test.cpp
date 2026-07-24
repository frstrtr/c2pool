// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/web_server.hpp>
#include <core/uint256.hpp>
#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>

// ---------------------------------------------------------------------------
// KATs for core::MiningInterface::submitblock — the SHARED-CORE HTTP won-block
// submit path (LTC's + NMC's PRIMARY block-submit path; also DASH/BTC/DGB/BCH).
//
// Invariant under test: a prev-hash MISMATCH ("stale") is a RACE, not a loss.
// The handler must FORWARD such a block to the coin daemon (never drop it) and
// return the DAEMON's verdict — accept => success, reject => error. It must NOT
// synthesize a "stale" error and drop the block before the daemon ever sees it.
// The normal (matching prev-hash) submit path must be unchanged.
// ---------------------------------------------------------------------------

namespace {

// Minimal ICoinNode test double: records whether the block reached the daemon
// and lets each test choose the daemon's verdict (accept / reject / RPC throw).
struct MockCoinNode : public core::coin::ICoinNode {
    nlohmann::json work_data;
    bool           accept          = true;   // submit_block_hex return value
    bool           throw_on_submit = false;  // model an RPC transport failure
    int            submit_calls    = 0;
    std::string    last_submitted_hex;

    core::coin::WorkView get_work_view() override {
        core::coin::WorkView v;
        v.m_data = work_data;
        return v;
    }
    bool submit_block_hex(const std::string& block_hex, bool /*ignore_failure*/) override {
        ++submit_calls;
        last_submitted_hex = block_hex;
        if (throw_on_submit) throw std::runtime_error("coin RPC unreachable");
        return accept;
    }
    bool is_embedded() const override { return false; }
    bool has_rpc()     const override { return true; }
};

std::string to_hex(const std::vector<uint8_t>& bytes) {
    static const char* H = "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) { s += H[b >> 4]; s += H[b & 0x0f]; }
    return s;
}

// Build an 80-byte block header (160 hex chars) whose prev-hash field (bytes
// 4..35, internal byte order) is exactly `prev32`. Other fields are arbitrary.
std::string make_header_hex(const std::vector<uint8_t>& prev32) {
    std::vector<uint8_t> hdr(80, 0);
    hdr[0] = 0x20;                         // version (LE) — arbitrary non-zero
    std::memcpy(hdr.data() + 4, prev32.data(), 32);
    for (int i = 36; i < 68; ++i) hdr[i] = static_cast<uint8_t>(i);  // merkle
    hdr[72] = 0xff; hdr[73] = 0x00; hdr[74] = 0x00; hdr[75] = 0x1d;  // nbits
    hdr[76] = 0x01;                        // nonce
    return to_hex(hdr);
}

// A MiningInterface primed with a live template whose previousblockhash is a
// known value; returns the 32 internal prev bytes so tests can build matching
// or mismatching headers.
struct Fixture {
    core::MiningInterface mi{/*testnet=*/true};
    MockCoinNode          node;
    std::vector<uint8_t>  template_prev32;

    Fixture() {
        // Pick a clearly non-zero template prev-hash.
        const std::string prev_hex =
            "00000000000000000000000000000000000000000000000000000000000000ab";
        uint256 pe;
        pe.SetHex(prev_hex);
        template_prev32.assign(pe.data(), pe.data() + 32);

        node.work_data = {
            {"previousblockhash", prev_hex},
            {"height", 100},
            {"bits", "1d00ffff"},
            {"coinbasevalue", 5000000000LL},
            {"transactions", nlohmann::json::array()},
            {"rules", nlohmann::json::array()},
        };
        mi.set_coin_node(&node);
        mi.refresh_work();  // populates m_cached_template from work_data
    }
};

bool is_error(const nlohmann::json& r) {
    return r.is_object() && r.contains("error");
}

// 1. STALE/RACE block, daemon ACCEPTS -> forwarded, handler returns success.
TEST(WebServerSubmitBlock, StaleRaceForwardedAndAccepted)
{
    Fixture f;
    f.node.accept = true;

    // prev-hash that does NOT match the template (all zeros) => "stale"/race.
    std::string hex = make_header_hex(std::vector<uint8_t>(32, 0x00));
    int calls_before = f.node.submit_calls;

    auto r = f.mi.submitblock(hex);

    EXPECT_EQ(f.node.submit_calls, calls_before + 1)
        << "race block MUST be forwarded to the daemon, not dropped";
    EXPECT_EQ(f.node.last_submitted_hex, hex);
    EXPECT_FALSE(is_error(r))
        << "daemon accepted => handler must return success, got: " << r.dump();
}

// 2. STALE/RACE block, daemon REJECTS -> forwarded, handler returns the reject.
TEST(WebServerSubmitBlock, StaleRaceForwardedAndRejectReturned)
{
    Fixture f;
    f.node.accept = false;  // daemon says invalid

    std::string hex = make_header_hex(std::vector<uint8_t>(32, 0x00));
    int calls_before = f.node.submit_calls;

    auto r = f.mi.submitblock(hex);

    EXPECT_EQ(f.node.submit_calls, calls_before + 1)
        << "race block MUST reach the daemon before any reject decision";
    EXPECT_TRUE(is_error(r))
        << "daemon rejected => handler must return the daemon's reject verdict";
    // And it must NOT be the old synthetic pre-daemon "stale" drop error.
    EXPECT_EQ(r["error"].get<std::string>().find("stale"), std::string::npos)
        << "reject must reflect the daemon verdict, not a synthetic stale drop";
}

// 3. NORMAL (matching prev-hash) block, daemon ACCEPTS -> forwarded, success.
//    Guards the byte-identical normal path.
TEST(WebServerSubmitBlock, NormalMatchingPrevForwardedAndAccepted)
{
    Fixture f;
    f.node.accept = true;

    std::string hex = make_header_hex(f.template_prev32);  // matches template
    int calls_before = f.node.submit_calls;

    auto r = f.mi.submitblock(hex);

    EXPECT_EQ(f.node.submit_calls, calls_before + 1)
        << "normal block must be forwarded to the daemon";
    EXPECT_FALSE(is_error(r))
        << "normal accepted block must return success, got: " << r.dump();
}

// 4. Guard: a too-short payload is still rejected locally (never forwarded).
TEST(WebServerSubmitBlock, TooShortRejectedLocally)
{
    Fixture f;
    int calls_before = f.node.submit_calls;

    auto r = f.mi.submitblock(std::string("00", 2));  // 1 byte, well under 80

    EXPECT_EQ(f.node.submit_calls, calls_before)
        << "malformed short payload must never reach the daemon";
    EXPECT_TRUE(is_error(r));
}

} // namespace
