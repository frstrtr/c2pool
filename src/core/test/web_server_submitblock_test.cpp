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
#include <core/coin/submitblock_result.hpp>

// ---------------------------------------------------------------------------
// KATs for core::MiningInterface::submitblock — the SHARED-CORE HTTP won-block
// submit path (LTC's + NMC's PRIMARY block-submit path; also DASH/BTC/DGB/BCH).
//
// Invariant under test: a prev-hash MISMATCH ("stale") is a RACE, not a loss.
// The handler must FORWARD such a block to the coin daemon (never drop it) and
// return the DAEMON's verdict — accept => success, reject => error. It must NOT
// synthesize a "stale" error and drop the block before the daemon ever sees it.
//
// REWARD-ACCOUNTING invariant (B1): the found-block callback fires EXACTLY ONCE
// per block, with the correct stale_info code, AFTER the daemon verdict — an
// accepted stale/race block must fire 0 (WON), NOT be left recorded only as an
// eager 253 (ORPHAN/pending), or the dashboard under-credits a real paid win.
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
// known value; also captures every found-block callback fire (stale_info code)
// so tests can assert EXACTLY ONE fire per path with the right code.
struct Fixture {
    core::MiningInterface mi{/*testnet=*/true};
    MockCoinNode          node;
    std::vector<uint8_t>  template_prev32;
    std::vector<int>      fires;   // stale_info codes captured, in order

    Fixture() {
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
        mi.set_on_block_submitted(
            [this](const std::string&, int stale_info) { fires.push_back(stale_info); });
        mi.refresh_work();  // populates m_cached_template from work_data
    }

    std::string stale_header()  const { return make_header_hex(std::vector<uint8_t>(32, 0x00)); }
    std::string normal_header() const { return make_header_hex(template_prev32); }
};

bool is_error(const nlohmann::json& r) {
    return r.is_object() && r.contains("error");
}

// ------------------------------ B1 / M3: fire accounting ------------------

// stale + accept => forwarded, single 0-fire (WON — the B1 regression case).
TEST(WebServerSubmitBlock, StaleAccept_SingleWonFire)
{
    Fixture f;
    f.node.accept = true;

    auto r = f.mi.submitblock(f.stale_header());

    EXPECT_EQ(f.node.submit_calls, 1) << "race block MUST be forwarded, not dropped";
    EXPECT_FALSE(is_error(r)) << "accepted => success, got: " << r.dump();
    ASSERT_EQ(f.fires.size(), 1u) << "exactly ONE found-block callback must fire";
    EXPECT_EQ(f.fires[0], 0)
        << "an accepted stale/race block is a WON block (0), not ORPHAN (253)";
}

// stale + reject => forwarded, single 253 (ORPHAN) fire, reject returned.
TEST(WebServerSubmitBlock, StaleReject_SingleOrphanFire)
{
    Fixture f;
    f.node.accept = false;

    auto r = f.mi.submitblock(f.stale_header());

    EXPECT_EQ(f.node.submit_calls, 1) << "race block MUST reach the daemon first";
    EXPECT_TRUE(is_error(r)) << "daemon rejected => handler returns the reject";
    EXPECT_EQ(r["error"].get<std::string>().find("stale"), std::string::npos)
        << "reject must reflect the daemon verdict, not a synthetic stale drop";
    ASSERT_EQ(f.fires.size(), 1u) << "exactly ONE found-block callback must fire";
    EXPECT_EQ(f.fires[0], 253) << "a rejected stale/race block records as ORPHAN (253)";
}

// normal + accept => forwarded, single 0 (WON) fire, success.
TEST(WebServerSubmitBlock, NormalAccept_SingleWonFire)
{
    Fixture f;
    f.node.accept = true;

    auto r = f.mi.submitblock(f.normal_header());

    EXPECT_EQ(f.node.submit_calls, 1);
    EXPECT_FALSE(is_error(r)) << "normal accepted block must succeed, got: " << r.dump();
    ASSERT_EQ(f.fires.size(), 1u);
    EXPECT_EQ(f.fires[0], 0);
}

// normal + reject => forwarded, error returned, NO won-fire (matches prior
// telemetry: plain reject recorded nothing; a "false" may be daemon-duplicate).
TEST(WebServerSubmitBlock, NormalReject_ErrorAndNoFire)
{
    Fixture f;
    f.node.accept = false;

    auto r = f.mi.submitblock(f.normal_header());

    EXPECT_EQ(f.node.submit_calls, 1);
    EXPECT_TRUE(is_error(r));
    EXPECT_EQ(f.fires.size(), 0u)
        << "a non-stale reject must not fire a found-block callback (no DOA mis-count)";
}

// RPC throw (transport failure) => single DOA fire: 254 non-stale, 253 stale.
TEST(WebServerSubmitBlock, RpcThrowNonStale_SingleDoaFire)
{
    Fixture f;
    f.node.throw_on_submit = true;

    auto r = f.mi.submitblock(f.normal_header());

    EXPECT_EQ(f.node.submit_calls, 1);
    EXPECT_TRUE(is_error(r));
    ASSERT_EQ(f.fires.size(), 1u);
    EXPECT_EQ(f.fires[0], 254) << "non-stale RPC throw records as DOA (254)";
}

TEST(WebServerSubmitBlock, RpcThrowStale_SingleOrphanFire)
{
    Fixture f;
    f.node.throw_on_submit = true;

    auto r = f.mi.submitblock(f.stale_header());

    EXPECT_EQ(f.node.submit_calls, 1);
    EXPECT_TRUE(is_error(r));
    ASSERT_EQ(f.fires.size(), 1u);
    EXPECT_EQ(f.fires[0], 253) << "stale RPC throw records as ORPHAN (253)";
}

// Guard: a too-short payload is rejected locally, never forwarded, never fires.
TEST(WebServerSubmitBlock, TooShortRejectedLocally)
{
    Fixture f;
    auto r = f.mi.submitblock(std::string("00", 2));
    EXPECT_EQ(f.node.submit_calls, 0) << "malformed short payload must never reach the daemon";
    EXPECT_TRUE(is_error(r));
    EXPECT_EQ(f.fires.size(), 0u);
}

// ------------------------------ M2: duplicate = ACK -----------------------

// The shared classifier used by LTC/BTC/DGB NodeRPC::submit_block_hex: a daemon
// "duplicate"/"inconclusive"/already-have (the dual-path / race outcome) is an
// ACK, so a won block never surfaces as a reject through the web_server seam.
TEST(SubmitblockResult, DuplicateAndInconclusiveAreAck)
{
    using core::coin::submitblock_result_accepted;
    EXPECT_TRUE(submitblock_result_accepted(nlohmann::json()));            // null = accept
    EXPECT_TRUE(submitblock_result_accepted("duplicate"));
    EXPECT_TRUE(submitblock_result_accepted("DUPLICATE"));
    EXPECT_TRUE(submitblock_result_accepted("inconclusive"));
    EXPECT_TRUE(submitblock_result_accepted("duplicate-inconclusive"));
    EXPECT_TRUE(submitblock_result_accepted("already have block"));
    // Genuine rejects stay rejects.
    EXPECT_FALSE(submitblock_result_accepted("duplicate-invalid"));
    EXPECT_FALSE(submitblock_result_accepted("high-hash"));
    EXPECT_FALSE(submitblock_result_accepted("bad-txnmrklroot"));
}

} // namespace
