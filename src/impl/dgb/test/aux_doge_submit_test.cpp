// ---------------------------------------------------------------------------
// DGB+DOGE merged-mining (phase DC) -- SUBMIT-half KAT, -DAUX_DOGE=ON only.
// Author-only companion to aux_doge_dc_proof_test (the proof/dual-target half).
//
// Pins the load-bearing contracts of the (b)-ruling submit path (integrator
// UID:3130): a won DOGE-aux block is submitted FROM DGBS OWN dispatch, RPC-ONLY,
// through a DGB-owned dogecoind seam DISTINCT from the digibyted parent seam; the
// shared doge module is consumed read-side-only (the AuxPoW proof is passed in,
// never rebuilt here). No external golden -- every assertion is a guard / wiring
// invariant, so it cannot drift against a re-shaped serializer (that drift is the
// sibling proof tests job).
//
// THE TRAP this KAT guards: a submit half that silently routes the won DOGE block
// through the PARENT (digibyted) seam, or that fires with no seam, or that submits
// a fabricated/partial block. Each is asserted impossible below.
//
// Per-coin isolation: links nothing from src/impl/doge/coin submit path -- only
// the core ICoinNode seam + the dgb header under test. Must appear in BOTH
// test/CMakeLists.txt AND the build.yml --target allowlist (cf. DGB #137/#143).
// ---------------------------------------------------------------------------
#include <gtest/gtest.h>

#include <impl/dgb/coin/aux_doge_submit.hpp>

#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>
#include <core/uint256.hpp>

#include <optional>
#include <stdexcept>
#include <string>

namespace {

// Minimal recording ICoinNode. has_rpc() toggleable so we can prove the guard.
// get_work_view() is never reached on the submit path -- throws if it is.
struct RecordingSeam : core::coin::ICoinNode {
    bool        rpc_present = true;
    bool        ack         = true;     // submitblock verdict to return
    int         submit_calls = 0;
    std::string last_hex;
    bool        last_ignore_failure = false;

    core::coin::WorkView get_work_view() override {
        throw std::runtime_error("get_work_view must NOT be called on the submit path");
    }
    bool submit_block_hex(const std::string& block_hex, bool ignore_failure) override {
        ++submit_calls;
        last_hex = block_hex;
        last_ignore_failure = ignore_failure;
        return ack && rpc_present;
    }
    bool is_embedded() const override { return false; }
    bool has_rpc()    const override { return rpc_present; }
};

const uint256 SHARE = uint256S(
    "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabca");
// Stand-in for the parent-built CAuxPow proof hex (content opaque to the submit
// half -- the proof test pins its bytes). The assembler frames it into a block.
const std::string AUXPOW = "0100000001deadbeef";
const std::string DOGE_BLOCK = "00112233445566778899aabbccddeeff";

} // namespace

// 1) Happy path: a present DGB-owned DOGE seam with has_rpc() submits EXACTLY the
//    assembled DOGE block hex, ignore_failure=true (duplicate never masks accept).
TEST(DGB_AuxDogeSubmit, SubmitsAssembledBlockThroughDogeSeam) {
    RecordingSeam doge;
    auto r = dgb::coin::submit_won_aux_doge_block(&doge, DOGE_BLOCK);
    EXPECT_TRUE(r.had_seam);
    EXPECT_TRUE(r.rpc_ok);
    EXPECT_TRUE(r.any());
    EXPECT_EQ(doge.submit_calls, 1);
    EXPECT_EQ(doge.last_hex, DOGE_BLOCK);
    EXPECT_TRUE(doge.last_ignore_failure);
}

// 2) No seam wired -> NEVER throws, submits nothing, reports had_seam=false. The
//    won block is logged-lost, not fabricated onto some other sink.
TEST(DGB_AuxDogeSubmit, NullSeamSubmitsNothingNoThrow) {
    auto r = dgb::coin::submit_won_aux_doge_block(nullptr, DOGE_BLOCK);
    EXPECT_FALSE(r.had_seam);
    EXPECT_FALSE(r.rpc_ok);
    EXPECT_FALSE(r.any());
}

// 3) Seam present but has_rpc()==false -> guarded the same as null: no submit.
TEST(DGB_AuxDogeSubmit, RpcLessSeamSubmitsNothing) {
    RecordingSeam doge; doge.rpc_present = false;
    auto r = dgb::coin::submit_won_aux_doge_block(&doge, DOGE_BLOCK);
    EXPECT_FALSE(r.had_seam);
    EXPECT_FALSE(r.rpc_ok);
    EXPECT_EQ(doge.submit_calls, 0);
}

// 4) Handler happy path: a wired assembler frames the proof and the handler
//    submits the assembled block. The assembler receives the SAME share hash +
//    proof the tracker fired (read-side consume of the parent-built proof).
TEST(DGB_AuxDogeSubmit, HandlerAssemblesThenSubmits) {
    RecordingSeam doge;
    uint256 seen_share; std::string seen_aux;
    auto assemble = [&](const uint256& s, const std::string& aux)
        -> std::optional<std::string> {
        seen_share = s; seen_aux = aux;
        return DOGE_BLOCK;
    };
    auto handler = dgb::coin::make_aux_doge_on_block_found(assemble, &doge);
    handler(SHARE, AUXPOW);
    EXPECT_EQ(seen_share, SHARE);
    EXPECT_EQ(seen_aux, AUXPOW);
    EXPECT_EQ(doge.submit_calls, 1);
    EXPECT_EQ(doge.last_hex, DOGE_BLOCK);
}

// 5) Assembler returns nullopt (unassemblable: missing DOGE template / tx) ->
//    submit NOTHING. Never fabricate or submit a partial DOGE block.
TEST(DGB_AuxDogeSubmit, UnassemblableSubmitsNothing) {
    RecordingSeam doge;
    auto assemble = [](const uint256&, const std::string&)
        -> std::optional<std::string> { return std::nullopt; };
    auto handler = dgb::coin::make_aux_doge_on_block_found(assemble, &doge);
    handler(SHARE, AUXPOW);
    EXPECT_EQ(doge.submit_calls, 0);
}

// 6) No assembler wired -> handler is a guarded no-op, never throws, never submits.
TEST(DGB_AuxDogeSubmit, NoAssemblerNoOp) {
    RecordingSeam doge;
    auto handler = dgb::coin::make_aux_doge_on_block_found(
        dgb::coin::AuxDogeBlockAssembler{}, &doge);
    handler(SHARE, AUXPOW);
    EXPECT_EQ(doge.submit_calls, 0);
}

// 7) (b)-INVARIANT: one parent per DOGE block. The DOGE submit NEVER touches the
//    parent (digibyted) seam. Passing a DISTINCT parent seam, it stays untouched
//    while only the DOGE seam receives the block -- separate deployment proven at
//    the wiring boundary, not just asserted in a comment.
TEST(DGB_AuxDogeSubmit, DogeSubmitDoesNotTouchParentSeam) {
    RecordingSeam parent_digibyted;   // the #82 parent seam
    RecordingSeam doge;               // the DGB-owned DOGE seam
    auto assemble = [](const uint256&, const std::string&)
        -> std::optional<std::string> { return DOGE_BLOCK; };
    auto handler = dgb::coin::make_aux_doge_on_block_found(assemble, &doge);
    handler(SHARE, AUXPOW);
    EXPECT_EQ(doge.submit_calls, 1);
    EXPECT_EQ(parent_digibyted.submit_calls, 0);   // parent path untouched
}
