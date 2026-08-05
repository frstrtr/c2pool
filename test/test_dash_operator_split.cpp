// SPDX-License-Identifier: AGPL-3.0-or-later
//
// ═══════════════════════════════════════════════════════════════════════════
// DASH masternode operator-reward split — incident h=2516595 KATs
// ═══════════════════════════════════════════════════════════════════════════
//
// INCIDENT (2026-08-05, production, binary ca5c9469): the FIRST block ever
// mined on an embedded daemonless template (h=2516595, pow 0…0d08e71b…) was
// REJECTED by dashd with bad-cb-payee. The scheduled masternode
// (proRegTxHash 0037c2c5…) has an 8% operator-reward split registered via
// ProTx; dashd's canonical coinbase pays TWO MN outputs
//     0.76413304 → XoDo3w4ZUqn93uL3FeRNb9fgfXvgg7BvDC   (owner)
//     0.06644635 → Xnem6ejaXAfKDTh5PFGSa9ozMQNMY6bvs7   (operator)
// while the embedded builder paid the ENTIRE share to the owner script.
// CheckMasternodePayments validates the full payout set (scripts AND
// amounts) → deterministic rejection → a lost won block.
//
// The split data was IN the shipped daemonless state the whole time: the
// mainnet checkpoint anchor (2513000) carries mn 0037c2c5… with bps=800 and
// both scripts; the omission was in the consumer (the builder), not the
// data. These KATs pin, against dashd masternode/payments.cpp
// GetBlockTxOuts (verbatim, v20.1.1):
//
//     CAmount operatorReward = 0;
//     if (dmnPayee->nOperatorReward != 0
//         && dmnPayee->pdmnState->scriptOperatorPayout != CScript()) {
//         operatorReward = (masternodeReward * dmnPayee->nOperatorReward) / 10000;
//         masternodeReward -= operatorReward;
//     }
//     if (masternodeReward > 0) emplace_back(masternodeReward, scriptPayout);
//     if (operatorReward > 0)   emplace_back(operatorReward, scriptOperatorPayout);
//
// (a) the builder emits BOTH outputs with dashd-exact amounts (truncating
//     division, owner-first order) — KAT'd with the real h=2516595 values;
// (b) an UNPROVEN split refuses the embedded serve with its own named
//     cause (cause=mn-payout-split-unprovable value=protx=… threshold=
//     payout-set-known) at BOTH the viability gate and the pre-emit gate;
// (c) a proven zero split builds the single owner output exactly as before;
// (d) the state machine mirrors dashd ResetOperatorFields on operator-key
//     change (ProUpRegTx) and revocation (ProUpRevTx) — the stale operator
//     payout script must go with the key.
//
// All hermetic: no live node, amounts recomputed from the same closed-form
// integer arithmetic dashd uses.

#include <gtest/gtest.h>

#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/mn_state_db.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>
#include <impl/dash/coin/embedded_oracle_shadow.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <array>
#include <cstring>
#include <vector>

using dash::coin::MNState;
using dash::coin::MnStateMachine;
using dash::coin::Mempool;
using dash::coin::MutableTransaction;
using dash::coin::NodeCoinState;
using dash::coin::DashWorkData;
using dash::coin::PackedPayment;
using dash::coin::build_embedded_workdata;
using dash::coin::compute_dash_block_reward_post_v20;
using dash::coin::compute_dash_mn_payment_post_v20;
using dash::coin::compute_dash_platform_reward_post_v20_mn_rr;
using ::core::coin::UTXOViewCache;

// Dash mainnet base58 version bytes (chainparams.cpp PUBKEY_ADDRESS=76,
// SCRIPT_ADDRESS=16) — same constants the sibling embedded_gbt KATs use.
static constexpr uint8_t DASH_PUBKEY_VER = 76;
static constexpr uint8_t DASH_P2SH_VER   = 16;

// Past V20 + MN_RR, matching the mainnet steady state (and the incident).
static constexpr uint32_t H = 2'400'000;

// ─── incident h=2516595 ground truth (canonical, dashd-accepted) ──────────
// Canonical MN share = owner + operator output values of the accepted block.
static constexpr int64_t K_MN_SHARE   = 83'057'939;  // duffs
static constexpr int64_t K_OWNER_OUT  = 76'413'304;  // → XoDo3w4…
static constexpr int64_t K_OPER_OUT   =  6'644'635;  // → Xnem6ej…
static constexpr uint16_t K_BPS       = 800;         // 8.00% (ProRegTx)
// scriptPubKeys, base58check-decoded from the two canonical payout
// addresses (and byte-identical to checkpoint-anchor row 0037c2c5…).
static const std::vector<unsigned char> K_OWNER_SCRIPT = {
    0x76, 0xa9, 0x14, 0x89, 0x7c, 0x15, 0x1a, 0x6a, 0xa2, 0x35, 0xb7, 0x88,
    0x0f, 0xb7, 0xd3, 0x4d, 0xac, 0xac, 0xa1, 0x78, 0xca, 0x03, 0x95, 0x88,
    0xac};
static const std::vector<unsigned char> K_OPER_SCRIPT = {
    0x76, 0xa9, 0x14, 0x83, 0x3c, 0xb9, 0xad, 0x96, 0x45, 0x55, 0xc7, 0x80,
    0x50, 0xae, 0x92, 0xb6, 0x85, 0xde, 0x5c, 0x32, 0x20, 0x0f, 0xc9, 0x88,
    0xac};

static uint256 raw256(uint8_t base) {
    uint256 h;
    std::array<uint8_t, 32> p{};
    for (size_t i = 0; i < 32; ++i) p[i] = static_cast<uint8_t>(base + i);
    std::memcpy(h.data(), p.data(), 32);
    return h;
}

static MNState split_mn(uint16_t bps,
                        const std::vector<unsigned char>& owner,
                        const std::vector<unsigned char>& oper,
                        uint8_t provenance = MNState::SPLIT_KNOWN) {
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 2'300'000;
    s.nLastPaidHeight = 0;
    s.scriptPayout.m_data = owner;
    s.nOperatorReward = bps;
    s.scriptOperatorPayout.m_data = oper;
    s.payoutSplitProvenance = provenance;
    return s;
}

static MnStateMachine machine_with(const MNState& s) {
    MnStateMachine m;
    m.load(std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}});
    return m;
}

// The non-burn packed payments (the "!6a" OP_RETURN is the platform
// credit-pool burn, not an MN payment).
static std::vector<PackedPayment> mn_payments(const DashWorkData& w) {
    std::vector<PackedPayment> out;
    for (const auto& p : w.m_packed_payments)
        if (p.payee != "!6a") out.push_back(p);
    return out;
}

// Arm the SML posture the emit gate requires (it is a no-op while
// require_sml is off) — same minimal fixture the collateral-spend emit KAT
// uses: a fully-confirmed 1-entry SML current at the tip, so the ONLY
// defect the gate can find is the one under test.
static void arm_emit_gate(NodeCoinState& st, const uint256& prev_hash) {
    using dash::coin::vendor::CSimplifiedMNList;
    using dash::coin::vendor::CSimplifiedMNListEntry;
    std::vector<CSimplifiedMNListEntry> entries;
    CSimplifiedMNListEntry e;
    e.nVersion = CSimplifiedMNListEntry::VER_BASIC_BLS;
    e.proRegTxHash = raw256(0x01);
    e.confirmedHash = raw256(0x77);
    e.isValid = true;
    entries.push_back(e);
    st.set_require_sml(true);
    st.sml() = CSimplifiedMNList(std::move(entries));
    st.set_have_sml(true);
    st.set_sml_current_hash(prev_hash);
}

// ════════════════════════════════════════════════════════════════════════
// The split arithmetic itself — dashd GetBlockTxOuts, bit-exact
// ════════════════════════════════════════════════════════════════════════

TEST(DashOperatorSplit, SplitMathKatH2516595) {
    MNState s = split_mn(K_BPS, K_OWNER_SCRIPT, K_OPER_SCRIPT);
    // floor(83'057'939 * 800 / 10000) = floor(6'644'635.12) = 6'644'635 —
    // the canonical operator output of the dashd-accepted block, truncating
    // division, NOT round-half-up (llround would give the same here; the
    // truncation edge is pinned separately below).
    EXPECT_EQ(s.operator_payment_of(K_MN_SHARE), K_OPER_OUT);
    EXPECT_EQ(K_MN_SHARE - s.operator_payment_of(K_MN_SHARE), K_OWNER_OUT);
}

TEST(DashOperatorSplit, SplitMathTruncatesLikeDashd) {
    MNState s = split_mn(1, K_OWNER_SCRIPT, K_OPER_SCRIPT);
    // 9'999 * 1 / 10000 = 0.9999 → 0 (dashd's own comment: "might turn out
    // to result in 0"). No operator output may be emitted for it.
    EXPECT_EQ(s.operator_payment_of(9'999), 0);
    // One duff more crosses the boundary.
    EXPECT_EQ(s.operator_payment_of(10'000), 1);
}

TEST(DashOperatorSplit, SplitZeroWhenNoScriptOrNoBps) {
    // bps registered, operator script unset → dashd pays a single owner
    // output (the `scriptOperatorPayout != CScript()` guard).
    MNState no_script = split_mn(K_BPS, K_OWNER_SCRIPT, {});
    EXPECT_EQ(no_script.operator_payment_of(K_MN_SHARE), 0);
    // script set, bps == 0 → likewise single-output (the `nOperatorReward
    // != 0` guard; consensus additionally forbids this state on-chain).
    MNState no_bps = split_mn(0, K_OWNER_SCRIPT, K_OPER_SCRIPT);
    EXPECT_EQ(no_bps.operator_payment_of(K_MN_SHARE), 0);
}

// ════════════════════════════════════════════════════════════════════════
// (a) the BUILDER emits both outputs, dashd-exact, owner first
// ════════════════════════════════════════════════════════════════════════

TEST(DashOperatorSplit, BuilderEmitsOwnerAndOperatorOutputs) {
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);   // empty template: subsidy-exact arithmetic

    auto mnstates = machine_with(split_mn(K_BPS, K_OWNER_SCRIPT, K_OPER_SCRIPT));

    auto w = build_embedded_workdata(
        /*prev_height=*/H - 1, raw256(0xAB), mnstates, mp,
        /*bits=*/0x1b104be3u, /*mtp=*/1'700'000'000u,
        DASH_PUBKEY_VER, DASH_P2SH_VER);

    // Independent re-derivation of THIS height's MN share.
    const int64_t reward          = compute_dash_block_reward_post_v20(H);
    const int64_t platform_reward = compute_dash_platform_reward_post_v20_mn_rr(H);
    const int64_t mn_payment      = compute_dash_mn_payment_post_v20(reward)
                                    - platform_reward;
    ASSERT_GT(mn_payment, 0);
    const int64_t op_due  = (mn_payment * K_BPS) / 10000;   // dashd formula
    const int64_t own_due = mn_payment - op_due;
    ASSERT_GT(op_due, 0);

    const auto mn_outs = mn_payments(w);
    ASSERT_EQ(mn_outs.size(), 2u)
        << "h=2516595 defect: the builder must emit the operator output, "
           "not fold the whole share into the owner's";
    // dashd GetBlockTxOuts order: owner first, operator second.
    EXPECT_EQ(mn_outs[0].amount, static_cast<uint64_t>(own_due));
    EXPECT_EQ(mn_outs[1].amount, static_cast<uint64_t>(op_due));
    // Set-level conservation: split, not duplicated.
    EXPECT_EQ(mn_outs[0].amount + mn_outs[1].amount,
              static_cast<uint64_t>(mn_payment));
    EXPECT_EQ(w.m_payment_amount, static_cast<uint64_t>(mn_payment));
    // The canonical incident addresses, re-encoded from the scripts.
    EXPECT_EQ(mn_outs[0].payee, "XoDo3w4ZUqn93uL3FeRNb9fgfXvgg7BvDC");
    EXPECT_EQ(mn_outs[1].payee, "Xnem6ejaXAfKDTh5PFGSa9ozMQNMY6bvs7");
}

// (c) proven zero split → the single owner output, exactly as before.
TEST(DashOperatorSplit, BuilderSingleOutputWhenSplitKnownZero) {
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);

    auto mnstates = machine_with(split_mn(0, K_OWNER_SCRIPT, {}));
    auto w = build_embedded_workdata(
        H - 1, raw256(0xAB), mnstates, mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);

    const auto mn_outs = mn_payments(w);
    ASSERT_EQ(mn_outs.size(), 1u);
    EXPECT_EQ(mn_outs[0].amount, w.m_payment_amount);
    EXPECT_EQ(mn_outs[0].payee, "XoDo3w4ZUqn93uL3FeRNb9fgfXvgg7BvDC");
}

// bps=10000 (a full-operator MN — one exists on mainnet at the checkpoint
// anchor): owner share is 0 → dashd's `if (masternodeReward > 0)` emits NO
// owner output; the single output is the operator's.
TEST(DashOperatorSplit, BuilderFullOperatorSplitOmitsZeroOwnerOutput) {
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);

    auto mnstates = machine_with(split_mn(10000, K_OWNER_SCRIPT, K_OPER_SCRIPT));
    auto w = build_embedded_workdata(
        H - 1, raw256(0xAB), mnstates, mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);

    const auto mn_outs = mn_payments(w);
    ASSERT_EQ(mn_outs.size(), 1u);
    EXPECT_EQ(mn_outs[0].amount, w.m_payment_amount);
    EXPECT_EQ(mn_outs[0].payee, "Xnem6ejaXAfKDTh5PFGSa9ozMQNMY6bvs7");
}

// ════════════════════════════════════════════════════════════════════════
// (b) UNPROVEN split → REFUSED, with its own named cause
// ════════════════════════════════════════════════════════════════════════

TEST(DashOperatorSplit, UnprovableSplitRefusesServeWithNamedCause) {
    NodeCoinState st;
    st.mnstates().load(std::vector<std::pair<uint256, MNState>>{
        {raw256(0x01),
         split_mn(0, K_OWNER_SCRIPT, {}, MNState::SPLIT_UNKNOWN)}});
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);
    ASSERT_TRUE(st.populated());

    // Guard ON (default posture): refuse, and say the cause's own name.
    auto e = st.make_embedded_work_inputs();
    ASSERT_FALSE(e.viable())
        << "an unproven payout split must refuse the embedded arm "
           "(h=2516595: serving it loses the won block to bad-cb-payee)";
    EXPECT_EQ(e.decline.cause, std::string("mn-payout-split-unprovable"));
    EXPECT_EQ(e.decline.value,
              "protx=" + raw256(0x01).GetHex().substr(0, 12));
    EXPECT_EQ(e.decline.threshold, std::string("payout-set-known"));
    // The greppable one-line marker discipline shared with the other gates.
    EXPECT_EQ(e.decline.one_line(),
              "cause=mn-payout-split-unprovable value=protx="
                  + raw256(0x01).GetHex().substr(0, 12)
                  + " threshold=payout-set-known");

    // NEGATIVE PASS — guard off reproduces the pre-fix fail-open.
    st.set_require_provable_payout_split(false);
    EXPECT_TRUE(st.make_embedded_work_inputs().viable())
        << "guard-off must reproduce the incident posture (fail-open)";
    st.set_require_provable_payout_split(true);

    // CONTROL — same tip, same MN, split PROVEN → viable again.
    st.mnstates().load(std::vector<std::pair<uint256, MNState>>{
        {raw256(0x01), split_mn(0, K_OWNER_SCRIPT, {})}});
    EXPECT_TRUE(st.make_embedded_work_inputs().viable())
        << "the gate must be provenance-specific, not a blanket refuse";
}

TEST(DashOperatorSplit, EmitGateMirrorsUnprovableSplit) {
    NodeCoinState st;
    st.mnstates().load(std::vector<std::pair<uint256, MNState>>{
        {raw256(0x01),
         split_mn(K_BPS, K_OWNER_SCRIPT, K_OPER_SCRIPT,
                  MNState::SPLIT_UNKNOWN)}});
    arm_emit_gate(st, raw256(0xAB));
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);

    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);
    auto w = build_embedded_workdata(
        H - 1, raw256(0xAB), st.mnstates(), mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);

    dash::coin::DeclineReport why;
    EXPECT_FALSE(st.embedded_template_emit_ok(w, &why))
        << "a cached/bypassed template must be stopped at emit too";
    EXPECT_EQ(why.cause, std::string("emit-mn-payout-split-unprovable"));
    EXPECT_EQ(why.threshold, std::string("payout-set-known"));
}

// Defence in depth: a template whose MN payment IGNORES a proven split (the
// exact h=2516595 builder defect, resurrected via any future regression)
// must be rejected at emit by amount re-derivation.
TEST(DashOperatorSplit, EmitGateRejectsSplitDriftTemplate) {
    NodeCoinState st;
    st.mnstates().load(std::vector<std::pair<uint256, MNState>>{
        {raw256(0x01), split_mn(K_BPS, K_OWNER_SCRIPT, K_OPER_SCRIPT)}});
    arm_emit_gate(st, raw256(0xAB));
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);

    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);
    auto w = build_embedded_workdata(
        H - 1, raw256(0xAB), st.mnstates(), mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);

    // Sanity: the fixed builder passes the emit re-derivation…
    dash::coin::DeclineReport why;
    // (viability preconditions like SML/qc are not armed in this bare
    // fixture; probe ONLY the split re-derivation by reproducing the
    // incident template: fold the operator output back into the owner's.)
    std::vector<PackedPayment> broken;
    uint64_t mn_total = 0;
    for (const auto& p : w.m_packed_payments) {
        if (p.payee == "!6a") { broken.push_back(p); continue; }
        mn_total += p.amount;
    }
    PackedPayment all_to_owner;
    all_to_owner.payee  = "XoDo3w4ZUqn93uL3FeRNb9fgfXvgg7BvDC";
    all_to_owner.amount = mn_total;                  // the h=2516595 coinbase
    broken.push_back(all_to_owner);
    DashWorkData incident = w;
    incident.m_packed_payments = broken;

    EXPECT_FALSE(st.embedded_template_emit_ok(incident, &why));
    EXPECT_EQ(why.cause, std::string("emit-mn-payout-split-drift"));
}

// ════════════════════════════════════════════════════════════════════════
// (d) ResetOperatorFields mirror — the stale operator script goes with the key
// ════════════════════════════════════════════════════════════════════════

static MutableTransaction protx_tx(uint16_t type,
                                   const std::vector<unsigned char>& payload) {
    MutableTransaction tx;
    tx.version = 3;
    tx.type = type;
    tx.extra_payload = payload;
    // A non-empty vin/vout so the tx is structurally a spend, not a
    // coinbase (pass 1 walks i>=1; the test block provides a coinbase).
    ::bitcoin_family::coin::TxIn in;
    in.prevout.hash = raw256(0x77);
    in.prevout.index = 0;
    in.sequence = 0xffffffffu;
    tx.vin.push_back(in);
    return tx;
}

static dash::coin::BlockType block_with(uint32_t /*height*/,
                                        std::vector<MutableTransaction> txs,
                                        const std::vector<unsigned char>& cb_payee,
                                        int64_t cb_value) {
    dash::coin::BlockType b;
    MutableTransaction cb;
    cb.version = 3;
    cb.type = 5;   // CbTx
    ::bitcoin_family::coin::TxOut o;
    o.value = cb_value;
    o.scriptPubKey.m_data = cb_payee;
    cb.vout.push_back(o);
    b.m_txs.push_back(cb);
    for (auto& t : txs) b.m_txs.push_back(std::move(t));
    return b;
}

TEST(DashOperatorSplit, ProUpRegTxOperatorKeyChangeClearsOperatorPayout) {
    // Seed one MN with a proven split, cursor at 999.
    MNState s = split_mn(K_BPS, K_OWNER_SCRIPT, K_OPER_SCRIPT);
    MnStateMachine m;
    m.load(std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}},
           /*as_of_height=*/999);

    // ProUpRegTx changing the operator BLS key.
    dash::coin::vendor::CProUpRegTx up;
    up.proTxHash = raw256(0x01);
    for (size_t i = 0; i < up.pubKeyOperator.size(); ++i)
        up.pubKeyOperator[i] = static_cast<uint8_t>(0xC0 + i);   // != seeded
    up.scriptPayout.m_data = K_OWNER_SCRIPT;
    auto ps = ::pack(up);
    auto sp = ps.get_span();
    std::vector<unsigned char> payload(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());

    auto blk = block_with(1000, {protx_tx(3, payload)}, K_OWNER_SCRIPT,
                          /*cb_value=*/100'000'000);
    auto r = m.apply_block(blk, 1000);
    ASSERT_FALSE(r.skipped_out_of_order);

    const auto& st2 = m.entries().at(raw256(0x01));
    // dashcore dmnstate.h ResetOperatorFields: scriptOperatorPayout,
    // addr(netInfo), platformNodeID cleared; MN PoSe-banned until the new
    // operator revives it. bps itself is immutable → split stays PROVEN.
    EXPECT_TRUE(st2.scriptOperatorPayout.m_data.empty())
        << "the OLD operator's payout script must go with the old key — "
           "keeping it pays a script dashd no longer pays (bad-cb-payee)";
    EXPECT_FALSE(st2.isValid);
    EXPECT_EQ(st2.payoutSplitProvenance, MNState::SPLIT_KNOWN);
    EXPECT_EQ(st2.operator_payment_of(K_MN_SHARE), 0)
        << "post-reset the payout set is single-owner";
}

TEST(DashOperatorSplit, ProUpRevTxClearsOperatorPayout) {
    MNState s = split_mn(K_BPS, K_OWNER_SCRIPT, K_OPER_SCRIPT);
    MnStateMachine m;
    m.load(std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}},
           /*as_of_height=*/999);

    dash::coin::vendor::CProUpRevTx rev;
    rev.proTxHash = raw256(0x01);
    rev.nReason = 1;   // termination of service
    auto ps = ::pack(rev);
    auto sp = ps.get_span();
    std::vector<unsigned char> payload(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());

    auto blk = block_with(1000, {protx_tx(4, payload)}, K_OWNER_SCRIPT,
                          100'000'000);
    auto r = m.apply_block(blk, 1000);
    ASSERT_FALSE(r.skipped_out_of_order);

    const auto& st2 = m.entries().at(raw256(0x01));
    EXPECT_TRUE(st2.scriptOperatorPayout.m_data.empty());
    EXPECT_FALSE(st2.isValid);
    EXPECT_EQ(st2.operator_payment_of(K_MN_SHARE), 0);
}

// ════════════════════════════════════════════════════════════════════════
// Pass-3 observation: the canonical coinbase proves / falsifies the split
// ════════════════════════════════════════════════════════════════════════

static dash::coin::BlockType coinbase_only_block(
    std::vector<std::pair<std::vector<unsigned char>, int64_t>> outs) {
    dash::coin::BlockType b;
    MutableTransaction cb;
    cb.version = 3;
    cb.type = 5;
    for (auto& [script, value] : outs) {
        ::bitcoin_family::coin::TxOut o;
        o.value = value;
        o.scriptPubKey.m_data = script;
        cb.vout.push_back(o);
    }
    b.m_txs.push_back(cb);
    return b;
}

TEST(DashOperatorSplit, Pass3AdoptsSplitFromObservedCanonicalPayout) {
    // Provenance UNKNOWN (filtered-seed shape: bps absent → 0).
    MNState s = split_mn(0, K_OWNER_SCRIPT, {}, MNState::SPLIT_UNKNOWN);
    MnStateMachine m;
    m.load(std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}},
           /*as_of_height=*/999);

    // The canonical h=2516595 payout shape: owner + operator outputs.
    auto blk = coinbase_only_block({{K_OWNER_SCRIPT, K_OWNER_OUT},
                                    {K_OPER_SCRIPT, K_OPER_OUT}});
    auto r = m.apply_block(blk, 1000);
    ASSERT_EQ(r.paid, 1u);
    EXPECT_EQ(r.split_adopted, 1u);

    const auto& st2 = m.entries().at(raw256(0x01));
    EXPECT_EQ(st2.payoutSplitProvenance, MNState::SPLIT_KNOWN);
    // bps uniquely determined: ceil(6'644'635 * 10000 / 83'057'939) = 800,
    // floor-verified against dashd's truncating recomputation.
    EXPECT_EQ(st2.nOperatorReward, K_BPS);
    EXPECT_EQ(st2.scriptOperatorPayout.m_data, K_OPER_SCRIPT);
    EXPECT_EQ(st2.operator_payment_of(K_MN_SHARE), K_OPER_OUT);
}

TEST(DashOperatorSplit, Pass3DemotesContradictedSplit) {
    // Proven split... that the network no longer pays (stale knowledge —
    // e.g. a pre-anchor ProUpServTx we never saw). Single-owner coinbase.
    MNState s = split_mn(K_BPS, K_OWNER_SCRIPT, K_OPER_SCRIPT);
    MnStateMachine m;
    m.load(std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}},
           /*as_of_height=*/999);

    auto blk = coinbase_only_block({{K_OWNER_SCRIPT, K_MN_SHARE}});
    auto r = m.apply_block(blk, 1000);
    ASSERT_EQ(r.paid, 1u);
    EXPECT_EQ(r.split_desync, 1u);
    EXPECT_EQ(m.entries().at(raw256(0x01)).payoutSplitProvenance,
              MNState::SPLIT_UNKNOWN)
        << "a contradicted split must fail closed (refused when scheduled) "
           "until re-proven";
}

// ════════════════════════════════════════════════════════════════════════
// Parity surface: the shadow field digests the full payout SET, fee-invariant
// ════════════════════════════════════════════════════════════════════════

TEST(DashOperatorSplit, ShadowSplitShapeIsFeeInvariant) {
    using dash::coin::mn_payout_split_shape_str;
    // Same MN, same split, DIFFERENT fee totals on the two sides (embedded
    // vs dashd selected different tx sets) — the shape must be EQUAL.
    auto side = [](int64_t mn_share) {
        std::vector<PackedPayment> pps;
        PackedPayment burn;  burn.payee = "!6a"; burn.amount = 1'000;
        PackedPayment owner; owner.payee = "Xowner";
        PackedPayment oper;  oper.payee = "Xoper";
        const int64_t op = (mn_share * K_BPS) / 10000;
        owner.amount = static_cast<uint64_t>(mn_share - op);
        oper.amount  = static_cast<uint64_t>(op);
        pps.push_back(burn); pps.push_back(owner); pps.push_back(oper);
        return pps;
    };
    const auto a = mn_payout_split_shape_str(side(K_MN_SHARE));       // canonical fees
    const auto b = mn_payout_split_shape_str(side(82'979'299));       // OUR fees (incident)
    EXPECT_EQ(a, b);
    EXPECT_EQ(a, "n=2;owner=Xowner;operator=Xoper;bps=800");
    // And the h=2516595 defect shape (owner-only) is DIFFERENT — the
    // owner-address-only compare could never see this.
    std::vector<PackedPayment> defect;
    PackedPayment owner_all; owner_all.payee = "Xowner";
    owner_all.amount = static_cast<uint64_t>(K_MN_SHARE);
    defect.push_back(owner_all);
    EXPECT_NE(mn_payout_split_shape_str(defect), a);
}
