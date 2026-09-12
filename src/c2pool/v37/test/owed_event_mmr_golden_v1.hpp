#pragma once
// Shared deterministic OWED-ledger event schedule (v1) + the pinned goldens.
//
// The GATE-OFF goldens at the bottom (owed_digest + StateCommitment root at
// each cut) were minted by compiling this very header against PRISTINE MASTER
// — no record log, no gate, no extra leaf — and the KAT asserts them unchanged
// on this branch. That IS the byte-identity proof: if anything in this change
// moved a committed root with the gate OFF, these constants stop matching.
//
// ONE definition, used by three consumers:
//   (1) the pristine-master baseline probe, which mints the gate-OFF goldens;
//   (2) the branch KAT, which asserts those same goldens byte-for-byte (the
//       gate-OFF byte-identity proof);
//   (3) the convergence check, which drives TWO independent ledgers from it.
//
// It touches every OwedLedger mutation path that bumps ledger_seq, plus the
// two that deliberately do NOT (duplicate FOUND, unknown-bid ORPHAN), so the
// "one leaf per ledger_seq increment" invariant is exercised in both
// directions. Stdlib only; public W4/W5 API only, so it compiles unchanged
// against master and against the branch.

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace oes_v1 {

using Bytes32 = std::array<std::uint8_t, 32>;
using AmountMap = std::map<Bytes32, long long>;

inline Bytes32 key_of(unsigned i) {
    Bytes32 k{};
    k[0] = static_cast<std::uint8_t>(i);
    for (int j = 1; j < 32; ++j)
        k[j] = static_cast<std::uint8_t>((i * 31u + j * 17u + 7u) & 0xff);
    return k;
}

inline std::string bid_of(unsigned i) {
    static const char* d = "0123456789abcdef";
    std::string s = "blk";
    s.push_back(d[(i >> 4) & 0xf]);
    s.push_back(d[i & 0xf]);
    return s;
}

// One scheduled step. `op`: 0 = FOUND, 1 = FINALIZE, 2 = ORPHAN.
struct Step {
    int         op = 0;
    std::string bid;
    AmountMap   credit;
    AmountMap   payout;
    AmountMap   settled;
    unsigned long long bin_height = 0;
    bool        expect_seq_bump = true;   // false for the two deliberate no-ops
    const char* note = "";
};

// The canonical v1 schedule. Order is the append order: leaf i (0-based) is
// the i-th step whose expect_seq_bump is true.
inline std::vector<Step> schedule_v1() {
    std::vector<Step> s;

    for (unsigned i = 0; i < 12; ++i) {
        Step f;
        f.op = 0;
        f.bid = bid_of(i);
        f.credit[key_of(i % 4)]       = 1000 + static_cast<long long>(i) * 7;
        f.credit[key_of((i % 4) + 1)] = 2000 + static_cast<long long>(i) * 13;
        f.credit[key_of((i % 4) + 2)] = 3000 + static_cast<long long>(i) * 17;
        if (i % 5 == 0) f.credit[key_of((i % 4) + 3)] = 0;   // zero row: normalized away
        f.payout[key_of(i % 4)] = 500 + static_cast<long long>(i) * 3;
        f.note = "FOUND";
        s.push_back(f);

        if (i % 3 == 0) {
            Step fin;
            fin.op = 1;
            fin.bid = bid_of(i);
            fin.bin_height = 1000ull + i * 10ull;
            fin.note = "FINALIZE";
            s.push_back(fin);
        } else if (i % 3 == 1) {
            Step orp;                       // pre-SETTLED orphan (pure removal)
            orp.op = 2;
            orp.bid = bid_of(i);
            orp.settled[key_of(i % 4)] = 999;   // argument the ledger IGNORES here
            orp.note = "ORPHAN pre-SETTLED";
            s.push_back(orp);
        }
        // i % 3 == 2 -> left PENDING on purpose
    }

    {   // duplicate FOUND on an already-pending bid: refused, no seq bump.
        Step dup;
        dup.op = 0;
        dup.bid = bid_of(2);                // i=2 was left pending
        dup.credit[key_of(0)] = 4242;
        dup.payout[key_of(0)] = 11;
        dup.expect_seq_bump = false;
        dup.note = "FOUND duplicate (no-op)";
        s.push_back(dup);
    }
    {   // ORPHAN on a bid the ledger never saw: no-op, no seq bump, no leaf.
        Step unk;
        unk.op = 2;
        unk.bid = "deadbeefdeadbeef";
        unk.settled[key_of(1)] = 777;
        unk.expect_seq_bump = false;
        unk.note = "ORPHAN unknown bid (no-op)";
        s.push_back(unk);
    }
    {   // post-SETTLED orphan of blk00 (finalized above): priced residual.
        Step res;
        res.op = 2;
        res.bid = bid_of(0);
        res.settled[key_of(0)] = 500;
        res.settled[key_of(1)] = 0;         // zero row: normalized away
        res.note = "ORPHAN post-SETTLED (residual)";
        s.push_back(res);
    }
    {   // post-SETTLED orphan with an all-zero map: still bumps, residual 0.
        Step res0;
        res0.op = 2;
        res0.bid = bid_of(3);               // i=3 was finalized
        res0.settled[key_of(2)] = 0;
        res0.note = "ORPHAN post-SETTLED (zero residual)";
        s.push_back(res0);
    }

    return s;
}

// Apply one step to any object exposing the three W4 mutators.
template <typename Ledger>
void apply_step(Ledger& led, const Step& st) {
    switch (st.op) {
        case 0: led.on_block_found(st.bid, st.credit, st.payout); break;
        case 1: led.on_block_finalized(st.bid, st.bin_height); break;
        case 2: led.on_block_orphaned(st.bid, st.settled); break;
        default: break;
    }
}

// Cuts at which the goldens are taken (number of steps applied).
inline std::vector<std::size_t> cut_points() { return {0, 6, 15, 21, 24}; }

// ─────────────────────────────────────────────────────────────────────────
// GOLDENS
//
// (1) GATE-OFF — minted on PRISTINE MASTER (commit 1b2f1956) with this exact
//     schedule. Both columns MUST stay byte-identical on this branch: the
//     owed-event MMR is additive, and the gate that would commit it into the
//     StateCommitment tree is OFF by default.
// (2) OWED-EVENT MMR — the new, additive value: the record-log root and leaf
//     count at the same cuts. Never committed while the gate is OFF.
// (3) GATE-ON — the NEW StateCommitment root the flag day produces, i.e. what
//     -DV37_OWED_EVENT_MMR_COMMIT=1 makes every node commit at each cut. Held
//     here so the operator can diff it before flipping anything.
//
// Column order matches cut_points(): 0, 6, 15, 21, 24(END).
// ─────────────────────────────────────────────────────────────────────────
struct Golden {
    std::size_t steps;
    unsigned long long ledger_seq;
    const char* owed_digest;          // (1) unchanged from master
    const char* sc_root_gate_off;     // (1) unchanged from master
    unsigned long long mmr_leaves;    // (2)
    const char* mmr_root;             // (2)
    const char* sc_root_gate_on;      // (3)
};

inline std::vector<Golden> goldens_v1() {
    return {
        {0,  0,
         "b4db1ded95a73f939975a259f9b48a1d182109f44397ed77e35d624f1a5cf339",
         "dcc852532ffae28c95e3d5af347c6dfb78e1552ac77228b3aef19c066d41a6b8",
         0, "0000000000000000000000000000000000000000000000000000000000000000", "c792cbb8d8309dfca86f0c8070fbefadc2bf3121359fa3e8b97a9d3df1361e1f"},
        {6,  6,
         "0971538e18b2c0a7c643ab937535a730f9a7b42650ebc5ceb02dedf6c43e822d",
         "404aeca6cef211cc630390211ff08b23abcc41e2260ec348c244ec83a6090a47",
         6, "e28e930deffcca3375c8640d48240b60f7d28c2a137952234fedfcdeae456c21", "dc7f3f03e8d2e86e2ff585d77cb2d0075a3479e4e115c6b7cfdb351039083357"},
        {15, 15,
         "d3e0b7ac447e54a77ae17448c486032e239f7d44adcf5d99d3f72379cb69b63a",
         "3224afac60c5a4de85470a845bc5f600a8aa6cf6c4629a11ea9613c5afcc3eca",
         15, "9fb5190d8c370013f9d152ee38a05d42c3574935ec8f688fb4fa226b47adbde3", "cfaaef55c160c4e1efb98ed51388868ef84267d891b62a3e8366cff57c19c051"},
        {21, 20,
         "5e3c0cd2ff4db05b1111ef2cb8174838f238f61dae0dea258ba818528908b2e4",
         "309662e29e0bec557f8fd14be593cbcd115173e00556bd0741ad5bfa901456dd",
         20, "e8916ef462325958a3d40d92e160bfe126c84b19285f5748c363b8bfc40a842b", "d45517c7b71878891a4eede39db4ca34482ddcfe4f50a72d029f1146737205b7"},
        {24, 22,
         "5e3c0cd2ff4db05b1111ef2cb8174838f238f61dae0dea258ba818528908b2e4",
         "55ff6625312a8d668ce9b60183c5ff9756a84e0fc797e0195a1d149519a0d8d8",
         22, "e233bbc5ea5243f47d90e40406de7171b102bff9127d690346669db49072e7be", "b8380f38c64e1c2da4791d36b69df520593ddc059ef20e9d8de11ac8dbd8b1c0"},
    };
}

// Absolute leaf-rule pins (independent of the schedule).
// LEAF_KAT_GOLDEN = sha256d(0x00 || "V37L-RECORD-LOG-KAT-VECTOR-0001").
inline constexpr const char* LEAF_KAT_PAYLOAD = "V37L-RECORD-LOG-KAT-VECTOR-0001";
inline constexpr const char* LEAF_KAT_GOLDEN  = "7c06abcf2456a0d141e51a8d8dc9fbf47e27f5b16da9440ebf13cae22a3e0d70";
// The canonical payload bytes of the schedule's FIRST leaf (a FOUND on blk00),
// hex, so the leaf ENCODING is pinned and not only its hash.
inline constexpr const char* FIRST_LEAF_PAYLOAD_HEX = "5633374c0105000000626c6b30300000000000000000030000000018293a4b5c6d7e8fa0b1c2d3e4f5061728394a5b6c7d8e9fb0c1d2e3f40516e803000000000000013748596a7b8c9daebfd0e1f2031425364758697a8b9cadbecfe0f102132435d00700000000000002566778899aabbccddeef00112233445566778899aabbccddeeff1021324354b80b000000000000010000000018293a4b5c6d7e8fa0b1c2d3e4f5061728394a5b6c7d8e9fb0c1d2e3f40516f40100000000000000000000";
inline constexpr const char* FIRST_LEAF_HASH        = "ad9feef1a67aa196e58a1fd61f7b8c8217bf73e8c96ce442a2bb8160b37d7fd0";
// The empty record log bags to 32 zero bytes (Lane::mmr_bag of no peaks).
// Deliberately NOT the empty owed_digest anchor: they commit different things.
inline constexpr const char* EMPTY_LOG_ROOT =
    "0000000000000000000000000000000000000000000000000000000000000000";
inline constexpr const char* EMPTY_OWED_DIGEST_ANCHOR =
    "b4db1ded95a73f939975a259f9b48a1d182109f44397ed77e35d624f1a5cf339";

} // namespace oes_v1
