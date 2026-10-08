// v37_rb_cb_class_kat — S2: per-share cb_class -> coinbase payout byte budget.
//
//   A  class table {750, 2250, 6500, 16384, 65535, K_max}, decode strictness,
//      template floor (unknown -> class 0 = 750 B)
//   B  budget = min(class - overhead, free_after_txs, lane K_max): each arm binds
//   C  HAZARD: a computed 0 never becomes the w5 "unbounded" 0 (lifted to 1)
//   D  recomputable from the block alone: template-side budget == validator-
//      side budget_from_block(); an invalid committed class byte rejects
//   E  W5 integration with the REAL OwedLedger + assemble(): the class budget
//      bounds payout_bytes, the emitted outputs are an in-order PREFIX of the
//      unbounded K_fair sequence (K_fair untouched: oldest-first, no younger
//      output jumps an older one), the rest carries; owed_digest + state root
//      are budget-independent
#include <map>
#include <string>
#include <vector>

#include <c2pool/v37/roundabout/rb_cb_class.hpp>
#include <c2pool/v37/w5_coinbase.hpp>

#include "rb_kat_harness.hpp"

using namespace c2pool::v37n::rb;
using rbkat::ok;
namespace S = ::c2pool::v37n::settle;
namespace CB = ::c2pool::v37n::coinbase;
using ::v37::ScriptKind;
using ::v37::ScriptRef;

static std::map<bytes32, ScriptRef> g_pay;
static ScriptRef pay_of(const bytes32& k) {
    auto it = g_pay.find(k);
    return it == g_pay.end() ? ScriptRef{} : it->second;
}

int main() {
    std::printf("v37_rb_cb_class_kat\n");

    // ── A ──
    {
        const u64 want[5] = {750, 2250, 6500, 16384, 65535};
        bool t = true;
        for (int c = 0; c < 5; ++c) if (class_bytes(CbClass(c), 100000) != want[c]) t = false;
        ok(t, "A1 class 0..4 bytes = 750/2250/6500/16384/65535");
        ok(class_bytes(CbClass::SV2_HEADER_ONLY, 1000000) == 1000000, "A2 class 5 (SV2) = lane K_max");
        ok(class_bytes(CbClass::SV2_HEADER_ONLY, 0) == ~u64(0), "A3 class 5 under unbounded lane = no class ceiling");
        bool dec = true;
        for (int b = 0; b < 256; ++b) {
            const auto c = decode_cb_class(std::uint8_t(b));
            if ((b <= 5) != c.has_value()) dec = false;
            if (c && encode_cb_class(*c) != b) dec = false;
        }
        ok(dec, "A4 on-chain decode: 0..5 valid (round-trip), 6..255 INVALID");
        ok(template_cb_class(std::nullopt) == CbClass::STOCK_ANTMINER &&
               template_cb_class(std::uint8_t(9)) == CbClass::STOCK_ANTMINER &&
               template_cb_class(std::uint8_t(3)) == CbClass::OPEN_FW_16K,
           "A5 template: unknown/out-of-range -> floor class 0 (750 B)");
        ok(CB_FLOOR_BYTES == 750 && class_bytes(CbClass(0), 0) == CB_FLOOR_BYTES, "A6 floor = 750 B");
    }

    // ── B ──
    {
        ok(cb_budget(CbClass::WHATSMINER, 400, 1000000, 0) == 6100, "B1 class arm binds: 6500 - 400");
        ok(cb_budget(CbClass::OPEN_FW_SV1_MAX, 400, 20000, 0) == 20000, "B2 free-space arm binds");
        ok(cb_budget(CbClass::OPEN_FW_SV1_MAX, 400, 1000000, 8000) == 8000, "B3 lane K_max arm binds");
        ok(cb_budget(CbClass::SV2_HEADER_ONLY, 400, 1000000, 50000) == 49600, "B4 SV2: class ceiling = K_max, minus overhead");
        ok(cb_budget(CbClass::SV2_HEADER_ONLY, 400, 30000, 0) == 30000, "B5 SV2 unbounded lane: free space binds");
        ok(cb_budget(CbClass::STOCK_ANTMINER, 200, 1000000, 0) == 550, "B6 floor class: 750 - 200");
    }

    // ── C ──
    {
        ok(cb_budget(CbClass::STOCK_ANTMINER, 750, 1000000, 0) == 1, "C1 overhead == class -> 1, never 0 (unbounded)");
        ok(cb_budget(CbClass::STOCK_ANTMINER, 5000, 1000000, 0) == 1, "C2 overhead > class -> 1");
        ok(cb_budget(CbClass::OPEN_FW_16K, 100, 0, 0) == 1, "C3 full block (0 free) -> 1");
    }

    // ── D ──
    {
        rbkat::SplitMix64 r(0xCBC1);
        bool same = true;
        for (int i = 0; i < 2000; ++i) {
            const CbClass c = template_cb_class(std::uint8_t(r.below(8)));
            BlockFacts f;
            f.cb_class_byte = encode_cb_class(c);
            f.coinbase_fixed_overhead = 100 + r.below(2000);
            f.block_limit_bytes = 1000000;
            f.txs_bytes = r.below(1000000);
            const u64 lane_kmax = r.below(3) == 0 ? 0 : 1000 + r.below(100000);
            const u64 tmpl = cb_budget(c, f.coinbase_fixed_overhead, free_space_after_txs(f), lane_kmax);
            const auto val = budget_from_block(f, lane_kmax);
            if (!val || *val != tmpl) same = false;
        }
        ok(same, "D1 validator recompute from block == template budget (2000 random blocks)");
        BlockFacts bad; bad.cb_class_byte = 6; bad.block_limit_bytes = 1000000;
        ok(!budget_from_block(bad, 0).has_value(), "D2 committed class byte 6 -> block invalid");
        ok(payout_within_budget(550, 550) && !payout_within_budget(551, 550), "D3 payout_bytes <= budget check");
    }

    // ── E: W5 integration ──
    {
        S::OwedLedger L(3);
        std::vector<bytes32> keys;
        for (int i = 0; i < 40; ++i) {
            bytes32 k = rbkat::fill(std::uint8_t(0x40 + i));
            ScriptRef sr;
            sr.kind = (i % 3 == 0) ? ScriptKind::P2WPKH : (i % 3 == 1) ? ScriptKind::P2PKH : ScriptKind::P2TR;
            sr.payload.assign(sr.kind == ScriptKind::P2TR ? 32 : 20, std::uint8_t(i));
            g_pay[k] = sr;
            keys.push_back(k);
            S::OwedLedger::Amounts credit{{k, 100000 + i * 10}};
            const std::string bid = "b" + std::to_string(i);
            L.on_block_found(bid, credit, {});
            L.on_block_finalized(bid, 100 + (i * 7) % 40);   // scrambled ages
        }
        const bytes32 od0 = L.owed_digest();
        CB::CoinbaseBudget unb;          // unbounded
        unb.k_floor = 1;
        const auto full = CB::assemble(L, 50000000, unb, pay_of);
        ok(full.outputs.size() == 40, "E0 unbounded: all 40 balances emit");
        bool all_prefix = true, all_bounded = true, carried_ok = true;
        for (int c = 0; c <= 4; ++c) {
            CB::CoinbaseBudget bud = unb;
            bud.max_payout_bytes = cb_budget(CbClass(c), 200, 900000, 0);
            const auto a = CB::assemble(L, 50000000, bud, pay_of);
            if (a.payout_bytes > bud.max_payout_bytes) all_bounded = false;
            for (std::size_t i = 0; i < a.outputs.size(); ++i)
                if (a.outputs[i].key != full.outputs[i].key || a.outputs[i].amount != full.outputs[i].amount)
                    all_prefix = false;
            if (a.outputs.size() + a.carried != full.outputs.size()) carried_ok = false;
            if (!(a.state_root == full.state_root)) carried_ok = false;
            std::printf("   class %d budget=%llu B -> %zu outputs, %llu payout B, %zu carried\n", c,
                        (unsigned long long)bud.max_payout_bytes, a.outputs.size(),
                        (unsigned long long)a.payout_bytes, (std::size_t)a.carried);
        }
        ok(all_bounded, "E1 payout_bytes <= class budget for every class");
        ok(all_prefix, "E2 bounded outputs are an in-order prefix of the K_fair sequence (K_fair untouched)");
        ok(carried_ok, "E3 outputs + carried == eligible; state root budget-independent");
        CB::CoinbaseBudget one = unb; one.max_payout_bytes = cb_budget(CbClass(0), 900, 900000, 0);
        const auto none = CB::assemble(L, 50000000, one, pay_of);
        ok(one.max_payout_bytes == 1 && none.outputs.empty() && none.carried == 40,
           "E4 hazard path: budget 1 emits nothing, carries all (0 would have been unbounded)");
        ok(L.owed_digest() == od0, "E5 assembly mutates nothing (owed_digest unchanged)");
    }

    return rbkat::finish("v37_rb_cb_class_kat");
}
