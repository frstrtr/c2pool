// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_snapshot_resume_kat.cpp
//
// RESUME WITHOUT RE-IBD: the snapshot is the node's trust root for this
// session, and the boot has to know it.
//
// THE DEFECT THIS FILE PINS, as it was observed on a live regtest run. The node
// loaded its snapshot straight into the chain index (`index_.load_snapshot`)
// after gate 4 settled, announced READY, and then wiped itself: ChainBoot still
// had `booted_ == false`, so the FIRST inbound blob went to `try_seed_()`,
// which seeds row zero with `ChainIndex::seed_direct` -- and seed_direct
// RESETS the index. The log said everything and explained nothing:
//
//     [snapshot] RESUMED at height 600 ... no re-IBD from the anchor
//     [tip] height=1 ... [tip] height=600
//     randomx hashes=601 verified=600
//
// -- a resumed chain, destroyed, re-fetched and re-hashed block by block, with
// the pool's own status line reading "native tip feed: events=300 best=0" a
// moment after READY.
//
// THE FIX IS STRUCTURAL, not an ordering tweak: the load now runs THROUGH
// ChainBoot (`resume_from_snapshot`), which installs the image and records that
// the boot is discharged, on the verify thread, in that order. Because
// on_objects() and on_chain_entry() test booted() FIRST, try_seed_() is then
// unreachable, the serving half advertises the resumed tip rather than height
// 1, and the sync driver asks for the next block rather than for genesis.
//
// WHAT IS CHECKED HERE, and why each part is not vacuous:
//
//   A  FIXTURE    -- the genesis row is DERIVED by the production
//                    genesis_row_from_blob() from a real monerod genesis blob,
//                    and the chain on top of it is built with the production
//                    parser, priced at the consensus emission, and connected by
//                    the real index with the PoW gate armed. Nothing below
//                    rests on a hand-written row.
//   B  RESUME     -- a fresh index plus a fresh ChainBoot resumed from that
//                    snapshot: the boot is DISCHARGED, the frontier is the
//                    snapshot's, the serving reads advertise the resumed tip,
//                    and the model verifier counts ZERO hashes.
//   B' THE CONTROL -- the same sequence with the OLD wiring (load at the index,
//                    boot never told) is run in the same file and must still be
//                    BROKEN: the boot stays owed its seed, the serving half
//                    keeps advertising height 1 no matter what the index holds,
//                    and no inbound blob can get it out of that state. Without
//                    this control, every assertion in B could pass for the
//                    wrong reason. (It is broken differently now than it was in
//                    production: the belt added to try_seed_() refuses to seed
//                    row zero over a populated index, so the rows survive and
//                    the node is merely stuck at the frontier instead of wiped
//                    back to height 0. Stuck is not acceptable either, which is
//                    why the fix is the booted flag and not the belt.)
//   C  FALLBACK   -- absent, corrupt, foreign-network and different-anchor
//                    images are all REFUSED, the index is left as it was, the
//                    boot stays owed its seed, and the ordinary genesis boot
//                    still works afterwards. Fail-closed, in five directions.
//   D  GATE 4     -- an INSTALLED but UNCONFIRMED anchor refuses the resume,
//                    checked inside ChainBoot rather than left to the caller's
//                    line order; once the network confirms, the same image
//                    resumes and the node carries on from the frontier instead
//                    of re-walking from the anchor.
//   E  NODE       -- the whole NativeNode, started and stopped for real, with
//                    no peers and no daemon: a genesis boot over a good
//                    snapshot comes up AT the snapshot's frontier and NOT owed
//                    a genesis seed (the READY-over-a-wipeable-index pin), a
//                    missing or corrupt or foreign snapshot still starts on the
//                    boot path, and a gate-4 REFUSAL arms no saver -- proven by
//                    the good file on disk being byte-identical afterwards.
//
// No sockets are dialled (the node is configured with no peers and no seeds),
// no daemon is contacted, and no RandomX is linked: the PoW gate is driven by a
// model verifier whose hash counter is what the "no re-IBD" claim is measured
// with. Registered in BOTH `--target` lists in .github/workflows/build.yml -- a
// registered-but-unbuilt target reads as "***Not Run" and fails ctest with exit
// 8 (the #1539 lesson).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/anchor/xmr_anchor_codec.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_load.hpp"
#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/chain/xmr_pow_gate.hpp"
#include "impl/xmr/native/consensus/xmr_block_id.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/consensus/xmr_reward.hpp"
#include "impl/xmr/native/contracts/fakes/fake_fetcher.hpp"
#include "impl/xmr/native/node/xmr_chain_boot.hpp"
#include "impl/xmr/native/node/xmr_chain_snapshot_store.hpp"
#include "impl/xmr/native/node/xmr_native_node.hpp"
#include "impl/xmr/native/p2p/chain_seeds.hpp"
#include "xmr_p2p_kat_util.hpp"

namespace native = c2pool::xmr::native;
namespace rt     = c2pool::xmr::native::rt;
namespace kat    = c2pool::xmr::native::kat;

using native::BlockEntry;
using native::ChainEntry;
using native::ChainRow;
using native::Hash;
using native::OfferOutcome;
using native::OfferResult;
using native::PeerRef;
using native::PeerSyncData;
using native::U128;

namespace {

// ===========================================================================
// 0. The genesis blob, and the model verifier the "no re-IBD" claim is
//    measured with
// ===========================================================================

// The genesis block of the Monero MAINNET chain, exactly as monerod 0.18.5.1
// returned it from get_block(height=0) -- the same bytes xmr_native_node_kat
// derives row zero from. A regtest (fakechain) daemon serves the SAME block at
// height 0, which is why the regtest boot path uses the mainnet genesis id.
constexpr const char* MAINNET_GENESIS_BLOB_HEX =
    "010000000000000000000000000000000000000000000000000000000000000000000010"
    "270000013c01ff0001ffffffffffff03029b2e4c0281c0b02e7c53291a94d1d0cbff8883"
    "f8024f5142ee494ffbbd08807121017767aafcde9be00dcfd098715ebcf7f410daebc582"
    "fda69d24a28e9d0bc890d100";

std::vector<std::uint8_t> from_hex(const std::string& h) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2) {
        const int hi = nib(h[i]), lo = nib(h[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::vector<std::uint8_t> genesis_blob() { return from_hex(MAINNET_GENESIS_BLOB_HEX); }

// Shaped exactly like c2pool::xmr::LightVerifier, and counting. `hashes` is the
// whole measurement behind "no proof of work was re-run for a height at or
// below the resumed frontier".
class ModelVerifier {
public:
    enum class VerifyStatus { Accept, BelowTarget, SeedNotResident, NotInitialized };

    bool prefetch_epoch(const Hash& current, const std::optional<Hash>& next) {
        ++rekeys;
        cur_ = current;
        nxt_ = next;
        return true;
    }

    bool seed_resident(const Hash& s) const {
        if (cur_ && *cur_ == s) return true;
        return nxt_ && *nxt_ == s;
    }

    VerifyStatus verify(const std::uint8_t*, std::size_t, const Hash& seed,
                        std::uint64_t, std::uint64_t, std::uint8_t out[32]) {
        if (!seed_resident(seed)) return VerifyStatus::SeedNotResident;
        ++hashes;
        for (int i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(i);
        return VerifyStatus::Accept;
    }

    std::uint64_t rekeys = 0;
    std::uint64_t hashes = 0;

private:
    std::optional<Hash> cur_, nxt_;
};

PeerRef peer(const char* addr, std::uint64_t id) {
    PeerRef p;
    p.addr    = addr;
    p.peer_id = id;
    return p;
}

// ===========================================================================
// 0b. Building a block (xmr_reorg_follow_kat's shape: a structurally real
//     Monero block with one coinbase output and no transactions)
// ===========================================================================
void put_varint(std::vector<std::uint8_t>& o, std::uint64_t v) { native::blob_write_varint(o, v); }

BlockEntry make_block(std::uint8_t major, std::uint8_t minor, std::uint64_t timestamp,
                      const Hash& prev, std::uint32_t nonce, std::uint64_t height,
                      std::uint64_t reward, std::uint8_t salt = 0) {
    std::vector<std::uint8_t> b;
    put_varint(b, major);
    put_varint(b, minor);
    put_varint(b, timestamp);
    b.insert(b.end(), prev.begin(), prev.end());
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>((nonce >> (8 * i)) & 0xff));

    put_varint(b, 2);                       // miner_tx version
    put_varint(b, height + 60);             // unlock_time
    put_varint(b, 1);                       // one input
    b.push_back(0xFF);                      // TX_IN_GEN
    put_varint(b, height);
    put_varint(b, 1);                       // one output
    put_varint(b, reward);
    b.push_back(0x03);                      // TX_OUT_TO_TAGGED_KEY
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<std::uint8_t>(0x10 + i));
    b.push_back(salt);                      // view tag doubles as the sibling salt
    put_varint(b, 33);                      // tx_extra length
    b.push_back(0x01);                      // TX_EXTRA_TAG_PUBKEY
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<std::uint8_t>(0x40 + i));
    b.push_back(0x00);                      // rct type NULL

    put_varint(b, 0);                       // no transaction hashes

    BlockEntry e;
    e.block_blob = std::move(b);
    return e;
}

Hash id_of(const BlockEntry& e) {
    native::EvaluatedBlock ev;
    std::string            why;
    if (native::evaluate_block(e, ev, why) != native::EvalStatus::Ok) return Hash{};
    return ev.input.identity.id;
}

// A private chain runs at the newest implemented fork version from height 1
// (REGTEST_HARD_FORKS), so every block above genesis carries that version.
constexpr std::uint8_t kRegMajor = native::MAX_IMPLEMENTED_HF_VERSION;

// The un-penalised base reward at a given already_generated_coins, straight out
// of the consensus reward code: a young chain is not in tail emission, so each
// block has to be priced at the emission standing under it.
std::uint64_t base_at(std::uint64_t agc) {
    std::uint64_t base = 0;
    (void)native::get_block_reward(/*penalty_median=*/300'000, /*block_weight=*/300, agc,
                                   native::hf_rules_version(kRegMajor), base);
    return base;
}

std::uint64_t agc_at(const native::ChainIndex& idx, std::uint64_t height) {
    for (const ChainRow& r : idx.view().state().rows())
        if (r.height == height) return r.already_generated_coins;
    return 0;
}

native::ChainIndexOptions regtest_options() {
    native::ChainIndexOptions o;
    o.net         = native::XmrNet::Regtest;
    o.require_pow = true;    // the hash counter is the measurement; keep the gate armed
    return o;
}

// ===========================================================================
// 0c. The fixture: a from-genesis regtest chain, seeded THROUGH ChainBoot from
//     the real genesis blob and extended by the real index.
//
// Everything about it is production code: the row comes out of
// genesis_row_from_blob(), the seed happens because a peer handed the boot a
// blob, and every block above it is judged by ChainIndex::offer_block with the
// PoW gate armed.
// ===========================================================================
constexpr std::uint64_t kChainHeight = 6;

struct GenesisChain {
    ModelVerifier                                 mv;
    native::LightVerifierPowSource<ModelVerifier> src{mv};
    native::ChainIndex                            idx{regtest_options(), src};
    rt::ChainBoot boot{idx, rt::BootMode::Genesis, native::p2p::MAINNET_GENESIS,
                       native::XmrNet::Regtest};
    native::fakes::FakeFetcher fetcher;
    std::vector<BlockEntry>    blocks;    // index 0 == height 1
    std::vector<Hash>          ids;       // index 0 == height 1

    explicit GenesisChain(std::uint64_t n = kChainHeight) {
        idx.set_fetcher(&fetcher);

        BlockEntry ge;
        ge.block_blob = genesis_blob();
        std::vector<BlockEntry> batch{ge};
        boot.on_objects(peer("127.0.0.1:18080", 1), std::move(batch), {}, 1);

        Hash prev = idx.tip() ? idx.tip()->id : Hash{};
        for (std::uint64_t h = 1; h <= n; ++h) {
            BlockEntry e = block_for(prev, h, agc_at(idx, h - 1));
            const OfferResult r = idx.offer_block(nullptr, e, /*own_mined=*/true);
            kat::checkf(r.outcome == OfferOutcome::Connected,
                        "fixture: block %llu became %s (%s)",
                        (unsigned long long)h, native::to_string(r.outcome), r.why.c_str());
            prev = r.id;
            blocks.push_back(std::move(e));
            ids.push_back(prev);
        }
    }

    // The genesis block's own timestamp is 0 (it is on mainnet), so the chain
    // above it is stamped from there at the two-minute target.
    static BlockEntry block_for(const Hash& prev, std::uint64_t height, std::uint64_t agc) {
        return make_block(kRegMajor, kRegMajor, /*timestamp=*/120 * height, prev,
                          static_cast<std::uint32_t>(height * 31), height, base_at(agc),
                          /*salt=*/0);
    }

    std::uint64_t tip_height() const { return idx.tip() ? idx.tip()->height : 0; }
    Hash          tip_id()     const { return idx.tip() ? idx.tip()->id : Hash{}; }
};

// The key a GENESIS boot on regtest computes for its envelope: this network's
// consensus id, height 0, and the pinned genesis id (NativeNode::snapshot_key_).
rt::SnapshotKey regtest_genesis_key() {
    rt::SnapshotKey k;
    k.net           = static_cast<std::uint64_t>(native::XmrNet::Regtest);
    k.anchor_height = 0;
    k.anchor_id     = native::p2p::MAINNET_GENESIS;
    return k;
}

bool write_file(const std::string& path, const std::vector<std::uint8_t>& bytes) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(f);
}

std::vector<std::uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(f)),
                                     std::istreambuf_iterator<char>());
}

// ===========================================================================
// A. The fixture is honest before anything rests on it
// ===========================================================================
void test_fixture() {
    GenesisChain c;

    kat::check(c.boot.booted(), "fixture: the real genesis blob seeds the boot");
    kat::checkf(c.tip_height() == kChainHeight,
                "fixture: the chain reached height %llu, got %llu",
                (unsigned long long)kChainHeight, (unsigned long long)c.tip_height());
    kat::checkf(c.mv.hashes == kChainHeight,
                "fixture: building the chain ran %llu proofs of work, expected %llu "
                "(the gate is armed, so a zero here later means something)",
                (unsigned long long)c.mv.hashes, (unsigned long long)kChainHeight);

    // Row zero is the one every implementation of this network compiles in, and
    // it was derived, not asserted.
    const auto zero = c.idx.by_height(0);
    kat::check(zero.has_value() && zero->id == native::p2p::MAINNET_GENESIS,
               "fixture: row zero is the pinned genesis, derived from its blob");

    std::vector<std::uint8_t> image;
    std::string               why;
    kat::checkf(c.idx.save_snapshot(image, why), "fixture: save_snapshot failed (%s)",
                why.c_str());
    kat::check(!image.empty(), "fixture: the image is not empty");
}

// ===========================================================================
// B. THE RESUME, and B' THE WIPE IT REPLACES
// ===========================================================================
void test_genesis_resume() {
    GenesisChain src;
    std::vector<std::uint8_t> image;
    std::string               why;
    if (!src.idx.save_snapshot(image, why)) {
        kat::checkf(false, "resume: the fixture could not be snapshotted (%s)", why.c_str());
        return;
    }
    const std::uint64_t frontier = src.tip_height();
    const Hash          tip_id   = src.tip_id();

    // --- the resumed node ---------------------------------------------------
    ModelVerifier                                 mv;
    native::LightVerifierPowSource<ModelVerifier> pow{mv};
    native::ChainIndex                            idx(regtest_options(), pow);
    rt::ChainBoot boot(idx, rt::BootMode::Genesis, native::p2p::MAINNET_GENESIS,
                       native::XmrNet::Regtest);
    native::fakes::FakeFetcher fetcher;
    idx.set_fetcher(&fetcher);

    kat::check(!boot.booted(), "resume: a genesis boot starts owed its seed");

    std::string load_why;
    const bool  ok = boot.resume_from_snapshot(image, load_why);
    kat::checkf(ok, "resume: the snapshot loads through the boot (%s)", load_why.c_str());
    if (!ok) return;

    kat::check(boot.booted(),
               "resume: the boot is DISCHARGED by the load -- a snapshot carries its own "
               "trust root, so no genesis seed is owed and try_seed_() is unreachable");
    kat::check(boot.serving_ready(),
               "resume: and the node may serve (the genesis path's gate 4 is Disarmed)");
    kat::checkf(idx.tip() && idx.tip()->height == frontier,
                "resume: the index came back at height %llu, got %llu",
                (unsigned long long)frontier,
                (unsigned long long)(idx.tip() ? idx.tip()->height : 0));
    kat::check(idx.tip() && idx.tip()->id == tip_id, "resume: and at the same tip id");
    kat::checkf(mv.hashes == 0, "resume: the load re-ran %llu proofs of work",
                (unsigned long long)mv.hashes);
    kat::check(boot.stats().why.find("resumed from snapshot") != std::string::npos,
               "resume: the boot's own status line says where its root came from");

    // --- the SERVING half now describes the resumed chain --------------------
    // Pre-fix this answered current_height 1 / top_id genesis, which is how a
    // resumed node ended up being handed the whole chain again.
    const PeerSyncData sd = boot.our_sync_data();
    kat::checkf(sd.current_height == frontier + 1,
                "resume: we advertise the RESUMED tip (current_height %llu, expected %llu)",
                (unsigned long long)sd.current_height, (unsigned long long)(frontier + 1));
    kat::check(sd.top_id == tip_id, "resume: with the resumed tip id, not the genesis");
    kat::check(boot.have_block(tip_id), "resume: we hold the resumed tip");
    kat::check(boot.locator().size() > 1,
               "resume: the locator spans the resumed chain rather than the genesis alone");

    // --- THE REGRESSION: the genesis blob, delivered the way a peer delivers it
    // This is the exact sequence that used to destroy the resumed chain: a
    // monerod that sees a peer it thinks is behind pushes blocks, and the first
    // blob through the un-booted gate seeded row zero over the top of
    // everything.
    {
        BlockEntry ge;
        ge.block_blob = genesis_blob();
        std::vector<BlockEntry> batch{ge};
        boot.on_objects(peer("127.0.0.1:18080", 2), std::move(batch), {}, frontier + 1);
    }
    kat::checkf(idx.tip() && idx.tip()->height == frontier,
                "resume: the genesis blob did NOT reset the resumed index (height %llu, "
                "expected %llu)",
                (unsigned long long)(idx.tip() ? idx.tip()->height : 0),
                (unsigned long long)frontier);

    // --- and the re-IBD itself does not happen -------------------------------
    // Every block at or below the frontier is already known: Duplicate, decided
    // before the PoW gate is reached, so nothing is re-hashed.
    for (std::size_t i = 0; i < src.blocks.size(); ++i) {
        const OfferResult r = idx.offer_block(nullptr, src.blocks[i], /*own_mined=*/false);
        kat::checkf(r.outcome == OfferOutcome::Duplicate,
                    "resume: re-delivered block %llu became %s, expected Duplicate",
                    (unsigned long long)(i + 1), native::to_string(r.outcome));
    }
    kat::checkf(mv.hashes == 0,
                "resume: re-delivering the resumed prefix re-ran %llu proofs of work "
                "(the whole point is that it runs none)",
                (unsigned long long)mv.hashes);

    // --- and the chain still GROWS from the frontier --------------------------
    {
        const std::uint64_t h = frontier + 1;
        BlockEntry next = GenesisChain::block_for(tip_id, h, agc_at(idx, frontier));
        const OfferResult r = idx.offer_block(nullptr, next, /*own_mined=*/false);
        kat::checkf(r.outcome == OfferOutcome::Connected,
                    "resume: the next block extends the resumed chain (got %s: %s)",
                    native::to_string(r.outcome), r.why.c_str());
        kat::checkf(mv.hashes == 1,
                    "resume: exactly the ONE new block was hashed, not the prefix (%llu)",
                    (unsigned long long)mv.hashes);
    }
}

// B'. The control. If this stops failing the way it does here, every assertion
// above has stopped meaning anything.
void test_old_wiring_is_stuck() {
    GenesisChain src;
    std::vector<std::uint8_t> image;
    std::string               why;
    if (!src.idx.save_snapshot(image, why)) {
        kat::checkf(false, "control: the fixture could not be snapshotted (%s)", why.c_str());
        return;
    }
    const std::uint64_t frontier = src.tip_height();

    ModelVerifier                                 mv;
    native::LightVerifierPowSource<ModelVerifier> pow{mv};
    native::ChainIndex                            idx(regtest_options(), pow);
    rt::ChainBoot boot(idx, rt::BootMode::Genesis, native::p2p::MAINNET_GENESIS,
                       native::XmrNet::Regtest);
    native::fakes::FakeFetcher fetcher;
    idx.set_fetcher(&fetcher);

    // THE OLD WIRING, reproduced deliberately: the image goes into the index and
    // the boot is never told.
    kat::checkf(idx.load_snapshot(image, why), "control: the image loads at the index (%s)",
                why.c_str());
    kat::check(idx.tip() && idx.tip()->height == frontier,
               "control: the index is at the resumed frontier, and the node would announce "
               "READY here");
    kat::check(!boot.booted(),
               "control: but the boot is STILL OWED A SEED -- this is the whole defect");

    // One inbound blob later, the resumed chain is gone. The belt added to
    // try_seed_() refuses to seed over a populated index, so the chain
    // SURVIVES; what the control pins is that the boot is still un-booted, and
    // therefore that the node is stuck rather than merely slow.
    {
        BlockEntry ge;
        ge.block_blob = genesis_blob();
        std::vector<BlockEntry> batch{ge};
        boot.on_objects(peer("127.0.0.1:18080", 3), std::move(batch), {}, frontier + 1);
    }
    kat::check(!boot.booted(),
               "control: the old wiring cannot boot itself out of this state");
    kat::checkf(idx.tip() && idx.tip()->height == frontier,
                "control: and the belt in try_seed_() kept the rows (height %llu)",
                (unsigned long long)(idx.tip() ? idx.tip()->height : 0));
    kat::check(boot.stats().refusals >= 1,
               "control: the refusal to seed over a populated index is counted");

    // The serving half is the visible half of being stuck: a node that keeps
    // advertising height 1 gets handed the whole chain again, forever.
    kat::check(boot.our_sync_data().current_height == 1,
               "control: an un-booted gate advertises height 1 no matter what the index "
               "holds -- which is what made the resumed node re-IBD");
}

// ===========================================================================
// C. FALLBACK: every way a resume can fail leaves the boot path intact
// ===========================================================================
void test_resume_fallbacks() {
    // --- at the image level --------------------------------------------------
    {
        ModelVerifier                                 mv;
        native::LightVerifierPowSource<ModelVerifier> pow{mv};
        native::ChainIndex                            idx(regtest_options(), pow);
        rt::ChainBoot boot(idx, rt::BootMode::Genesis, native::p2p::MAINNET_GENESIS,
                           native::XmrNet::Regtest);

        std::string why;
        kat::check(!boot.resume_from_snapshot({}, why), "fallback: an empty image is refused");
        kat::check(!why.empty(), "fallback: and it says why");
        kat::check(!boot.booted(), "fallback: a refused resume does not discharge the boot");
        kat::check(!idx.tip().has_value(), "fallback: and leaves the index empty");

        GenesisChain              src;
        std::vector<std::uint8_t> image;
        std::string               w2;
        if (src.idx.save_snapshot(image, w2) && image.size() > 40) {
            std::vector<std::uint8_t> corrupt = image;
            corrupt[corrupt.size() / 2] ^= 0x01;
            kat::check(!boot.resume_from_snapshot(corrupt, why),
                       "fallback: a corrupt image is refused by the index's own digest");
            kat::check(!boot.booted(), "fallback: still owed its seed");

            std::vector<std::uint8_t> truncated(image.begin(), image.begin() + 30);
            kat::check(!boot.resume_from_snapshot(truncated, why),
                       "fallback: a truncated image is refused");

            // A snapshot from another NETWORK, at the index's own gate.
            native::ChainIndexOptions so;
            so.net = native::XmrNet::Stagenet;
            ModelVerifier                                 mv2;
            native::LightVerifierPowSource<ModelVerifier> pow2{mv2};
            native::ChainIndex                            other(so, pow2);
            rt::ChainBoot other_boot(other, rt::BootMode::Genesis,
                                     native::p2p::STAGENET_GENESIS, native::XmrNet::Stagenet);
            kat::check(!other_boot.resume_from_snapshot(image, why),
                       "fallback: a regtest image is refused by a stagenet index");
            kat::check(!other_boot.booted(), "fallback: and that boot is still owed its seed");
        }

        // The whole point of failing closed: the ORDINARY boot still works.
        BlockEntry ge;
        ge.block_blob = genesis_blob();
        std::vector<BlockEntry> batch{ge};
        boot.on_objects(peer("127.0.0.1:18080", 4), std::move(batch), {}, 1);
        kat::check(boot.booted(),
                   "fallback: after every refusal the genesis seed still boots the node");
        kat::check(idx.tip() && idx.tip()->height == 0,
                   "fallback: from row zero, exactly as a node with no snapshot does");
    }

    // --- at the envelope level (the file the node actually reads) -------------
    {
        GenesisChain              src;
        std::vector<std::uint8_t> image;
        std::string               why;
        if (!src.idx.save_snapshot(image, why)) return;

        const rt::SnapshotKey key  = regtest_genesis_key();
        const std::vector<std::uint8_t> file = rt::encode_snapshot_envelope(key, image);

        std::vector<std::uint8_t> back;
        kat::checkf(rt::decode_snapshot_envelope(file, key, back, why),
                    "envelope: a file written for this key decodes (%s)", why.c_str());
        kat::check(back == image, "envelope: and the image comes back byte-identical");

        rt::SnapshotKey foreign_net = key;
        foreign_net.net = static_cast<std::uint64_t>(native::XmrNet::Stagenet);
        kat::check(!rt::decode_snapshot_envelope(file, foreign_net, back, why),
                   "envelope: a file from another network is REFUSED");

        rt::SnapshotKey other_anchor = key;
        other_anchor.anchor_height = 2204000;
        kat::check(!rt::decode_snapshot_envelope(file, other_anchor, back, why),
                   "envelope: a file bound to a different trust anchor is REFUSED");

        std::vector<std::uint8_t> tampered = file;
        tampered[tampered.size() / 2] ^= 0x80;
        kat::check(!rt::decode_snapshot_envelope(tampered, key, back, why),
                   "envelope: a tampered file is REFUSED by the digest, before any length "
                   "inside it is trusted");
    }
}

// ===========================================================================
// D. GATE 4: a resume may not fast-forward along an UNCONFIRMED anchor
// ===========================================================================
constexpr std::uint64_t kAnchorHeight = 2204000;

// The same builder the gate-4 KAT uses, with the parent made explicit so a
// child of the anchor can be built.
struct AnchorBlockSpec {
    std::uint64_t height    = kAnchorHeight;
    std::uint64_t timestamp = 1788965550;
    std::uint64_t major     = 16;
    std::uint64_t minor     = 16;
    std::uint32_t nonce     = 0x0badc0de;
    std::uint64_t reward    = 600000000000ull;   // tail emission
    std::uint8_t  flavour   = 0x11;
    bool          pin_prev  = false;
    Hash          prev{};
};

std::vector<std::uint8_t> build_anchor_blob(const AnchorBlockSpec& spec) {
    std::vector<std::uint8_t> b;
    put_varint(b, spec.major);
    put_varint(b, spec.minor);
    put_varint(b, spec.timestamp);
    if (spec.pin_prev) {
        b.insert(b.end(), spec.prev.begin(), spec.prev.end());
    } else {
        for (std::size_t i = 0; i < 32; ++i)
            b.push_back(static_cast<std::uint8_t>((spec.height - 1 + i) ^ spec.flavour));
    }
    b.push_back(static_cast<std::uint8_t>(spec.nonce & 0xff));
    b.push_back(static_cast<std::uint8_t>((spec.nonce >> 8) & 0xff));
    b.push_back(static_cast<std::uint8_t>((spec.nonce >> 16) & 0xff));
    b.push_back(static_cast<std::uint8_t>((spec.nonce >> 24) & 0xff));

    put_varint(b, 2);                                        // miner_tx version
    put_varint(b, spec.height + 60);                         // unlock_time
    put_varint(b, 1);                                        // one input
    b.push_back(native::TX_IN_GEN);
    put_varint(b, spec.height);
    put_varint(b, 1);                                        // one output
    put_varint(b, spec.reward);
    b.push_back(native::TX_OUT_TO_TAGGED_KEY);
    for (std::size_t i = 0; i < 33; ++i)
        b.push_back(static_cast<std::uint8_t>((i * 7u) ^ spec.flavour));
    {
        std::vector<std::uint8_t> extra;
        extra.push_back(0x01);                               // TX_EXTRA_TAG_PUBKEY
        for (std::size_t i = 0; i < 32; ++i)
            extra.push_back(static_cast<std::uint8_t>((i * 3u) + spec.flavour));
        put_varint(b, extra.size());
        b.insert(b.end(), extra.begin(), extra.end());
    }
    b.push_back(0x00);                                       // rct type NULL
    put_varint(b, 0);                                        // no transaction hashes
    return b;
}

Hash model_hash(std::uint64_t seed, std::uint8_t tag) {
    Hash h{};
    for (std::size_t i = 0; i < 8; ++i) h[i] = static_cast<std::uint8_t>(seed >> (8 * i));
    for (std::size_t i = 8; i < h.size(); ++i) h[i] = static_cast<std::uint8_t>(tag + i);
    return h;
}

// A valid stagenet bundle at a real stagenet height and fork version, with the
// id of a block this file built -- the gate-4 KAT's fixture, because the point
// here is the ORDER of the two gates, not the bundle format.
native::AnchorBundle make_bundle(std::uint64_t height, const Hash& id) {
    native::AnchorBundle b;
    b.network       = "stagenet";
    b.height        = height;
    b.id            = id;
    b.prev_id       = model_hash(height - 1, 0x10);
    b.timestamp     = 1788965550;
    b.major_version = 16;
    b.cumulative_difficulty.hi = 0;
    b.cumulative_difficulty.lo = 0xc3772e00dbull;
    b.already_generated_coins  = 18163913490712907281ull;

    const std::uint64_t seed_h = native::rx_seedheight(b.height + 1);
    b.seed_ids.emplace_back(seed_h, model_hash(seed_h, 0x20));

    U128 cd{};
    cd.lo = 0xc2cb6d9d38ull;
    for (std::size_t i = 0; i < native::ANCHOR_DIFFICULTY_WINDOW; ++i) {
        b.difficulty_window.emplace_back(1788876380ull + i * 37ull, cd);
        cd = native::u128_add(cd, U128{0, 3766353ull});
    }
    for (std::size_t i = 0; i < native::ANCHOR_SHORT_TERM_WEIGHTS; ++i)
        b.short_term_weights.push_back(87ull + (i % 5));
    b.long_term_weights.assign(native::ANCHOR_LONG_TERM_WEIGHTS, 176470ull);
    b.monerod_checkpoints.emplace_back(b.height + 4096, model_hash(b.height + 4096, 0x30));
    b.digest = native::anchor_digest(b);
    return b;
}

bool write_bundle(const std::string& path, const native::AnchorBundle& b) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << native::write_anchor_inc(b, "snapshot-resume KAT bundle");
    return static_cast<bool>(f);
}

native::ChainIndexOptions stagenet_options() {
    native::ChainIndexOptions o;
    o.net         = native::XmrNet::Stagenet;
    o.require_pow = false;   // this suite is about the two gates' order, not hashes
    return o;
}

void test_anchor_resume_is_behind_gate4() {
    AnchorBlockSpec spec;
    const std::vector<std::uint8_t> anchor_blob = build_anchor_blob(spec);
    native::ParsedBlock pb;
    if (native::parse_block(anchor_blob, pb) != native::BlockParseStatus::Ok) {
        kat::check(false, "anchor: the fixture blob parses");
        return;
    }
    const Hash anchor_id = native::block_identity(anchor_blob.data(), pb).id;

    const std::string path = "snapres_kat_anchor.inc";
    if (!write_bundle(path, make_bundle(kAnchorHeight, anchor_id))) {
        kat::check(false, "anchor: the KAT can write its bundle");
        return;
    }

    // --- the session that WROTE the snapshot ---------------------------------
    // It booted on the anchor, had it confirmed, and then advanced. Its image is
    // what the next session is handed.
    std::vector<std::uint8_t> image;
    std::uint64_t             written_frontier = 0;
    {
        native::NoPowSource pow;
        native::ChainIndex  idx(stagenet_options(), pow);
        rt::ChainBoot       boot(idx, rt::BootMode::Anchor,
                                 native::p2p::genesis_id(native::p2p::XmrNet::Stagenet),
                                 native::XmrNet::Stagenet);
        std::string why;
        if (!boot.boot_from_anchor(path, native::XmrNet::Stagenet, {}, why)) {
            kat::checkf(false, "anchor: gates 1..3 accept the bundle (%s)", why.c_str());
            std::remove(path.c_str());
            return;
        }
        std::vector<BlockEntry> blocks;
        BlockEntry              e;
        e.block_blob = anchor_blob;
        blocks.push_back(std::move(e));
        boot.on_objects(peer("198.51.100.1:38080", 1001), std::move(blocks), {},
                        kAnchorHeight + 1);
        kat::check(boot.serving_ready(), "anchor: the writing session confirmed its anchor");

        // One block on top, so the image describes progress the next session
        // must not throw away.
        AnchorBlockSpec child;
        child.height   = kAnchorHeight + 1;
        child.pin_prev = true;
        child.prev     = anchor_id;
        child.timestamp = spec.timestamp + 120;
        child.flavour  = 0x33;
        BlockEntry ce;
        ce.block_blob = build_anchor_blob(child);
        const OfferResult r = idx.offer_block(nullptr, ce, /*own_mined=*/false);
        kat::checkf(r.outcome == OfferOutcome::Connected,
                    "anchor: the writing session extended past its anchor (got %s: %s)",
                    native::to_string(r.outcome), r.why.c_str());

        if (!idx.save_snapshot(image, why)) {
            kat::checkf(false, "anchor: the writing session could not snapshot (%s)",
                        why.c_str());
            std::remove(path.c_str());
            return;
        }
        written_frontier = idx.tip() ? idx.tip()->height : 0;
    }

    // --- the session that READS it -------------------------------------------
    native::NoPowSource pow;
    native::ChainIndex  idx(stagenet_options(), pow);
    rt::ChainBoot       boot(idx, rt::BootMode::Anchor,
                             native::p2p::genesis_id(native::p2p::XmrNet::Stagenet),
                             native::XmrNet::Stagenet);
    std::string why;
    const bool  installed = boot.boot_from_anchor(path, native::XmrNet::Stagenet, {}, why);
    std::remove(path.c_str());
    kat::checkf(installed, "anchor: gates 1..3 accept the bundle (%s)", why.c_str());
    if (!installed) return;

    kat::check(boot.booted() && !boot.serving_ready(),
               "anchor: INSTALLED IS NOT TRUSTED -- gate 4 is pending");

    // THE ORDER, pinned inside ChainBoot rather than left to start()'s line
    // order: resuming here would fast-forward the node along a chain the
    // network has not vouched for.
    std::string resume_why;
    kat::check(!boot.resume_from_snapshot(image, resume_why),
               "anchor: a resume over an UNCONFIRMED anchor is REFUSED");
    kat::check(resume_why.find("unconfirmed") != std::string::npos,
               "anchor: and the refusal names the unconfirmed anchor");
    kat::checkf(idx.tip() && idx.tip()->height == kAnchorHeight,
                "anchor: the refused resume left the index on the anchor row (height %llu)",
                (unsigned long long)(idx.tip() ? idx.tip()->height : 0));

    // The network confirms, exactly as it does in production (the block arrives
    // as the answer to our GET_OBJECTS).
    {
        std::vector<BlockEntry> blocks;
        BlockEntry              e;
        e.block_blob = anchor_blob;
        blocks.push_back(std::move(e));
        boot.on_objects(peer("198.51.100.2:38080", 1002), std::move(blocks), {},
                        kAnchorHeight + 1);
    }
    kat::check(boot.serving_ready(), "anchor: the network CONFIRMS the anchor");

    // And only now does the same image resume.
    kat::checkf(boot.resume_from_snapshot(image, resume_why),
                "anchor: after the confirm the snapshot resumes (%s)", resume_why.c_str());
    kat::checkf(idx.tip() && idx.tip()->height == written_frontier,
                "anchor: the node carries on from the frontier (height %llu, expected %llu) "
                "instead of re-walking from the anchor",
                (unsigned long long)(idx.tip() ? idx.tip()->height : 0),
                (unsigned long long)written_frontier);
    kat::check(boot.booted() && boot.serving_ready(),
               "anchor: the resume neither disarms nor re-arms gate 4");
}

// ===========================================================================
// E. THE NODE ITSELF: start(), stop(), and the file on disk
//
// No peers (`connect` empty, `use_seeds` false) and no daemon, so nothing is
// dialled; RandomX is not linked into this target, so the PoW gate is the null
// source and no block is connected here anyway. What is exercised is exactly
// the ordering start() owns: gate 4, then the resume, then the saver.
// ===========================================================================
rt::NativeNodeConfig node_cfg(const std::string& snap_path) {
    rt::NativeNodeConfig c;
    c.net              = rt::NativeNet::Regtest;
    c.boot             = rt::BootMode::Genesis;
    c.snapshot_path    = snap_path;
    c.snapshot_every_s = 0;        // only on a clean stop: no timer races in a KAT
    c.parity           = false;
    c.use_seeds        = false;
    c.driver_tick_ms   = 100;
    c.allow_unverified_pow = true; // no RandomX in this target; say so rather than pretend
    return c;
}

bool log_has(const std::vector<std::string>& lines, const char* needle) {
    for (const std::string& l : lines)
        if (l.find(needle) != std::string::npos) return true;
    return false;
}

void test_node_resumes_without_reibd() {
    GenesisChain              src;
    std::vector<std::uint8_t> image;
    std::string               why;
    if (!src.idx.save_snapshot(image, why)) {
        kat::checkf(false, "node: the fixture could not be snapshotted (%s)", why.c_str());
        return;
    }
    const std::uint64_t frontier = src.tip_height();
    const Hash          tip_id   = src.tip_id();

    const std::string path = "snapres_kat_node.snap";
    if (!write_file(path, rt::encode_snapshot_envelope(regtest_genesis_key(), image))) {
        kat::check(false, "node: the KAT can write its snapshot file");
        return;
    }

    rt::NativeNode node(node_cfg(path));
    std::string    start_why;
    const bool     started = node.start(start_why);
    kat::checkf(started, "node: a genesis boot with a good snapshot starts (%s)",
                start_why.c_str());
    if (!started) { std::remove(path.c_str()); return; }

    const rt::NodeStatus st = node.status();
    kat::checkf(st.sync.header_frontier == frontier,
                "node: READY at the resumed frontier %llu, got %llu",
                (unsigned long long)frontier, (unsigned long long)st.sync.header_frontier);
    kat::check(st.boot.booted,
               "node: and NOT owed a genesis seed -- the node never announces READY over "
               "an index that the next inbound blob would wipe");
    kat::check(st.boot.why.find("resumed from snapshot") != std::string::npos,
               "node: the boot's status line names the snapshot as its root");
    kat::check(node.index().tip() && node.index().tip()->id == tip_id,
               "node: the resumed tip is the one the snapshot recorded");
    kat::checkf(node.mainchain_events_seen() == 0,
                "node: the resume emitted %llu mainchain event(s); a resumed chain is not "
                "re-announced block by block",
                (unsigned long long)node.mainchain_events_seen());

    const std::vector<std::string> log = node.take_log();
    kat::check(log_has(log, "[snapshot] RESUMED"), "node: the run says it resumed");

    node.stop();

    // The clean stop wrote the image back. It must still be the resumed chain,
    // which is the other half of "no re-IBD": a node that had wiped itself
    // would have saved a one-row index over the good file.
    std::vector<std::uint8_t> after;
    kat::checkf(rt::read_snapshot_file(path, after, why), "node: the file survives (%s)",
                why.c_str());
    std::vector<std::uint8_t> back;
    kat::checkf(rt::decode_snapshot_envelope(after, regtest_genesis_key(), back, why),
                "node: and still decodes for this node's key (%s)", why.c_str());
    {
        ModelVerifier                                 mv;
        native::LightVerifierPowSource<ModelVerifier> pow{mv};
        native::ChainIndex                            check(regtest_options(), pow);
        kat::checkf(check.load_snapshot(back, why), "node: the written image loads (%s)",
                    why.c_str());
        kat::checkf(check.tip() && check.tip()->height == frontier,
                    "node: the file written on the clean stop is still at height %llu, got "
                    "%llu -- the good image was not clobbered",
                    (unsigned long long)frontier,
                    (unsigned long long)(check.tip() ? check.tip()->height : 0));
    }
    std::remove(path.c_str());
}

void test_node_falls_back_when_the_snapshot_is_unusable() {
    // --- absent --------------------------------------------------------------
    {
        const std::string path = "snapres_kat_absent.snap";
        std::remove(path.c_str());
        rt::NativeNode node(node_cfg(path));
        std::string    why;
        kat::checkf(node.start(why), "node: a missing snapshot still starts (%s)", why.c_str());
        const rt::NodeStatus st = node.status();
        kat::check(st.sync.header_frontier == 0, "node: on the ordinary genesis boot path");
        kat::check(!st.boot.booted,
                   "node: still owed its genesis seed, which is what a fresh node is");
        kat::check(log_has(node.take_log(), "[snapshot] no resume"),
                   "node: and it says there was nothing to resume from");
        node.stop();
        std::remove(path.c_str());
    }

    // --- corrupt -------------------------------------------------------------
    {
        GenesisChain              src;
        std::vector<std::uint8_t> image;
        std::string               why;
        if (!src.idx.save_snapshot(image, why)) return;
        std::vector<std::uint8_t> file =
            rt::encode_snapshot_envelope(regtest_genesis_key(), image);
        file[file.size() / 2] ^= 0x40;

        const std::string path = "snapres_kat_corrupt.snap";
        if (!write_file(path, file)) return;
        rt::NativeNode node(node_cfg(path));
        std::string    start_why;
        kat::checkf(node.start(start_why), "node: a corrupt snapshot still starts (%s)",
                    start_why.c_str());
        const rt::NodeStatus st = node.status();
        kat::check(st.sync.header_frontier == 0 && !st.boot.booted,
                   "node: fail-closed onto the genesis boot path");
        kat::check(log_has(node.take_log(), "[snapshot] REFUSED"),
                   "node: and the refusal is on the record");
        node.stop();
        std::remove(path.c_str());
    }

    // --- foreign: a good file, written by a node on another network ----------
    {
        GenesisChain              src;
        std::vector<std::uint8_t> image;
        std::string               why;
        if (!src.idx.save_snapshot(image, why)) return;
        rt::SnapshotKey foreign = regtest_genesis_key();
        foreign.net = static_cast<std::uint64_t>(native::XmrNet::Stagenet);

        const std::string path = "snapres_kat_foreign.snap";
        if (!write_file(path, rt::encode_snapshot_envelope(foreign, image))) return;
        rt::NativeNode node(node_cfg(path));
        std::string    start_why;
        kat::checkf(node.start(start_why), "node: a foreign snapshot still starts (%s)",
                    start_why.c_str());
        const rt::NodeStatus st = node.status();
        kat::check(st.sync.header_frontier == 0 && !st.boot.booted,
                   "node: a file written for another network is REFUSED, not adapted");
        node.stop();
        std::remove(path.c_str());
    }
}

// A gate-4 REFUSAL must arm no saver: the session that could not confirm its
// anchor is exactly the session whose index is worthless, and it must not be
// allowed to write that index over a good file.
void test_refused_gate4_writes_nothing() {
    GenesisChain              src;
    std::vector<std::uint8_t> image;
    std::string               why;
    if (!src.idx.save_snapshot(image, why)) return;

    const std::string path = "snapres_kat_gate4.snap";
    // A file that is GOOD for some other node -- what an operator's real
    // snapshot looks like to a node that is about to refuse to start.
    const std::vector<std::uint8_t> before =
        rt::encode_snapshot_envelope(regtest_genesis_key(), image);
    if (!write_file(path, before)) {
        kat::check(false, "gate4: the KAT can write its sentinel file");
        return;
    }

    rt::NativeNodeConfig c;
    c.net           = rt::NativeNet::Stagenet;   // the embedded bundle's network
    c.boot          = rt::BootMode::Anchor;      // gates 1..3 on the embedded anchor
    c.anchor_path   = "";                        // the release-pinned bundle
    c.snapshot_path = path;
    c.snapshot_every_s = 0;
    c.parity        = false;
    c.use_seeds     = false;                     // no peers at all: the gate must refuse
    c.driver_tick_ms = 100;
    c.allow_unverified_pow = true;
    c.anchor_confirm.peers       = 1;
    c.anchor_confirm.per_peer_ms = 100;
    c.anchor_confirm.timeout_ms  = 500;

    rt::NativeNode node(c);
    std::string    start_why;
    const bool     started = node.start(start_why);
    kat::check(!started,
               "gate4: with no peer able to serve the anchor block, the node REFUSES to "
               "start -- fail-closed, not silent trust");
    // WHICH refusal it was, so this cannot pass because gates 1..3 rejected the
    // bundle (or because the bundle could not be found at all): the anchor must
    // have been INSTALLED and gate 4 must be the thing that said no.
    const rt::NodeStatus st = node.status();
    kat::checkf(st.boot.booted,
                "gate4: the embedded bundle passed gates 1..3 and was installed (%s)",
                start_why.c_str());
    kat::checkf(st.boot.anchor.state == rt::AnchorConfirmState::Refused,
                "gate4: and it is GATE 4 that refused, not an earlier gate (state %s, %s)",
                rt::to_string(st.boot.anchor.state), start_why.c_str());
    kat::check(start_why.find("gate 4") != std::string::npos,
               "gate4: and the refusal says the network confirm is why");
    node.stop();

    const std::vector<std::uint8_t> after = read_file(path);
    kat::check(after == before,
               "gate4: a refused start armed NO saver -- the snapshot on disk is "
               "byte-identical, so a session that could not confirm its anchor cannot "
               "clobber a good image");
    std::remove(path.c_str());
}

} // namespace

int main() {
    test_fixture();
    test_genesis_resume();
    test_old_wiring_is_stuck();
    test_resume_fallbacks();
    test_anchor_resume_is_behind_gate4();
    test_node_resumes_without_reibd();
    test_node_falls_back_when_the_snapshot_is_unusable();
    test_refused_gate4_writes_nothing();
    return kat::report("xmr_native_snapshot_resume_kat");
}
