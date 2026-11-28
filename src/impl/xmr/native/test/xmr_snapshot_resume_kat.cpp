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
//   F  OUTPUT SET -- a genesis boot (no seeded set) resumes the image together
//                    with the boot overlay written beside it: ring resolution
//                    stays on, twice in a row (the clean stop writes both);
//                    an image without a usable overlay (a snapshot of a build
//                    that wrote none, a crash between the two writes: an
//                    overlay of another image) is not resumed: the boot
//                    re-walks from its root, and two later starts never resume
//                    with ring resolution off.
//   G  LATE REFUSAL -- an image refused by the row, evaluation or connection
//                    test leaves the index as it was (its rows, state, output
//                    counter, booking tail and seed table), with no event and
//                    no row-sink call, at the index, on the anchor row and at
//                    the node (whose refusal line names the image's sha256);
//                    a good image resumes with one seeded row-sink call plus
//                    one per tail block, also under a set clock.
//
// No sockets are dialled (the node is configured with no peers and no seeds),
// no daemon is contacted, and no RandomX is linked: the PoW gate is driven by a
// model verifier whose hash counter is what the "no re-IBD" claim is measured
// with. Registered in BOTH `--target` lists in .github/workflows/build.yml -- a
// registered-but-unbuilt target reads as "***Not Run" and fails ctest with exit
// 8 (the #1539 lesson).
// ---------------------------------------------------------------------------

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
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
    native::ChainOutputSet     outs{0};   // fed as the node feeds its own (the boot overlay's source)

    explicit GenesisChain(std::uint64_t n = kChainHeight) {
        idx.set_fetcher(&fetcher);
        idx.subscribe_txs([this](const native::BlockTxEvent& ev) {
            if (ev.kind == native::BlockTxEvent::Kind::Connected) outs.on_block_connected(ev);
            else                                          outs.on_block_disconnected(ev);
        });

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
// The image file and the boot overlay beside it (`<path>.outset`: sha256 of the image, then the fixture set's
// overlay), as a node's save writes them.
bool write_pair(const std::string& path, GenesisChain& src, const std::vector<std::uint8_t>& image) {
    std::vector<std::uint8_t> ovl;
    std::string               why;
    if (!src.outs.serialize_overlay(ovl, why)) return false;
    native::anchor_hash::Sha256 h;
    h.update(image.data(), image.size());
    const std::array<std::uint8_t, 32> d = h.finish();
    std::vector<std::uint8_t> ofile(d.begin(), d.end());
    ofile.insert(ofile.end(), ovl.begin(), ovl.end());
    return write_file(path, rt::encode_snapshot_envelope(regtest_genesis_key(), image)) && write_file(path + ".outset", ofile);
}

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
    if (!write_pair(path, src, image)) {
        kat::check(false, "node: the KAT can write its snapshot file and its output-set overlay");
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
    std::remove((path + ".outset").c_str());
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

// ===========================================================================
// F. THE OUTPUT SET RESUMES WITH THE IMAGE (a genesis boot, no seeded set)
//    The image and the boot overlay beside it (`<snapshot>.outset`: sha256 of
//    the image, then the set the boot built) resume together: ring resolution
//    stays on. The node's clean stop writes both again, and the next start
//    resumes with them. Without the overlay file the image resumes alone and
//    ring resolution is off (the old posture, still the fallback).
// ===========================================================================
void test_node_resumes_the_output_set() {
    GenesisChain              src;
    std::vector<std::uint8_t> image, ovl;
    std::string               why;
    const bool img_ok = src.idx.save_snapshot(image, why);
    const bool ovl_ok = src.outs.serialize_overlay(ovl, why);
    kat::checkf(img_ok && ovl_ok, "outset: the fixture's image and its set's overlay are written (%s)", why.c_str());
    if (!img_ok || !ovl_ok) return;
    const std::string path = "snapres_kat_outset.snap";
    std::vector<std::uint8_t> ofile;
    {
        native::anchor_hash::Sha256 h;
        h.update(image.data(), image.size());
        const std::array<std::uint8_t, 32> d = h.finish();
        ofile.assign(d.begin(), d.end());
        ofile.insert(ofile.end(), ovl.begin(), ovl.end());
    }
    kat::check(write_file(path, rt::encode_snapshot_envelope(regtest_genesis_key(), image))
                       && write_file(path + ".outset", ofile),
               "outset: the KAT writes the image and the overlay");
    for (int run = 1; run <= 2; ++run) {
        rt::NativeNode node(node_cfg(path));
        std::string    start_why;
        const bool     started = node.start(start_why);
        kat::checkf(started, "outset: run %d starts (%s)", run, start_why.c_str());
        if (!started) break;
        const std::vector<std::string> log = node.take_log();
        kat::checkf(log_has(log, "[snapshot] RESUMED") && log_has(log, "ring resolution intact")
                            && !log_has(log, "ring resolution disabled"),
                    "outset: run %d resumed the image together with its output set: ring resolution intact", run);
        kat::checkf(node.index().tip() && node.index().tip()->id == src.tip_id(),
                    "outset: run %d at the snapshot's tip", run);
        std::remove((path + ".outset").c_str());   // what run 2 finds is what this run's stop writes
        node.stop();   // the clean stop writes the image and the overlay again, for run 2
    }
    // An image the boot cannot pair with an overlay is not resumed: the boot re-walks from its root (on the boot
    // path, not booted, nothing resumed), and ring resolution is never off after a resume.
    const auto rewalks = [&](const char* what) {
        rt::NativeNode node(node_cfg(path));
        std::string    start_why;
        const bool     started = node.start(start_why);
        const std::vector<std::string> log = started ? node.take_log() : std::vector<std::string>{};
        const rt::NodeStatus st = started ? node.status() : rt::NodeStatus{};
        kat::checkf(started && !log_has(log, "[snapshot] RESUMED") && log_has(log, "re-walk")
                            && !log_has(log, "ring resolution disabled") && st.sync.header_frontier == 0 && !st.boot.booted,
                    "outset: %s: the image is not resumed; the boot re-walks from genesis", what);
        if (started) node.stop();
    };
    // (1) an image with no overlay beside it (a snapshot of a build that wrote none, a lost overlay)
    std::remove((path + ".outset").c_str());
    rewalks("no overlay file (a snapshot of a build that wrote none)");
    // (2) a crash between the two writes: the overlay of the next image beside the previous image
    {
        (void)write_pair(path, src, image);
        std::vector<std::uint8_t> ofile = read_file(path + ".outset");
        if (!ofile.empty()) ofile[0] ^= 0x01;   // bound to another image
        kat::check(!ofile.empty() && write_file(path + ".outset", ofile), "outset: the KAT writes an overlay of another image");
        rewalks("a crash between the two writes (the overlay of another image)");
    }
    // (3) two later starts: each resumes with ring resolution intact or re-walks; none resumes with it off
    for (int run = 4; run <= 5; ++run) {
        rt::NativeNode node(node_cfg(path));
        std::string    start_why;
        const bool     started = node.start(start_why);
        const std::vector<std::string> log = started ? node.take_log() : std::vector<std::string>{};
        const bool intact = log_has(log, "[snapshot] RESUMED") && log_has(log, "ring resolution intact");
        const bool rewalk = !log_has(log, "[snapshot] RESUMED") && log_has(log, "re-walk");
        kat::checkf(started && (intact || rewalk) && !log_has(log, "ring resolution disabled"),
                    "outset: later start %d resumes with ring resolution intact or re-walks (never resumed with it off)", run);
        if (started) node.stop();
    }
    // (4) the pair written again: the next start resumes with ring resolution intact
    kat::check(write_pair(path, src, image), "outset: the KAT writes the image with its overlay again");
    {
        rt::NativeNode node(node_cfg(path));
        std::string    start_why;
        const bool     started = node.start(start_why);
        const std::vector<std::string> log = started ? node.take_log() : std::vector<std::string>{};
        kat::check(started && log_has(log, "[snapshot] RESUMED") && log_has(log, "ring resolution intact"),
                   "outset: an image with its overlay resumes with ring resolution intact");
        if (started) node.stop();
    }
    std::remove(path.c_str());
    std::remove((path + ".outset").c_str());
}

// ===========================================================================
// G. LATE REFUSAL: an image refused by the row, evaluation or connection test
//    leaves the index as it was: no reset, no event, no row-sink call
// ===========================================================================
namespace {

constexpr std::size_t kNpos = static_cast<std::size_t>(-1);

// The image header: magic, version, network, anchor height, anchor id, base height, depth.
constexpr std::size_t kImageBaseOff  = 8 + 8 + 8 + 8 + 32;
constexpr std::size_t kImageDepthOff = kImageBaseOff + 8;

constexpr std::uint64_t kClock    = 1;
constexpr std::uint64_t kClockLen = 61;

std::vector<std::uint8_t> le64(std::uint64_t v) {
    std::vector<std::uint8_t> o;
    for (int i = 0; i < 8; ++i) o.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xff));
    return o;
}

std::uint64_t image_u64(const std::vector<std::uint8_t>& img, std::size_t off) {
    std::uint64_t v = 0;
    if (off + 8 > img.size()) return v;
    for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(img[off + static_cast<std::size_t>(i)]) << (8 * i);
    return v;
}

// The offset of the one occurrence of `pat` in hay[0, len); kNpos when it occurs zero times or more than once.
std::size_t find_once(const std::vector<std::uint8_t>& hay, std::size_t len, const std::vector<std::uint8_t>& pat) {
    if (pat.empty() || len > hay.size()) return kNpos;
    const auto end = hay.begin() + static_cast<std::ptrdiff_t>(len);
    std::size_t at = kNpos;
    for (auto it = std::search(hay.begin(), end, pat.begin(), pat.end()); it != end;
         it = std::search(it + 1, end, pat.begin(), pat.end())) {
        if (at != kNpos) return kNpos;
        at = static_cast<std::size_t>(it - hay.begin());
    }
    return at;
}

// In an image body (the trailing digest excluded).
std::size_t find_in_image(const std::vector<std::uint8_t>& img, const std::vector<std::uint8_t>& pat) {
    return img.size() < 32 ? kNpos : find_once(img, img.size() - 32, pat);
}

void redigest(std::vector<std::uint8_t>& img) {
    const std::size_t n = img.size() - 32;
    native::anchor_hash::Sha256 h;
    h.update(img.data(), n);
    const std::array<std::uint8_t, 32> d = h.finish();
    std::copy(d.begin(), d.end(), img.begin() + static_cast<std::ptrdiff_t>(n));
}

std::string sha256_hex(const std::vector<std::uint8_t>& b) {
    native::anchor_hash::Sha256 h;
    h.update(b.data(), b.size());
    return native::anchor_codec::to_hex(h.finish());
}

std::vector<std::uint8_t> row_pattern(std::uint64_t height, const Hash& id, const Hash& prev) {
    std::vector<std::uint8_t> p = le64(height);
    p.insert(p.end(), id.begin(), id.end());
    p.insert(p.end(), prev.begin(), prev.end());
    return p;
}

std::vector<std::uint8_t> blob_pattern(const BlockEntry& e) {
    std::vector<std::uint8_t> p = le64(e.block_blob.size());
    p.insert(p.end(), e.block_blob.begin(), e.block_blob.end());
    return p;
}

struct IndexPrint {
    bool          has_tip = false;
    std::uint64_t tip_h   = 0;
    Hash          tip_id{};
    std::uint64_t header_frontier = 0, verified_frontier = 0, anchor_height = 0, rows = 0, alt_rows = 0;
    std::uint64_t best_lo = 0, best_hi = 0;
    bool          synced = false;
    std::uint64_t rct = 0;
    std::uint64_t state_rows = 0, state_anchor = 0, state_epoch = 0, state_agc = 0;
    std::uint64_t tail_kept = 0, tail_dropped = 0, tail_lowest = 0;
    bool          has_seed = false;
    Hash          seed{};
    std::vector<std::pair<std::uint64_t, Hash>> held;
};

IndexPrint print_of(const native::ChainIndex& idx) {
    IndexPrint p;
    const auto t = idx.tip();
    p.has_tip = t.has_value();
    if (t) {
        p.tip_h  = t->height;
        p.tip_id = t->id;
    }
    const native::SyncState s = idx.sync_state();
    p.header_frontier   = s.header_frontier;
    p.verified_frontier = s.verified_frontier;
    p.anchor_height     = s.anchor_height;
    p.rows              = s.rows;
    p.alt_rows          = s.alt_rows;
    p.best_lo           = s.best_cumulative_difficulty.lo;
    p.best_hi           = s.best_cumulative_difficulty.hi;
    p.synced            = s.synced;
    p.rct               = idx.view().rct_output_count();
    const native::ConsensusState& st = idx.view().state();
    p.state_rows   = st.rows().size();
    p.state_anchor = st.anchor_height();
    p.state_epoch  = st.epoch_seq();
    p.state_agc    = st.already_generated_coins();
    const auto bt = idx.booking_tail_stats();
    p.tail_kept    = bt.kept;
    p.tail_dropped = bt.dropped;
    p.tail_lowest  = bt.lowest;
    const auto sd = idx.seed_hash_for_height(p.tip_h + 1);
    p.has_seed = sd.has_value();
    if (sd) p.seed = *sd;
    if (p.has_tip) {
        const std::uint64_t lo = s.rows > p.tip_h ? 0 : p.tip_h + 1 - s.rows;
        for (std::uint64_t h = lo; h <= p.tip_h; ++h)
            if (const auto r = idx.by_height(h)) p.held.emplace_back(h, r->id);
    }
    return p;
}

// The fields that differ, comma-separated; empty when none does.
std::string print_diff(const IndexPrint& a, const IndexPrint& b) {
    std::string d;
    const auto f = [&d](bool same, const char* name) {
        if (same) return;
        if (!d.empty()) d += ", ";
        d += name;
    };
    f(a.has_tip == b.has_tip && a.tip_h == b.tip_h && a.tip_id == b.tip_id, "tip");
    f(a.header_frontier == b.header_frontier, "header_frontier");
    f(a.verified_frontier == b.verified_frontier, "verified_frontier");
    f(a.anchor_height == b.anchor_height, "anchor_height");
    f(a.rows == b.rows, "rows");
    f(a.alt_rows == b.alt_rows, "alt_rows");
    f(a.best_lo == b.best_lo && a.best_hi == b.best_hi, "best_cumulative_difficulty");
    f(a.synced == b.synced, "synced");
    f(a.rct == b.rct, "rct_output_count");
    f(a.state_rows == b.state_rows, "state.rows");
    f(a.state_anchor == b.state_anchor, "state.anchor_height");
    f(a.state_epoch == b.state_epoch, "state.epoch_seq");
    f(a.state_agc == b.state_agc, "state.already_generated_coins");
    f(a.tail_kept == b.tail_kept && a.tail_dropped == b.tail_dropped && a.tail_lowest == b.tail_lowest,
      "booking_tail_stats");
    f(a.has_seed == b.has_seed && a.seed == b.seed, "seed_hash_for_height(tip + 1)");
    f(a.held == b.held, "by_height");
    return d;
}

struct Seen {
    std::uint64_t events = 0, tx_events = 0, row_calls = 0, seeded = 0;
};

void watch(native::ChainIndex& idx, Seen& s) {
    idx.subscribe([&s](const auto&) { ++s.events; });
    idx.subscribe_txs([&s](const auto&) { ++s.tx_events; });
    idx.subscribe_rows([&s](const auto&, const auto&, bool seeded) {
        ++s.row_calls;
        if (seeded) ++s.seeded;
    });
}

bool starts_with(const std::string& s, const std::string& prefix) { return s.rfind(prefix, 0) == 0; }

// Source: GenesisChain(snapshot_depth + 1). Row 0 (below the base) takes the base's height.
bool image_rows_broken(GenesisChain& src, std::vector<std::uint8_t>& img) {
    std::string why;
    if (!src.idx.save_snapshot(img, why)) {
        kat::checkf(false, "late-rows: the source could not be snapshotted (%s)", why.c_str());
        return false;
    }
    const std::uint64_t base_h = image_u64(img, kImageBaseOff);
    kat::checkf(base_h == 1 && image_u64(img, kImageDepthOff) == regtest_options().snapshot_depth,
                "late-rows: the source image is based at 1 with row 0 below (base %llu, depth %llu)",
                (unsigned long long)base_h, (unsigned long long)image_u64(img, kImageDepthOff));
    const auto r0 = src.idx.by_height(0);
    const std::size_t at = r0 ? find_in_image(img, row_pattern(0, r0->id, r0->prev_id)) : kNpos;
    kat::check(at != kNpos, "late-rows: row 0 occurs exactly once in the image");
    if (at == kNpos) return false;
    const std::vector<std::uint8_t> h = le64(base_h);
    std::copy(h.begin(), h.end(), img.begin() + static_cast<std::ptrdiff_t>(at));
    redigest(img);
    return true;
}

// Source: GenesisChain(). The last tail block's major version := the first one this build does not implement.
bool image_eval_broken(GenesisChain& src, std::vector<std::uint8_t>& img) {
    std::string why;
    if (!src.idx.save_snapshot(img, why)) {
        kat::checkf(false, "late-eval: the source could not be snapshotted (%s)", why.c_str());
        return false;
    }
    kat::checkf(image_u64(img, kImageDepthOff) == kChainHeight,
                "late-eval: the image carries the whole chain as its tail (depth %llu)",
                (unsigned long long)image_u64(img, kImageDepthOff));
    const std::size_t at = find_in_image(img, blob_pattern(src.blocks.back()));
    kat::check(at != kNpos && img[at + 8] == kRegMajor,
               "late-eval: the last tail block occurs exactly once, its first byte the major version");
    if (at == kNpos) return false;
    const unsigned next_major = static_cast<unsigned>(native::MAX_IMPLEMENTED_HF_VERSION) + 1;
    kat::check(next_major < 0x80, "late-eval: the next major version still encodes in one varint byte");
    img[at + 8] = static_cast<std::uint8_t>(next_major);
    redigest(img);
    return true;
}

// Source: GenesisChain(). One bit of the last tail block's prev id flipped.
bool image_connect_broken(GenesisChain& src, std::vector<std::uint8_t>& img) {
    std::string why;
    if (!src.idx.save_snapshot(img, why)) {
        kat::checkf(false, "late-connect: the source could not be snapshotted (%s)", why.c_str());
        return false;
    }
    kat::checkf(image_u64(img, kImageDepthOff) == kChainHeight,
                "late-connect: the image carries the whole chain as its tail (depth %llu)",
                (unsigned long long)image_u64(img, kImageDepthOff));
    const BlockEntry& last = src.blocks.back();
    const Hash&       prev = src.ids[src.ids.size() - 2];
    const std::size_t at   = find_in_image(img, blob_pattern(last));
    const std::size_t in   = find_once(last.block_blob, last.block_blob.size(),
                                       std::vector<std::uint8_t>(prev.begin(), prev.end()));
    kat::check(at != kNpos && in != kNpos,
               "late-connect: the last tail block occurs exactly once, and its prev id once inside it");
    if (at == kNpos || in == kNpos) return false;
    img[at + 8 + in] ^= 0x01;
    redigest(img);
    return true;
}

// The target holds row zero, as an anchor or local-genesis node does at the moment of the load.
void expect_refused_as_it_was(const char* what, const std::vector<std::uint8_t>& img, const std::string& text,
                              bool exact) {
    Seen         seen;
    GenesisChain tgt(0);
    watch(tgt.idx, seen);
    const IndexPrint before        = print_of(tgt.idx);
    const bool       booted_before = tgt.boot.booted();

    std::string why;
    const bool  ok = tgt.boot.resume_from_snapshot(img, why);
    kat::checkf(!ok, "%s: refused", what);
    kat::checkf(exact ? why == text : starts_with(why, text), "%s: the refusal text is the pre-check's (%s)", what,
                why.c_str());
    const std::string d = print_diff(before, print_of(tgt.idx));
    kat::checkf(d.empty(), "%s: the index is as it was (changed: %s)", what, d.c_str());
    kat::checkf(seen.events == 0 && seen.tx_events == 0 && seen.row_calls == 0,
                "%s: no event (%llu), tx event (%llu) or row-sink call (%llu)", what,
                (unsigned long long)seen.events, (unsigned long long)seen.tx_events,
                (unsigned long long)seen.row_calls);
    kat::checkf(tgt.boot.booted() == booted_before, "%s: booted() unchanged", what);
}

void test_late_refusal_rows() {
    GenesisChain              src(regtest_options().snapshot_depth + 1);
    std::vector<std::uint8_t> img;
    if (!image_rows_broken(src, img)) return;
    expect_refused_as_it_was("late-rows", img, "snapshot rows are not contiguous", true);
}

void test_late_refusal_eval() {
    GenesisChain              src;
    std::vector<std::uint8_t> img;
    if (!image_eval_broken(src, img)) return;
    expect_refused_as_it_was("late-eval", img, "a snapshotted block no longer evaluates", false);
}

void test_late_refusal_connect() {
    GenesisChain              src;
    std::vector<std::uint8_t> img;
    if (!image_connect_broken(src, img)) return;
    expect_refused_as_it_was("late-connect", img, "a snapshotted block no longer connects", false);
}

// The node: the image and its overlay (bound to the refused image) on disk, a genesis boot.
void node_late_refusal(const char* what, GenesisChain& src, const std::vector<std::uint8_t>& img,
                       const std::string& text) {
    const std::string path = std::string("snapres_kat_late_") + what + ".snap";
    if (!write_pair(path, src, img)) {
        kat::checkf(false, "node-late %s: the KAT writes the image and its overlay", what);
        return;
    }
    std::atomic<std::uint64_t> row_calls{0};
    rt::NativeNodeConfig c = node_cfg(path);
    c.row_sink = [&row_calls](const native::ConsensusState&, const ChainRow&, bool) { ++row_calls; };
    {
        rt::NativeNode node(c);
        std::string    start_why;
        const bool     started = node.start(start_why);
        kat::checkf(started, "node-late %s: the node starts (%s)", what, start_why.c_str());
        if (started) {
            const std::vector<std::string> log  = node.take_log();
            const std::string              head = "[snapshot] REFUSED: " + text;
            const std::string tail = "; image sha256 " + sha256_hex(img) + "; starting from the genesis";
            bool found = false;
            for (const std::string& l : log)
                if (l.find(head) != std::string::npos && l.find(tail) != std::string::npos) found = true;
            kat::checkf(found, "node-late %s: the log has \"%s ...%s\"", what, head.c_str(), tail.c_str());
            const rt::NodeStatus st = node.status();
            kat::checkf(st.sync.header_frontier == 0 && !st.boot.booted && !node.index().tip().has_value(),
                        "node-late %s: the node is on its genesis boot path, as the log says (frontier %llu, "
                        "booted %d, tip %d)",
                        what, (unsigned long long)st.sync.header_frontier, st.boot.booted ? 1 : 0,
                        node.index().tip().has_value() ? 1 : 0);
            kat::checkf(node.mainchain_events_seen() == 0, "node-late %s: no mainchain event (%llu)", what,
                        (unsigned long long)node.mainchain_events_seen());
            kat::checkf(row_calls.load() == 0, "node-late %s: no row-sink call (%llu)", what,
                        (unsigned long long)row_calls.load());
            node.stop();
        }
    }
    std::remove(path.c_str());
    std::remove((path + ".outset").c_str());
}

void test_node_late_refusals() {
    {
        GenesisChain              src(regtest_options().snapshot_depth + 1);
        std::vector<std::uint8_t> img;
        if (image_rows_broken(src, img)) node_late_refusal("rows", src, img, "snapshot rows are not contiguous");
    }
    {
        GenesisChain              src;
        std::vector<std::uint8_t> img;
        if (image_eval_broken(src, img))
            node_late_refusal("eval", src, img, "a snapshotted block no longer evaluates");
    }
    {
        GenesisChain              src;
        std::vector<std::uint8_t> img;
        if (image_connect_broken(src, img))
            node_late_refusal("connect", src, img, "a snapshotted block no longer connects");
    }
}

// The anchor shape: the image of a session that booted on the anchor and connected one block above it (base = the
// anchor + 1, the anchor row below it); the anchor row takes the base's height. Read after the confirm.
void test_anchor_late_refusal() {
    AnchorBlockSpec spec;
    const std::vector<std::uint8_t> anchor_blob = build_anchor_blob(spec);
    native::ParsedBlock pb;
    if (native::parse_block(anchor_blob, pb) != native::BlockParseStatus::Ok) {
        kat::check(false, "anchor-late: the fixture blob parses");
        return;
    }
    const Hash anchor_id = native::block_identity(anchor_blob.data(), pb).id;

    const std::string path = "snapres_kat_late_anchor.inc";
    if (!write_bundle(path, make_bundle(kAnchorHeight, anchor_id))) {
        kat::check(false, "anchor-late: the KAT can write its bundle");
        return;
    }

    std::vector<std::uint8_t> image;
    {
        native::NoPowSource pow;
        native::ChainIndex  idx(stagenet_options(), pow);
        rt::ChainBoot       boot(idx, rt::BootMode::Anchor,
                                 native::p2p::genesis_id(native::p2p::XmrNet::Stagenet), native::XmrNet::Stagenet);
        std::string why;
        if (!boot.boot_from_anchor(path, native::XmrNet::Stagenet, {}, why)) {
            kat::checkf(false, "anchor-late: gates 1..3 accept the bundle (%s)", why.c_str());
            std::remove(path.c_str());
            return;
        }
        std::vector<BlockEntry> blocks;
        BlockEntry              e;
        e.block_blob = anchor_blob;
        blocks.push_back(std::move(e));
        boot.on_objects(peer("198.51.100.1:38080", 1001), std::move(blocks), {}, kAnchorHeight + 1);

        AnchorBlockSpec child;
        child.height    = kAnchorHeight + 1;
        child.pin_prev  = true;
        child.prev      = anchor_id;
        child.timestamp = spec.timestamp + 120;
        child.flavour   = 0x33;
        BlockEntry ce;
        ce.block_blob = build_anchor_blob(child);
        const OfferResult r = idx.offer_block(nullptr, ce, /*own_mined=*/false);
        kat::checkf(r.outcome == OfferOutcome::Connected, "anchor-late: the writing session extended past its "
                    "anchor (got %s: %s)", native::to_string(r.outcome), r.why.c_str());
        if (!idx.save_snapshot(image, why)) {
            kat::checkf(false, "anchor-late: the writing session could not snapshot (%s)", why.c_str());
            std::remove(path.c_str());
            return;
        }
        const std::uint64_t base_h = image_u64(image, kImageBaseOff);
        kat::checkf(base_h == kAnchorHeight + 1 && image_u64(image, kImageDepthOff) == 0,
                    "anchor-late: the image is based at the anchor + 1 with no tail (base %llu, depth %llu)",
                    (unsigned long long)base_h, (unsigned long long)image_u64(image, kImageDepthOff));
        const auto ar = idx.by_height(kAnchorHeight);
        const std::size_t at = ar ? find_in_image(image, row_pattern(kAnchorHeight, ar->id, ar->prev_id)) : kNpos;
        kat::check(at != kNpos && ar && ar->id == anchor_id,
                   "anchor-late: the anchor row occurs exactly once in the image");
        if (at == kNpos) {
            std::remove(path.c_str());
            return;
        }
        const std::vector<std::uint8_t> h = le64(base_h);
        std::copy(h.begin(), h.end(), image.begin() + static_cast<std::ptrdiff_t>(at));
        redigest(image);
    }

    Seen                seen;
    native::NoPowSource pow;
    native::ChainIndex  idx(stagenet_options(), pow);
    rt::ChainBoot       boot(idx, rt::BootMode::Anchor, native::p2p::genesis_id(native::p2p::XmrNet::Stagenet),
                             native::XmrNet::Stagenet);
    std::string why;
    const bool  installed = boot.boot_from_anchor(path, native::XmrNet::Stagenet, {}, why);
    std::remove(path.c_str());
    kat::checkf(installed, "anchor-late: gates 1..3 accept the bundle (%s)", why.c_str());
    if (!installed) return;
    {
        std::vector<BlockEntry> blocks;
        BlockEntry              e;
        e.block_blob = anchor_blob;
        blocks.push_back(std::move(e));
        boot.on_objects(peer("198.51.100.2:38080", 1002), std::move(blocks), {}, kAnchorHeight + 1);
    }
    kat::check(boot.serving_ready(), "anchor-late: the network confirms the anchor");

    watch(idx, seen);
    const IndexPrint before = print_of(idx);
    std::string      resume_why;
    kat::check(!boot.resume_from_snapshot(image, resume_why), "anchor-late: refused");
    kat::checkf(resume_why == "snapshot rows are not contiguous", "anchor-late: the refusal text is the pre-check's (%s)",
                resume_why.c_str());
    kat::checkf(idx.tip() && idx.tip()->height == kAnchorHeight && idx.tip()->id == anchor_id,
                "anchor-late: the index is on the confirmed anchor row (height %llu)",
                (unsigned long long)(idx.tip() ? idx.tip()->height : 0));
    const std::string d = print_diff(before, print_of(idx));
    kat::checkf(d.empty(), "anchor-late: the index is as it was (changed: %s)", d.c_str());
    kat::checkf(seen.events == 0 && seen.tx_events == 0 && seen.row_calls == 0,
                "anchor-late: no event (%llu), tx event (%llu) or row-sink call (%llu)",
                (unsigned long long)seen.events, (unsigned long long)seen.tx_events,
                (unsigned long long)seen.row_calls);
    kat::check(boot.booted() && boot.serving_ready(), "anchor-late: booted and serving, as before the load");
}

// A good image into a target holding row zero: one seeded row-sink call, then one per tail block; no event.
void good_image_into_root(const char* what, std::uint64_t n, std::uint64_t want_base, std::uint64_t want_k) {
    GenesisChain              src(n);
    std::vector<std::uint8_t> img;
    std::string               why;
    if (!src.idx.save_snapshot(img, why)) {
        kat::checkf(false, "%s: the source could not be snapshotted (%s)", what, why.c_str());
        return;
    }
    const std::uint64_t base_h = image_u64(img, kImageBaseOff);
    const std::uint64_t k      = image_u64(img, kImageDepthOff);
    kat::checkf(base_h == want_base && k == want_k, "%s: the image is based at %llu with a tail of %llu (got %llu, %llu)",
                what, (unsigned long long)want_base, (unsigned long long)want_k, (unsigned long long)base_h,
                (unsigned long long)k);

    Seen         seen;
    GenesisChain tgt(0);
    watch(tgt.idx, seen);
    const bool ok = tgt.boot.resume_from_snapshot(img, why);
    kat::checkf(ok, "%s: resumes (%s)", what, why.c_str());
    kat::checkf(tgt.idx.tip() && tgt.idx.tip()->height == src.tip_height() && tgt.idx.tip()->id == src.tip_id(),
                "%s: at the image's tip", what);
    kat::checkf(seen.row_calls == 1 + k && seen.seeded == 1,
                "%s: row sinks called 1 + k = %llu times, one seeded (got %llu, %llu seeded)", what,
                (unsigned long long)(1 + k), (unsigned long long)seen.row_calls, (unsigned long long)seen.seeded);
    kat::checkf(seen.events == 0 && seen.tx_events == 0, "%s: no event (%llu) or tx event (%llu)", what,
                (unsigned long long)seen.events, (unsigned long long)seen.tx_events);
}

void test_good_image_sinks() {
    good_image_into_root("good-image", kChainHeight, 0, kChainHeight);
    good_image_into_root("good-image (row below the base)", regtest_options().snapshot_depth + 1, 1,
                         regtest_options().snapshot_depth);
}

// A good image whose last tail block is stamped beyond the future limit of the target's clock.
void test_clock_not_judged() {
    GenesisChain              src(kClockLen);
    std::vector<std::uint8_t> img;
    std::string               why;
    if (!src.idx.save_snapshot(img, why)) {
        kat::checkf(false, "clock: the source could not be snapshotted (%s)", why.c_str());
        return;
    }
    const std::uint64_t last_stamp = src.idx.tip() ? src.idx.tip()->timestamp : 0;
    kat::checkf(last_stamp > kClock + native::CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT,
                "clock: the last tail block (stamp %llu) is beyond clock %llu + the future limit",
                (unsigned long long)last_stamp, (unsigned long long)kClock);
    kat::checkf(image_u64(img, kImageDepthOff) == kClockLen && find_in_image(img, blob_pattern(src.blocks.back())) != kNpos,
                "clock: the last block is in the image's tail (depth %llu)",
                (unsigned long long)image_u64(img, kImageDepthOff));

    GenesisChain tgt(0);
    tgt.idx.set_clock([] { return kClock; });
    const bool ok = tgt.boot.resume_from_snapshot(img, why);
    kat::checkf(ok, "clock: resumes under a set clock (%s)", why.c_str());
    kat::checkf(tgt.idx.tip() && tgt.idx.tip()->height == src.tip_height() && tgt.idx.tip()->id == src.tip_id(),
                "clock: at the image's tip");
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
    test_node_resumes_the_output_set();
    test_late_refusal_rows();
    test_late_refusal_eval();
    test_late_refusal_connect();
    test_node_late_refusals();
    test_anchor_late_refusal();
    test_good_image_sinks();
    test_clock_not_judged();
    return kat::report("xmr_native_snapshot_resume_kat");
}
