// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// ===========================================================================
// v37_xmr_pinned_snapshot_kat -- the release's PINNED bootstrap snapshot.
//
// Operator ruling 09-24: a node bootstraps from a pinned snapshot -- the
// format-2 anchor plus the output-set snapshot it commits to, both pinned by
// sha256 in the release and reproducible by anyone from their own monerod.
// This KAT pins that promise from four sides:
//
//   A  THE PINS ARE TRUE. Both compiled-in bundles (stagenet, mainnet) load
//      through load_anchor("") and carry exactly the documented height, block
//      id, rct_output_count and output/spent roots; the committed .inc files
//      hash to the documented sha256, and so do the bytes compiled into this
//      binary (rebuilt from the raw-string frame).
//   B  THE DOC IS TRUE. docs/xmr-lane/PINNED-SNAPSHOTS.md lists every pinned
//      value (heights, ids, both sha256 per network) and the table in
//      anchor/xmr_anchor_pinned.hpp agrees with this file's literals.
//   C  THE DEFAULT IS THE PIN. native_template_config_of(): an output-set
//      snapshot with no --native-anchor boots Anchor from the embedded bundle
//      (anchor_path ""); neither flag stays Genesis; an explicit anchor still
//      wins; --native-solo still boots LocalGenesis.
//   D  A WRONG SNAPSHOT REFUSES. check_output_set_against_pin(): the right
//      file passes; a truncated copy (size) and a one-byte flip (sha256)
//      refuse with a message naming the expected sha256 and pinned height; a
//      missing file refuses.
//
// Built against a tree without the pin (the base), this file still compiles
// (the pin header is feature-tested) and FAILS: A finds no mainnet bundle and
// C finds the snapshot does not select Anchor.
//
// No sockets, no daemon, no RandomX. Listed in both build.yml --target lists.
// ===========================================================================
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <unistd.h>

#include "c2pool/v37/xmr/xmr_native_template_backend.hpp"
#include "c2pool/v37/xmr/xmr_node_config.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_codec.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_load.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_sha256.hpp"
#if __has_include("impl/xmr/native/anchor/xmr_anchor_pinned.hpp")
#include "impl/xmr/native/anchor/xmr_anchor_pinned.hpp"
#define PINNED_KAT_HAVE_PIN 1
#else
#define PINNED_KAT_HAVE_PIN 0
#endif

#ifndef C2POOL_SOURCE_DIR
#error "C2POOL_SOURCE_DIR must name the repository root"
#endif

namespace cfgns  = c2pool::v37n::xmr;
namespace o2     = c2pool::v37n::xmr::o2;
namespace native = c2pool::xmr::native;
namespace rt     = c2pool::xmr::native::rt;

namespace {

int g_pass = 0;
int g_fail = 0;

void check(bool ok, const std::string& what) {
    if (ok) { ++g_pass; return; }
    ++g_fail;
    std::printf("  FAIL: %s\n", what.c_str());
}

// The documented values (docs/xmr-lane/PINNED-SNAPSHOTS.md), spelled out here
// independently of the table under test.
struct Expect {
    native::XmrNet net;
    const char*    name;
    std::uint64_t  height;
    const char*    id;
    const char*    inc_file;
    const char*    inc_sha;
    const char*    set_sha;
    std::uint64_t  set_bytes;
    std::uint64_t  rct_output_count;
    const char*    output_root;
    const char*    spent_root;
};

const Expect kStagenet{
    native::XmrNet::Stagenet, "stagenet", 2213803,
    "571f97ae8e7cd7816065c08260a3b65d0192b85d57e9961fa93e102629e6d3ee",
    "src/impl/xmr/native/anchor/xmr_chain_anchor_stagenet_f2.inc",
    "7e39e1a206c4f18776f6f6d83b518fd7146cdd66eacd6d28752446168e88a4a5",
    "186b23c3b43cbc61e6132a9b4927e4eeb3666f153d2f2c5f9d52814d670dcb7d",
    1170058729ull, 10051944ull,
    "ecd05c67cb7ee42af59177e99e5f073dedf3179ec722f1e9f9147ac4384a92ec",
    "a8776b6c0dc5316a0af18dcb247064eb3a287220a43b79c3d2ab2dd13cc33d81",
};

const Expect kMainnet{
    native::XmrNet::Mainnet, "mainnet", 3765865,
    "ff732eb5bd91e3d7a5188841a04af3146360ffa6f5acbc20ff93797f5351fe33",
    "src/impl/xmr/native/anchor/xmr_chain_anchor_mainnet_f2.inc",
    "616407ba7d2ab2d304532ba1a10aa174c945c28109436ab2eac7d255061782e2",
    "506aa2480fcab4ec6d4514f68898ca638065548675de9740e56a1b80b571390d",
    18320778025ull, 163820597ull,
    "6a89a1111aaa59484bd56376977f47dffe5ecaf9acbc58022494eb44816f0ccf",
    "dc5063730476829c73344b34968f13468b9315fab2ff18cb1ea89b232a74bf5e",
};

bool read_file(const std::string& path, std::string& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

std::string src_path(const std::string& rel) { return std::string(C2POOL_SOURCE_DIR) + "/" + rel; }

// =============================================================================
// A. the compiled-in bundles and the committed files are the pinned ones
// =============================================================================
void suite_a_pins(const Expect& e) {
    std::printf("A. %s: compiled-in bundle and committed .inc\n", e.name);
    native::AnchorBundle b;
    const native::AnchorLoadResult r = native::load_anchor_detailed("", e.net, b);
    check(r.ok, std::string("A1: the embedded ") + e.name + " anchor does not load: " + r.why);
    if (r.ok) {
        check(r.source == "embedded", "A1: the bundle did not come from the binary");
        check(b.height == e.height, std::string("A2: ") + e.name + " height is "
                                    + std::to_string(b.height));
        check(native::anchor_codec::to_hex(b.id) == e.id, std::string("A2: ") + e.name + " block id");
        check(b.has_output_set(), std::string("A3: ") + e.name + " bundle is not format 2");
        check(b.rct_output_count == e.rct_output_count,
              std::string("A3: ") + e.name + " rct_output_count");
        check(b.output_set_leaves == e.height && b.spent_set_leaves == e.height,
              std::string("A3: ") + e.name + " leaf counts are not one per block 1..H_a");
        check(native::anchor_codec::to_hex(b.output_set_root) == e.output_root,
              std::string("A3: ") + e.name + " output_set_root");
        check(native::anchor_codec::to_hex(b.spent_set_root) == e.spent_root,
              std::string("A3: ") + e.name + " spent_set_root");
    }

    // The committed file on disk.
    std::string file;
    check(read_file(src_path(e.inc_file), file), std::string("A4: cannot read ") + e.inc_file);
    const std::string file_sha = native::anchor_codec::to_hex(native::anchor_hash::sha256(file));
    check(file_sha == e.inc_sha, std::string("A4: ") + e.inc_file + " hashes to " + file_sha);

#if PINNED_KAT_HAVE_PIN
    // The bytes compiled into this binary, rebuilt from the raw-string frame.
    check(native::embedded_anchor_file_sha256(e.net) == e.inc_sha,
          std::string("A5: the compiled-in ") + e.name + " bytes are not the pinned file");
    check(native::embedded_anchor_file_bytes(e.net) == file,
          std::string("A5: the compiled-in ") + e.name + " bytes differ from the committed file");
    if (r.ok) {
        const native::PinnedSnapshot* pin = native::pinned_snapshot(e.net);
        std::string why;
        check(pin != nullptr && native::pinned_anchor_matches(*pin, b, why),
              std::string("A6: the pin table rejects the compiled-in ") + e.name + " bundle: " + why);
    }
#else
    check(false, "A5: this tree has no anchor/xmr_anchor_pinned.hpp (no pinned snapshot)");
#endif
}

// =============================================================================
// B. the pin table and the document say the same thing as this file
// =============================================================================
void suite_b_doc() {
    std::printf("B. pin table and docs/xmr-lane/PINNED-SNAPSHOTS.md\n");
    std::string doc;
    check(read_file(src_path("docs/xmr-lane/PINNED-SNAPSHOTS.md"), doc),
          "B1: docs/xmr-lane/PINNED-SNAPSHOTS.md is missing");
    for (const Expect* e : {&kStagenet, &kMainnet}) {
        for (const std::string v : {std::to_string(e->height), std::string(e->id),
                                    std::string(e->inc_sha), std::string(e->set_sha),
                                    std::to_string(e->set_bytes)}) {
            check(doc.find(v) != std::string::npos,
                  std::string("B2: the doc does not list ") + e->name + " value " + v);
        }
#if PINNED_KAT_HAVE_PIN
        const native::PinnedSnapshot* pin = native::pinned_snapshot(e->net);
        check(pin != nullptr, std::string("B3: no pin for ") + e->name);
        if (pin) {
            check(pin->height == e->height, std::string("B3: ") + e->name + " pinned height");
            check(std::string(pin->block_id) == e->id, std::string("B3: ") + e->name + " pinned id");
            check(std::string(pin->anchor_inc_sha256) == e->inc_sha,
                  std::string("B3: ") + e->name + " pinned .inc sha256");
            check(std::string(pin->output_set_sha256) == e->set_sha,
                  std::string("B3: ") + e->name + " pinned output-set sha256");
            check(pin->output_set_bytes == e->set_bytes,
                  std::string("B3: ") + e->name + " pinned output-set size");
            check(std::string(pin->anchor_inc_file) == e->inc_file,
                  std::string("B3: ") + e->name + " pinned .inc path");
        }
#endif
    }
#if PINNED_KAT_HAVE_PIN
    check(native::pinned_snapshot(native::XmrNet::Regtest) == nullptr
              && native::pinned_snapshot(native::XmrNet::Testnet) == nullptr,
          "B4: regtest/testnet must carry no pin");
#else
    check(false, "B3: this tree has no pin table");
#endif
}

// =============================================================================
// C. no --native-anchor + an output set = the pinned anchor
// =============================================================================
cfgns::XmrNodeConfig base_config(cfgns::MoneroNetwork net) {
    cfgns::XmrNodeConfig c;
    c.network         = net;
    c.template_source = cfgns::TemplateSourceMode::Native;
    c.arm_order       = cfgns::ArmOrderMode::P2PFirst;
    c.coinbase        = cfgns::CoinbaseMode::V37Settlement;
    return c;
}

void suite_c_forward() {
    std::printf("C. boot-mode forward\n");
    for (const auto net : {cfgns::MoneroNetwork::Stagenet, cfgns::MoneroNetwork::Mainnet}) {
        {
            cfgns::XmrNodeConfig c = base_config(net);
            c.native_output_set_path = "/tmp/pinned.bin";
            const o2::NativeTemplateConfig n = o2::native_template_config_of(c);
            check(n.boot == rt::BootMode::Anchor,
                  "C1: an output set without --native-anchor did not select the pinned anchor");
            check(n.anchor_path.empty(), "C1: the pinned boot must use the embedded bundle");
            check(n.output_set_path == "/tmp/pinned.bin", "C1: the output-set path was dropped");
        }
        {
            cfgns::XmrNodeConfig c = base_config(net);
            const o2::NativeTemplateConfig n = o2::native_template_config_of(c);
            check(n.boot == rt::BootMode::Genesis, "C2: no anchor and no output set is not Genesis");
        }
        {
            cfgns::XmrNodeConfig c = base_config(net);
            c.native_anchor_path     = "/tmp/a.inc";
            c.native_output_set_path = "/tmp/b.bin";
            const o2::NativeTemplateConfig n = o2::native_template_config_of(c);
            check(n.boot == rt::BootMode::Anchor && n.anchor_path == "/tmp/a.inc",
                  "C3: an explicit --native-anchor no longer wins");
        }
        {
            cfgns::XmrNodeConfig c = base_config(net);
            c.native_solo = true;
            const o2::NativeTemplateConfig n = o2::native_template_config_of(c);
            check(n.boot == rt::BootMode::LocalGenesis, "C4: --native-solo no longer LocalGenesis");
        }
    }
}

// =============================================================================
// D. a snapshot that is not the pinned one refuses, loudly
// =============================================================================
void suite_d_refusal() {
    std::printf("D. output-set snapshot against the pin\n");
#if PINNED_KAT_HAVE_PIN
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / ("pinned_kat_" + std::to_string(::getpid()));
    std::error_code ec;
    fs::create_directories(dir, ec);

    // A synthetic 3 MiB + 17 byte "snapshot" (spans the 4 MiB read buffer's
    // partial last read) and a pin built for it.
    std::string blob(3u * 1024u * 1024u + 17u, '\0');
    for (std::size_t i = 0; i < blob.size(); ++i)
        blob[i] = static_cast<char>((i * 2654435761u) >> 13);
    const std::string sha = native::anchor_codec::to_hex(native::anchor_hash::sha256(blob));
    const auto write = [](const fs::path& p, const std::string& s) {
        std::ofstream f(p, std::ios::binary);
        f.write(s.data(), static_cast<std::streamsize>(s.size()));
        return static_cast<bool>(f);
    };
    const fs::path good = dir / "good.bin", trunc = dir / "trunc.bin", flip = dir / "flip.bin";
    std::string flipped = blob;
    flipped[blob.size() / 2] = static_cast<char>(flipped[blob.size() / 2] ^ 0x01);
    check(write(good, blob) && write(trunc, blob.substr(0, blob.size() - 4096))
              && write(flip, flipped),
          "D0: the KAT can write its fixtures");

    native::PinnedSnapshot pin = native::PINNED_SNAPSHOT_STAGENET;
    pin.output_set_sha256 = sha.c_str();
    pin.output_set_bytes  = blob.size();

    std::string why, got;
    check(native::check_output_set_against_pin(good.string(), pin, why, &got)
              == native::PinnedSetCheck::Ok && why.empty() && got == sha,
          "D1: the pinned file itself is refused: " + why);

    const auto names_pin = [&](const std::string& w) {
        return w.find(sha) != std::string::npos
            && w.find(std::to_string(pin.height)) != std::string::npos
            && w.find("refusing to start") != std::string::npos;
    };
    check(native::check_output_set_against_pin(trunc.string(), pin, why)
              == native::PinnedSetCheck::WrongSize,
          "D2: a truncated snapshot is not refused on size");
    check(names_pin(why), "D2: the truncation refusal does not name the pinned sha256 + height: " + why);

    check(native::check_output_set_against_pin(flip.string(), pin, why, &got)
              == native::PinnedSetCheck::WrongHash,
          "D3: a one-byte flip is not refused on sha256");
    check(names_pin(why) && why.find(got) != std::string::npos,
          "D3: the flip refusal does not name expected + actual sha256: " + why);

    check(native::check_output_set_against_pin((dir / "absent.bin").string(), pin, why)
              == native::PinnedSetCheck::CannotOpen && names_pin(why),
          "D4: a missing snapshot is not refused with the pin named");

    // The real pins: a snapshot of the right size is still hashed, and the
    // stagenet pin never accepts the mainnet size (or vice versa).
    check(native::PINNED_SNAPSHOT_STAGENET.output_set_bytes
              != native::PINNED_SNAPSHOT_MAINNET.output_set_bytes,
          "D5: the two pinned sizes coincide");
    const std::string line = native::pinned_boot_line(native::PINNED_SNAPSHOT_STAGENET);
    check(line.find(kStagenet.id) != std::string::npos
              && line.find(kStagenet.set_sha) != std::string::npos
              && line.find(std::to_string(kStagenet.height)) != std::string::npos,
          "D6: the boot line does not name the pinned id, height and output-set sha256");

    fs::remove_all(dir, ec);
#else
    check(false, "D0: this tree cannot check a snapshot against a pin");
#endif
}

}  // namespace

int main() {
    std::printf("v37_xmr_pinned_snapshot_kat -- the release's pinned bootstrap snapshot\n");
    suite_a_pins(kStagenet);
    suite_a_pins(kMainnet);
    suite_b_doc();
    suite_c_forward();
    suite_d_refusal();
    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
