// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_anchor_self_check_kat.cpp
//
// The anchor KAT: the node's trust root, checked from four directions.
//
//   1. THE HASH. SHA-256 against the published NIST vectors, including a
//      multi-block message and a length that lands exactly on the padding
//      boundary. Everything below rests on it, so it is pinned first.
//
//   2. THE FORMAT. A synthetic bundle survives write -> parse -> write with
//      every field and every one of the 100 835 window values intact, and each
//      documented way of damaging the file produces its OWN AnchorParse code.
//      A loader that says "malformed" for a bundle that is merely for the wrong
//      chain is a loader that gets debugged at 3am, so the two vocabularies are
//      tested apart.
//
//   3. THE JUDGEMENT. Every AnchorStatus in contracts/anchor.hpp is REACHED by
//      mutating one field of an otherwise valid bundle. A status that no input
//      can produce is either dead code or a check that silently does not fire;
//      this block is what tells the two apart.
//
//   4. THE REAL BUNDLE. The stagenet anchor this build embeds is loaded, and
//      the C++ canonical writer is run over the parsed result: the body must
//      hash to the digest line the capture tool wrote. That single assertion is
//      what pins tools/xmr-anchor-gen/xmr_anchor_gen.py to anchor_body_text()
//      -- the tool and the loader are two implementations of one format, and a
//      byte of drift between them is a RED KAT here rather than a bundle that
//      loads on the author's machine and nowhere else.
//
//   Plus generate_anchor() against a model daemon, honest and dishonest: the
//   fault cases (a broken prev_id chain, a short response, cumulative
//   difficulty going backwards, coins that underflow) cannot be staged against
//   a live daemon on purpose, which is the whole reason the RPC port is
//   abstract.
//
// STL only. No network, no daemon, no crypto library.
// ---------------------------------------------------------------------------

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/anchor/xmr_anchor_codec.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_embedded.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_generate.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_load.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_sha256.hpp"
#include "impl/xmr/native/contracts/anchor.hpp"

using namespace c2pool::xmr::native;

// --- tiny harness ------------------------------------------------------------
static int g_checks = 0;
static int g_fail   = 0;

static void check(bool cond, const char* what) {
    ++g_checks;
    if (!cond) { ++g_fail; std::fprintf(stderr, "FAIL: %s\n", what); }
}

#if defined(__GNUC__)
__attribute__((format(printf, 2, 3)))
#endif
static void checkf(bool cond, const char* fmt, ...) {
    ++g_checks;
    if (cond) return;
    ++g_fail;
    char buf[512];
    std::va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    std::fprintf(stderr, "FAIL: %s\n", buf);
}

// ---------------------------------------------------------------------------
// 1) SHA-256 known answers
// ---------------------------------------------------------------------------
static void test_sha256() {
    struct Row { const char* in; const char* out; };
    static const Row kRows[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
    };
    for (const Row& r : kRows) {
        const std::string got = anchor_codec::to_hex(anchor_hash::sha256(r.in));
        checkf(got == r.out, "sha256(\"%.20s\") = %s", r.in, got.c_str());
    }

    // 1 000 000 'a': multi-block, and it exercises the streaming update path
    // rather than the one-shot helper.
    {
        anchor_hash::Sha256 h;
        const std::string chunk(1000, 'a');
        for (int i = 0; i < 1000; ++i) h.update(chunk);
        check(anchor_codec::to_hex(h.finish())
                  == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
              "sha256 of a million 'a' matches the NIST vector");
    }

    // A message of exactly 55 bytes fits its padding in the same block; 56 does
    // not. Both boundaries in one place because that is where hand-rolled
    // implementations break.
    check(anchor_codec::to_hex(anchor_hash::sha256(std::string(55, 'x')))
              != anchor_codec::to_hex(anchor_hash::sha256(std::string(56, 'x'))),
          "the 55/56-byte padding boundary produces different digests");
    check(anchor_codec::to_hex(anchor_hash::sha256(std::string(64, 'x'))).size() == 64,
          "an exact-block message hashes without a short read");
}

// ---------------------------------------------------------------------------
// a valid synthetic bundle to mutate
// ---------------------------------------------------------------------------
static Hash model_hash(std::uint64_t seed, std::uint8_t tag) {
    Hash h{};
    for (std::size_t i = 0; i < 8; ++i) h[i] = static_cast<std::uint8_t>(seed >> (8 * i));
    for (std::size_t i = 8; i < h.size(); ++i) h[i] = static_cast<std::uint8_t>(tag + i);
    return h;
}

// Heights and the major version are the real stagenet ones so the hard-fork
// table is exercised for real rather than against a made-up chain.
static constexpr std::uint64_t kModelHeight = 2204000;
static constexpr std::uint64_t kModelTip    = 2204848;

static AnchorBundle make_valid_bundle() {
    AnchorBundle b;
    b.network       = "stagenet";
    b.height        = kModelHeight;
    b.id            = model_hash(b.height, 0x10);
    b.prev_id       = model_hash(b.height - 1, 0x10);
    b.timestamp     = 1788965550;
    b.major_version = 16;
    b.cumulative_difficulty = U128{};
    b.cumulative_difficulty.hi = 0;
    b.cumulative_difficulty.lo = 0xc3772e00dbull;
    b.already_generated_coins = 18163913490712907281ull;

    const std::uint64_t seed_h = rx_seedheight(b.height + 1);
    b.seed_ids.emplace_back(seed_h, model_hash(seed_h, 0x20));

    U128 cd{};
    cd.lo = 0xc2cb6d9d38ull;
    for (std::size_t i = 0; i < ANCHOR_DIFFICULTY_WINDOW; ++i) {
        b.difficulty_window.emplace_back(1788876380ull + i * 37ull, cd);
        cd = u128_add(cd, U128{0, 3766353ull});
    }
    for (std::size_t i = 0; i < ANCHOR_SHORT_TERM_WEIGHTS; ++i)
        b.short_term_weights.push_back(87ull + (i % 5));

    // A shape with every run length the encoder cares about: singles, a pair, a
    // triple (all spelled inline) and long runs (spelled as counts).
    b.long_term_weights.reserve(ANCHOR_LONG_TERM_WEIGHTS);
    b.long_term_weights.push_back(216879);
    b.long_term_weights.push_back(300781);
    b.long_term_weights.push_back(298639);
    b.long_term_weights.push_back(298639);
    b.long_term_weights.push_back(298687);
    b.long_term_weights.push_back(298687);
    b.long_term_weights.push_back(298687);
    while (b.long_term_weights.size() < ANCHOR_LONG_TERM_WEIGHTS - 3)
        b.long_term_weights.push_back(176470);
    b.long_term_weights.push_back(1);
    b.long_term_weights.push_back(2);
    b.long_term_weights.push_back(3);

    b.monerod_checkpoints.emplace_back(b.height + 4096, model_hash(b.height + 4096, 0x30));
    b.digest = anchor_digest(b);
    return b;
}

static bool same_bundle(const AnchorBundle& a, const AnchorBundle& b) {
    return a.network == b.network && a.height == b.height && a.id == b.id
        && a.prev_id == b.prev_id && a.timestamp == b.timestamp
        && a.major_version == b.major_version
        && a.cumulative_difficulty.hi == b.cumulative_difficulty.hi
        && a.cumulative_difficulty.lo == b.cumulative_difficulty.lo
        && a.already_generated_coins == b.already_generated_coins
        && a.seed_ids == b.seed_ids
        && a.difficulty_window.size() == b.difficulty_window.size()
        && a.short_term_weights == b.short_term_weights
        && a.long_term_weights == b.long_term_weights
        && a.monerod_checkpoints == b.monerod_checkpoints
        && a.digest == b.digest;
}

// ---------------------------------------------------------------------------
// 2) the format: round-trip and every documented damage
// ---------------------------------------------------------------------------
static void test_codec_round_trip() {
    const AnchorBundle b = make_valid_bundle();
    const std::string text = write_anchor_inc(b, "kat synthetic bundle\nsecond comment line");

    AnchorBundle got;
    std::string why;
    const AnchorParse p = parse_anchor_inc(text, got, why);
    checkf(p == AnchorParse::Ok, "synthetic bundle parses: %s (%s)", to_string(p), why.c_str());
    check(same_bundle(b, got), "every field survives write -> parse");
    for (std::size_t i = 0; i < b.difficulty_window.size(); ++i) {
        if (b.difficulty_window[i].first != got.difficulty_window[i].first
            || b.difficulty_window[i].second.hi != got.difficulty_window[i].second.hi
            || b.difficulty_window[i].second.lo != got.difficulty_window[i].second.lo) {
            checkf(false, "difficulty window row %zu differs after round-trip", i);
            break;
        }
    }
    check(anchor_body_text(b) == anchor_body_text(got),
          "the canonical body is idempotent under parse");

    // Run-length spelling is a spelling, not a value: the parsed window has the
    // long runs expanded back to individual entries.
    check(got.long_term_weights.size() == ANCHOR_LONG_TERM_WEIGHTS,
          "the run-encoded long-term window expands to exactly 100000 entries");
    check(got.long_term_weights[0] == 216879 && got.long_term_weights[3] == 298639
              && got.long_term_weights[ANCHOR_LONG_TERM_WEIGHTS - 1] == 3,
          "run expansion preserves order at both ends");
    check(text.find("x176470") != std::string::npos,
          "the writer really does emit the long run as a count");

    // Comments are outside the digest, so annotating a bundle does not change it.
    const std::string other = write_anchor_inc(b, "a completely different comment");
    AnchorBundle got2;
    check(parse_anchor_inc(other, got2, why) == AnchorParse::Ok && got2.digest == got.digest,
          "the header comment does not change the digest");
}

// Replace the first occurrence of `from` with `to`; returns "" when absent so a
// stale test string fails loudly instead of testing nothing.
static std::string sub_once(const std::string& s, const std::string& from, const std::string& to) {
    const std::size_t at = s.find(from);
    if (at == std::string::npos) return std::string();
    std::string out = s;
    out.replace(at, from.size(), to);
    return out;
}

static void expect_parse(const std::string& text, AnchorParse want, const char* what) {
    if (text.empty()) { checkf(false, "%s: the mutation did not apply", what); return; }
    AnchorBundle b;
    std::string why;
    const AnchorParse got = parse_anchor_inc(text, b, why);
    checkf(got == want, "%s: expected %s, got %s (%s)", what, to_string(want),
           to_string(got), why.c_str());
    if (got != AnchorParse::Ok)
        checkf(!why.empty(), "%s: a refusal always says why", what);
}

static void test_codec_refusals() {
    const AnchorBundle b = make_valid_bundle();
    const std::string ok = write_anchor_inc(b, "kat");

    expect_parse("R\"ANCHOR(\n)ANCHOR\"\n", AnchorParse::Empty, "a bundle with no body");
    expect_parse(sub_once(ok, "format 1\n", ""), AnchorParse::BadFormat,
                 "a key before the format line");
    expect_parse(sub_once(ok, "format 1", "format 2"), AnchorParse::BadFormat,
                 "a format version this build does not read");
    expect_parse(sub_once(ok, "network stagenet", "netwrok stagenet"), AnchorParse::UnknownKey,
                 "a keyword the reader does not implement");
    expect_parse(sub_once(ok, "height 2204000", "height 2204000\nheight 2204000"),
                 AnchorParse::DuplicateKey, "a once-only key twice");
    expect_parse(sub_once(ok, "timestamp 1788965550", "timestamp 17889z5550"),
                 AnchorParse::BadField, "a decimal field that is not decimal");
    expect_parse(sub_once(ok, "major_version 16", "major_version 256"),
                 AnchorParse::BadField, "a major version outside a byte");
    expect_parse(sub_once(ok, "\nid ", "\nid zz"), AnchorParse::BadField,
                 "an id that is not 64 hex");
    expect_parse(sub_once(ok, "diff 1788876380", "diff 1788876380 0 0\ndiff 1788876380"),
                 AnchorParse::BadField, "one difficulty row too many");

    // Short windows are staged by writing a SHORT BUNDLE rather than by cutting
    // the text: that way the file is internally consistent -- correct digest,
    // every line understood -- and the only thing wrong with it is the count,
    // which is exactly the defect the length check exists to catch.
    {
        AnchorBundle s = b; s.difficulty_window.pop_back();
        expect_parse(write_anchor_inc(s, "kat"), AnchorParse::BadField,
                     "a difficulty window short by one");
    }
    {
        AnchorBundle s = b; s.short_term_weights.pop_back();
        expect_parse(write_anchor_inc(s, "kat"), AnchorParse::BadField,
                     "a short-term window short by one");
    }
    {
        AnchorBundle s = b; s.long_term_weights.pop_back();
        expect_parse(write_anchor_inc(s, "kat"), AnchorParse::BadField,
                     "a long-term window short by one");
    }

    // Dropping the `stw` keyword leaves its values as a bare line, which is an
    // unknown keyword rather than a short window -- worth pinning, because it is
    // the difference between "the file was edited" and "the capture was wrong".
    expect_parse(sub_once(ok, "\nstw", "\n"), AnchorParse::UnknownKey,
                 "a value line that lost its keyword");
    expect_parse(sub_once(ok, "digest ", "diegst "), AnchorParse::UnknownKey,
                 "a misspelled digest keyword");
    expect_parse(sub_once(ok, ")ANCHOR\"", "height 9\n)ANCHOR\""), AnchorParse::DigestPlace,
                 "content hidden after the digest line");
    expect_parse(sub_once(ok, "already_generated_coins 18163913490712907281",
                          "already_generated_coins 18163913490712907282"),
                 AnchorParse::DigestMismatch, "one digit changed in the body");
    expect_parse(sub_once(ok, "ltw 99", "ltw 100000000000x176470\nltw 99"),
                 AnchorParse::BadField, "a run count above the window cap");
    expect_parse(sub_once(ok, "ltw 216879", "ltw 0x176470"), AnchorParse::BadField,
                 "a run of length zero");

    // A digest line that is well-formed but wrong, rather than a damaged body.
    const std::size_t d = ok.rfind("digest ");
    if (d != std::string::npos) {
        std::string flipped = ok;
        flipped[d + 7] = (flipped[d + 7] == '0') ? '1' : '0';
        expect_parse(flipped, AnchorParse::DigestMismatch, "a digest line that does not match");
    } else {
        check(false, "the written bundle has a digest line");
    }
}

// ---------------------------------------------------------------------------
// 3) the judgement: every AnchorStatus is reachable
// ---------------------------------------------------------------------------
static void expect_status(AnchorBundle b, AnchorStatus want, const char* what) {
    std::string why;
    const AnchorStatus got = anchor_self_check(b, XmrNet::Stagenet, why);
    checkf(got == want, "%s: expected %s, got %s (%s)", what, to_string(want),
           to_string(got), why.c_str());
    if (want == AnchorStatus::Ok) checkf(why.empty(), "%s: a pass says nothing", what);
    else checkf(!why.empty(), "%s: a refusal always says why", what);
}

static void test_self_check() {
    const AnchorBundle base = make_valid_bundle();
    expect_status(base, AnchorStatus::Ok, "the unmodified synthetic bundle");

    {
        AnchorBundle b = base; b.network = "mainnet";
        expect_status(b, AnchorStatus::NetworkMismatch, "a bundle for another network");
    }
    {
        AnchorBundle b = base; b.difficulty_window.pop_back();
        expect_status(b, AnchorStatus::WindowSize, "a difficulty window short by one");
    }
    {
        AnchorBundle b = base; b.short_term_weights.push_back(1);
        expect_status(b, AnchorStatus::WindowSize, "a short-term window long by one");
    }
    {
        AnchorBundle b = base; b.long_term_weights.pop_back();
        expect_status(b, AnchorStatus::WindowSize, "a long-term window short by one");
    }
    {
        AnchorBundle b = base; b.seed_ids.clear();
        expect_status(b, AnchorStatus::SeedMisaligned, "a bundle with no seed id");
    }
    {
        AnchorBundle b = base;
        b.seed_ids[0].first += 1;
        expect_status(b, AnchorStatus::SeedMisaligned, "a seed height off the epoch boundary");
    }
    {
        AnchorBundle b = base;
        b.seed_ids[0].first = ((b.height / SEEDHASH_EPOCH_BLOCKS) + 4) * SEEDHASH_EPOCH_BLOCKS;
        expect_status(b, AnchorStatus::SeedMisaligned, "a seed height above the anchor");
    }
    {
        AnchorBundle b = base;
        b.difficulty_window[400].second = U128{0, 1};
        expect_status(b, AnchorStatus::NonMonotone, "cumulative difficulty going backwards");
    }
    {
        AnchorBundle b = base;
        b.major_version = 15;                       // stagenet is 16 from 1 151 720
        expect_status(b, AnchorStatus::VersionMismatch,
                      "a major version below what the fork table requires");
    }
    {
        AnchorBundle b = base;
        b.major_version = MAX_IMPLEMENTED_HF_VERSION + 1;
        expect_status(b, AnchorStatus::Fenced, "a fork this build does not implement");
    }
    {
        AnchorBundle b = base;
        b.monerod_checkpoints.emplace_back(b.height - 1, model_hash(1, 0x40));
        expect_status(b, AnchorStatus::CheckpointBelow, "a checkpoint below the anchor");
    }
    {
        AnchorBundle b = base; b.monerod_checkpoints.clear();
        expect_status(b, AnchorStatus::Ok, "a bundle carrying no checkpoints at all");
    }
    // The fence is checked BEFORE the table lookup, so a fenced version does not
    // masquerade as a version mismatch.
    {
        AnchorBundle b = base; b.major_version = 250;
        expect_status(b, AnchorStatus::Fenced, "a wildly future fork reads as fenced");
    }
}

// ---------------------------------------------------------------------------
// 4) load_anchor: source, tamper, and the duty it cannot discharge
// ---------------------------------------------------------------------------
static bool write_file(const std::string& path, const std::string& text) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(text.data(), static_cast<std::streamsize>(text.size()));
    return static_cast<bool>(f);
}

static void test_load_anchor() {
    const AnchorBundle b = make_valid_bundle();
    const std::string path = "xmr_anchor_kat_bundle.inc";
    if (!write_file(path, write_anchor_inc(b, "kat temp bundle"))) {
        check(false, "the KAT can write its temporary bundle");
        return;
    }

    AnchorBundle got;
    std::string why;
    checkf(load_anchor(path, XmrNet::Stagenet, got, why),
           "a well-formed bundle loads from a path: %s", why.c_str());
    check(same_bundle(b, got), "the loaded bundle is the one that was written");
    check(why.empty(), "a successful load says nothing");

    // Right file, wrong chain: refused, and the reason names the network rather
    // than blaming the file.
    AnchorBundle none;
    check(!load_anchor(path, XmrNet::Mainnet, none, why), "the same bundle is refused on mainnet");
    check(why.find("NetworkMismatch") != std::string::npos,
          "and the refusal is reported as a network mismatch, not as damage");
    check(none.height == 0 && none.long_term_weights.empty(),
          "a refused load leaves the caller holding nothing");

    // One byte, and the whole file is refused.
    {
        std::string text = write_anchor_inc(b, "kat temp bundle");
        const std::size_t at = text.find("timestamp 1788965550");
        check(at != std::string::npos, "the tamper target is present");
        if (at != std::string::npos) {
            text[at + 10] = '2';
            const std::string tpath = "xmr_anchor_kat_tampered.inc";
            check(write_file(tpath, text), "the KAT can write its tampered bundle");
            AnchorBundle t;
            check(!load_anchor(tpath, XmrNet::Stagenet, t, why), "a tampered bundle is refused");
            check(why.find("DigestMismatch") != std::string::npos,
                  "and the refusal names the digest");
            std::remove(tpath.c_str());
        }
    }

    check(!load_anchor("no/such/anchor.inc", XmrNet::Stagenet, none, why),
          "a path that does not exist is refused");
    check(why.find("cannot open") != std::string::npos, "and says so plainly");

    // The embedded path, including the networks this build does not carry.
    check(!load_anchor("", XmrNet::Mainnet, none, why),
          "an empty path on a network with no embedded bundle is refused");
    check(why.find("no embedded anchor bundle") != std::string::npos,
          "and says the build carries none");

    // Gate 4: the duty load_anchor cannot discharge.
    check(anchor_confirmed_by_network(b, b.id, why), "a matching network id confirms the anchor");
    check(!anchor_confirmed_by_network(b, model_hash(999, 0x50), why),
          "a different block at the anchor height refuses the start");
    check(why.find("refusing to start") != std::string::npos,
          "and the refusal is unambiguous about what happens next");
    check(std::string(anchor_boot_duty()).find("anchor_confirmed_by_network") != std::string::npos,
          "the boot duty names the function that discharges it");

    std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// 5) generate_anchor against a model daemon
// ---------------------------------------------------------------------------
namespace {

struct ModelDaemon final : MoneroDaemonRpc {
    std::string   network = "stagenet";
    std::uint64_t tip     = kModelTip;
    std::uint64_t coins_height = kModelTip;
    std::uint64_t coins   = 1000000000000000000ull;
    std::uint64_t reward  = 600000000000ull;

    // fault injection
    bool break_prev_at   = false;   // one header's prev_id does not link
    bool short_response  = false;   // return fewer rows than asked
    bool cumdiff_backward = false;  // cumulative difficulty dips
    bool tiny_coins      = false;   // coins too small to subtract back

    int calls = 0;

    static Hash id_at(std::uint64_t h) { return model_hash(h, 0x10); }

    bool net_and_tip(std::string& n, std::uint64_t& t, std::string&) override {
        n = network; t = tip; return true;
    }

    bool headers_range(std::uint64_t from, std::uint64_t to,
                       std::vector<AnchorRpcHeader>& out, std::string& why) override {
        ++calls;
        out.clear();
        if (to < from) { why = "empty range"; return false; }
        std::uint64_t last = to;
        if (short_response && to - from > 2) last = to - 1;
        for (std::uint64_t h = from; h <= last; ++h) {
            AnchorRpcHeader x;
            x.height = h;
            x.id = id_at(h);
            x.prev_id = id_at(h - 1);
            if (break_prev_at && h == kModelHeight - 5000) x.prev_id = model_hash(7, 0x99);
            x.timestamp = 1700000000ull + h * 120ull;
            x.major_version = 16;
            x.reward = reward;
            x.block_weight = 87 + (h % 5);
            x.long_term_weight = (h % 9973 == 0) ? 300781 : 176470;
            x.cumulative_difficulty = U128{0, 3766353ull * h};
            if (cumdiff_backward && h == kModelHeight - 100)
                x.cumulative_difficulty = U128{0, 1};
            out.push_back(x);
        }
        return true;
    }

    bool coins_at_tip(std::uint64_t& h, std::uint64_t& c, std::string&) override {
        h = coins_height;
        c = tiny_coins ? 1000ull : coins;
        return true;
    }

    bool checkpoints_at_or_above(std::uint64_t, std::vector<std::pair<std::uint64_t, Hash>>& out,
                                 std::string&) override {
        out.clear();
        return true;
    }
};

}  // namespace

static void test_generate_anchor() {
    {
        ModelDaemon d;
        AnchorBundle b;
        std::string why;
        checkf(generate_anchor(d, kModelHeight, b, why),
               "an honest daemon mints a bundle: %s", why.c_str());
        check(b.height == kModelHeight && b.network == "stagenet",
              "the minted bundle names the height and network it was asked for");
        check(b.id == ModelDaemon::id_at(kModelHeight)
                  && b.prev_id == ModelDaemon::id_at(kModelHeight - 1),
              "the anchor block and its parent come from the daemon");
        check(b.difficulty_window.size() == ANCHOR_DIFFICULTY_WINDOW
                  && b.short_term_weights.size() == ANCHOR_SHORT_TERM_WEIGHTS
                  && b.long_term_weights.size() == ANCHOR_LONG_TERM_WEIGHTS,
              "the five windows come out at exactly the pinned lengths");
        check(b.already_generated_coins
                  == 1000000000000000000ull - (kModelTip - kModelHeight) * 600000000000ull,
              "already_generated_coins is walked back from the tip block by block");
        check(!b.seed_ids.empty() && b.seed_ids[0].first % SEEDHASH_EPOCH_BLOCKS == 0
                  && b.seed_ids[0].second == ModelDaemon::id_at(b.seed_ids[0].first),
              "the seed id is read out of the block at the epoch height");
        check(b.digest == anchor_digest(b), "the minted bundle carries its own digest");

        std::string sc_why;
        check(anchor_self_check(b, XmrNet::Stagenet, sc_why) == AnchorStatus::Ok,
              "and it passes the loader's own judgement");

        // The generator's output is a file the loader accepts, which is the only
        // interface that actually matters between C6a and C2b.
        AnchorBundle back;
        check(parse_anchor_inc(write_anchor_inc(b, "model daemon"), back, why) == AnchorParse::Ok
                  && same_bundle(b, back),
              "a generated bundle round-trips through the on-disk format");

        // 100 000 headers at the 1000-row RPC cap, plus the span above the anchor.
        checkf(d.calls >= 100, "the window is fetched in chunks (%d calls)", d.calls);
    }

    struct Case { const char* what; void (*arm)(ModelDaemon&); std::uint64_t height; };
    static const Case kCases[] = {
        {"an anchor that is not buried deep enough",
         [](ModelDaemon& d) { d.tip = kModelHeight + 10; }, kModelHeight},
        {"an anchor above the daemon's tip",
         [](ModelDaemon& d) { d.tip = kModelHeight - 1; }, kModelHeight},
        {"an anchor below the long-term window",
         [](ModelDaemon&) {}, ANCHOR_LONG_TERM_WEIGHTS - 2},
        {"a daemon on an unknown network",
         [](ModelDaemon& d) { d.network = "somenet"; }, kModelHeight},
        {"a header chain whose prev_id does not link",
         [](ModelDaemon& d) { d.break_prev_at = true; }, kModelHeight},
        {"a response shorter than the range asked for",
         [](ModelDaemon& d) { d.short_response = true; }, kModelHeight},
        {"cumulative difficulty going backwards mid-window",
         [](ModelDaemon& d) { d.cumdiff_backward = true; }, kModelHeight},
        {"coins that underflow when walked back to the anchor",
         [](ModelDaemon& d) { d.tiny_coins = true; }, kModelHeight},
        {"a daemon whose coins are reported below the anchor height",
         [](ModelDaemon& d) { d.coins_height = kModelHeight - 1; }, kModelHeight},
    };
    for (const Case& c : kCases) {
        ModelDaemon d;
        c.arm(d);
        AnchorBundle b;
        std::string why;
        const bool ok = generate_anchor(d, c.height, b, why);
        checkf(!ok, "%s is refused", c.what);
        checkf(!ok && !why.empty(), "%s: the refusal says why", c.what);
        checkf(!ok && b.height == 0 && b.long_term_weights.empty(),
               "%s: the caller is left holding nothing", c.what);
    }

    // The bool-only signature the plan pins is the same gate, not a laxer one.
    {
        ModelDaemon d;
        d.break_prev_at = true;
        AnchorBundle b;
        check(!generate_anchor(d, kModelHeight, b),
              "the pinned two-argument form refuses exactly where the detailed one does");
    }
}

// ---------------------------------------------------------------------------
// 6) THE REAL BUNDLE: the stagenet anchor this build embeds
// ---------------------------------------------------------------------------
static void test_embedded_stagenet() {
    AnchorBundle b;
    std::string why;
    const AnchorLoadResult r = load_anchor_detailed("", XmrNet::Stagenet, b);
    checkf(r.ok, "the embedded stagenet anchor loads: %s", r.why.c_str());
    if (!r.ok) return;
    check(r.source == "embedded", "and it came from the binary, not from a path");

    // The pins a reviewer checks against a block explorer.
    check(b.network == "stagenet", "the embedded bundle is the stagenet one");
    checkf(b.height == 2204000, "the anchor sits at height %llu",
           static_cast<unsigned long long>(b.height));
    check(anchor_codec::to_hex(b.id)
              == "c55f08bce08d3514f520611d6262afb15247e506d58453a73fd48067813dcdf5",
          "the anchor block id is the pinned one");
    check(b.major_version == 16, "the anchor sits in the major-16 band");
    check(b.major_version == hf_version_for_height(XmrNet::Stagenet, b.height),
          "and that is exactly what the hard-fork table says for its height");
    check(b.timestamp > 1700000000ull, "the anchor timestamp is a plausible recent one");
    check(b.already_generated_coins > 0, "already_generated_coins is populated");

    check(b.difficulty_window.size() == ANCHOR_DIFFICULTY_WINDOW,
          "the real difficulty window is exactly 735 rows");
    check(b.short_term_weights.size() == ANCHOR_SHORT_TERM_WEIGHTS,
          "the real short-term window is exactly 100 rows");
    check(b.long_term_weights.size() == ANCHOR_LONG_TERM_WEIGHTS,
          "the real long-term window is exactly 100000 rows");
    check(!b.seed_ids.empty() && b.seed_ids[0].first % SEEDHASH_EPOCH_BLOCKS == 0,
          "the real seed height is on an epoch boundary");
    check(b.seed_ids[0].first == rx_seedheight(b.height + 1),
          "and it is the seed the first post-anchor block needs");

    std::string sc_why;
    checkf(anchor_self_check(b, XmrNet::Stagenet, sc_why) == AnchorStatus::Ok,
           "the real bundle passes anchor_self_check: %s", sc_why.c_str());

    // THE CROSS-CHECK. The digest in the file was computed by the Python capture
    // tool; this recomputes it with the C++ canonical writer over the parsed
    // bundle. Equal means the two implementations of the format agree byte for
    // byte -- which is the only thing that keeps them from drifting apart.
    check(anchor_hash::sha256(anchor_body_text(b)) == b.digest,
          "the C++ canonical body hashes to the digest the capture tool wrote");

    // And the whole file survives a re-write with the C++ writer.
    AnchorBundle again;
    check(parse_anchor_inc(write_anchor_inc(b, "re-written by the KAT"), again, why)
              == AnchorParse::Ok && same_bundle(b, again),
          "the real bundle round-trips through the C++ writer unchanged");

    // A real bundle is also a real refusal on the wrong network.
    AnchorBundle none;
    check(!load_anchor("", XmrNet::Testnet, none, why),
          "the stagenet bundle is not offered to a testnet node");
}

// ---------------------------------------------------------------------------
int main() {
    test_sha256();
    test_codec_round_trip();
    test_codec_refusals();
    test_self_check();
    test_load_anchor();
    test_generate_anchor();
    test_embedded_stagenet();

    std::printf("xmr_anchor_self_check_kat: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
