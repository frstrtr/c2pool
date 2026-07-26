// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DASH P2Pool sharechain network configuration (oracle-sourced SSOT).
//
// SOURCE OF TRUTH: the DASH oracle frstrtr/p2pool-dash, networks/dash.py +
// networks/dash_testnet.py (operator 2026-06-17 per-coin re-scope: DASH conforms
// to its OWN older-than-v35 oracle, NOT a v35-uniform baseline).
//
// SCOPE: pins the p2pool *sharechain* framing constants (PREFIX/IDENTIFIER/
// SHARE_PERIOD/CHAIN_LENGTH/TARGET_LOOKBEHIND/SPREAD/P2P_PORT/WORKER_PORT/
// MIN_PROTOCOL/MAX_TARGET) as the single place a DASH sharechain constant can
// drift. Consumed by test_dash_conformance (oracle pin) and is the SSOT the
// dash::make_coin_params factory will read. Factory wiring + Fileconfig/pool.yaml
// runtime-override integration are the S6 follow-on, deliberately out of scope
// here so this header carries no file-loading machinery.
//
// PREFIX/IDENTIFIER are ISOLATION PRIMITIVES (operator v36_standardization_goal
// 2026-06-17): kept per-coin AND per-instance, NEVER unified cross-coin.

#include <cstdint>
#include <string>

#include <core/uint256.hpp>

namespace dash
{

// DASH sharechain p2pool constants. Source of truth: p2pool-dash oracle
// networks/dash.py (mainnet) + networks/dash_testnet.py (testnet).
struct SharechainConfig
{
    // ---- mainnet (networks/dash.py) ----
    static constexpr uint16_t P2P_PORT                  = 8999;
    static constexpr uint16_t WORKER_PORT               = 7903;
    static constexpr uint32_t SHARE_PERIOD              = 20;     // seconds
    static constexpr uint32_t CHAIN_LENGTH              = 4320;   // 24*60*60//20
    static constexpr uint32_t REAL_CHAIN_LENGTH         = 4320;
    static constexpr uint32_t TARGET_LOOKBEHIND         = 100;
    static constexpr uint32_t SPREAD                    = 10;     // blocks
    static constexpr uint32_t MINIMUM_PROTOCOL_VERSION  = 1700;   // protocol v1700 floor (COLD accept-all; oracle dash.py:23)

    // ── v36 crossing protocol versions (c2pool v36-native — NOT oracle-derived) ──
    // The DASH oracle (frstrtr/p2pool-dash) has NO NEW_MINIMUM_PROTOCOL_VERSION and
    // NO advertised-capability field; MINIMUM_PROTOCOL_VERSION is the static 1700 net
    // constant. The two values below are c2pool v36-native choices made at the ratchet
    // wire-up (dash/v36-ratchet-wireup) and are FLAGGED for integrator review:
    //
    //   NEW_MINIMUM_PROTOCOL_VERSION (3600): the RATCHET TARGET floor. It is the DASH
    //     analog of ltc MINIMUM_PROTOCOL_VERSION=3301 / dgb SHARE_MINIMUM_PROTOCOL_VERSION
    //     =3500 and matches the cross-coin v36 protocol lineage (ltc advertises 3600 for
    //     v36 capability). The accept floor is NEVER set to this statically — that was the
    //     v36 min-proto-3600 transition regression (a hard cut that blocked pre-v36 peers
    //     from joining). It is reached ONLY by the work-weighted 95% AutoRatchet
    //     (auto_ratchet.hpp), so a node still JOINS at the cold 1700 floor and ratchets UP.
    //
    //   ADVERTISED_PROTOCOL_VERSION (3600): the protocol version a v36-capable DASH node
    //     puts on the wire in its version handshake. Required for ratchet COHERENCE: once
    //     two nodes ratchet their accept floor to 3600 they must each advertise >= 3600 or
    //     they would reject each other. Backward-compatible: legacy p2pool-dash peers accept
    //     any version >= their own 1700 floor, so advertising 3600 pre-crossing rejects
    //     nobody and does NOT prematurely negotiate the "actual" (v36) protocol path
    //     (handle_version gates that on the accept floor being ratcheted, not on the advert).
    static constexpr uint32_t NEW_MINIMUM_PROTOCOL_VERSION = 3600;  // AutoRatchet TARGET floor (v36-native)
    static constexpr uint32_t ADVERTISED_PROTOCOL_VERSION  = 3600;  // v36-capability advert (>= target floor)

    // ---- testnet (networks/dash_testnet.py) ----
    static constexpr uint16_t TESTNET_P2P_PORT          = 18999;
    static constexpr uint16_t TESTNET_WORKER_PORT       = 17903;
    static constexpr uint32_t TESTNET_SHARE_PERIOD      = 20;
    static constexpr uint32_t TESTNET_CHAIN_LENGTH      = 4320;
    static constexpr uint32_t TESTNET_REAL_CHAIN_LENGTH = 4320;

    static inline bool is_testnet = false;

    static uint16_t p2p_port()          { return is_testnet ? TESTNET_P2P_PORT : P2P_PORT; }
    static uint16_t worker_port()       { return is_testnet ? TESTNET_WORKER_PORT : WORKER_PORT; }
    static uint32_t share_period()      { return is_testnet ? TESTNET_SHARE_PERIOD : SHARE_PERIOD; }
    static uint32_t chain_length()      { return is_testnet ? TESTNET_CHAIN_LENGTH : CHAIN_LENGTH; }
    static uint32_t real_chain_length() { return is_testnet ? TESTNET_REAL_CHAIN_LENGTH : REAL_CHAIN_LENGTH; }

    // ISOLATION PRIMITIVES — per-coin AND per-instance, never unified cross-coin.
    static inline const std::string IDENTIFIER_HEX         = "7242ef345e1bed6b";
    static inline const std::string PREFIX_HEX             = "3b3e1286f446b891";
    static inline const std::string TESTNET_IDENTIFIER_HEX = "b6deb1e543fe2427";
    static inline const std::string TESTNET_PREFIX_HEX     = "198b644f6821e3b3";

    static const std::string& identifier_hex() { return is_testnet ? TESTNET_IDENTIFIER_HEX : IDENTIFIER_HEX; }
    static const std::string& prefix_hex()     { return is_testnet ? TESTNET_PREFIX_HEX     : PREFIX_HEX; }

    // ---- COINBASEEXT: the canonical p2pool coinbase marker ------------------
    // SOURCE OF TRUTH: oracle networks/dash.py:11 / dash_testnet.py:11 —
    //     dash.py         COINBASEEXT = '0D2F5032506F6F6C2D444153482F'.decode('hex')
    //     dash_testnet.py COINBASEEXT = '0E2F5032506F6F6C2D74444153482F'.decode('hex')
    // Transcribed VERBATIM, including the leading one-byte push opcode (0x0D =
    // push 13, the length of "/P2Pool-DASH/"; 0x0E = push 14 for
    // "/P2Pool-tDASH/"), so this header pins the oracle constant exactly as the
    // oracle writes it. What c2pool EMITS is the text payload with the push
    // opcode stripped — see coinbaseext_text() for why.
    //
    // WHY IT EXISTS: block explorers attribute blocks to a pool BY COINBASE
    // TEXT. chainz.cryptoid.info/dash/extraction.dws?30.htm registers the pool
    // as "P2Pool-DASH" and has no knowledge of the string "c2pool", so blocks
    // c2pool won for the p2pool-dash sharechain were credited to nobody.
    //
    // CONSENSUS STATUS: NOT consensus-bearing — the coinbase text is a
    // customizable parameter (that is what --coinbase-text is). COINBASEEXT
    // appears NOWHERE in the oracle's data.py (the consensus module); it lives
    // only in networks/*.py and the stratum assembly at work.py:339. The
    // scriptSig travels on the wire as share_info.share_data.coinbase (VarStr,
    // 2..100 B) and Share.check() re-derives the gentx from the RECEIVED
    // share's own coinbase field, never from a network constant. Framing notes
    // (BIP34 prefix, extranonce offsets) on build_coinbase_scriptsig().
    //
    // REGTEST: the oracle's dash_regtest.py:11 constant
    // '0F2F5032506F6F6C2D724441534828' is MALFORMED — it declares push-15 but
    // carries only 14 bytes, and its final byte is 0x28 '(' where a '/' (0x2F)
    // was clearly intended ("/P2Pool-rDASH("). c2pool has no separate regtest
    // sharechain profile (main_dash.cpp maps --regtest onto testnet=true), so a
    // c2pool regtest node emits the tDASH marker and the oracle typo is not
    // reproduced. Recorded here so the divergence is deliberate, not drift.
    static inline const std::string COINBASEEXT_HEX         = "0D2F5032506F6F6C2D444153482F";
    static inline const std::string TESTNET_COINBASEEXT_HEX = "0E2F5032506F6F6C2D74444153482F";

    // Implementation tag appended after the marker so a human reading the
    // coinbase can tell WHICH p2pool implementation produced the block. Shared
    // by mainnet and testnet.
    static inline const std::string IMPL_TAG = "c2pool/";

    // Explicit-network forms — PREFERRED. Callers on the coinbase path already
    // hold core::CoinParams::is_testnet, so they never have to trust the mutable
    // process-global below (and tests can exercise both networks in one binary).
    static const std::string& coinbaseext_hex(bool testnet)
    {
        return testnet ? TESTNET_COINBASEEXT_HEX : COINBASEEXT_HEX;
    }
    static const std::string& coinbaseext_hex() { return coinbaseext_hex(is_testnet); }

    // COINBASEEXT decoded to raw bytes, push opcode INCLUDED — the oracle's
    // literal constant. Local decoder: this header is the SSOT the conformance
    // tests pin and deliberately carries no dependency beyond
    // <cstdint>/<string>/uint256.
    static std::string coinbaseext_bytes(bool testnet)
    {
        const std::string& h = coinbaseext_hex(testnet);
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        std::string out;
        out.reserve(h.size() / 2);
        for (size_t i = 0; i + 1 < h.size(); i += 2) {
            const int hi = nib(h[i]), lo = nib(h[i + 1]);
            if (hi < 0 || lo < 0) return {};          // malformed SSOT -> emit nothing
            out.push_back(static_cast<char>((hi << 4) | lo));
        }
        return out;
    }
    static std::string coinbaseext_bytes() { return coinbaseext_bytes(is_testnet); }

    // The marker TEXT — COINBASEEXT with its leading push opcode stripped:
    //     mainnet "/P2Pool-DASH/"   testnet "/P2Pool-tDASH/"
    //
    // This, not the raw constant, is what c2pool writes. The push opcode is
    // dropped deliberately: c2pool exposes the coinbase scriptSig payload as an
    // operator-settable TEXT parameter (--coinbase-text, README "Coinbase
    // structure"), and a bare control byte inside a text field would be lost the
    // moment an operator overrode it — the default would then behave unlike
    // every other value the field can take. Attribution is unaffected: explorers
    // key on the coinbase TEXT (cryptoid lists this pool as "P2Pool-DASH"), and
    // the ASCII substring "/P2Pool-DASH/" is byte-identical to what a canonical
    // p2pool-dash node renders. The push byte is a script-encoding artefact of
    // p2pool's assembly, not part of the name.
    //
    // Fail-closed: if the SSOT hex is ever edited into an inconsistent state
    // (leading byte != payload length, as in the oracle's own regtest constant),
    // this returns the decoded bytes unchanged rather than silently trimming a
    // real character.
    static std::string coinbaseext_text(bool testnet)
    {
        std::string b = coinbaseext_bytes(testnet);
        if (b.size() >= 2 &&
            static_cast<unsigned char>(b[0]) == b.size() - 1)
            return b.substr(1);
        return b;
    }

    // Default coinbase scriptSig text for this network:
    //     mainnet "/P2Pool-DASH/c2pool/"     testnet "/P2Pool-tDASH/c2pool/"
    // The p2pool marker makes explorers attribute the block to the pool; the
    // c2pool suffix says which implementation mined it.
    static std::string default_coinbase_text(bool testnet)
    {
        return coinbaseext_text(testnet) + IMPL_TAG;
    }

    // ---- Operator override (--coinbase-text / pool.yaml coinbase_text) -------
    // Pool-level runtime setting, resolved ONCE at startup in main_dash.cpp
    // before any coinbase is built. Empty means "use the network default".
    // Lives here rather than being threaded through every build call so the
    // stratum job path and the share-mint path cannot end up disagreeing.
    static inline std::string coinbase_text_override;

    static std::string coinbase_text(bool testnet)
    {
        return coinbase_text_override.empty() ? default_coinbase_text(testnet)
                                              : coinbase_text_override;
    }
    static std::string coinbase_text() { return coinbase_text(is_testnet); }

    // ---- Dust threshold (payout-dust semantic) -----------------------------
    // DUST_THRESHOLD: minimum per-recipient payout to justify a coinbase output.
    // SOURCE: p2pool-dash oracle DUST_THRESHOLD = 0.001e8 = 100000 satoshi
    // (PARENT.DUST_THRESHOLD). This is the PAYOUT-dust floor, NOT the dashd relay
    // policy floor (5460/54600) which is wrong-semantic for the PPLNS path.
    // V36 Option-A conform-to-p2pool: 100000 is the V36-correct value, matching
    // the BTC/BCH/DGB sibling payout-dust semantic.
    static constexpr uint64_t DUST_THRESHOLD         = 100000;  // satoshi (mainnet)
    static constexpr uint64_t TESTNET_DUST_THRESHOLD = 100000;  // satoshi (testnet: oracle carries no separate floor)
    static uint64_t dust_threshold() { return is_testnet ? TESTNET_DUST_THRESHOLD : DUST_THRESHOLD; }

    // MAX_TARGET: easiest allowed share difficulty (share-diff floor).
    //   mainnet : 0xFFFF * 2**208      (standard bdiff difficulty-1 target)
    //   testnet : 2**256 // 2**20 - 1
    static uint256 max_target()
    {
        static const uint256 MAINNET_MAX = [] {
            uint256 t;
            t.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
            return t;
        }();
        static const uint256 TESTNET_MAX = [] {
            uint256 t;
            t.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            return t;
        }();
        return is_testnet ? TESTNET_MAX : MAINNET_MAX;
    }

    // SANE_TARGET_RANGE = (min_target/hardest, max_target/easiest) — the parent-coin
    // sane vardiff bounds the stratum get_work() pseudoshare target is clipped into
    // (p2pool work.py:380-393, math.clip). SOURCE: oracle networks/dash.py:33 +
    // dash_testnet.py:27.
    //   mainnet min = (0xFFFF*2**208)//10000        max = 0xFFFF*2**208
    //   testnet min = 2**256//2**32//1000000 - 1    max = 2**256//2**20 - 1
    // sane_target_max() mainnet == max_target() (both = _DIFF1_TARGET); kept as its
    // own accessor so the clip reads the oracle SANE pair, not the share-diff floor.
    static uint256 sane_target_min()
    {
        static const uint256 MAINNET_MIN = [] {
            uint256 t; t.SetHex("0000000000068db22d0e5604189374bc6a7ef9db22d0e5604189374bc6a7ef9d"); return t;
        }();
        static const uint256 TESTNET_MIN = [] {
            uint256 t; t.SetHex("00000000000010c6f7a0b5ed8d36b4c7f34938583621fafc8b0079a2834d26f9"); return t;
        }();
        return is_testnet ? TESTNET_MIN : MAINNET_MIN;
    }

    static uint256 sane_target_max() { return max_target(); }
};

} // namespace dash