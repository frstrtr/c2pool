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
#include <vector>

#include <core/uint256.hpp>

namespace dash
{

// DASH sharechain p2pool constants. Source of truth: p2pool-dash oracle
// networks/dash.py (mainnet) + networks/dash_testnet.py (testnet).
struct SharechainConfig
{
    // ---- mainnet (networks/dash.py) ----
    static constexpr uint16_t P2P_PORT                  = 8999;
    // Sharechain port of the named DASH v36 network (--net dash-v36). Not an
    // oracle constant: the v36 network is c2pool's own, and a separate port lets
    // a v36 node run on the same host as a v16 node on P2P_PORT.
    static constexpr uint16_t V36_P2P_PORT              = 8998;
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

    //   ISOLATED_V36_PROTOCOL_VERSION (3601): the protocol version the private/
    //     isolated DASH v36 sharechain ADVERTISES and the accept floor its nodes
    //     start at (ISOLATED_V36_PROFILE below). Strictly above
    //     ADVERTISED_PROTOCOL_VERSION: a c2pool-dash build without v36 isolated
    //     support advertises 3600 and cannot parse a type-36 share, so with the
    //     same --network-id/--prefix it would pass a 3600 floor, get peered and
    //     then fail on every share it is sent; at 3601 it is refused at the
    //     handshake instead ("peer build lacks v36 isolated support — upgrade"),
    //     not banned. It is NOT a ratchet target (NEW_MINIMUM_PROTOCOL_VERSION
    //     stays the public 3600 target; apply_min_protocol_ratchet latches on
    //     current >= target, so a 3601 seed is a no-op there) and the public
    //     network never sees it (PUBLIC_PROFILE advertises 3600). Every protocol
    //     comparison is an ordering (>=, <, max), none keys off "exactly 3600":
    //     node.hpp handle_version (peer < floor -> refused; floor > 1700 &&
    //     peer >= floor -> actual), node.cpp apply_min_protocol_ratchet and
    //     auto_ratchet.hpp (current >= target -> latched), min_protocol_gate.hpp
    //     (peer >= knob, composed by max), main_dash.cpp live share version
    //     (floor >= 3600 -> 36), p2pool-dash p2p.py (peer < 1700 -> refused).
    //     "v36 isolated support" is keyed on this bare number: any later change
    //     to the isolated v36 share/ref/gentx wire format MUST bump it (3602, ...),
    //     or builds with the older format pass the handshake again.
    // BUMP RULE (docs/dash-v36-network.md): ANY change to the DASH v36 share,
    // ref-stream or gentx wire format MUST bump this number (3601 -> 3602 -> ...)
    // in the same PR, together with a KAT, or older builds pass the handshake
    // again and then fail on every share they are sent.
    static constexpr uint32_t ISOLATED_V36_PROTOCOL_VERSION = 3601;  // DASH v36 network advert AND accept floor

    // ---- testnet (networks/dash_testnet.py) ----
    static constexpr uint16_t TESTNET_P2P_PORT          = 18999;
    static constexpr uint16_t TESTNET_WORKER_PORT       = 17903;
    static constexpr uint32_t TESTNET_SHARE_PERIOD      = 20;
    static constexpr uint32_t TESTNET_CHAIN_LENGTH      = 4320;
    static constexpr uint32_t TESTNET_REAL_CHAIN_LENGTH = 4320;

    static inline bool is_testnet = false;

    // --net dash-v36 is mainnet-only, so the testnet port needs no v36 variant.
    // A custom --network-id (private network) keeps P2P_PORT.
    static uint16_t p2p_port()
    {
        if (is_testnet) return TESTNET_P2P_PORT;
        return is_named_v36_network() ? V36_P2P_PORT : P2P_PORT;
    }
    static uint16_t worker_port()       { return is_testnet ? TESTNET_WORKER_PORT : WORKER_PORT; }
    static uint32_t share_period()      { return is_testnet ? TESTNET_SHARE_PERIOD : SHARE_PERIOD; }
    static uint32_t chain_length()      { return is_testnet ? TESTNET_CHAIN_LENGTH : CHAIN_LENGTH; }
    static uint32_t real_chain_length() { return is_testnet ? TESTNET_REAL_CHAIN_LENGTH : REAL_CHAIN_LENGTH; }

    // ISOLATION PRIMITIVES — per-coin AND per-instance, never unified cross-coin.
    // Identifier + prefix are the sharechain's network isolation keys — they are NOT just
    // handshake framing: the identifier is committed inside every share's ref_hash (the ref
    // stream prepends active_identifier_hex()), so it gates BOTH the p2p prefix match AND share
    // PoW/ref-hash validation. Nodes with different values form disjoint, mutually-rejecting
    // sharechains, so the default MUST equal the live network's identity.
    //
    // Mainnet = the live p2pool-dash fleet identity (oracle p2pool/dash.py:9-10). The single
    // live DASH sharechain is keyed to 7242ef345e1bed6b / 3b3e1286f446b891.
    //
    // HISTORY of the v36 identity ac2785363c0180b8 / 8d8516bac9edd280: it was
    // RESERVED as the future v36 self-identity. A 2026-08-25 switch (#1344) made it
    // the default before any v36 network existed, isolating the node from the only
    // live network and breaking both handshake AND share validation against the
    // fleet; that was reverted (#1424). The rule kept from then: this identity is
    // NEVER the plain default. It is now the identity of the DASH v36 network and is
    // selected ONLY by name (--net dash-v36 / settings key sharechain.network = "v36",
    // select_named_network below); the no-flag default stays the live p2pool-dash
    // identity above.
    static inline const std::string IDENTIFIER_HEX         = "7242ef345e1bed6b";  // live p2pool-dash fleet
    static inline const std::string PREFIX_HEX             = "3b3e1286f446b891";  // live p2pool-dash fleet
    static inline const std::string TESTNET_IDENTIFIER_HEX = "b6deb1e543fe2427";
    static inline const std::string TESTNET_PREFIX_HEX     = "198b644f6821e3b3";

    // ---- The DASH v36 network (--net dash-v36) ------------------------------
    // A p2pool v36 sharechain for DASH that starts at share v36 from genesis. Its
    // identifier/prefix pair is the formerly reserved v36 self-identity (history
    // above). Two independent constants, like every other network's pair: the
    // prefix is NEVER derived from the identifier.
    static inline const std::string V36_NETWORK_IDENTIFIER_HEX = "ac2785363c0180b8";
    static inline const std::string V36_NETWORK_PREFIX_HEX     = "8d8516bac9edd280";
    // Canonical CLI name (--net) and settings-file value (sharechain.network).
    // Both surfaces accept both spellings (parse_named_network).
    static constexpr const char* V36_NETWORK_NAME          = "dash-v36";
    static constexpr const char* V36_NETWORK_SETTINGS_NAME = "v36";

    // ---- Private sharechain override (--network-id / --prefix) -----------
    // Port of btc::PoolConfig::set_network_id (btc/config_pool.hpp). Set ONCE in
    // main_dash.cpp main(), after argv + settings-file resolution and BEFORE any
    // run/mine/selftest dispatch, so every consumer sees one identity:
    //   * p2p framing  : main_dash.cpp run_node -> config.pool()->m_prefix = prefix_hex()
    //   * ref_hash     : make_coin_params() copies the override into BOTH the
    //                    mainnet and testnet CoinParams slots, so
    //                    CoinParams::active_identifier_hex() (share_check.hpp
    //                    share_init_verify + gentx ref recompute,
    //                    share_producer.hpp compute_ref_hash) returns it on
    //                    either network.
    // Empty (the default) = the public live identity above, byte-identical to a
    // build without this seam. constant-initialized (no dynamic init), like BTC.
    static inline std::string override_identifier_hex;   // empty = public network
    static inline std::string override_prefix_hex;       // empty = compiled network default

    // Named network selection (--net). None = no named network: the identity is
    // the public default or a custom --network-id. V36 = the DASH v36 network: the
    // identity above is set through the same override slots, so every consumer of
    // identifier_hex()/prefix_hex()/data_subdir() needs no change.
    enum class NamedNetwork { None, V36 };
    static inline NamedNetwork named_network = NamedNetwork::None;

    /// True for every spelling of "the public network": the empty string or
    /// any run of '0' characters of any length ("0", "00", "00000000",
    /// "0000000000000000", ...). An all-zero identifier left-pads to the same
    /// 16 zeros whatever its length, so all of these must mean one thing; BTC
    /// only special-cases "0" and "00000000", which would let "0000000000000000"
    /// silently become a private id. Shared by set_network_id() and
    /// validate_network_id_args() so the two can never disagree.
    static bool is_public_network_id(const std::string& network_id_hex)
    {
        for (char c : network_id_hex)
            if (c != '0') return false;
        return true;  // empty, or all '0'
    }

    /// Set a private sharechain identity. IDENTIFIER and PREFIX are TWO
    /// INDEPENDENT per-network constants (p2pool model): PREFIX is NEVER derived
    /// from IDENTIFIER. A bare network id keeps the compiled prefix of the
    /// selected network (mainnet 3b3e1286f446b891 / testnet 198b644f6821e3b3).
    /// An empty or all-'0' id (is_public_network_id) selects the public network
    /// (no override). Inputs are normalized to exactly 16 hex chars (left-padded
    /// with '0').
    /// Callers MUST validate with validate_network_id_args() first: this
    /// function does not hex-check (BTC parity) and a non-hex identifier would
    /// reach the share ref stream.
    static void set_network_id(const std::string& network_id_hex,
                               const std::string& prefix_hex_override = "")
    {
        if (is_public_network_id(network_id_hex))
            return;  // public network, use defaults

        auto to8 = [](std::string h) {
            while (h.size() < 16) h = "0" + h;
            if (h.size() > 16) h = h.substr(0, 16);
            return h;
        };

        override_identifier_hex = to8(network_id_hex);
        if (!prefix_hex_override.empty())
            override_prefix_hex = to8(prefix_hex_override);
    }

    /// Select a named network. V36 sets exactly the DASH v36 network identity
    /// (V36_NETWORK_IDENTIFIER_HEX / V36_NETWORK_PREFIX_HEX). Callers MUST
    /// validate with validate_named_network_args() first (it rejects a named
    /// network combined with --network-id / --prefix), so this never mixes a
    /// named identity with a custom one. None is a no-op.
    static void select_named_network(NamedNetwork n)
    {
        if (n == NamedNetwork::None)
            return;
        named_network           = n;
        override_identifier_hex = V36_NETWORK_IDENTIFIER_HEX;
        override_prefix_hex     = V36_NETWORK_PREFIX_HEX;
    }

    /// Clear any override (tests only: production sets the identity once).
    static void reset_network_id()
    {
        override_identifier_hex.clear();
        override_prefix_hex.clear();
        named_network = NamedNetwork::None;
    }

    /// True for ANY non-default identity: a custom --network-id AND the named
    /// DASH v36 network (both fill the override slots).
    static bool has_custom_network_id() { return !override_identifier_hex.empty(); }

    /// True only for the named DASH v36 network (--net dash-v36).
    static bool is_named_v36_network() { return named_network == NamedNetwork::V36; }

    // ---- DASH v36 network profile -------------------------------------------
    // The DASH v36 network (--net dash-v36) and any custom --network-id (test
    // networks) run the v36 profile: a sharechain that no p2pool-dash node can
    // join (the identifier is committed in every ref_hash), so it starts at share
    // v36 from genesis. The public network (no flag, or any all-'0' spelling, see
    // is_public_network_id) is NEVER v36_network() and stays the v16, p2pool-dash
    // compatible chain.
    //
    // The profile is DERIVED from override_identifier_hex (no state of its own),
    // so select_named_network / set_network_id / reset_network_id drive it and it
    // can never disagree with has_custom_network_id().
    static bool v36_network() { return has_custom_network_id(); }

    /// Per-network share parameters, the single source of truth. Consumers:
    ///   target_share_version           -> params.hpp current_share_version (the
    ///                                     admitted AND minted share type), the
    ///                                     mint path desired_version
    ///                                     (mint_runloop.hpp build_producer_job
    ///                                     reads params.current_share_version) and
    ///                                     the data_subdir version key below.
    ///   ratchet_floor_protocol_version -> node.hpp runtime accept-floor seed
    ///                                     (m_runtime_min_protocol_version). NOT
    ///                                     CoinParams::minimum_protocol_version,
    ///                                     which stays the cold 1700 floor on
    ///                                     both profiles.
    ///   advertised_protocol_version    -> the version this node puts on the
    ///                                     wire: node.hpp send_version and
    ///                                     params.hpp make_coin_params
    ///                                     (CoinParams::advertised_protocol_version)
    ///                                     read it. 3600 on PUBLIC,
    ///                                     ISOLATED_V36_PROTOCOL_VERSION (3601,
    ///                                     == the isolated ratchet floor) on
    ///                                     isolated (pinned by KAT).
    ///   v36_donation_p2pkh             -> params.hpp donation_script_func: on the
    ///                                     isolated chain a v36 share pays the
    ///                                     P2PKH DONATION_SCRIPT, not the COMBINED
    ///                                     P2SH.
    ///   maintainer_only_authority      -> share_messages.hpp authority_pubkeys()
    ///                                     for decrypt/validate of message_data,
    ///                                     and the operator blob embed selection
    ///                                     (mint_runloop.hpp select_embed_blob).
    ///   future_timestamp_bound         -> share_check.hpp
    ///                                     future_timestamp_bound_active() /
    ///                                     check_share_timestamp_bound: now+600
    ///                                     bound, first statement of
    ///                                     share_init_verify (wired; the v36
    ///                                     share verifier reuses it).
    ///   emergency_decay                -> v36 time-decay retarget on the producer
    ///                                     side (share_producer.hpp
    ///                                     compute_share_target).
    ///   max_shares_per_shares_msg,
    ///   max_shares_per_sharereply,
    ///   max_share_wire_bytes           -> share_precheck.hpp precheck_raw_shares:
    ///                                     per-message caps on incoming
    ///                                     'shares' / 'sharereply', applied
    ///                                     before any share is parsed or
    ///                                     hashed (#1828). Public: the
    ///                                     oracle's 3145728-byte payload cap
    ///                                     re-expressed (nothing an honest
    ///                                     p2pool-dash peer sends is refused).
    ///                                     DASH v36 network: 64 / 1001 /
    ///                                     65536. Pinned against the
    ///                                     share_precheck.hpp constants by
    ///                                     static_assert there.
    ///   full_misbehaviour_grading      -> peer_misbehaviour.hpp applies() /
    ///                                     classify_verify_failure: which
    ///                                     receive-path offences are charged
    ///                                     to the sending peer (#1829).
    ///                                     Public: only the two the
    ///                                     p2pool-dash oracle itself answers
    ///                                     with a disconnect (invalid PoW /
    ///                                     target, structural field checks).
    ///                                     DASH v36 network: every offence.
    ///   naughty_seed                   -> naughty_seed.hpp naughty_seed_active():
    ///                                     share_tracker.hpp mark_naughty seeds
    ///                                     naughty = 1 on a share whose block
    ///                                     would pay more than the block reward
    ///                                     (the pre-v34 p2pool excessive-reward
    ///                                     rule). False on BOTH networks: the
    ///                                     v35+ p2pool lineage gates the rule
    ///                                     off (VERSION < 34) and the DASH v36
    ///                                     network follows it.
    ///   excessive_reward_warning       -> naughty_seed.hpp
    ///                                     excessive_reward_warning_active(): the
    ///                                     same test, reported only (a log line
    ///                                     and a counter); it never touches
    ///                                     naughty or head selection. On for the
    ///                                     DASH v36 network, off on public v16.
    ///   naughty_fee_allowance_x_reward -> naughty_seed.hpp fee_allowance(): the
    ///                                     fees (in block rewards) the test
    ///                                     accepts for a share whose coinbase
    ///                                     merkle_link commits transactions
    ///                                     (a peer cannot compute them). 0 for
    ///                                     a coinbase-only share. Unused where
    ///                                     both flags above are false.
    // The profiles below use designated initializers: C++20 requires them in
    // declaration order, so adding a field can never shift a value into the
    // neighbouring field of the same type without a compile error.
    struct ShareProfile
    {
        uint32_t target_share_version;
        uint32_t ratchet_floor_protocol_version;
        uint32_t advertised_protocol_version;
        bool     v36_donation_p2pkh;
        bool     maintainer_only_authority;
        bool     future_timestamp_bound;
        bool     emergency_decay;
        uint32_t max_shares_per_shares_msg;
        uint32_t max_shares_per_sharereply;
        uint32_t max_share_wire_bytes;
        bool     full_misbehaviour_grading;
        bool     naughty_seed;
        bool     excessive_reward_warning;
        uint32_t naughty_fee_allowance_x_reward;
    };

    static constexpr ShareProfile PUBLIC_PROFILE{
        .target_share_version = 16,
        .ratchet_floor_protocol_version = MINIMUM_PROTOCOL_VERSION,
        .advertised_protocol_version = ADVERTISED_PROTOCOL_VERSION,
        .v36_donation_p2pkh = false,
        .maintainer_only_authority = false,
        .future_timestamp_bound = false,
        .emergency_decay = false,
        .max_shares_per_shares_msg = 13162,   // (3145728 - 3) / 239
        .max_shares_per_sharereply = 13162,
        .max_share_wire_bytes = 3145728,
        .full_misbehaviour_grading = false,
        .naughty_seed = false,
        .excessive_reward_warning = false,
        .naughty_fee_allowance_x_reward = 0,
    };
    static constexpr ShareProfile ISOLATED_V36_PROFILE{
        .target_share_version = 36,
        .ratchet_floor_protocol_version = ISOLATED_V36_PROTOCOL_VERSION,
        .advertised_protocol_version = ISOLATED_V36_PROTOCOL_VERSION,
        .v36_donation_p2pkh = true,
        .maintainer_only_authority = true,
        .future_timestamp_bound = true,
        .emergency_decay = true,
        .max_shares_per_shares_msg = 64,
        .max_shares_per_sharereply = 1001,
        .max_share_wire_bytes = 65536,
        .full_misbehaviour_grading = true,
        .naughty_seed = false,   // p2pool v35+ parity: no excessive-reward seed
        .excessive_reward_warning = true,
        .naughty_fee_allowance_x_reward = 1,
    };
    // The public profile is master's protocol pair, byte for byte.
    static_assert(PUBLIC_PROFILE.advertised_protocol_version == ADVERTISED_PROTOCOL_VERSION &&
                  PUBLIC_PROFILE.ratchet_floor_protocol_version == MINIMUM_PROTOCOL_VERSION,
                  "public DASH protocol advert/floor must stay master's 3600/1700");
    // The isolated advert is its own floor (two nodes of this build admit each
    // other), strictly above a build without v36 isolated support, and at or
    // above the public ratchet target (the ratchet is latched there).
    static_assert(ISOLATED_V36_PROFILE.advertised_protocol_version ==
                      ISOLATED_V36_PROFILE.ratchet_floor_protocol_version &&
                  ISOLATED_V36_PROFILE.ratchet_floor_protocol_version > ADVERTISED_PROTOCOL_VERSION &&
                  ISOLATED_V36_PROFILE.ratchet_floor_protocol_version >= NEW_MINIMUM_PROTOCOL_VERSION,
                  "isolated DASH v36 protocol advert must equal its floor and exceed 3600");

    /// The active per-network share profile. Read LIVE from the process-global
    /// identity, so it is only coherent under the same ordering contract as the
    /// identifier: main() sets the identity ONCE before any dispatch. A consumer
    /// that snapshots it (make_coin_params) and one that reads it live agree
    /// only under that ordering.
    static const ShareProfile& share_profile()
    {
        return v36_network() ? ISOLATED_V36_PROFILE : PUBLIC_PROFILE;
    }

    static const std::string& identifier_hex()
    {
        if (!override_identifier_hex.empty())
            return override_identifier_hex;
        return is_testnet ? TESTNET_IDENTIFIER_HEX : IDENTIFIER_HEX;
    }
    static const std::string& prefix_hex()
    {
        if (!override_prefix_hex.empty())
            return override_prefix_hex;
        return is_testnet ? TESTNET_PREFIX_HEX : PREFIX_HEX;
    }

    /// Per-network data-dir subdirectory (under core::filesystem::config_path()).
    /// EVERY piece of per-network on-disk state is rooted here: the sharechain
    /// LevelDB (<subdir>/sharechain_leveldb, trusted on load including its
    /// is_verified flags), addrs.json, pool/coin config files, graph_db,
    /// found_blocks_db and the coin-side caches. A custom --network-id appends
    /// "_<identifier>" so a private identity can never load shares, verified
    /// flags or learned peers persisted under a different identity (and
    /// switching back finds its own state untouched). The public (no-flag) path
    /// returns the legacy "dash" / "dash_testnet", byte-identical to master.
    /// Keyed on the identifier, not the prefix: the ref_hash commits the
    /// identifier, not the prefix, so persisted shares are valid across a
    /// prefix change.
    ///
    /// The named DASH v36 network takes the same rule on its identifier:
    /// "dash_ac2785363c0180b8_v36".
    ///
    /// A custom identity is ALSO keyed on the share version the chain mints
    /// ("_v<target_share_version>", i.e. "dash_<id>_v36"): one store holds
    /// exactly one share type. Rows a pre-v36 build of the same identity
    /// persisted (v16, under "dash_<id>") are never opened by the v36 chain, so
    /// no LevelDB height index is shared between the two types (one hash per
    /// height: a v36 row at the same absheight would overwrite it) and the
    /// reload window counts only rows of the type the chain speaks.
    static std::string data_subdir(bool testnet)
    {
        std::string d = testnet ? "dash_testnet" : "dash";
        if (has_custom_network_id())
            d += "_" + override_identifier_hex + "_v"
               + std::to_string(share_profile().target_share_version);
        return d;
    }

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

// ---------------------------------------------------------------------------
// --network-id / --prefix argument validation (pure, testable seam)
//
// Runs in main() on the MERGED value (argv overlaid by the settings file: the
// file loader does not hex-validate). Stricter than BTC on purpose:
//   * each value must be 1..16 hex chars (<= 8 bytes), even length, [0-9a-fA-F];
//     BTC's to8 silently truncates a longer value, which on an identity that is
//     committed into every share's ref_hash would be a silent fork.
//   * --prefix without --network-id is an ERROR (BTC only warns): a prefix on
//     the public identity can only isolate the node from the live fleet.
// An empty or all-'0' id of any length ("0", "00", "00000000",
// "0000000000000000", ...) means "public network" and is accepted as a no-op
// (SharechainConfig::is_public_network_id). On success both values are
// lower-cased in place so logs and the identity-scoped data subdir are
// canonical.
// ---------------------------------------------------------------------------
inline bool validate_network_id_args(std::string& network_id_hex,
                                     std::string& prefix_hex,
                                     std::string& err)
{
    auto check_hex = [&err](std::string& v, const char* flag) -> bool {
        if (v.empty() || v.size() > 16 || (v.size() % 2) != 0) {
            err = std::string(flag) + " must be 2..16 hex characters (1..8 bytes, even length), got \""
                + v + "\"";
            return false;
        }
        for (char& c : v) {
            const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) {
                err = std::string(flag) + " is not hex: \"" + v + "\"";
                return false;
            }
            if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
        }
        return true;
    };

    if (SharechainConfig::is_public_network_id(network_id_hex)) {
        if (!prefix_hex.empty()) {
            err = "--prefix requires --network-id (a prefix on the public identity would only isolate this node from the live sharechain)";
            return false;
        }
        return true;  // public network, no override
    }
    if (!check_hex(network_id_hex, "--network-id")) return false;
    if (!prefix_hex.empty() && !check_hex(prefix_hex, "--prefix")) return false;
    return true;
}

// ---------------------------------------------------------------------------
// --net NAME / settings key sharechain.network argument validation (pure seam)
//
// Runs in main() on the MERGED values (argv overlaid by the settings file),
// BEFORE validate_network_id_args. Accepted names:
//   ""                      no named network: the identity comes from
//                           --network-id / --prefix, or is the public default
//   "dash-v36" or "v36"     the DASH v36 network (V36_NETWORK_IDENTIFIER_HEX /
//                           V36_NETWORK_PREFIX_HEX, the v36 profile)
// Case-insensitive; normalized in place to the canonical "dash-v36".
// Rejected:
//   * any other name (the error lists the valid ones);
//   * a named network together with --network-id or --prefix (ANY value, even
//     an all-'0' public spelling): the name already fixes both, so a second
//     identity source is an operator mistake, never silently resolved;
//   * a named network with --testnet / --regtest: the DASH v36 network is a
//     mainnet sharechain; a test network uses --testnet with its own
//     --network-id / --prefix.
// ---------------------------------------------------------------------------
inline bool parse_named_network(std::string& name,
                                SharechainConfig::NamedNetwork& out,
                                std::string& err)
{
    std::string lc = name;
    for (char& c : lc)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    if (lc.empty()) {
        out = SharechainConfig::NamedNetwork::None;
        return true;
    }
    if (lc == SharechainConfig::V36_NETWORK_NAME || lc == SharechainConfig::V36_NETWORK_SETTINGS_NAME) {
        out  = SharechainConfig::NamedNetwork::V36;
        name = SharechainConfig::V36_NETWORK_NAME;
        return true;
    }
    err = "unknown --net \"" + name + "\" (sharechain.network): valid names are \""
        + std::string(SharechainConfig::V36_NETWORK_NAME) + "\" (settings value \""
        + SharechainConfig::V36_NETWORK_SETTINGS_NAME
        + "\"), or leave it unset for the public DASH sharechain";
    return false;
}

inline bool validate_named_network_args(std::string& net_name,
                                        const std::string& network_id_hex,
                                        const std::string& prefix_hex,
                                        bool testnet,
                                        SharechainConfig::NamedNetwork& out,
                                        std::string& err)
{
    if (!parse_named_network(net_name, out, err))
        return false;
    if (out == SharechainConfig::NamedNetwork::None)
        return true;
    if (!network_id_hex.empty() || !prefix_hex.empty()) {
        err = "--net " + net_name + " cannot be combined with "
            + std::string(!network_id_hex.empty() ? "--network-id" : "--prefix")
            + " (sharechain.network_id / sharechain.prefix): the DASH v36 network"
              " already fixes its identifier " + SharechainConfig::V36_NETWORK_IDENTIFIER_HEX
            + " and prefix " + SharechainConfig::V36_NETWORK_PREFIX_HEX
            + ". Use --net " + net_name + " alone, or --network-id/--prefix alone"
              " for a different network";
        return false;
    }
    if (testnet) {
        err = "--net " + net_name + " is a mainnet sharechain and cannot be combined with"
              " --testnet / --regtest; for a test network use --testnet with its own"
              " --network-id / --prefix";
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// The whole identity resolution main() runs, as one pure seam (KAT-covered):
// validate the merged (settings file + CLI) --net / --network-id / --prefix
// values, then apply them ONCE. A named network and a custom id are mutually
// exclusive (validate_named_network_args), so apply sets exactly one of them.
// ---------------------------------------------------------------------------
inline bool validate_sharechain_identity_args(std::string& net_name,
                                              std::string& network_id_hex,
                                              std::string& prefix_hex,
                                              bool testnet,
                                              SharechainConfig::NamedNetwork& named,
                                              std::string& err)
{
    return validate_named_network_args(net_name, network_id_hex, prefix_hex, testnet, named, err)
        && validate_network_id_args(network_id_hex, prefix_hex, err);
}

inline void apply_sharechain_identity(SharechainConfig::NamedNetwork named,
                                      const std::string& network_id_hex,
                                      const std::string& prefix_hex)
{
    if (named != SharechainConfig::NamedNetwork::None)
        SharechainConfig::select_named_network(named);  // --net dash-v36
    else
        SharechainConfig::set_network_id(network_id_hex, prefix_hex);
}

// ---------------------------------------------------------------------------
// Built-in sharechain seeds of the DASH v36 network. Dialed ONLY when --net
// dash-v36 is set and no --addnode/--connect is given
// (SharechainBootstrapMode::V36NetworkSeeds). Operator-approved public nodes
// of the network, HOST:PORT on the v36 sharechain port
// (SharechainConfig::V36_P2P_PORT);
// IP literals, so dialing needs no DNS. An explicit --addnode/--connect
// replaces the whole list.
// ---------------------------------------------------------------------------
inline std::vector<std::string> v36_network_seed_hosts()
{
    return {
        "158.220.92.171:8998",   // dash.voidbind.com
        "109.123.238.32:8998",   // Singapore
    };
}

// ---------------------------------------------------------------------------
// Sharechain bootstrap-source selection (pure, testable seam)
//
// Mirror of btc::select_sharechain_bootstrap_mode (btc/config_pool.hpp). DASH
// ships NO compiled public sharechain seed list today (peers come only from
// --addnode/--connect), so PublicDefault dials nothing; the resolver exists so
// a custom --network-id can never start dialing public seeds if a default list
// is ever added. (A learned-peer book from another identity cannot leak in:
// addrs.json lives under SharechainConfig::data_subdir(), which is
// identity-scoped.)
// DASH has no separate regtest identity (--regtest maps onto testnet), so the
// regtest arm is kept for signature parity and passed false by main_dash.
// ---------------------------------------------------------------------------
enum class SharechainBootstrapMode {
    ExplicitPeers,        // --addnode/--connect given: dial ONLY those
    RegtestIsolated,      // (unused on DASH; BTC parity)
    CustomNetSuppressed,  // custom --network-id, no explicit peers: 0 public seeds
    PublicDefault,        // public net, no explicit peers: compiled defaults (none today)
    V36NetworkSeeds,      // --net dash-v36, no explicit peers: v36_network_seed_hosts() only
};

// Precedence: explicit peers > regtest > named DASH v36 network > custom
// network id > public default. The named network sets the override slots too
// (has_custom_network_id is true for it), so it is tested FIRST: it dials its
// own seed list, never the public one, and is never treated as an unnamed
// custom id. The 3-argument form (named_v36_network = false) is the BTC-parity
// signature, unchanged.
inline SharechainBootstrapMode select_sharechain_bootstrap_mode(
    bool has_explicit_peers, bool regtest, bool has_custom_network_id,
    bool named_v36_network = false)
{
    if (has_explicit_peers)    return SharechainBootstrapMode::ExplicitPeers;
    if (regtest)               return SharechainBootstrapMode::RegtestIsolated;
    if (named_v36_network)     return SharechainBootstrapMode::V36NetworkSeeds;
    if (has_custom_network_id) return SharechainBootstrapMode::CustomNetSuppressed;
    return SharechainBootstrapMode::PublicDefault;
}

} // namespace dash