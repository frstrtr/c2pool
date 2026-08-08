// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DASH spork listener — pure state + verification layer (KAT-able, no socket).
//
// ══ WHY THIS EXISTS ═════════════════════════════════════════════════════════
// dashd gates several subsystems (InstantSend, ChainLocks, DKG, superblocks,
// quorum PoSe) on SPORKS: operator-signed (id, value, timeSigned) messages
// relayed over P2P. A peer serves its full spork set in reply to "getsporks"
// and relays every new spork unsolicited. Until now the embedded coin-P2P
// client DROPPED every spork on the unhandled-command path — the same silent
// failure class as the qrinfo #1077 outage (handler written, type never
// REGISTERED in p2p::Handler, payload discarded at DEBUG before the handler
// could run). This header is the state the registered handler feeds.
//
// ══ ASSUME-ACTIVE DEFAULTS (a spork-blind node must be RIGHT) ═══════════════
// Current mainnet has all 7 defined sporks ACTIVE (dashd has retired live
// spork values on mainnet entirely: CSporkManager::GetSporkValue hardcodes the
// mainnet answer — 0 for every spork, 1 for SPORK_21_QUORUM_ALL_CONNECTED —
// and IsSporkActive is `value < now`, so all 7 are unconditionally active).
// SporkState therefore SEEDS those hardened values at construction: a node
// that never hears a single spork message holds the same 7/7-active answer
// dashd itself computes. The listener REFINES this seed with verified
// messages; it can never be required for correctness on mainnet today.
//
// ══ STATE + TELEMETRY ONLY ══════════════════════════════════════════════════
// Nothing gates on this state yet. No serve-gate, no template decision, no
// relay decision consults it. It exists so the node KNOWS and SAYS what the
// network's spork posture is ([SPORK] log lines + counters) before any later
// slice is allowed to depend on it.
//
// ══ SIGNATURE VERIFICATION ══════════════════════════════════════════════════
// A spork is only evidence if the signature verifies against the spork key in
// dashd's chainparams. Mainnet (dashd src/chainparams.cpp CMainParams):
//
//     vSporkAddresses = {"Xgtyuk76vhuFW2iT7UAiHgNdWXCf3J34wh"};
//     nMinSporkKeys   = 1;
//
// which base58check-decodes (version 0x4C) to the key ID hardcoded below.
// Verification mirrors dashd CSporkMessage::CheckSignature exactly: recover
// the pubkey from the 65-byte compact signature over the NEW sig hash
// (CHashWriter << nSporkID << nValue << nTimeSigned), fall back to the LEGACY
// signed-message digest ("DarkCoin Signed Message:\n" magic over
// ToString(id)+ToString(value)+ToString(timeSigned)), and compare the
// recovered key's HASH160 to the spork key ID. An unverifiable spork is
// counted + logged and NEVER touches the state — the assume-active seed stays
// authoritative.
//
// Header-only to match the sibling dash coin leaves.

#include <core/hash.hpp>      // CHash256 / CHash160
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace dash
{
namespace coin
{

// ── Spork IDs (dashd src/spork.h SporkId) ────────────────────────────────────
enum : int32_t
{
    SPORK_2_INSTANTSEND_ENABLED          = 10001,
    SPORK_3_INSTANTSEND_BLOCK_FILTERING  = 10002,
    SPORK_9_SUPERBLOCKS_ENABLED          = 10008,
    SPORK_17_QUORUM_DKG_ENABLED          = 10016,
    SPORK_19_CHAINLOCKS_ENABLED          = 10018,
    SPORK_21_QUORUM_ALL_CONNECTED        = 10020,
    SPORK_23_QUORUM_POSE                 = 10022,
};

inline const char* spork_name(int32_t id)
{
    switch (id)
    {
    case SPORK_2_INSTANTSEND_ENABLED:         return "SPORK_2_INSTANTSEND_ENABLED";
    case SPORK_3_INSTANTSEND_BLOCK_FILTERING: return "SPORK_3_INSTANTSEND_BLOCK_FILTERING";
    case SPORK_9_SUPERBLOCKS_ENABLED:         return "SPORK_9_SUPERBLOCKS_ENABLED";
    case SPORK_17_QUORUM_DKG_ENABLED:         return "SPORK_17_QUORUM_DKG_ENABLED";
    case SPORK_19_CHAINLOCKS_ENABLED:         return "SPORK_19_CHAINLOCKS_ENABLED";
    case SPORK_21_QUORUM_ALL_CONNECTED:       return "SPORK_21_QUORUM_ALL_CONNECTED";
    case SPORK_23_QUORUM_POSE:                return "SPORK_23_QUORUM_POSE";
    default:                                  return "SPORK_UNKNOWN";
    }
}

/// HASH160 key ID of the mainnet spork key — base58check decode of dashd
/// chainparams vSporkAddresses[0] = "Xgtyuk76vhuFW2iT7UAiHgNdWXCf3J34wh"
/// (Dash P2PKH version byte 0x4C stripped). nMinSporkKeys is 1 on mainnet, so
/// this single key ID is the whole trust set.
inline constexpr std::array<uint8_t, 20> MAINNET_SPORK_PUBKEY_ID = {
    0x44, 0x1c, 0x7d, 0x2b, 0x02, 0x3c, 0xcb, 0x80, 0x5c, 0x02,
    0xf6, 0x27, 0x93, 0x72, 0x06, 0xba, 0x9f, 0xe0, 0x36, 0x5a,
};

/// Hardened mainnet spork values (dashd CSporkManager::GetSporkValue mainnet
/// branch): 0 for every spork, 1 for SPORK_21_QUORUM_ALL_CONNECTED. With
/// IsSporkActive == (value < now), every one of the 7 is ACTIVE.
inline const std::map<int32_t, int64_t>& mainnet_spork_defaults()
{
    static const std::map<int32_t, int64_t> defaults = {
        {SPORK_2_INSTANTSEND_ENABLED,          0},
        {SPORK_3_INSTANTSEND_BLOCK_FILTERING,  0},
        {SPORK_9_SUPERBLOCKS_ENABLED,          0},
        {SPORK_17_QUORUM_DKG_ENABLED,          0},
        {SPORK_19_CHAINLOCKS_ENABLED,          0},
        {SPORK_21_QUORUM_ALL_CONNECTED,        1},
        {SPORK_23_QUORUM_POSE,                 0},
    };
    return defaults;
}

// ── Signature hashes (dashd CSporkMessage, byte-exact) ──────────────────────

/// NEW-sigs digest: double-SHA256 of the 20-byte LE serialization
/// nSporkID(i32) + nValue(i64) + nTimeSigned(i64) — dashd
/// CSporkMessage::GetSignatureHash (CHashWriter s(SER_GETHASH,0)).
inline uint256 spork_signature_hash(int32_t spork_id, int64_t value, int64_t time_signed)
{
    unsigned char buf[20];
    const uint32_t id_le = static_cast<uint32_t>(spork_id);
    const uint64_t v_le  = static_cast<uint64_t>(value);
    const uint64_t t_le  = static_cast<uint64_t>(time_signed);
    for (int i = 0; i < 4; ++i) buf[i]      = static_cast<unsigned char>((id_le >> (8 * i)) & 0xff);
    for (int i = 0; i < 8; ++i) buf[4 + i]  = static_cast<unsigned char>((v_le  >> (8 * i)) & 0xff);
    for (int i = 0; i < 8; ++i) buf[12 + i] = static_cast<unsigned char>((t_le  >> (8 * i)) & 0xff);
    uint256 out;
    CHash256().Write(std::span<const unsigned char>(buf, sizeof(buf)))
              .Finalize(std::span<unsigned char>(out.data(), 32));
    return out;
}

/// LEGACY signed-message digest fallback (dashd CMessageSigner path):
/// double-SHA256 of varstr(MESSAGE_MAGIC) + varstr(strMessage), where
/// MESSAGE_MAGIC = "DarkCoin Signed Message:\n" and strMessage is the ASCII
/// concatenation ToString(nSporkID)+ToString(nValue)+ToString(nTimeSigned).
inline uint256 spork_legacy_message_hash(int32_t spork_id, int64_t value, int64_t time_signed)
{
    static const std::string magic = "DarkCoin Signed Message:\n";
    const std::string message = std::to_string(spork_id) + std::to_string(value)
                              + std::to_string(time_signed);

    auto write_varstr = [](CHash256& h, const std::string& s) {
        // CompactSize length prefix. Both strings here are far below 253 bytes,
        // but encode the full rule anyway so the helper cannot silently rot.
        unsigned char len[9];
        size_t len_n = 0;
        const uint64_t n = s.size();
        if (n < 253) { len[0] = static_cast<unsigned char>(n); len_n = 1; }
        else if (n <= 0xffff) {
            len[0] = 253;
            len[1] = static_cast<unsigned char>(n & 0xff);
            len[2] = static_cast<unsigned char>((n >> 8) & 0xff);
            len_n = 3;
        } else {
            len[0] = 254;
            for (int i = 0; i < 4; ++i)
                len[1 + i] = static_cast<unsigned char>((n >> (8 * i)) & 0xff);
            len_n = 5;
        }
        h.Write(std::span<const unsigned char>(len, len_n));
        h.Write(std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(s.data()), s.size()));
    };

    CHash256 hasher;
    write_varstr(hasher, magic);
    write_varstr(hasher, message);
    uint256 out;
    hasher.Finalize(std::span<unsigned char>(out.data(), 32));
    return out;
}

/// Process-lifetime verify context (verify-only; tests that need to SIGN make
/// their own signing context).
inline const secp256k1_context* spork_secp256k1_context()
{
    static const secp256k1_context* ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    return ctx;
}

/// Recover the signer from a 65-byte compact signature over `hash` and check
/// its HASH160 against `key_id` — dashd CPubKey::RecoverCompact + GetID
/// semantics (header byte 27..34 carries recid + compressed flag; the
/// compressed flag selects which serialization the key ID is the hash of).
inline bool spork_compact_sig_matches(const uint256& hash,
                                      const std::vector<uint8_t>& vch_sig,
                                      const std::array<uint8_t, 20>& key_id)
{
    if (vch_sig.size() != 65)
        return false;
    const int header = vch_sig[0];
    if (header < 27 || header >= 35)
        return false;
    const int  recid      = (header - 27) & 3;
    const bool compressed = ((header - 27) & 4) != 0;

    const secp256k1_context* ctx = spork_secp256k1_context();

    secp256k1_ecdsa_recoverable_signature rsig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
            ctx, &rsig, vch_sig.data() + 1, recid))
        return false;

    secp256k1_pubkey pubkey;
    if (!secp256k1_ecdsa_recover(ctx, &pubkey, &rsig, hash.data()))
        return false;

    unsigned char pub[65];
    size_t publen = sizeof(pub);
    secp256k1_ec_pubkey_serialize(ctx, pub, &publen, &pubkey,
        compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

    uint160 got;
    CHash160().Write(std::span<const unsigned char>(pub, publen))
              .Finalize(std::span<unsigned char>(got.data(), 20));
    return std::memcmp(got.data(), key_id.data(), key_id.size()) == 0;
}

/// Full dashd CSporkMessage::CheckSignature: NEW sig hash first, LEGACY
/// signed-message digest as the fallback (dashd tries both, in this order).
inline bool verify_spork_signature(int32_t spork_id, int64_t value, int64_t time_signed,
                                   const std::vector<uint8_t>& vch_sig,
                                   const std::array<uint8_t, 20>& key_id)
{
    if (spork_compact_sig_matches(
            spork_signature_hash(spork_id, value, time_signed), vch_sig, key_id))
        return true;
    return spork_compact_sig_matches(
        spork_legacy_message_hash(spork_id, value, time_signed), vch_sig, key_id);
}

// ── Spork state (assume-active seed + listener refinement) ──────────────────

enum class SporkIngest
{
    Applied,        // verified + newer than what we hold — state updated
    Stale,          // verified but not newer than a listener-held entry — kept
    BadSignature,   // did not verify against the spork key — state untouched
};

inline const char* spork_ingest_name(SporkIngest o)
{
    switch (o)
    {
    case SporkIngest::Applied:      return "applied";
    case SporkIngest::Stale:        return "stale";
    case SporkIngest::BadSignature: return "bad-signature";
    }
    return "?";
}

class SporkState
{
public:
    struct Entry
    {
        int64_t value{0};
        int64_t time_signed{0};
        // false => assume-active seed; true => refined by a VERIFIED message.
        bool    from_listener{false};
    };

    struct Counters
    {
        uint64_t received{0};       // every spork message offered
        uint64_t verified{0};       // signature checked out
        uint64_t applied{0};        // state actually updated
        uint64_t stale{0};          // verified but older than what we hold
        uint64_t rejected_sig{0};   // signature failed — dropped by name
    };

private:
    std::map<int32_t, Entry> m_sporks;
    Counters m_counters;

public:
    /// Seeded so a spork-blind node holds today's mainnet answer (7/7 active).
    SporkState()
    {
        for (const auto& [id, value] : mainnet_spork_defaults())
            m_sporks[id] = Entry{value, /*time_signed=*/0, /*from_listener=*/false};
    }

    /// Ingest one spork message. `sig_ok` is the caller's verification verdict
    /// (kept out of here so the state machine is KAT-able without crypto).
    /// dashd staleness rule: an entry we already hold from the wire wins over
    /// anything not strictly newer (nTimeSigned). The assume-active seed never
    /// wins over a verified message — it is a stand-in, not evidence.
    SporkIngest on_spork(int32_t spork_id, int64_t value, int64_t time_signed, bool sig_ok)
    {
        ++m_counters.received;
        if (!sig_ok)
        {
            ++m_counters.rejected_sig;
            return SporkIngest::BadSignature;
        }
        ++m_counters.verified;
        auto it = m_sporks.find(spork_id);
        if (it != m_sporks.end() && it->second.from_listener
            && it->second.time_signed >= time_signed)
        {
            ++m_counters.stale;
            return SporkIngest::Stale;
        }
        m_sporks[spork_id] = Entry{value, time_signed, /*from_listener=*/true};
        ++m_counters.applied;
        return SporkIngest::Applied;
    }

    /// dashd SporkManager::IsSporkActive: value < now. Unknown spork => inactive.
    bool is_active(int32_t spork_id, int64_t now) const
    {
        auto it = m_sporks.find(spork_id);
        return it != m_sporks.end() && it->second.value < now;
    }

    std::optional<int64_t> value(int32_t spork_id) const
    {
        auto it = m_sporks.find(spork_id);
        if (it == m_sporks.end()) return std::nullopt;
        return it->second.value;
    }

    const std::map<int32_t, Entry>& sporks() const { return m_sporks; }
    const Counters& counters() const { return m_counters; }

    std::size_t known_count() const { return m_sporks.size(); }

    std::size_t active_count(int64_t now) const
    {
        std::size_t n = 0;
        for (const auto& [id, e] : m_sporks)
            if (e.value < now) ++n;
        return n;
    }

    std::size_t listener_refined_count() const
    {
        std::size_t n = 0;
        for (const auto& [id, e] : m_sporks)
            if (e.from_listener) ++n;
        return n;
    }

    nlohmann::json to_json(int64_t now) const
    {
        nlohmann::json j;
        j["spork-known"]            = known_count();
        j["spork-active"]           = active_count(now);
        j["spork-listener-refined"] = listener_refined_count();
        j["spork-received"]         = m_counters.received;
        j["spork-verified"]         = m_counters.verified;
        j["spork-applied"]          = m_counters.applied;
        j["spork-stale"]            = m_counters.stale;
        j["spork-rejected-sig"]     = m_counters.rejected_sig;
        nlohmann::json by = nlohmann::json::object();
        for (const auto& [id, e] : m_sporks)
        {
            nlohmann::json s;
            s["id"]          = id;
            s["value"]       = e.value;
            s["time-signed"] = e.time_signed;
            s["active"]      = (e.value < now);
            s["source"]      = e.from_listener ? "listener" : "assume-active-default";
            by[spork_name(id)] = s;
        }
        j["sporks"] = by;
        return j;
    }
};

} // namespace coin
} // namespace dash
