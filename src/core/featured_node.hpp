// SPDX-License-Identifier: AGPL-3.0-or-later
// featured_node.hpp — Featured developer-node dashboard banner store.
//
// A signed AUTHORITY-MESSAGE subtype (MSG_FEATURED_NODE = 0x06) carries a
// service/presentation banner for a "featured developer node" (URL, label,
// commission, location) into the dashboard HEADER. This store holds the
// verified banner state and enforces FRESHEST-WINS supersession.
//
// CONSENSUS-NEUTRAL: this class touches NO share validity, PPLNS, target,
// block validity, or payout state. It is pure downstream-of-verification
// presentation state and can be deleted wholesale without affecting a single
// share, target, or payout. It is fed ONLY by blobs that have already passed
// full authority verification (MAC decrypt + ECDSA + pinned-pubkey) upstream.
//
// FRESHEST-WINS + REPLAY PROTECTION: the store keeps exactly ONE record — the
// verified message with the strictly-highest monotonic `seq`. A newer seq
// supersedes; an older-or-equal seq is dropped (an old signed blob can never
// override or re-apply after a newer one is seen). The highest seq is persisted
// through to disk (atomic rename) and restored at startup BEFORE any blob/share
// processing, so a restart can never resurrect an older message.

#pragma once

#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <system_error>

#include <nlohmann/json.hpp>

namespace core {

class FeaturedNodeStore
{
public:
    struct Record
    {
        uint64_t    seq{0};
        uint32_t    timestamp{0};
        std::string payload_json;        // the raw signed JSON payload
        std::string signer_pubkey_hex;   // authority key that ECDSA-signed it
        bool        present{false};
    };

    // Path to the persistence file. Setting it does NOT load; call load().
    void set_path(const std::string& path)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_path = path;
    }

    // Restore the highest-seq record from disk. Call at startup BEFORE any
    // blob/share processing so an older startup message cannot resurrect.
    // The persisted state was written only after full authority verification,
    // so it is trusted local node state (same trust class as the share store).
    void load()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_path.empty()) return;
        std::ifstream f(m_path);
        if (!f) return;
        try {
            nlohmann::json j;
            f >> j;
            Record rec;
            rec.seq               = j.value("seq", uint64_t(0));
            rec.timestamp         = j.value("timestamp", uint32_t(0));
            rec.payload_json      = j.value("payload_json", std::string());
            rec.signer_pubkey_hex = j.value("signer_pubkey_hex", std::string());
            rec.present           = rec.seq > 0 && !rec.payload_json.empty();
            if (rec.present) m_rec = rec;
        } catch (...) {
            // Corrupt state file → start empty (banner simply hidden).
        }
    }

    // Freshest-wins comparator with strict-greater replay protection.
    // Returns true iff the message was accepted (strictly newer). Callers MUST
    // only pass messages that have already passed authority verification.
    bool apply(uint64_t seq, uint32_t timestamp,
               const std::string& payload_json,
               const std::string& signer_pubkey_hex)
    {
        if (seq == 0) return false;                 // seq is REQUIRED, non-zero
        std::lock_guard<std::mutex> lock(m_mutex);
        // REPLAY REJECT: older-or-equal seq never overrides or re-applies.
        if (m_rec.present && seq <= m_rec.seq) return false;
        m_rec.seq               = seq;
        m_rec.timestamp         = timestamp;
        m_rec.payload_json      = payload_json;
        m_rec.signer_pubkey_hex = signer_pubkey_hex;
        m_rec.present           = true;
        persist_locked();
        return true;
    }

    // Emit the banner JSON for /version_signaling, or null when there is no
    // banner to show (none seen, expired, or explicitly retracted via hl bit).
    // Expiry/retraction only HIDE rendering; the persisted seq is never lowered.
    nlohmann::json emit() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_rec.present) return nullptr;
        nlohmann::json pj;
        try { pj = nlohmann::json::parse(m_rec.payload_json); }
        catch (...) { return nullptr; }
        if (!pj.is_object()) return nullptr;

        auto now = static_cast<uint32_t>(std::time(nullptr));
        uint32_t exp = pj.value("exp", uint32_t(0));
        if (exp > 0 && now > exp) return nullptr;   // self-clear; seq kept

        unsigned hl = pj.value("hl", 1u);
        if ((hl & 0x01u) == 0) return nullptr;      // hl bit0 clear = retract banner

        return nlohmann::json{
            {"url",           pj.value("url", "")},
            {"label",         pj.value("label", "Featured node")},
            {"commission",    pj.value("com", "")},
            {"location",      pj.value("loc", "")},
            {"highlight",     (hl & 0x01u) != 0},
            {"announce",      (hl & 0x02u) != 0},
            {"seq",           m_rec.seq},
            {"timestamp",     m_rec.timestamp},
            {"expiry",        exp},
            {"signer_pubkey", m_rec.signer_pubkey_hex},
            {"verified",      true}
        };
    }

    uint64_t current_seq() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_rec.present ? m_rec.seq : 0;
    }

    bool present() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_rec.present;
    }

private:
    void persist_locked() const  // caller holds m_mutex
    {
        if (m_path.empty() || !m_rec.present) return;
        try {
            nlohmann::json j = {
                {"seq",               m_rec.seq},
                {"timestamp",         m_rec.timestamp},
                {"payload_json",      m_rec.payload_json},
                {"signer_pubkey_hex", m_rec.signer_pubkey_hex}
            };
            const std::string tmp = m_path + ".tmp";
            {
                std::ofstream out(tmp, std::ios::trunc | std::ios::binary);
                out << j.dump();
                out.flush();
            }
            std::error_code ec;
            std::filesystem::rename(tmp, m_path, ec);   // atomic replace
            if (ec) std::filesystem::remove(tmp, ec);
        } catch (...) {
            // Best-effort persistence; a write failure only means the banner is
            // re-fetched from the next signed message after a restart.
        }
    }

    mutable std::mutex m_mutex;
    Record             m_rec;
    std::string        m_path;
};

} // namespace core
