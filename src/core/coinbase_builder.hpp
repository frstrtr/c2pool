#pragma once
// coinbase_builder.hpp — Coinbase scriptSig layout, THE metadata, space budget
//
// ScriptSig space budget (100 bytes max, Bitcoin consensus):
//
//   With merged mining (AuxPoW active):
//     [4]   BIP34 height
//     [44]  AuxPoW commitment (fabe6d6d + merkle_root(32) + size(4) + nonce(4))
//     [N]   tag_or_text: "/c2pool/" (default) OR --coinbase-text (max 20 bytes)
//     [32]  THE state_root
//     [M]   THE metadata (fills remaining: 20 - N bytes)
//     Total: 80 + N + M = 100
//
//   Without merged mining:
//     [4]   BIP34 height
//     [N]   tag_or_text: "/c2pool/" (default) OR --coinbase-text (max 64 bytes)
//     [32]  THE state_root
//     [M]   THE metadata (fills remaining: 64 - N bytes)
//     Total: 36 + N + M = 100
//
//   c2pool is always identified by the combined donation address in
//   coinbase outputs — visible in block explorers without parsing scriptSig.
//
// THE metadata layout (variable size, fills remaining space):
//   [0]     c2pool protocol version (0x01 = V36)
//   [1-4]   sharechain height at block-find (4 bytes LE)
//   [5-6]   miner count in PPLNS window (2 bytes LE)
//   [7]     pool hashrate class (log2 of H/s)
//   [8-9]   share_period (current value, 2 bytes LE)
//   [10-11] verified chain length (2 bytes LE)
//   [12-15] pool_aps compressed (4 bytes)
//   [16-19] reserved (future THE temporal layer flags)
//   If fewer than 20 bytes available, metadata is truncated from the end.

#include <cstdint>
#include <string>
#include <vector>
#include <cmath>
#include <algorithm>
#include "uint256.hpp"

namespace c2pool {

// Maximum coinbase scriptSig size (Bitcoin consensus)
static constexpr size_t SCRIPTSIG_MAX = 100;

// AuxPoW merged mining commitment size: fabe6d6d(4) + merkle_root(32) + size(4) + nonce(4)
static constexpr size_t AUXPOW_COMMITMENT_SIZE = 44;

// THE state root size
static constexpr size_t THE_STATE_ROOT_SIZE = 32;

// Default pool tag (used when no --coinbase-text provided)
static constexpr const char* DEFAULT_POOL_TAG = "/c2pool/";
static constexpr size_t DEFAULT_POOL_TAG_SIZE = 8;

// Protocol version byte
static constexpr uint8_t C2POOL_PROTOCOL_VERSION = 0x01; // V36

// Maximum operator text with merged mining active
static constexpr size_t MAX_OPERATOR_TEXT_MM = 20;
// Maximum operator text without merged mining
static constexpr size_t MAX_OPERATOR_TEXT_SOLO = 64;

// Public p2pool network chain_id (default — no private chain)
static constexpr uint32_t PUBLIC_CHAIN_ID = 0;
static constexpr uint32_t PUBLIC_CHAIN_PREFIX = 0;

/// THE metadata — compact pool state for on-chain commitment
struct TheMetadata {
    uint8_t  version = C2POOL_PROTOCOL_VERSION;
    uint32_t sharechain_height = 0;    // share chain height at block-find
    uint16_t miner_count = 0;          // unique miners in PPLNS window
    uint8_t  hashrate_class = 0;       // log2(pool_hashrate_in_h_per_s)
    uint32_t chain_id = PUBLIC_CHAIN_ID;       // 0 = public network, nonzero = private chain
    uint32_t chain_prefix = PUBLIC_CHAIN_PREFIX; // P2P magic prefix (0 = default)
    uint16_t share_period = 0;         // current share period (seconds)
    uint16_t verified_length = 0;      // verified chain length
    uint32_t reserved = 0;            // future: THE temporal layer flags

    /// Pack into bytes (up to max_bytes, truncated from end)
    std::vector<uint8_t> pack(size_t max_bytes = 20) const {
        std::vector<uint8_t> out;
        out.reserve(max_bytes);
        auto push8 = [&](uint8_t v) { if (out.size() < max_bytes) out.push_back(v); };
        auto push16 = [&](uint16_t v) {
            if (out.size() < max_bytes) out.push_back(v & 0xff);
            if (out.size() < max_bytes) out.push_back((v >> 8) & 0xff);
        };
        auto push32 = [&](uint32_t v) {
            if (out.size() < max_bytes) out.push_back(v & 0xff);
            if (out.size() < max_bytes) out.push_back((v >> 8) & 0xff);
            if (out.size() < max_bytes) out.push_back((v >> 16) & 0xff);
            if (out.size() < max_bytes) out.push_back((v >> 24) & 0xff);
        };

        push8(version);              // [0]
        push32(sharechain_height);   // [1-4]
        push16(miner_count);         // [5-6]
        push8(hashrate_class);       // [7]
        push32(chain_id);            // [8-11]  0 = public network
        push32(chain_prefix);        // [12-15] P2P magic prefix
        push16(share_period);        // [16-17]
        push16(verified_length);     // [18-19]
        return out;
    }

    /// Unpack from bytes
    static TheMetadata unpack(const uint8_t* data, size_t len) {
        TheMetadata m;
        if (len >= 1) m.version = data[0];
        if (len >= 5) m.sharechain_height = data[1] | (data[2]<<8) | (data[3]<<16) | (data[4]<<24);
        if (len >= 7) m.miner_count = data[5] | (data[6]<<8);
        if (len >= 8) m.hashrate_class = data[7];
        if (len >= 12) m.chain_id = data[8] | (data[9]<<8) | (data[10]<<16) | (data[11]<<24);
        if (len >= 16) m.chain_prefix = data[12] | (data[13]<<8) | (data[14]<<16) | (data[15]<<24);
        if (len >= 18) m.share_period = data[16] | (data[17]<<8);
        if (len >= 20) m.verified_length = data[18] | (data[19]<<8);
        return m;
    }

    /// Compute hashrate class from actual hashrate (log2)
    static uint8_t encode_hashrate(double hashrate_hps) {
        if (hashrate_hps <= 0) return 0;
        return static_cast<uint8_t>(std::min(255.0, std::log2(hashrate_hps)));
    }

    /// Decode hashrate class back to approximate hashrate
    static double decode_hashrate(uint8_t cls) {
        if (cls == 0) return 0;
        return std::pow(2.0, static_cast<double>(cls));
    }
};

/// ScriptSig layout configuration
struct ScriptSigLayout {
    std::string operator_text;           // --coinbase-text (empty = use default tag)
    bool has_merged_mining = false;      // AuxPoW commitment present
    uint256 the_state_root;              // THE state root (zero if not computed)
    TheMetadata metadata;                // THE metadata

    /// Compute the tag/text bytes
    std::vector<uint8_t> get_tag_bytes() const {
        if (operator_text.empty()) {
            // Default: "/c2pool/"
            return std::vector<uint8_t>(DEFAULT_POOL_TAG, DEFAULT_POOL_TAG + DEFAULT_POOL_TAG_SIZE);
        }
        // Operator text — enforce size limit
        size_t max = has_merged_mining ? MAX_OPERATOR_TEXT_MM : MAX_OPERATOR_TEXT_SOLO;
        size_t len = std::min(operator_text.size(), max);
        return std::vector<uint8_t>(operator_text.begin(), operator_text.begin() + len);
    }

    /// Maximum operator text size for current config
    size_t max_text_size() const {
        return has_merged_mining ? MAX_OPERATOR_TEXT_MM : MAX_OPERATOR_TEXT_SOLO;
    }

    /// How many bytes available for THE metadata after tag
    size_t metadata_space() const {
        size_t fixed = 4 + THE_STATE_ROOT_SIZE; // height + state_root
        if (has_merged_mining) fixed += AUXPOW_COMMITMENT_SIZE;
        size_t tag_size = get_tag_bytes().size();
        size_t used = fixed + tag_size;
        return (SCRIPTSIG_MAX > used) ? (SCRIPTSIG_MAX - used) : 0;
    }

    /// Build the complete scriptSig data portion (after BIP34 height)
    /// Caller adds BIP34 height prefix and mm_commitment separately.
    /// Returns: [tag_bytes][state_root(32)][metadata(variable)]
    std::vector<uint8_t> build_extra_data() const {
        std::vector<uint8_t> out;
        size_t meta_space = metadata_space();

        // Tag or operator text
        auto tag = get_tag_bytes();
        out.insert(out.end(), tag.begin(), tag.end());

        // THE state root (32 bytes)
        if (!the_state_root.IsNull()) {
            out.insert(out.end(), the_state_root.data(), the_state_root.data() + 32);
        } else {
            out.insert(out.end(), 32, 0x00);
        }

        // THE metadata (fills remaining space)
        if (meta_space > 0) {
            auto meta = metadata.pack(meta_space);
            out.insert(out.end(), meta.begin(), meta.end());
        }

        return out;
    }

    /// Validate operator text fits within budget
    bool validate_text(std::string& error_msg) const {
        size_t max = max_text_size();
        if (operator_text.size() > max) {
            error_msg = "Coinbase text too long: " + std::to_string(operator_text.size())
                      + " bytes (max " + std::to_string(max) + " with"
                      + (has_merged_mining ? "" : "out") + " merged mining)";
            return false;
        }
        return true;
    }
};

/// Parse a coinbase scriptSig to extract THE data
struct ParsedScriptSig {
    int block_height = 0;
    bool has_auxpow = false;
    std::string tag_or_text;       // "/c2pool/" or operator text
    uint256 the_state_root;
    TheMetadata metadata;
    bool is_c2pool = false;        // detected as c2pool block

    /// Parse from raw scriptSig bytes. Returns true if c2pool block detected.
    static bool parse(const uint8_t* data, size_t len, ParsedScriptSig& out) {
        if (len < 4) return false;

        size_t pos = 0;

        // BIP34 height
        uint8_t height_len = data[pos++];
        if (height_len <= 16) {
            // OP_1..OP_16
            out.block_height = height_len - 0x50;
            pos--; pos++; // height was the opcode itself
        } else if (height_len > 0 && height_len <= 8 && pos + height_len <= len) {
            out.block_height = 0;
            for (size_t i = 0; i < height_len; ++i)
                out.block_height |= static_cast<int>(data[pos + i]) << (8 * i);
            pos += height_len;
        }

        // Check for AuxPoW marker: fabe6d6d
        if (pos + 4 <= len &&
            data[pos] == 0xfa && data[pos+1] == 0xbe &&
            data[pos+2] == 0x6d && data[pos+3] == 0x6d) {
            out.has_auxpow = true;
            pos += AUXPOW_COMMITMENT_SIZE; // skip entire commitment
        }

        // Check for c2pool tag or operator text
        // Look for "/c2pool/" (8 bytes) or "/P2Pool/" (8 bytes)
        if (pos + 8 <= len) {
            std::string candidate(reinterpret_cast<const char*>(data + pos), 8);
            if (candidate == "/c2pool/" || candidate == "/P2Pool/") {
                out.tag_or_text = candidate;
                out.is_c2pool = (candidate == "/c2pool/");
                pos += 8;
            } else {
                // Try to read as operator text (until we hit THE state root pattern)
                // Heuristic: text is printable ASCII, state_root starts with non-ASCII
                size_t text_end = pos;
                while (text_end < len && text_end - pos < 64 &&
                       data[text_end] >= 0x20 && data[text_end] < 0x7f)
                    text_end++;
                if (text_end > pos) {
                    out.tag_or_text = std::string(reinterpret_cast<const char*>(data + pos), text_end - pos);
                    out.is_c2pool = true; // has structured data after text
                    pos = text_end;
                }
            }
        }

        // THE state root (32 bytes)
        if (pos + 32 <= len) {
            std::memcpy(out.the_state_root.data(), data + pos, 32);
            pos += 32;
        }

        // THE metadata (remaining bytes)
        if (pos < len) {
            out.metadata = TheMetadata::unpack(data + pos, len - pos);
        }

        return out.is_c2pool;
    }
};

} // namespace c2pool
