#pragma once

/// MWEB (MimbleWimble Extension Block) builder for embedded LTC mode.
///
/// Implements the carry-forward approach: extract MWEB state from the
/// previous block (via P2P full block), then construct an empty MWEB
/// block + HogEx transaction for the next block.
///
/// Key structures:
///   MWEBState       — carries forward roots/sizes/HogEx outpoint
///   MWEBBuilder     — constructs empty mw::Block bytes + HogEx tx
///
/// The MWEB block hash uses blake3 (matching Litecoin Core's libmw).

#include "transaction.hpp"
#include "block.hpp"

#include <core/pack.hpp>
#include <core/log.hpp>
#include <btclibs/uint256.h>
#include <btclibs/serialize.h>
#include <btclibs/util/strencodings.h>
#include <crypto/blake3/blake3.h>

#include <array>
#include <cstring>
#include <mutex>
#include <optional>
#include <vector>

namespace ltc {
namespace coin {

// ─── MWEB Header (matches libmw mw::Header serialization) ──────────────────

/// Serializable MWEB header — exact wire format matching Litecoin Core.
/// Fields are serialized as:
///   VARINT_MODE(height, NONNEGATIVE_SIGNED), output_root[32], kernel_root[32],
///   leafset_root[32], kernel_offset[32], stealth_offset[32],
///   VARINT(output_mmr_size), VARINT(kernel_mmr_size)
struct MWEBHeader {
    int64_t  height{0};
    uint256  output_root;
    uint256  kernel_root;
    uint256  leafset_root;
    std::array<uint8_t, 32> kernel_offset{};
    std::array<uint8_t, 32> stealth_offset{};
    uint64_t output_mmr_size{0};
    uint64_t kernel_mmr_size{0};

    template <typename Stream>
    void Serialize(Stream& s) const {
        // Height uses NONNEGATIVE_SIGNED varint — write manually matching libmw format
        // libmw uses same varint encoding as Bitcoin's WriteVarInt with NONNEGATIVE_SIGNED
        legacy::WriteVarInt<Stream, legacy::VarIntMode::NONNEGATIVE_SIGNED, int64_t>(s, height);
        ::Serialize(s, output_root);
        ::Serialize(s, kernel_root);
        ::Serialize(s, leafset_root);
        // Blinding factors are raw 32-byte arrays
        auto ko_span = std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(kernel_offset.data()), 32);
        s.write(ko_span);
        auto so_span = std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(stealth_offset.data()), 32);
        s.write(so_span);
        // MMR sizes use default unsigned varint
        legacy::WriteVarInt<Stream, legacy::VarIntMode::DEFAULT, uint64_t>(s, output_mmr_size);
        legacy::WriteVarInt<Stream, legacy::VarIntMode::DEFAULT, uint64_t>(s, kernel_mmr_size);
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        height = legacy::ReadVarInt<Stream, legacy::VarIntMode::NONNEGATIVE_SIGNED, int64_t>(s);
        ::Unserialize(s, output_root);
        ::Unserialize(s, kernel_root);
        ::Unserialize(s, leafset_root);
        auto ko_span = std::span<std::byte>(
            reinterpret_cast<std::byte*>(kernel_offset.data()), 32);
        s.read(ko_span);
        auto so_span = std::span<std::byte>(
            reinterpret_cast<std::byte*>(stealth_offset.data()), 32);
        s.read(so_span);
        output_mmr_size = legacy::ReadVarInt<Stream, legacy::VarIntMode::DEFAULT, uint64_t>(s);
        kernel_mmr_size = legacy::ReadVarInt<Stream, legacy::VarIntMode::DEFAULT, uint64_t>(s);
    }
};

// ─── MWEB TxBody (empty) ───────────────────────────────────────────────────

/// Empty MWEB transaction body — 3 zero-varint vectors.
struct MWEBTxBody {
    // For carry-forward with no MWEB activity, all vectors are empty.
    template <typename Stream>
    void Serialize(Stream& s) const {
        // inputs: varint(0), outputs: varint(0), kernels: varint(0)
        uint8_t zero = 0;
        ::Serialize(s, zero);
        ::Serialize(s, zero);
        ::Serialize(s, zero);
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        // Skip varint-encoded vector lengths
        uint64_t n_inputs, n_outputs, n_kernels;
        ::Unserialize(s, VARINT(n_inputs));
        ::Unserialize(s, VARINT(n_outputs));
        ::Unserialize(s, VARINT(n_kernels));
        // We don't parse individual items — embedded mode only produces empty bodies
    }
};

// ─── MWEB Block (Header + TxBody) ──────────────────────────────────────────

/// Full MWEB block = Header + TxBody.
/// Serialization matches libmw mw::Block::Serialize.
struct MWEBBlock {
    MWEBHeader header;
    MWEBTxBody body;

    template <typename Stream>
    void Serialize(Stream& s) const {
        ::Serialize(s, header);
        ::Serialize(s, body);
    }
    template <typename Stream>
    void Unserialize(Stream& s) {
        ::Unserialize(s, header);
        ::Unserialize(s, body);
    }
};

// ─── Blake3 hash helper ─────────────────────────────────────────────────────

/// Compute blake3 hash of arbitrary data (matches libmw Hasher).
inline uint256 blake3_hash(const std::vector<unsigned char>& data) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, data.data(), data.size());
    uint256 result;
    blake3_hasher_finalize(&hasher, result.data(), 32);
    return result;
}

/// Compute blake3 hash of a serializable object.
inline uint256 blake3_hash_serialized(const MWEBHeader& hdr) {
    PackStream ps;
    ps << hdr;
    auto sp = ps.get_span();
    std::vector<unsigned char> data(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return blake3_hash(data);
}

// ─── MWEB State ─────────────────────────────────────────────────────────────

/// State carried forward from the previous block's MWEB data.
/// Extracted from a full block received via P2P.
struct MWEBState {
    // Previous HogEx outpoint (for building chain link input)
    uint256  prev_hogex_txid;
    uint32_t prev_hogex_vout{0};  // always 0 (first output)
    int64_t  hogaddr_value{0};    // carry-forward value in satoshis

    // MWEB header fields to carry forward (roots don't change without MWEB activity)
    MWEBHeader prev_header;

    // The raw serialized MWEB block from the previous block (for reference)
    std::vector<unsigned char> prev_mweb_raw;

    // Height at which this state was captured
    uint32_t captured_at_height{0};
    bool     valid{false};
};

// ─── MWEB Builder ───────────────────────────────────────────────────────────

class MWEBBuilder {
public:
    /// Extract MWEB state from a full block received via P2P.
    /// The block must have at least 2 transactions, with the last being HogEx.
    /// Returns true if extraction succeeded.
    static bool extract_state(const BlockType& block, uint32_t block_height, MWEBState& state) {
        if (block.m_txs.size() < 2) {
            LOG_DEBUG_COIND << "[MWEB] Block has " << block.m_txs.size()
                           << " txs, need >=2 for HogEx";
            return false;
        }

        // Last transaction should be HogEx
        const auto& hogex_tx = block.m_txs.back();
        if (hogex_tx.vout.empty()) {
            LOG_WARNING << "[MWEB] Last tx has no outputs — not a valid HogEx";
            return false;
        }

        // First output should be HogAddr: OP_8 (0x58) PUSH32 (0x20) <32-byte-hash>
        const auto& hogaddr_out = hogex_tx.vout[0];
        const auto& script = hogaddr_out.scriptPubKey;
        if (script.m_data.size() != 34 ||
            script.m_data[0] != 0x58 ||  // OP_8
            script.m_data[1] != 0x20)     // PUSH 32 bytes
        {
            LOG_WARNING << "[MWEB] First output not HogAddr (script size="
                       << script.m_data.size() << ")";
            return false;
        }

        // Compute HogEx txid (non-witness, non-MWEB serialization)
        auto hogex_txid = compute_hogex_txid(hogex_tx);

        state.prev_hogex_txid = hogex_txid;
        state.prev_hogex_vout = 0;
        state.hogaddr_value = hogaddr_out.value;
        state.captured_at_height = block_height;
        state.valid = true;

        LOG_INFO << "[MWEB] Extracted state from height " << block_height
                 << ": HogEx txid=" << hogex_txid.GetHex().substr(0, 16) << "..."
                 << " value=" << hogaddr_out.value
                 << " HogEx_ins=" << hogex_tx.vin.size()
                 << " HogEx_outs=" << hogex_tx.vout.size();

        return true;
    }

    /// Extract MWEB header from raw MWEB block bytes.
    /// These bytes come after the transaction list in the full block serialization,
    /// prefixed by the OptionalPtr 0x01 byte.
    static bool extract_mweb_header_from_raw(const std::vector<unsigned char>& mweb_raw,
                                              MWEBState& state) {
        if (mweb_raw.empty()) {
            LOG_WARNING << "[MWEB] Empty MWEB raw data";
            return false;
        }

        try {
            PackStream ps(mweb_raw);
            // The raw bytes ARE the mw::Block (Header + TxBody), no OptionalPtr wrapper
            MWEBBlock mweb_block;
            ps >> mweb_block;
            state.prev_header = mweb_block.header;
            state.prev_mweb_raw = mweb_raw;

            LOG_INFO << "[MWEB] Parsed header: height=" << mweb_block.header.height
                     << " output_mmr=" << mweb_block.header.output_mmr_size
                     << " kernel_mmr=" << mweb_block.header.kernel_mmr_size;
            return true;
        } catch (const std::exception& e) {
            LOG_WARNING << "[MWEB] Failed to parse MWEB block: " << e.what();
            return false;
        }
    }

    /// Build an empty MWEB block for the given height.
    /// Carries forward all roots/sizes from the previous block.
    /// Returns the serialized mw::Block bytes (WITHOUT OptionalPtr wrapper).
    static std::vector<unsigned char> build_empty_mweb_block(
        const MWEBState& state,
        uint32_t next_height)
    {
        MWEBBlock block;
        // Carry forward header roots and sizes
        block.header = state.prev_header;
        // Update height to next block
        block.header.height = static_cast<int64_t>(next_height);
        // Offsets stay zero for empty MWEB activity
        // Body is empty (no inputs/outputs/kernels)

        PackStream ps;
        ps << block;
        auto sp = ps.get_span();
        return std::vector<unsigned char>(
            reinterpret_cast<const unsigned char*>(sp.data()),
            reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    }

    /// Compute the blake3 hash of an MWEB block's header.
    /// This hash goes into the HogAddr output script.
    static uint256 compute_mweb_hash(const MWEBState& state, uint32_t next_height) {
        MWEBHeader hdr = state.prev_header;
        hdr.height = static_cast<int64_t>(next_height);
        return blake3_hash_serialized(hdr);
    }

    /// Build the HogEx transaction for a block with no MWEB activity.
    /// This is a minimal transaction that:
    ///   vin[0]: spends previous HogEx output[0] (chain link)
    ///   vout[0]: HogAddr = OP_8 <32-byte mweb_block_hash>, value = carry-forward
    static MutableTransaction build_hogex(
        const MWEBState& state,
        uint32_t next_height)
    {
        uint256 mweb_hash = compute_mweb_hash(state, next_height);

        MutableTransaction tx;
        tx.version = 2;
        tx.locktime = 0;
        tx.m_hogEx = true;

        // Input: spend previous block's HogEx output[0]
        TxIn input;
        input.prevout.hash = state.prev_hogex_txid;
        input.prevout.index = state.prev_hogex_vout;
        input.sequence = 0xffffffff;
        // scriptSig is empty (HogEx inputs don't need signatures — validated by consensus)
        tx.vin.push_back(std::move(input));

        // Output: HogAddr = OP_8 (0x58) PUSH32 (0x20) <mweb_hash>
        TxOut output;
        output.value = state.hogaddr_value;  // carry forward
        output.scriptPubKey.m_data.resize(34);
        output.scriptPubKey.m_data[0] = 0x58;  // OP_8
        output.scriptPubKey.m_data[1] = 0x20;  // PUSH 32 bytes
        std::memcpy(output.scriptPubKey.m_data.data() + 2, mweb_hash.data(), 32);
        tx.vout.push_back(std::move(output));

        LOG_INFO << "[MWEB] Built HogEx for height " << next_height
                 << ": mweb_hash=" << mweb_hash.GetHex().substr(0, 16) << "..."
                 << " value=" << state.hogaddr_value
                 << " prev_txid=" << state.prev_hogex_txid.GetHex().substr(0, 16) << "...";

        return tx;
    }

    /// Serialize HogEx as hex for GBT template "transactions" entry.
    /// CRITICAL: must include MWEB flag (0x08) so litecoind recognizes it as HogEx.
    static std::string serialize_hogex_hex(const MutableTransaction& hogex) {
        // Serialize with witness+MWEB support
        // HogEx wire format:
        //   [version 4B] [00] [08] [vin] [vout] [00=null_mweb_tx] [locktime 4B]
        // The flag 0x08 triggers m_hogEx=true on deserialization
        PackStream ps;
        // Version
        ::Serialize(ps, hogex.version);
        // Dummy vin (marker for extended format)
        std::vector<TxIn> dummy;
        ::Serialize(ps, dummy);
        // Flags: 0x08 = MWEB (no witness needed for HogEx)
        uint8_t flags = 0x08;
        ::Serialize(ps, flags);
        // Actual vin and vout
        ::Serialize(ps, hogex.vin);
        ::Serialize(ps, hogex.vout);
        // Null MWEB tx (OptionalPtr null = 0x00)
        uint8_t null_mweb = 0x00;
        ::Serialize(ps, null_mweb);
        // Locktime
        ::Serialize(ps, hogex.locktime);

        return HexStr(ps.get_span());
    }

    /// Compute the txid of a HogEx transaction.
    /// txid = SHA256d of non-witness, non-MWEB serialization.
    static uint256 compute_hogex_txid(const MutableTransaction& tx) {
        // Non-witness serialization: [version][vin][vout][locktime]
        PackStream ps;
        ps << TX_NO_WITNESS(tx);
        return Hash(ps.get_span());
    }

    /// Compute the wtxid of a HogEx transaction.
    /// For HogEx with null mweb_tx, HasWitness() is false, so wtxid == txid.
    static uint256 compute_hogex_wtxid(const MutableTransaction& tx) {
        return compute_hogex_txid(tx);
    }
};

// ─── Thread-safe MWEB State Tracker ─────────────────────────────────────────

/// Tracks the latest MWEB state, updated when full blocks are received.
class MWEBTracker {
public:
    /// Update state from a full block.
    /// Called when a new block is received via P2P.
    bool update(const BlockType& block, uint32_t height,
                const std::vector<unsigned char>& mweb_raw) {
        MWEBState new_state;
        if (!MWEBBuilder::extract_state(block, height, new_state))
            return false;
        if (!mweb_raw.empty()) {
            if (!MWEBBuilder::extract_mweb_header_from_raw(mweb_raw, new_state))
                return false;
        }
        std::lock_guard<std::mutex> lock(m_mutex);
        m_state = std::move(new_state);
        return true;
    }

    /// Get current MWEB state (thread-safe copy).
    std::optional<MWEBState> get_state() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_state.valid)
            return std::nullopt;
        return m_state;
    }

    bool has_state() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_state.valid;
    }

private:
    mutable std::mutex m_mutex;
    MWEBState m_state;
};

} // namespace coin
} // namespace ltc
