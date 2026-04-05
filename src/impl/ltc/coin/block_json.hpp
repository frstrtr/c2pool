#pragma once

/// block_to_explorer_json(): Convert a BlockType into litecoind-compatible
/// getblock verbosity=2 JSON for the lite block explorer API.
///
/// Handles: full header fields, all script types (P2PKH/P2SH/P2WPKH/P2WSH/
/// P2TR/P2PK/P2MS/OP_RETURN/nonstandard), THE commitment decoding for
/// c2pool-found blocks.

#include "block.hpp"
#include "transaction.hpp"
#include "mempool.hpp"  // compute_txid()

#include <core/address_utils.hpp>
#include <core/coinbase_builder.hpp>
#include <core/target_utils.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>

#include <nlohmann/json.hpp>

#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace ltc {
namespace coin {

/// Chain parameters needed for address encoding.
struct ExplorerChainParams {
    std::string bech32_hrp;   // "ltc", "tltc", etc.
    uint8_t p2pkh_ver;        // 0x30 (LTC mainnet), 0x6f (testnet)
    uint8_t p2sh_ver;         // 0x32 (LTC mainnet), 0xc4 (testnet)
    std::string chain_name;   // "main", "test", etc.
};

namespace detail {

inline std::string to_hex(const unsigned char* data, size_t len) {
    static const char H[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += H[data[i] >> 4];
        out += H[data[i] & 0x0f];
    }
    return out;
}

inline std::string bits_to_hex_str(uint32_t bits) {
    char buf[9];
    snprintf(buf, sizeof(buf), "%08x", bits);
    return buf;
}

inline nlohmann::json classify_to_json(const core::ScriptClassification& sc) {
    nlohmann::json spk;
    spk["type"] = sc.type;
    spk["hex"] = sc.hex;

    if (!sc.addresses.empty()) {
        spk["addresses"] = sc.addresses;
        if (sc.addresses.size() == 1)
            spk["address"] = sc.addresses[0];
    }

    if (sc.type == "pubkey" && !sc.pubkey.empty())
        spk["pubkey"] = sc.pubkey;

    if (sc.type == "multisig") {
        nlohmann::json ms;
        ms["required"] = sc.multisig_required;
        ms["total"] = sc.multisig_total;
        nlohmann::json pks = nlohmann::json::array();
        for (size_t i = 0; i < sc.multisig_pubkeys.size(); ++i) {
            nlohmann::json pk;
            pk["hex"] = sc.multisig_pubkeys[i];
            if (i < sc.multisig_addresses.size())
                pk["address"] = sc.multisig_addresses[i];
            pks.push_back(std::move(pk));
        }
        ms["pubkeys"] = std::move(pks);
        spk["multisig"] = std::move(ms);
    }

    if (sc.type == "nulldata" && !sc.op_return_hex.empty())
        spk["data"] = sc.op_return_hex;

    return spk;
}

/// Parse c2pool THE commitment from coinbase scriptSig.
/// Layout: [BIP34 height push][...optional AuxPoW...]["/c2pool/" tag][state_root 32B][TheMetadata]
inline nlohmann::json parse_the_commitment(const std::vector<unsigned char>& scriptSig) {
    // Search for "/c2pool/" tag
    const uint8_t tag[] = {'/', 'c', '2', 'p', 'o', 'o', 'l', '/'};
    const size_t tag_len = 8;
    const auto* data = scriptSig.data();
    const size_t len = scriptSig.size();

    size_t tag_pos = std::string::npos;
    for (size_t i = 0; i + tag_len <= len; ++i) {
        if (std::memcmp(data + i, tag, tag_len) == 0) {
            tag_pos = i;
            break;
        }
    }
    if (tag_pos == std::string::npos)
        return nullptr;

    nlohmann::json the;
    the["pool_tag"] = "/c2pool/";

    size_t after_tag = tag_pos + tag_len;

    // State root: 32 bytes after tag
    if (after_tag + 32 <= len) {
        the["state_root"] = to_hex(data + after_tag, 32);
        size_t meta_start = after_tag + 32;

        // TheMetadata: remaining bytes
        if (meta_start < len) {
            auto meta = c2pool::TheMetadata::unpack(data + meta_start, len - meta_start);
            nlohmann::json md;
            md["version"] = meta.version;
            md["sharechain_height"] = meta.sharechain_height;
            md["miner_count"] = meta.miner_count;
            md["hashrate_class"] = meta.hashrate_class;
            double hr = c2pool::TheMetadata::decode_hashrate(meta.hashrate_class);
            // Format human-readable hashrate
            const char* suffix = "H/s";
            if (hr >= 1e12)      { hr /= 1e12; suffix = "TH/s"; }
            else if (hr >= 1e9)  { hr /= 1e9;  suffix = "GH/s"; }
            else if (hr >= 1e6)  { hr /= 1e6;  suffix = "MH/s"; }
            else if (hr >= 1e3)  { hr /= 1e3;  suffix = "KH/s"; }
            char buf[64];
            snprintf(buf, sizeof(buf), "%.2f %s", hr, suffix);
            md["hashrate_human"] = buf;

            // Chain fingerprint as hex
            char fp[17];
            snprintf(fp, sizeof(fp), "%016lx",
                     static_cast<unsigned long>(meta.chain_fingerprint));
            md["chain_fingerprint"] = fp;
            md["share_period"] = meta.share_period;
            md["verified_length"] = meta.verified_length;
            the["metadata"] = std::move(md);
        }
    } else {
        the["state_root"] = nullptr;
    }

    return the;
}

} // namespace detail

/// Convert a BlockType + metadata into litecoind-compatible getblock JSON.
inline nlohmann::json block_to_explorer_json(
    const BlockType& block,
    uint32_t height,
    const uint256& block_hash,
    const ExplorerChainParams& params)
{
    using namespace detail;

    nlohmann::json j;

    // Block header fields
    j["hash"] = block_hash.GetHex();
    j["height"] = height;
    j["version"] = static_cast<int64_t>(block.m_version);
    j["previousblockhash"] = block.m_previous_block.GetHex();
    j["merkleroot"] = block.m_merkle_root.GetHex();
    j["time"] = block.m_timestamp;
    j["bits"] = bits_to_hex_str(block.m_bits);
    j["nonce"] = block.m_nonce;

    // Difficulty from bits
    auto target = chain::bits_to_target(block.m_bits);
    j["difficulty"] = chain::target_to_difficulty(target);

    // Compute serialized size
    {
        PackStream ps;
        ps << block;
        j["size"] = ps.get_span().size();
    }

    // Transactions
    nlohmann::json txs = nlohmann::json::array();
    bool first_tx = true;
    for (const auto& mtx : block.m_txs) {
        nlohmann::json tx;

        // txid (non-witness hash)
        uint256 txid = compute_txid(mtx);
        tx["txid"] = txid.GetHex();

        // vin
        nlohmann::json vins = nlohmann::json::array();
        if (first_tx && !mtx.vin.empty()) {
            // Coinbase
            nlohmann::json vin;
            auto& scriptSig = mtx.vin[0].scriptSig;
            std::vector<unsigned char> sig_vec(scriptSig.m_data.begin(), scriptSig.m_data.end());
            vin["coinbase"] = to_hex(sig_vec.data(), sig_vec.size());
            vin["sequence"] = mtx.vin[0].sequence;
            vins.push_back(std::move(vin));
        } else {
            for (const auto& in : mtx.vin) {
                nlohmann::json vin;
                vin["txid"] = in.prevout.hash.GetHex();
                vin["vout"] = in.prevout.index;
                vins.push_back(std::move(vin));
            }
        }
        tx["vin"] = std::move(vins);

        // vout
        nlohmann::json vouts = nlohmann::json::array();
        for (size_t i = 0; i < mtx.vout.size(); ++i) {
            nlohmann::json vout;
            vout["value"] = static_cast<double>(mtx.vout[i].value) / 1e8;
            vout["n"] = i;

            std::vector<unsigned char> script_vec(
                mtx.vout[i].scriptPubKey.m_data.begin(),
                mtx.vout[i].scriptPubKey.m_data.end());
            auto sc = core::classify_script(script_vec,
                params.bech32_hrp, params.p2pkh_ver, params.p2sh_ver);
            vout["scriptPubKey"] = classify_to_json(sc);

            vouts.push_back(std::move(vout));
        }
        tx["vout"] = std::move(vouts);

        txs.push_back(std::move(tx));
        first_tx = false;
    }
    j["tx"] = std::move(txs);

    // THE commitment (c2pool-found blocks)
    if (!block.m_txs.empty() && !block.m_txs[0].vin.empty()) {
        auto& scriptSig = block.m_txs[0].vin[0].scriptSig;
        std::vector<unsigned char> sig_vec(scriptSig.m_data.begin(), scriptSig.m_data.end());
        auto the = parse_the_commitment(sig_vec);
        if (!the.is_null())
            j["_the"] = std::move(the);
    }

    return j;
}

} // namespace coin
} // namespace ltc
