#include "address_utils.hpp"

#include <cstring>
#include <sstream>
#include <iomanip>

#include <btclibs/crypto/sha256.h>
#include <btclibs/crypto/ripemd160.h>
#include <btclibs/bech32.h>
#include <btclibs/base58.h>
#include <btclibs/span.h>

namespace core {

std::string base58check_to_hash160(const std::string& address)
{
    static constexpr const char* B58 =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // decoded[0..24]: 1 version byte + 20 hash160 bytes + 4 checksum bytes
    uint8_t decoded[25] = {};
    for (unsigned char ch : address) {
        const char* p = std::strchr(B58, static_cast<char>(ch));
        if (!p) return "";
        int carry = static_cast<int>(p - B58);
        for (int i = 24; i >= 0; --i) {
            carry += 58 * static_cast<int>(decoded[i]);
            decoded[i] = static_cast<uint8_t>(carry & 0xFF);
            carry >>= 8;
        }
        if (carry) return "";
    }

    // Verify checksum: SHA256d(decoded[0..20])[0..4] == decoded[21..24]
    uint8_t tmp[32], chk[32];
    CSHA256().Write(decoded, 21).Finalize(tmp);
    CSHA256().Write(tmp, 32).Finalize(chk);
    for (int i = 0; i < 4; ++i)
        if (chk[i] != decoded[21 + i]) return "";

    static const char* HEX = "0123456789abcdef";
    std::string hex;
    hex.reserve(40);
    for (int i = 1; i <= 20; ++i) {
        hex += HEX[decoded[i] >> 4];
        hex += HEX[decoded[i] & 0x0f];
    }
    return hex;
}

std::string address_to_hash160(const std::string& address, std::string& addr_type)
{
    addr_type.clear();

    // Try Bech32 first
    static const std::vector<std::string> bech32_hrps = {"tltc", "ltc", "bc", "tb"};
    for (const auto& hrp : bech32_hrps) {
        std::string prefix = hrp + "1";
        if (address.size() > prefix.size() &&
            address.substr(0, prefix.size()) == prefix)
        {
            int witver = -1;
            std::vector<uint8_t> prog;
            if (bech32::decode_segwit(hrp, address, witver, prog)) {
                if (witver == 0 && prog.size() == 20) {
                    addr_type = "p2wpkh";
                    static const char* HEX = "0123456789abcdef";
                    std::string hex;
                    hex.reserve(40);
                    for (uint8_t b : prog) { hex += HEX[b >> 4]; hex += HEX[b & 0x0f]; }
                    return hex;
                }
                // P2WSH: witness v0, 32-byte script hash — non-convertible
                if (witver == 0 && prog.size() == 32) {
                    addr_type = "p2wsh";
                    return "";
                }
                // P2TR (witness v1) or future witness versions — non-convertible
                if (witver >= 1) {
                    addr_type = "p2tr";
                    return "";
                }
            }
            return "";
        }
    }

    // Base58Check
    auto h160 = base58check_to_hash160(address);
    if (h160.size() == 40) {
        static constexpr const char* B58 =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        uint8_t decoded[25] = {};
        for (unsigned char ch : address) {
            const char* p = std::strchr(B58, static_cast<char>(ch));
            if (!p) return "";
            int carry = static_cast<int>(p - B58);
            for (int i = 24; i >= 0; --i) {
                carry += 58 * static_cast<int>(decoded[i]);
                decoded[i] = static_cast<uint8_t>(carry & 0xFF);
                carry >>= 8;
            }
        }
        uint8_t version = decoded[0];
        if (version == 0x32 || version == 0x05 || version == 0x3a ||
            version == 0xc4 || version == 0x16) {
            addr_type = "p2sh";
        } else {
            addr_type = "p2pkh";
        }
        return h160;
    }

    return "";
}

std::vector<unsigned char> hash160_to_merged_script(
    const std::string& h160_hex, const std::string& addr_type)
{
    if (h160_hex.size() != 40) return {};
    std::vector<unsigned char> hash_bytes;
    hash_bytes.reserve(20);
    for (size_t i = 0; i < h160_hex.size(); i += 2)
        hash_bytes.push_back(static_cast<unsigned char>(
            std::stoul(h160_hex.substr(i, 2), nullptr, 16)));

    std::vector<unsigned char> script;
    if (addr_type == "p2sh") {
        script.reserve(23);
        script.push_back(0xa9);
        script.push_back(0x14);
        script.insert(script.end(), hash_bytes.begin(), hash_bytes.end());
        script.push_back(0x87);
    } else {
        script.reserve(25);
        script.push_back(0x76);
        script.push_back(0xa9);
        script.push_back(0x14);
        script.insert(script.end(), hash_bytes.begin(), hash_bytes.end());
        script.push_back(0x88);
        script.push_back(0xac);
    }
    return script;
}

bool is_address_for_chain(const std::string& address,
    const std::vector<std::string>& chain_hrps,
    const std::vector<uint8_t>& chain_versions)
{
    // Check bech32
    for (const auto& hrp : chain_hrps) {
        std::string prefix = hrp + "1";
        if (address.size() > prefix.size() &&
            address.substr(0, prefix.size()) == prefix)
            return true;
    }
    // Check base58 version byte
    if (address.size() >= 25) {
        static constexpr const char* B58 =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        uint8_t decoded[25] = {};
        bool valid = true;
        for (unsigned char ch : address) {
            const char* p = std::strchr(B58, static_cast<char>(ch));
            if (!p) { valid = false; break; }
            int carry = static_cast<int>(p - B58);
            for (int i = 24; i >= 0; --i) {
                carry += 58 * static_cast<int>(decoded[i]);
                decoded[i] = static_cast<uint8_t>(carry & 0xFF);
                carry >>= 8;
            }
        }
        if (valid) {
            for (uint8_t ver : chain_versions) {
                if (decoded[0] == ver) return true;
            }
        }
    }
    return false;
}

std::string script_to_address(const std::vector<unsigned char>& script,
    const std::string& bech32_hrp, uint8_t p2pkh_ver, uint8_t p2sh_ver)
{
    const size_t n = script.size();

    // P2PKH: OP_DUP OP_HASH160 <20> <hash160> OP_EQUALVERIFY OP_CHECKSIG
    if (n == 25 && script[0] == 0x76 && script[1] == 0xa9 &&
        script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac)
    {
        std::vector<unsigned char> payload(21);
        payload[0] = p2pkh_ver;
        std::copy(script.begin() + 3, script.begin() + 23, payload.begin() + 1);
        return EncodeBase58Check({payload.data(), payload.size()});
    }

    // P2SH: OP_HASH160 <20> <hash160> OP_EQUAL
    if (n == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87)
    {
        std::vector<unsigned char> payload(21);
        payload[0] = p2sh_ver;
        std::copy(script.begin() + 2, script.begin() + 22, payload.begin() + 1);
        return EncodeBase58Check({payload.data(), payload.size()});
    }

    // P2WPKH: OP_0 <20> <witness-program-20-bytes>
    if (n == 22 && script[0] == 0x00 && script[1] == 0x14)
    {
        std::vector<uint8_t> prog(script.begin() + 2, script.end());
        return bech32::encode_segwit(bech32_hrp, 0, prog);
    }

    // P2WSH: OP_0 <32> <witness-program-32-bytes>
    if (n == 34 && script[0] == 0x00 && script[1] == 0x20)
    {
        std::vector<uint8_t> prog(script.begin() + 2, script.end());
        return bech32::encode_segwit(bech32_hrp, 0, prog);
    }

    // P2TR: OP_1 <32> <x-only-pubkey>
    if (n == 34 && script[0] == 0x51 && script[1] == 0x20)
    {
        std::vector<uint8_t> prog(script.begin() + 2, script.end());
        return bech32::encode_segwit(bech32_hrp, 1, prog);
    }

    return {};
}

std::string script_to_address(const std::vector<unsigned char>& script,
    bool is_litecoin, bool is_testnet)
{
    uint8_t p2pkh_ver, p2sh_ver;
    std::string bech32_hrp;
    if (is_litecoin) {
        if (is_testnet) { p2pkh_ver = 0x6f; p2sh_ver = 0xc4; bech32_hrp = "tltc"; }
        else            { p2pkh_ver = 0x30; p2sh_ver = 0x32; bech32_hrp = "ltc";  }
    } else {
        if (is_testnet) { p2pkh_ver = 0x6f; p2sh_ver = 0xc4; bech32_hrp = "tb";  }
        else            { p2pkh_ver = 0x00; p2sh_ver = 0x05; bech32_hrp = "bc";   }
    }
    return script_to_address(script, bech32_hrp, p2pkh_ver, p2sh_ver);
}

std::vector<unsigned char> address_to_script(const std::string& address)
{
    // Try Bech32 first
    static const std::vector<std::string> bech32_hrps = {"tltc", "ltc", "bc", "tb"};
    for (const auto& hrp : bech32_hrps) {
        std::string prefix = hrp + "1";
        if (address.size() > prefix.size() &&
            address.substr(0, prefix.size()) == prefix)
        {
            int witver = -1;
            std::vector<uint8_t> prog;
            if (bech32::decode_segwit(hrp, address, witver, prog)) {
                std::vector<unsigned char> script;
                script.push_back(static_cast<unsigned char>(witver == 0 ? 0x00 : (0x50 + witver)));
                script.push_back(static_cast<unsigned char>(prog.size()));
                script.insert(script.end(), prog.begin(), prog.end());
                return script;
            }
            break;
        }
    }

    // Try Base58Check (P2PKH or P2SH)
    std::string addr_type;
    auto h160 = address_to_hash160(address, addr_type);
    if (h160.size() == 40) {
        return hash160_to_merged_script(h160, addr_type);
    }

    return {};
}

// ── Helper: hex encoding ────────────────────────────────────────────────

static std::string to_hex(const unsigned char* data, size_t len) {
    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += H[data[i] >> 4];
        out += H[data[i] & 0x0f];
    }
    return out;
}

// ── Hash160: SHA256 + RIPEMD160 ─────────────────────────────────────────

static void hash160(const unsigned char* data, size_t len, unsigned char out[20]) {
    unsigned char sha[32];
    CSHA256().Write(data, len).Finalize(sha);
    CRIPEMD160().Write(sha, 32).Finalize(out);
}

std::string pubkey_to_p2pkh_address(const unsigned char* pubkey, size_t len, uint8_t p2pkh_ver) {
    if (len != 33 && len != 65) return {};
    unsigned char h160[20];
    hash160(pubkey, len, h160);
    std::vector<unsigned char> payload(21);
    payload[0] = p2pkh_ver;
    std::memcpy(payload.data() + 1, h160, 20);
    return EncodeBase58Check({payload.data(), payload.size()});
}

ScriptClassification classify_script(const std::vector<unsigned char>& script,
    const std::string& bech32_hrp, uint8_t p2pkh_ver, uint8_t p2sh_ver)
{
    ScriptClassification result;
    result.hex = to_hex(script.data(), script.size());
    const size_t n = script.size();

    // Try standard address types first
    auto addr = script_to_address(script, bech32_hrp, p2pkh_ver, p2sh_ver);
    if (!addr.empty()) {
        // Determine type from pattern
        if (n == 25 && script[0] == 0x76 && script[24] == 0xac) {
            result.type = "pubkeyhash";
        } else if (n == 23 && script[0] == 0xa9 && script[22] == 0x87) {
            result.type = "scripthash";
        } else if (n == 22 && script[0] == 0x00 && script[1] == 0x14) {
            result.type = "witness_v0_keyhash";
        } else if (n == 34 && script[0] == 0x00 && script[1] == 0x20) {
            result.type = "witness_v0_scripthash";
        } else if (n == 34 && script[0] == 0x51 && script[1] == 0x20) {
            result.type = "witness_v1_taproot";
        }
        result.addresses.push_back(std::move(addr));
        return result;
    }

    // P2PK: <33|65 byte pubkey> OP_CHECKSIG (0xac)
    if (n > 1 && script[n - 1] == 0xac) {
        size_t push_len = script[0];
        if ((push_len == 33 || push_len == 65) && n == push_len + 2) {
            result.type = "pubkey";
            result.pubkey = to_hex(script.data() + 1, push_len);
            auto pk_addr = pubkey_to_p2pkh_address(script.data() + 1, push_len, p2pkh_ver);
            if (!pk_addr.empty())
                result.addresses.push_back(std::move(pk_addr));
            return result;
        }
    }

    // P2MS: OP_M <pubkey>... OP_N OP_CHECKMULTISIG (0xae)
    if (n > 3 && script[n - 1] == 0xae) {
        // OP_N is the byte before OP_CHECKMULTISIG
        uint8_t op_n = script[n - 2];
        if (op_n >= 0x51 && op_n <= 0x60) {  // OP_1 .. OP_16
            int total = op_n - 0x50;
            // OP_M is the first byte
            uint8_t op_m = script[0];
            if (op_m >= 0x51 && op_m <= 0x60) {
                int required = op_m - 0x50;
                if (required <= total) {
                    // Walk pubkeys starting at offset 1
                    size_t pos = 1;
                    std::vector<std::string> pubkeys;
                    std::vector<std::string> addrs;
                    bool valid = true;
                    for (int i = 0; i < total; ++i) {
                        if (pos >= n - 2) { valid = false; break; }
                        size_t pk_len = script[pos];
                        if (pk_len != 33 && pk_len != 65) { valid = false; break; }
                        if (pos + 1 + pk_len > n - 2) { valid = false; break; }
                        pubkeys.push_back(to_hex(script.data() + pos + 1, pk_len));
                        auto pk_addr = pubkey_to_p2pkh_address(
                            script.data() + pos + 1, pk_len, p2pkh_ver);
                        addrs.push_back(pk_addr.empty() ? "" : pk_addr);
                        pos += 1 + pk_len;
                    }
                    if (valid && pos == n - 2) {
                        result.type = "multisig";
                        result.multisig_required = required;
                        result.multisig_total = total;
                        result.multisig_pubkeys = std::move(pubkeys);
                        result.multisig_addresses = std::move(addrs);
                        result.addresses = result.multisig_addresses;
                        return result;
                    }
                }
            }
        }
    }

    // OP_RETURN: OP_RETURN (0x6a) ...
    if (n >= 1 && script[0] == 0x6a) {
        result.type = "nulldata";
        if (n > 1)
            result.op_return_hex = to_hex(script.data() + 1, n - 1);
        return result;
    }

    result.type = "nonstandard";
    return result;
}

ScriptClassification classify_script(const std::vector<unsigned char>& script,
    bool is_litecoin, bool is_testnet)
{
    uint8_t p2pkh_ver, p2sh_ver;
    std::string bech32_hrp;
    if (is_litecoin) {
        if (is_testnet) { p2pkh_ver = 0x6f; p2sh_ver = 0xc4; bech32_hrp = "tltc"; }
        else            { p2pkh_ver = 0x30; p2sh_ver = 0x32; bech32_hrp = "ltc";  }
    } else {
        if (is_testnet) { p2pkh_ver = 0x6f; p2sh_ver = 0xc4; bech32_hrp = "tb";  }
        else            { p2pkh_ver = 0x00; p2sh_ver = 0x05; bech32_hrp = "bc";   }
    }
    return classify_script(script, bech32_hrp, p2pkh_ver, p2sh_ver);
}

} // namespace core
