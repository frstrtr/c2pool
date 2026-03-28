#include "address_utils.hpp"

#include <cstring>
#include <sstream>
#include <iomanip>

#include <btclibs/crypto/sha256.h>
#include <btclibs/bech32.h>

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

} // namespace core
