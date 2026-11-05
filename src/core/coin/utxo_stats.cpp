// SPDX-License-Identifier: AGPL-3.0-or-later
#include "utxo_stats.hpp"

#include "coin_compressor.hpp"

#include <btclibs/crypto/sha256.h>

#include <algorithm>
#include <cstring>
#include <vector>

namespace core {
namespace coin {

namespace {

struct Out {
    uint32_t index;
    Coin     coin;
};

/// The length of serialize.h WriteVarInt(n) (MSB base-128, -1 per group).
size_t varint_size(uint64_t n)
{
    size_t len = 1;
    while (n > 0x7F) {
        n = (n >> 7) - 1;
        ++len;
    }
    return len;
}

/// coins.h CCoins::Serialize's size for the txid's unspent outputs `outs`
/// (sorted by index), the tx version counted as one byte.
uint64_t ccoins_value_size(const std::vector<Out>& outs)
{
    const uint32_t vsize = outs.back().index + 1;
    auto present = [&outs](uint32_t i) {
        const auto it = std::lower_bound(outs.begin(), outs.end(), i,
                                         [](const Out& o, uint32_t v) { return o.index < v; });
        return it != outs.end() && it->index == i;
    };
    // CCoins::CalcMaskSize
    unsigned int mask_bytes = 0, mask_code = 0;
    for (uint32_t b = 0; 2 + b * 8 < vsize; ++b) {
        bool zero = true;
        for (uint32_t i = 0; i < 8 && 2 + b * 8 + i < vsize; ++i)
            if (present(2 + b * 8 + i))
                zero = false;
        if (!zero) {
            mask_bytes = b + 1;
            ++mask_code;
        }
    }
    const bool first = present(0);
    const bool second = present(1);
    const uint64_t code = 8ull * (mask_code - (first || second ? 0 : 1))
                        + (outs.front().coin.coinbase ? 1 : 0) + (first ? 2 : 0) + (second ? 4 : 0);
    uint64_t size = 1 /* VARINT(nVersion), not kept: 1 or 2 */ + varint_size(code) + mask_bytes;
    for (const auto& o : outs) {
        size += varint_size(CompressAmount(static_cast<uint64_t>(o.coin.value)));
        CompressedScript compressed;
        const auto& script = o.coin.scriptPubKey.m_data;
        if (CompressScript(script, compressed))
            size += compressed.size();
        else
            size += varint_size(script.size() + nSpecialScripts) + script.size();
    }
    return size + varint_size(outs.front().coin.height);
}

} // namespace

UtxoStats utxo_stats(UTXOViewDB& db, const std::function<void(uint64_t records)>& progress)
{
    UtxoStats s;
    s.best_height = db.get_best_height();
    s.best_block = db.get_best_block();
    s.sync = db.get_sync_state();

    CSHA256 sha;
    sha.Write(s.best_block.data(), 32);
    std::vector<unsigned char> buf;
    std::vector<Out> group;
    std::string group_txid;  // the 32 raw bytes of the txid being collected
    bool bad = false;
    uint64_t records = 0;

    auto finish_group = [&]() {
        if (group.empty())
            return;
        std::sort(group.begin(), group.end(), [](const Out& a, const Out& b) { return a.index < b.index; });
        group.erase(std::remove_if(group.begin(), group.end(),
                                   [&s](const Out& o) {
                                       if (!is_unspendable(o.coin.scriptPubKey))
                                           return false;
                                       ++s.unspendable_skipped;
                                       return true;
                                   }),
                    group.end());
        if (group.empty())
            return;
        ++s.transactions;
        buf.clear();
        buf.insert(buf.end(), group_txid.begin(), group_txid.end());
        for (const auto& o : group) {
            WriteVarInt(buf, static_cast<uint64_t>(o.index) + 1);
            const uint64_t v = static_cast<uint64_t>(o.coin.value);
            for (int i = 0; i < 8; ++i)
                buf.push_back(static_cast<unsigned char>(v >> (8 * i)));
            const auto& script = o.coin.scriptPubKey.m_data;
            WriteCompactSize(buf, script.size());
            buf.insert(buf.end(), script.begin(), script.end());
            ++s.txouts;
            s.total_amount.add(v);
        }
        buf.push_back(0x00);  // VARINT(0)
        sha.Write(buf.data(), buf.size());
        s.bytes_serialized += 32 + ccoins_value_size(group);
        group.clear();
    };

    const bool scanned = db.for_each_record(std::string(1, 'C'),
        [&](const std::string& key, const std::vector<uint8_t>& value) {
            if (key.size() != 37) {
                bad = true;
                return false;
            }
            if (group_txid.size() != 32 || std::memcmp(group_txid.data(), key.data() + 1, 32) != 0) {
                finish_group();
                group_txid.assign(key.data() + 1, 32);
            }
            const auto* p = reinterpret_cast<const uint8_t*>(key.data() + 33);
            Out o;
            o.index = uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
            if (!deserialize_coin(value, o.coin)) {
                bad = true;
                return false;
            }
            group.push_back(std::move(o));
            if (progress && (++records % 10000000) == 0)
                progress(records);
            return true;
        });
    if (!scanned || bad)
        return s;
    finish_group();

    unsigned char first[CSHA256::OUTPUT_SIZE], second[CSHA256::OUTPUT_SIZE];
    sha.Finalize(first);
    CSHA256().Write(first, sizeof(first)).Finalize(second);
    std::memcpy(s.hash_serialized.data(), second, 32);
    s.ok = true;
    return s;
}

namespace {

/// x /= d, returning x % d, for d < 2^32 (32-bit limbs, 64-bit steps).
uint32_t divmod_small(Amount128& x, uint32_t d)
{
    uint64_t limbs[4] = {x.hi >> 32, x.hi & 0xffffffffull, x.lo >> 32, x.lo & 0xffffffffull};
    uint64_t rem = 0;
    for (auto& l : limbs) {
        const uint64_t cur = (rem << 32) | l;
        l = cur / d;
        rem = cur % d;
    }
    x.hi = (limbs[0] << 32) | limbs[1];
    x.lo = (limbs[2] << 32) | limbs[3];
    return static_cast<uint32_t>(rem);
}

} // namespace

std::string u128_to_string(Amount128 v)
{
    if (v.hi == 0)
        return std::to_string(v.lo);
    std::string out;
    while (v.hi != 0 || v.lo != 0)
        out.push_back(static_cast<char>('0' + divmod_small(v, 10)));
    std::reverse(out.begin(), out.end());
    return out;
}

std::string format_coin_amount(Amount128 koinu)
{
    std::string frac = std::to_string(divmod_small(koinu, 100000000u));  // koinu = whole coins
    frac.insert(0, 8 - frac.size(), '0');
    return u128_to_string(koinu) + "." + frac;
}

} // namespace coin
} // namespace core
