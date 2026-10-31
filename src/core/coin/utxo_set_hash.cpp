#include "utxo_set_hash.hpp"

#include "coin_compressor.hpp"

#include <cstring>
#include <limits>

namespace core::coin {

namespace {

inline void put_le32(std::vector<unsigned char>& b, uint32_t v)
{
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<unsigned char>(v >> (8 * i)));
}

inline void put_le64(std::vector<unsigned char>& b, uint64_t v)
{
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<unsigned char>(v >> (8 * i)));
}

inline int cmp_txid(const uint256& a, const uint256& b)
{
    return std::memcmp(a.data(), b.data(), 32);
}

} // namespace

void TxOutSer(std::vector<unsigned char>& out, const Outpoint& outpoint, const Coin& coin)
{
    // ss << outpoint;
    out.insert(out.end(), outpoint.txid.data(), outpoint.txid.data() + 32);
    put_le32(out, outpoint.index);
    // ss << static_cast<uint32_t>(coin.nHeight * 2 + coin.fCoinBase);
    put_le32(out, static_cast<uint32_t>(coin.height * 2u + (coin.coinbase ? 1u : 0u)));
    // ss << coin.out;  (CTxOut: nValue, scriptPubKey)
    put_le64(out, static_cast<uint64_t>(coin.value));
    WriteCompactSize(out, coin.scriptPubKey.m_data.size());
    out.insert(out.end(), coin.scriptPubKey.m_data.begin(), coin.scriptPubKey.m_data.end());
}

UtxoSetHasher::UtxoSetHasher(const uint256& best_block, Options opts)
    : m_opts(opts)
{
    m_out.best_block = best_block;
    // PrepareHash(HashWriter&): ss << stats.hashBlock;
    if (m_opts.hash_serialized_2)
        m_serialized.Write(best_block.data(), 32);
    m_buf.reserve(256);
}

bool UtxoSetHasher::add(const Outpoint& outpoint, const Coin& coin)
{
    if (!m_refusal.empty() || m_finalized)
        return false;
    if (m_have_group && outpoint.txid == m_group_txid) {
        if (!m_group.emplace(outpoint.index, coin).second) {
            m_refusal = "utxo-set-duplicate-outpoint " + outpoint.txid.GetHex() + ":" +
                        std::to_string(outpoint.index);
            return false;
        }
    } else {
        if (m_have_group) {
            if (cmp_txid(outpoint.txid, m_group_txid) <= 0) {
                m_refusal = "utxo-set-unordered txid " + outpoint.txid.GetHex() + " after " +
                            m_group_txid.GetHex();
                return false;
            }
            flush_group();
        }
        m_group_txid = outpoint.txid;
        m_have_group = true;
        m_group.emplace(outpoint.index, coin);
    }

    ++m_out.coins;
    const uint64_t v = static_cast<uint64_t>(coin.value);
    m_out.total_amount = (m_out.total_amount > std::numeric_limits<uint64_t>::max() - v)
                             ? std::numeric_limits<uint64_t>::max()
                             : m_out.total_amount + v;
    if (coin.value == 0) ++m_out.zero_value_coins;
    if (coin.scriptPubKey.m_data.empty()) ++m_out.empty_script_coins;

    if (m_opts.muhash) {
        // ApplyHash(MuHash3072&): muhash.Insert(MakeUCharSpan(TxOutSer(outpoint, coin)));
        m_buf.clear();
        TxOutSer(m_buf, outpoint, coin);
        m_muhash.Insert(std::span<const unsigned char>(m_buf.data(), m_buf.size()));
    }
    return true;
}

void UtxoSetHasher::flush_group()
{
    if (!m_have_group || m_group.empty())
        return;
    if (m_opts.hash_serialized_2) {
        // ApplyHash(HashWriter& ss, hash, outputs), verbatim order:
        //   if first: ss << hash; ss << VARINT(nHeight * 2 + fCoinBase ? 1u : 0u);
        //   ss << VARINT(n + 1); ss << scriptPubKey;
        //   ss << VARINT_MODE(nValue, NONNEGATIVE_SIGNED);
        //   if last: ss << VARINT(0u);
        m_buf.clear();
        for (auto it = m_group.begin(); it != m_group.end(); ++it) {
            if (it == m_group.begin()) {
                m_buf.insert(m_buf.end(), m_group_txid.data(), m_group_txid.data() + 32);
                const uint32_t code_expr = it->second.height * 2u + (it->second.coinbase ? 1u : 0u);
                WriteVarInt(m_buf, static_cast<unsigned int>(code_expr ? 1u : 0u));
            }
            WriteVarInt(m_buf, static_cast<uint32_t>(it->first + 1));
            WriteCompactSize(m_buf, it->second.scriptPubKey.m_data.size());
            m_buf.insert(m_buf.end(), it->second.scriptPubKey.m_data.begin(),
                         it->second.scriptPubKey.m_data.end());
            WriteVarInt(m_buf, static_cast<uint64_t>(it->second.value));
            if (std::next(it) == m_group.end())
                WriteVarInt(m_buf, 0u);
        }
        m_serialized.Write(m_buf.data(), m_buf.size());
    }
    ++m_out.tx_groups;
    m_group.clear();
}

std::optional<UtxoSetHashes> UtxoSetHasher::finalize()
{
    if (!m_refusal.empty() || m_finalized)
        return std::nullopt;
    flush_group();
    m_have_group = false;
    m_finalized = true;
    if (m_opts.muhash) {
        m_muhash.Finalize(m_out.muhash);
        m_out.have_muhash = true;
    }
    if (m_opts.hash_serialized_2) {
        // FinalizeHash(HashWriter&): ss.GetHash() = SHA256(SHA256(stream)).
        unsigned char first[CSHA256::OUTPUT_SIZE];
        m_serialized.Finalize(first);
        unsigned char second[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(first, sizeof(first)).Finalize(second);
        std::memcpy(m_out.hash_serialized_2.data(), second, sizeof(second));
        m_out.have_hash_serialized_2 = true;
    }
    return m_out;
}

std::vector<uint8_t> encode_view_db_best(const uint256& best_block, uint32_t best_height)
{
    std::vector<uint8_t> d(36);
    std::memcpy(d.data(), best_block.data(), 32);
    d[32] = best_height & 0xFF;
    d[33] = (best_height >> 8) & 0xFF;
    d[34] = (best_height >> 16) & 0xFF;
    d[35] = (best_height >> 24) & 0xFF;
    return d;
}

bool decode_view_db_best(const std::vector<uint8_t>& data, uint256& best_block, uint32_t& best_height)
{
    if (data.size() != 36)
        return false;
    std::memcpy(best_block.data(), data.data(), 32);
    best_height = uint32_t(data[32]) | (uint32_t(data[33]) << 8) |
                  (uint32_t(data[34]) << 16) | (uint32_t(data[35]) << 24);
    return true;
}

bool decode_view_db_coin(const std::vector<uint8_t>& value, Coin& coin)
{
    const uint8_t* data = value.data();
    const size_t len = value.size();
    size_t pos = 0;
    uint64_t code = 0, amount = 0, slen = 0;
    if (!read_varint_checked(data, len, pos, code)
        || !read_varint_checked(data, len, pos, amount)
        || !read_varint_checked(data, len, pos, slen)
        || slen != len - pos)
        return false;
    if (amount > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
        return false;
    coin.pegout = (code >> 31) & 1;
    code &= ~(uint64_t(1) << 31);
    if (code > 0xffffffffULL)
        return false;
    coin.coinbase = (code & 1) != 0;
    coin.height = static_cast<uint32_t>(code >> 1);
    coin.value = static_cast<int64_t>(amount);
    coin.scriptPubKey.m_data.assign(data + pos, data + len);
    return true;
}

std::string view_db_coin_key(const Outpoint& op)
{
    std::string key;
    key.reserve(37);
    key.push_back('C');
    key.append(outpoint_to_key(op));
    return key;
}

std::optional<UtxoViewDbHashes> hash_utxo_view_db(core::LevelDBStore& store,
                                                  UtxoSetHasher::Options opts,
                                                  std::string& refusal)
{
    refusal.clear();
    if (!store.is_open()) {
        refusal = "utxo-view-db-not-open";
        return std::nullopt;
    }
    std::vector<uint8_t> best;
    UtxoViewDbHashes out;
    uint256 best_block;
    if (!store.get(std::string(1, 'B'), best) ||
        !decode_view_db_best(best, best_block, out.best_height)) {
        refusal = "utxo-view-db-no-best-block";
        return std::nullopt;
    }

    UtxoSetHasher hasher(best_block, opts);
    std::string bad;
    const bool scan_ok = store.for_each_prefix(
        std::string(1, 'C'),
        [&](const std::string& key, const std::vector<uint8_t>& value) {
            if (key.size() != 37) {
                bad = "utxo-view-db-bad-key size=" + std::to_string(key.size());
                return false;
            }
            Outpoint op = key_to_outpoint(key.substr(1));
            Coin coin;
            if (!decode_view_db_coin(value, coin)) {
                bad = "utxo-view-db-bad-coin " + op.txid.GetHex() + ":" + std::to_string(op.index);
                return false;
            }
            return hasher.add(op, coin);
        });
    if (!scan_ok) {
        refusal = "utxo-view-db-scan-failed";
        return std::nullopt;
    }
    if (!bad.empty()) {
        refusal = bad;
        return std::nullopt;
    }
    auto hashes = hasher.finalize();
    if (!hashes) {
        refusal = hasher.refusal();
        return std::nullopt;
    }
    out.hashes = *hashes;
    return out;
}

} // namespace core::coin
