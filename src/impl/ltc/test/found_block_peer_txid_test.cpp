// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// #946 peer found-block rows: coinbase_txid = ltc::derive_gentx_hash(share).
//
// Non-circular: the derived gentx hash is folded through the share's own
// merkle link into an 80-byte header, and that header's scrypt PoW must meet
// the share target. A wrong txid (wrong identifier, ref_hash or hash_link
// resume) cannot satisfy the target by chance. Corpus = the real v35 LTC
// testnet share share_test.cpp / wirecompat_runtime_test.cpp already use.
// The v33 corpus share is left out: share_init_verify itself rejects its PoW
// under the current testnet params, so it cannot anchor this check.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <span>
#include <string>

#include <core/uint256.hpp>
#include <sharechain/sharechain.hpp>
#include <impl/ltc/params.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_check.hpp>

namespace {

const char* PEER_TXID_TYPE35 =
    "23fd9601fe00000020654f11363698fc9a54e43f126f294bd1a33b650148e8b6bb532fc08500cb6966e8103066140b041db0022a77e3af9c1de80a16583bed2a6179b63ed410b890b113cfd0fcd68bafa4096779b90503fd823100731a92d3226d6839617a4b44785235374766374a575a756e6e43324a7a37325351747746544b68dec14025000000000000fe2302a41fb37f52f6747afbbeae61462feaa40b8b3655f8fb7af60843111101ec5f958e93b9a76bb46536bf807b1caef9635f432d982bd907eb5050130b6ec00aeabc2bb9ca34c5f1ba0bd332fc3d217d9853754fe42797e32cf9ddddcab6f66ab8056f1b64efa2157281c406fc6a5d9de6db5e2adf63c86646a4edc91c51f86d74c707c0221e8828011ef310306675b3210073990593df0d00000000000000000000000100000000000000c357550d5a390b342f665a3d853c039a626b803bb37976c20ba0b5ee5a56fceedc0220e67c088987582af73218c99820276bbf0004c5c18f7dd691f9c4326bfd9930d5567a6d109fec00f4eca887c42e80ddaa57df9bda8db8b277110a50a9a268b6";

// Header PoW (scrypt) of the block the derived coinbase txid implies.
template <typename ShareT>
uint256 pow_from_derived_txid(const ShareT& share, const core::CoinParams& params)
{
    const uint256 txid = ltc::derive_gentx_hash(share, params);
    uint256 merkle_root = ltc::check_merkle_link(txid, share.m_merkle_link);
    if constexpr (requires { share.m_segwit_data; }) {
        if constexpr (ShareT::version >= ltc::SEGWIT_ACTIVATION_VERSION) {
            if (share.m_segwit_data.has_value())
                merkle_root = ltc::check_merkle_link(txid, share.m_segwit_data->m_txid_merkle_link);
        }
    }
    PackStream hdr;
    hdr << static_cast<uint32_t>(share.m_min_header.m_version);
    hdr << share.m_min_header.m_previous_block;
    hdr << merkle_root;
    hdr << share.m_min_header.m_timestamp;
    hdr << share.m_min_header.m_bits;
    hdr << share.m_min_header.m_nonce;
    return params.pow_func(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(hdr.data()), hdr.size()));
}

void expect_txid_meets_share_target(const char* hex)
{
    PackStream stream;
    stream.from_hex(hex);
    chain::RawShare rshare;
    stream >> rshare;
    auto share = ltc::load_share(rshare, NetService{"0.0.0.0", 0});
    const auto params = ltc::make_coin_params(true);

    share.ACTION({
        const uint256 txid = ltc::derive_gentx_hash(*obj, params);
        EXPECT_FALSE(txid.IsNull());
        const uint256 pow = pow_from_derived_txid(*obj, params);
        const uint256 target = chain::bits_to_target(obj->m_bits);
        EXPECT_LE(pow, target) << "derived coinbase txid " << txid.GetHex()
                               << " does not reproduce the share's PoW";
    });
}

} // namespace

TEST(LTC_found_block_peer_txid, type35_derived_txid_reproduces_pow)
{
    expect_txid_meets_share_target(PEER_TXID_TYPE35);
}
