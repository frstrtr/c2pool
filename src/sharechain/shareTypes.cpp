#include <uint256.h>
#include <shareTypes.h>
#include <iostream>
#include <string>

//HashLinkType
namespace c2pool::shares
{
    std::istream &operator>>(std::istream &is, HashLinkType &value)
    {
        is >> value.state >> value.extra_data >> value.length;
        return is;
    }

    std::ostream &operator<<(std::ostream &os, const HashLinkType &value)
    {
        os << value.state << "," << value.extra_data << "," << value.length;
        return os;
    }

} // namespace c2pool::shares

//TODO: MerkleLink
namespace c2pool::shares
{
    std::istream &operator>>(std::istream &is, MerkleLink &value)
    {
        //TODO:value.branch
        is >> value.branch >> value.index;
        return is;
    }

    std::ostream &operator<<(std::ostream &os, const MerkleLink &value)
    {
        //TODO:value.branch
        os << value.branch << "," << value.index;
        return os;
    }

} // namespace c2pool::shares

//TODO: SmallBlockHeaderType
namespace c2pool::shares
{
    std::istream &operator>>(std::istream &is, SmallBlockHeaderType &value)
    {
        is >> value.version >> value.previousBlock >> value.timeStamp >> value.bits >> value.nonce;
        return is;
    }

    std::ostream &operator<<(std::ostream &os, const SmallBlockHeaderType &value)
    {
        os << value.version << "," << value.previousBlock << "," << value.timeStamp << "," << value.bits << "," << value.nonce;
        return os;
    }

} // namespace c2pool::shares

//TODO: ShareData
namespace c2pool::shares
{
    std::istream &operator>>(std::istream &is, ShareData &value)
    {
        is >> value.previous_share_hash >> value.coinbase >> value.nonce >> value.pubkey_hash >> value.subsidy >> value.donation >> value.stale_info >> value.desired_version;
        return is;
    }

    std::ostream &operator<<(std::ostream &os, const ShareData &value)
    {
        os << value.previous_share_hash << "," << value.coinbase << "," << value.nonce << "," << value.pubkey_hash << "," << value.subsidy << "," << value.donation << "," << value.stale_info << "," << value.desired_version;
        return os;
    }

} // namespace c2pool::shares

//TODO: SegwitData
namespace c2pool::shares
{
    std::istream &operator>>(std::istream &is, SegwitData &value)
    {
        is >> value.txid_merkle_link >> value.wtxid_merkle_root;
        return is;
    }

    std::ostream &operator<<(std::ostream &os, const SegwitData &value)
    {
        os << value.txid_merkle_link << "," << value.wtxid_merkle_root;
        return os;
    }

} // namespace c2pool::shares

//TODO: ShareInfoType
namespace c2pool::shares
{
    std::istream &operator>>(std::istream &is, ShareInfoType &value)
    {
        is >> value.share_data >> value.segwit_data >> value.new_transaction_hashes >> value.transaction_hash_refs >> value.far_share_hash >> value.max_bits >> value.bits >> value.timestamp >> value.absheigth >> value.abswork;
        return is;
    }

    std::ostream &operator<<(std::ostream &os, const ShareInfoType &value)
    {
        os << value.share_data << "," << value.segwit_data << "," << value.new_transaction_hashes << "," << value.transaction_hash_refs << "," << value.far_share_hash << "," << value.max_bits << "," << value.bits << "," << value.timestamp << "," << value.absheigth << "," << value.abswork;
        return os;
    }

} // namespace c2pool::shares

//TODO: ShareType
namespace c2pool::shares
{
    std::istream &operator>>(std::istream &is, ShareType &value)
    {
        is >> value.min_header >> value.share_info >> value.ref_merkle_link >> value.last_txout_nonce >> value.hash_link >> value.merkle_link;
        return is;
    }

    std::ostream &operator<<(std::ostream &os, const ShareType &value)
    {
        os << value.min_header << "," << value.share_info << "," << value.ref_merkle_link << "," << value.last_txout_nonce << "," << value.hash_link << "," << value.merkle_link;
        return os;
    }

} // namespace c2pool::shares

//TODO: RefType
namespace c2pool::shares
{
    std::istream &operator>>(std::istream &is, RefType &value)
    {
        is >> value.identifier >> value.share_info;
        return is;
    }

    std::ostream &operator<<(std::ostream &os, const RefType &value)
    {
        os << value.txid_merkle_link << "," << value.wtxid_merkle_root;
        return os;
    }

} // namespace c2pool::shares