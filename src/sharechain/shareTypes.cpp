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
        int branch_count;
        is >> branch_count;
        for (int i = 0; i < branch_count; i++)
        {
            uint256 temp;
            is >> temp;
            value.branch.push_back(temp);
        }
        is >> value.index;
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
        value.txid_merkle_link = std::make_shared<MerkleLink>();
        is >> *value.txid_merkle_link;

        is >> value.wtxid_merkle_root;

        return is;
    }

    std::ostream &operator<<(std::ostream &os, const SegwitData &value)
    {
        os << *value.txid_merkle_link << "," << value.wtxid_merkle_root;
        return os;
    }

} // namespace c2pool::shares

//TODO: TransactionHashRef
namespace c2pool::shares
{
    std::istream &operator>>(std::istream &is, TransactionHashRef &value)
    {
        is >> value.share_count >> value.tx_count;
        return is;
    }

    std::ostream &operator<<(std::ostream &os, const TransactionHashRef &value)
    {
        os << value.share_count << "," << value.tx_count;
        return os;
    }

} // namespace c2pool::shares

//TODO: ShareInfoType
namespace c2pool::shares
{
    std::istream &operator>>(std::istream &is, ShareInfoType &value)
    {
        //share_data
        value.share_data = std::make_shared<ShareData>();
        is >> *value.share_data;
        
        //segwit_data
        value.segwit_data = std::make_shared<SegwitData>();
        is >> *value.segwit_data;
        
        //new_transaction_hashes
        int new_transaction_hashes_count;
        is >> new_transaction_hashes_count;
        for (int i = 0; i < new_transaction_hashes_count; i++)
        {
            uint256 new_transaction_hash;
            is >> new_transaction_hash;
            value.new_transaction_hashes.push_back(new_transaction_hash);
        }

        //transaction_hash_refs
        int transaction_hash_refs_count;
        is >> transaction_hash_refs_count;
        for (int i = 0; i < transaction_hash_refs_count; i++)
        {
            TransactionHashRef transaction_hash_ref;
            is >> transaction_hash_ref;
            value.transaction_hash_refs.push_back(transaction_hash_ref);
        }

        is >> value.far_share_hash >> value.max_bits >> value.bits >> value.timestamp >> value.absheigth >> value.abswork;
        return is;
    }

    std::ostream &operator<<(std::ostream &os, const ShareInfoType &value)
    {
        os << *value.share_data << "," << *value.segwit_data;

        //TODO: "<<" for vector
        os << "," << value.new_transaction_hashes << "," << value.transaction_hash_refs;
        
        os << "," << value.far_share_hash << "," << value.max_bits << "," << value.bits << "," << value.timestamp << "," << value.absheigth << "," << value.abswork;
        return os;
    }

} // namespace c2pool::shares

//TODO: ShareType
namespace c2pool::shares
{
    std::istream &operator>>(std::istream &is, ShareType &value)
    {
        //min_header
        value.min_header = std::make_shared<SmallBlockHeaderType>();
        is >> *value.min_header;
        //share_info
        value.share_info = std::make_shared<ShareInfoType>();
        is >> *value.share_info;
        //ref_merkle_link
        value.ref_merkle_link = std::make_shared<MerkleLink>();
        is >> *value.ref_merkle_link;
        //last_txout_nonce
        is >> value.last_txout_nonce;
        //hash_link
        value.hash_link = std::make_shared<HashLinkType>();
        is >> *value.hash_link;
        //merkle_link
        value.merkle_link = std::make_shared<MerkleLink>();
        is >> *value.merkle_link;

        return is;
    }

    std::ostream &operator<<(std::ostream &os, const ShareType &value)
    {
        os << *value.min_header << "," << *value.share_info << "," << *value.ref_merkle_link << "," << value.last_txout_nonce << "," << *value.hash_link << "," << *value.merkle_link;
        return os;
    }

} // namespace c2pool::shares

//TODO: RefType
namespace c2pool::shares
{
    std::istream &operator>>(std::istream &is, RefType &value)
    {
        //identifier
        is >> value.identifier;
        //share_info
        value.share_info = std::make_shared<ShareInfoType>();
        is >> *value.share_info;

        return is;
    }

    std::ostream &operator<<(std::ostream &os, const RefType &value)
    {
        os << value.identifier << "," << *value.share_info;
        return os;
    }

} // namespace c2pool::shares