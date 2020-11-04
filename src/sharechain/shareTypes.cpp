#include <uint256.h>
#include <shareTypes.h>
#include <iostream>
#include <string>

//HashLinkType
namespace c2pool::shares
{
    HashLinkType::HashLinkType(std::string _state, std::string _extra_data, unsigned long long length)
    {
        state = _state;
        extra_data = _extra_data;
    }

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

    bool operator==(const HashLinkType &first, const HashLinkType &second)
    {
        if (first.state != second.state)
            return false;
        if (first.extra_data != second.extra_data)
            return false;
        if (first.length != second.length)
            return false;
        return true;
    }

    bool operator!=(const HashLinkType &first, const HashLinkType &second)
    {
        return !(first == second);
    }

} // namespace c2pool::shares

//TODO: MerkleLink
namespace c2pool::shares
{
    MerkleLink::MerkleLink(std::vector<uint256> _branch, int _index)
    {
        branch = _branch;
        index = _index;
    }

    std::istream &operator>>(std::istream &is, MerkleLink &value)
    {
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
        os << value.branch.size() << ",";
        for (int i = 0; i < value.branch.size(); i++)
        {
            os << value.branch[i] << ",";
        }
        os << value.index;
        return os;
    }

} // namespace c2pool::shares

//TODO: SmallBlockHeaderType
namespace c2pool::shares
{
    SmallBlockHeaderType::SmallBlockHeaderType(unsigned long long _version, uint256 _previousBlock, unsigned int _timeStamp, unsigned int _bits, unsigned int _nonce)
    {
        version = _version;
        previousBlock = _previousBlock;
        timeStamp = _timeStamp;
        bits = _bits;
        nonce = _nonce;
    };

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
    ShareData::ShareData(uint256 _previous_share_hash, std::string _coinbase, unsigned int _nonce, uint160 _pubkey_hash, unsigned long long _subsidy, unsigned short _donation, StaleInfo _stale_info, unsigned long long _desired_version)
    {
        previous_share_hash = _previous_share_hash;
        coinbase = _coinbase;
        nonce = _nonce;
        pubkey_hash = _pubkey_hash;
        subsidy = _subsidy;
        donation = _donation;
        stale_info = _stale_info;
        desired_version = _desired_version;
    };

    std::istream &operator>>(std::istream &is, ShareData &value)
    {

        is >> value.previous_share_hash >> value.coinbase >> value.nonce >> value.pubkey_hash >> value.subsidy >> value.donation;

        int stale_info_int;
        is >> stale_info_int;
        value.stale_info = (StaleInfo)stale_info_int;

        is >> value.desired_version;
        return is;
    }

    std::ostream &operator<<(std::ostream &os, const ShareData &value)
    {
        os << value.previous_share_hash.GetHex() << "," << value.coinbase << "," << value.nonce << "," << value.pubkey_hash.GetHex() << "," << value.subsidy << "," << value.donation << "," << value.stale_info << "," << value.desired_version;
        return os;
    }

} // namespace c2pool::shares

//TODO: SegwitData
namespace c2pool::shares
{
    SegwitData::SegwitData(std::shared_ptr<MerkleLink> _txid_merkle_link, uint256 _wtxid_merkle_root)
    {
        txid_merkle_link = _txid_merkle_link;
        wtxid_merkle_root = _wtxid_merkle_root;
    };

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
    TransactionHashRef::TransactionHashRef(unsigned long long _share_count, unsigned long long _tx_count)
    {
        share_count = _share_count;
        tx_count = _tx_count;
    };

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
    ShareInfoType::ShareInfoType(std::shared_ptr<ShareData> _share_data, std::vector<uint256> _new_transaction_hashes, std::vector<TransactionHashRef> _transaction_hash_refs, uint256 _far_share_hash, unsigned int _max_bits, unsigned int _bits, unsigned int _timestamp, unsigned long _absheigth, uint128 _abswork, std::shared_ptr<SegwitData> _segwit_data)
    {
        share_data = _share_data;
        segwit_data = _segwit_data;
        new_transaction_hashes = _new_transaction_hashes;
        transaction_hash_refs = _transaction_hash_refs;
        far_share_hash = _far_share_hash;
        max_bits = _max_bits;
        bits = _bits;
        timestamp = _timestamp;
        absheigth = _absheigth;
        abswork = _abswork;
    };

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

        os << "," << value.new_transaction_hashes.size();
        for (int i = 0; i < value.new_transaction_hashes.size(); i++)
        {
            os << "," << value.new_transaction_hashes[i];
        }

        os << "," << value.transaction_hash_refs.size();
        for (int i = 0; i < value.new_transaction_hashes.size(); i++)
        {
            os << "," << value.transaction_hash_refs[i];
        }

        os << "," << value.far_share_hash << "," << value.max_bits << "," << value.bits << "," << value.timestamp << "," << value.absheigth << "," << value.abswork;
        return os;
    }

} // namespace c2pool::shares

//TODO: ShareType
namespace c2pool::shares
{
    ShareType::ShareType(std::shared_ptr<SmallBlockHeaderType> _min_header, std::shared_ptr<ShareInfoType> _share_info, std::shared_ptr<MerkleLink> _ref_merkle_link, unsigned long long _last_txout_nonce, std::shared_ptr<HashLinkType> _hash_link, std::shared_ptr<MerkleLink> _merkle_link)
    {
        min_header = _min_header;
        share_info = _share_info;
        ref_merkle_link = _ref_merkle_link;
        last_txout_nonce = _last_txout_nonce;
        hash_link = _hash_link;
        merkle_link = _merkle_link;
    };

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
    RefType::RefType(std::string _identifier, std::shared_ptr<ShareInfoType> _share_info)
    {
        identifier = _identifier;
        share_info = _share_info;
    };

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

namespace c2pool::shares
{
    std::istream &operator>>(std::istream &is, RawShare &value)
    {
        is >> value.type >> value.contents;
        return is;
    }

    std::ostream &operator<<(std::ostream &os, const RawShare &value)
    {
        os << value.type << "," << value.contents;
        return os;
    }
} // namespace c2pool::shares
