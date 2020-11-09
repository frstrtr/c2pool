#include <uint256.h>
#include <shareTypes.h>
#include <iostream>
#include <string>

//HashLinkType
namespace c2pool::shares
{
    HashLinkType::HashLinkType(std::string _state, std::string _extra_data, unsigned long long _length)
    {
        state = _state;
        extra_data = _extra_data;
        length = _length;
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

    bool operator==(const MerkleLink &first, const MerkleLink &second)
    {
        if (first.branch.size() == second.branch.size())
        {
            for (int i = 0; i < first.branch.size(); i++)
            {
                if (first.branch[i].Compare(second.branch[i]) != 0)
                {
                    return false;
                }
            }
        }
        else
        {
            return false;
        }

        if (first.index != second.index)
            return false;
        return true;
    }

    bool operator!=(const MerkleLink &first, const MerkleLink &second)
    {
        return !(first == second);
    }

} // namespace c2pool::shares

//TODO: SmallBlockHeaderType
namespace c2pool::shares
{
    SmallBlockHeaderType::SmallBlockHeaderType(unsigned long long _version, uint256 _previousBlock, unsigned int _timeStamp, unsigned int _bits, unsigned int _nonce)
    {
        version = _version;
        previous_block = _previousBlock;
        timestamp = _timeStamp;
        bits = _bits;
        nonce = _nonce;
    };

    std::istream &operator>>(std::istream &is, SmallBlockHeaderType &value)
    {
        is >> value.version >> value.previous_block >> value.timestamp >> value.bits >> value.nonce;
        return is;
    }

    std::ostream &operator<<(std::ostream &os, const SmallBlockHeaderType &value)
    {
        os << value.version << "," << value.previous_block << "," << value.timestamp << "," << value.bits << "," << value.nonce;
        return os;
    }

    bool operator==(const SmallBlockHeaderType &first, const SmallBlockHeaderType &second)
    {
        if (first.version != second.version)
            return false;
        if (first.previous_block.Compare(second.previous_block) != 0)
            return false;
        if (first.timestamp != second.timestamp)
            return false;
        if (first.bits != second.bits)
            return false;
        if (first.nonce != second.nonce)
            return false;
        return true;
    }

    bool operator!=(const SmallBlockHeaderType &first, const SmallBlockHeaderType &second)
    {
        return !(first == second);
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

    bool operator==(const ShareData &first, const ShareData &second)
    {
        if (first.previous_share_hash.Compare(second.previous_share_hash) != 0)
            return false;

        if (first.coinbase != second.coinbase)
            return false;

        if (first.nonce != second.nonce)
            return false;

        if (first.pubkey_hash.Compare(second.pubkey_hash) != 0)
            return false;

        if (first.subsidy != second.subsidy)
            return false;

        if (first.donation != second.donation)
            return false;

        if (first.stale_info != second.stale_info)
            return false;

        if (first.desired_version != second.desired_version)
            return false;

        return true;
    }

    bool operator!=(const ShareData &first, const ShareData &second)
    {
        return !(first == second);
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

    bool operator==(const SegwitData &first, const SegwitData &second)
    {
        if (first.wtxid_merkle_root.Compare(second.wtxid_merkle_root) != 0)
            return false;

        if (*first.txid_merkle_link != *second.txid_merkle_link)
            return false;

        return true;
    }

    bool operator!=(const SegwitData &first, const SegwitData &second)
    {
        return !(first == second);
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

    bool operator==(const TransactionHashRef &first, const TransactionHashRef &second)
    {
        if (first.share_count != second.share_count)
            return false;

        if (first.tx_count != second.tx_count)
            return false;

        return true;
    }

    bool operator!=(const TransactionHashRef &first, const TransactionHashRef &second)
    {
        return !(first == second);
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

    bool operator==(const ShareInfoType &first, const ShareInfoType &second)
    {
        if (*first.share_data != *second.share_data)
            return false;

        if (*first.segwit_data != *second.segwit_data)
            return false;

        if (first.new_transaction_hashes.size() == second.new_transaction_hashes.size())
        {
            for (int i = 0; i < first.new_transaction_hashes.size(); i++)
            {
                if (first.new_transaction_hashes[i].Compare(second.new_transaction_hashes[i]) != 0)
                {
                    return false;
                }
            }
        }
        else
        {
            return false;
        }

        if (first.transaction_hash_refs.size() == second.transaction_hash_refs.size())
        {
            for (int i = 0; i < first.transaction_hash_refs.size(); i++)
            {
                if (first.transaction_hash_refs[i] != second.transaction_hash_refs[i])
                {
                    return false;
                }
            }
        }
        else
        {
            return false;
        }

        if (first.far_share_hash.Compare(second.far_share_hash) != 0)
        {
            return false;
        }

        if (first.max_bits != second.max_bits)
            return false;
        if (first.bits != second.bits)
            return false;
        if (first.timestamp != second.timestamp)
            return false;
        if (first.absheigth != second.absheigth)
            return false;

        if (first.abswork.Compare(second.abswork) != 0)
        {
            return false;
        }

        return true;
    }

    bool operator!=(const ShareInfoType &first, const ShareInfoType &second)
    {
        return !(first == second);
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

    bool operator==(const ShareType &first, const ShareType &second)
    {
        if (*first.min_header != *second.min_header)
            return false;

        if (*first.share_info != *second.share_info)
            return false;

        if (*first.ref_merkle_link != *second.ref_merkle_link)
            return false;

        if (first.last_txout_nonce != second.last_txout_nonce)
            return false;

        if (*first.hash_link != *second.hash_link)
            return false;

        if (*first.merkle_link != *second.merkle_link)
            return false;

        return true;
    }

    bool operator!=(const ShareType &first, const ShareType &second)
    {
        return !(first == second);
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

    bool operator==(const RefType &first, const RefType &second)
    {
        if (first.identifier != second.identifier)
            return false;

        if (*first.share_info != *second.share_info)
            return false;

        return true;
    }

    bool operator!=(const RefType &first, const RefType &second)
    {
        return !(first == second);
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

    bool operator==(const RawShare &first, const RawShare &second)
    {
        if (first.type != second.type)
            return false;

        if (first.contents != second.contents)
            return false;

        return true;
    }

    bool operator!=(const RawShare &first, const RawShare &second)
    {
        return !(first == second);
    }
} // namespace c2pool::shares
