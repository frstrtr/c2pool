#include <shareTypes.h>
namespace c2pool::shares::share
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

    ShareInfo::ShareInfo(std::shared_ptr<ShareData> _share_data, std::vector<uint256> _new_transaction_hashes, std::vector<TransactionHashRef> _transaction_hash_refs, uint256 _far_share_hash, unsigned int _max_bits, unsigned int _bits, unsigned int _timestamp, unsigned long _absheigth, uint128 _abswork, std::shared_ptr<SegwitData> _segwit_data)
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

    bool operator==(const ShareInfo &first, const ShareInfo &second)
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

    bool operator!=(const ShareInfo &first, const ShareInfo &second)
    {
        return !(first == second);
    }

} // namespace c2pool::shares