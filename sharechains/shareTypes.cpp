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

} // namespace c2pool::shares