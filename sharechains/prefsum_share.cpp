#include "prefsum_share.h"

#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include "share.h"
#include <deque>

using namespace std;

namespace c2pool::shares::tracker
{
    void PrefixSumShare::reverse_add(uint256 hash, deque<PrefixSumShareElement>::iterator _it)
    {
        _reverse[hash] = _it;
    }

    void PrefixSumShare::reverse_remove(uint256 hash)
    {
        _reverse.erase(hash);
    }

    void PrefixSumWeights::reverse_add(uint256 hash, deque<PrefixSumWeightsElement>::iterator _it)
    {
        _reverse[hash] = _it;
    }

    void PrefixSumWeights::reverse_remove(uint256 hash)
    {
        _reverse.erase(hash);
    }

    PrefixSumWeightsElement::PrefixSumWeightsElement(shared_ptr<c2pool::shares::share::BaseShare> share)
    {
        hash = share->hash;
        auto att = UintToArith256(coind::data::target_to_average_attempts(share->target));

        weights = {{share->new_script, att * (65535 - share->donation)}};
        total_weight = att * 65535;
        total_donation_weight = att * share->donation;

        my_weights = weights;
        my_total_weight = total_weight;
        my_total_donation_weight = total_donation_weight;
    }
}