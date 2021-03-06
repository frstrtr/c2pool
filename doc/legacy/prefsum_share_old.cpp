#include "prefsum_share.h"

#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <cstring>

using namespace std;

namespace c2pool::shares
{
    //PrefsumWeightsElement::PrefsumWeightsElement(shared_ptr<c2pool::shares::BaseShare> share)
    PrefsumWeightsElement::PrefsumWeightsElement(uint256 hash, uint256 target, char* new_script, uint256 donation)
    {
        // share->hash; share->target; share->donation; share->new_script; share->donation
        arith_uint256 _donation = UintToArith256(donation);

        hash = hash;
        auto att = UintToArith256(coind::data::target_to_average_attempts(target));

        char* new_script_copy = new char[strlen(new_script)];
        strcpy(new_script_copy, new_script);

        weights = {{new_script_copy, att * (65535 - _donation)}};
        total_weight = att * 65535;
        total_donation_weight = att * _donation;

        my_weights = weights;
        my_total_weight = total_weight;
        my_total_donation_weight = total_donation_weight;
    }
}