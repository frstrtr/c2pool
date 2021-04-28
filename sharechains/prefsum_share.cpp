#include "prefsum_share.h"

#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
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
}