#include "math.h"

namespace c2pool::math{
    string natural_to_string(uint256 n)
    {
        auto s = n.GetHex();
        if (s.length() % 2)
        {
            s = string("0") + s;
        }
        return s;
    }
}