#include "math.hpp"

#include <btclibs/util/strencodings.h>

namespace c2pool
{

namespace math
{

    std::vector<unsigned char> natural_to_string(uint256 n)
    {
        auto s = n.GetHex();
        int pos = 0;
        while (s[pos] == '0' && pos < s.size())
            pos++;
        s.erase(0, pos);
        if (s.length() % 2)
        {
            s = std::string("0") + s;
        }
        return ParseHex(s);
    }

} // namespace math

} // namespace c2pool