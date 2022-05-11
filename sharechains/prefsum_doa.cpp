#include "prefsum_doa.h"

namespace shares
{
    bool doa_element_type::rules = 0;

    std::function<std::tuple<int32_t, int32_t, int32_t, int32_t>(ShareType)> doa_element_type::_rules_func;
}