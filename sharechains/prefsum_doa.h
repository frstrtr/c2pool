#pragma once

#include <memory>
#include <map>
#include <list>
#include <vector>

#include <btclibs/uint256.h>

#include "share.h"
//#include <libcoind/data.h>

namespace shares
{

    // TODO: test
    class doa_element_type
    {
    private:
        // Правила добавления данных в prefsum.
        static bool rules;
        static std::function<std::tuple<int32_t, int32_t, int32_t, int32_t>(ShareType)> _rules_func;
    public:
        int32_t my_count;
        int32_t my_doa_count;
        int32_t my_orphan_announce_count;
        int32_t my_dead_announce_count;
    public:
        static void set_rules(std::function<std::tuple<int32_t, int32_t, int32_t, int32_t>(ShareType)> _rule)
        {
            doa_element_type::_rules_func = std::move(_rule);
            doa_element_type::rules = true;
        }

        static std::tuple<int32_t, int32_t, int32_t, int32_t> get_rules(ShareType share)
        {
            if (doa_element_type::rules)
                return _rules_func(share);
            else
            {
                LOG_WARNING << "EMPTY RULES IN doa_element_type!";
                return std::make_tuple<int32_t, int32_t, int32_t, int32_t>(0, 0, 0, 0);
            }
        }
    public:
        doa_element_type() = default;

        doa_element_type(ShareType share)
        {
            auto [count, doa_count, orphan_announce_count, dead_announce_count] = get_rules(share);
            my_count = count;
            my_doa_count = doa_count;
            my_orphan_announce_count = orphan_announce_count;
            my_dead_announce_count = dead_announce_count;
        }

        doa_element_type operator+(const doa_element_type &el)
        {
            doa_element_type res = *this;

            res.my_count += el.my_count;
            res.my_doa_count += el.my_doa_count;
            res.my_orphan_announce_count += el.my_orphan_announce_count;
            res.my_dead_announce_count += el.my_dead_announce_count;

            return res;
        }

        doa_element_type operator-(const doa_element_type &el)
        {
            doa_element_type res = *this;

            res.my_count -= el.my_count;
            res.my_doa_count -= el.my_doa_count;
            res.my_orphan_announce_count -= el.my_orphan_announce_count;
            res.my_dead_announce_count -= el.my_dead_announce_count;

            return res;
        }

        doa_element_type &operator+=(const doa_element_type &el)
        {
            this->my_count += el.my_count;
            this->my_doa_count += el.my_doa_count;
            this->my_orphan_announce_count += el.my_orphan_announce_count;
            this->my_dead_announce_count += el.my_dead_announce_count;

            return *this;
        }

        doa_element_type &operator-=(const doa_element_type &el)
        {
            this->my_count -= el.my_count;
            this->my_doa_count -= el.my_doa_count;
            this->my_orphan_announce_count -= el.my_orphan_announce_count;
            this->my_dead_announce_count -= el.my_dead_announce_count;

            return *this;
        }
    };
}