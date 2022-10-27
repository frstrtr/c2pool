#pragma once

#include "share.h"
#include "prefsum_weights.h"
#include "prefsum_doa.h"
#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <libdevcore/prefsum.h>

namespace shares
{
    class SharePrefsumElement : public BasePrefsumElement<uint256, ShareType, SharePrefsumElement>
    {
    public:
        int32_t height;
        arith_uint256 work;
        arith_uint256 min_work;
        weight::weight_element_type weight;
        doa_element_type doa;

        SharePrefsumElement() : BasePrefsumElement<uint256, ShareType, SharePrefsumElement>()
        {}

        SharePrefsumElement(ShareType data)
        { set_value(data); }

        bool is_none() override
        {
            return ArithToUint256(work).IsNull() && ArithToUint256(min_work).IsNull() &&
                   height == 0;
        }

        void set_value(value_type value) override
        {
            head = value->hash;
            tail = *value->previous_hash;

            work = coind::data::target_to_average_attempts(value->target);
            min_work = coind::data::target_to_average_attempts(value->max_target);
            height = 1;
            weight = weight::weight_element_type(value);
            doa = doa_element_type(value);
        }

        SharePrefsumElement &push(SharePrefsumElement sub) override
        {
            if (tail != sub.head)
                throw std::invalid_argument("tail != sub.head");

            tail = sub.tail;

            work += sub.work;
            height += sub.height;
            weight += sub.weight;
            doa += sub.doa;
            return *this;
        }
    };

    class SharePrefsum2 : public Prefsum<SharePrefsumElement>
    {
    public:
        element_type make_element(value_type value) override
        {
            element_type element {value};
            element.prev = sum.find(*value->previous_hash);
            return element;
        }

        element_type none_element(key_type value) override
        {
            element_type element;
            element.head = value;
            element.tail = value;
            return element;
        }

    public:
        uint256 get_work(uint256 hash)
        {
            return ArithToUint256(get_sum_to_last(hash).work);
        }
    };
}