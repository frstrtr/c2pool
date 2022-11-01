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
    protected:
        SharePrefsumElement &_push(const SharePrefsumElement &sub) override
        {
            work += sub.work;
            weight += sub.weight;
            doa += sub.doa;
            return *this;
        }

        SharePrefsumElement &_erase(const SharePrefsumElement &sub) override
        {
            work -= sub.work;
            weight -= sub.weight;
            doa -= sub.doa;
            return *this;
        }
    public:
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
            weight = weight::weight_element_type(value);
            doa = doa_element_type(value);
        }
    };

    class SharePrefsum2 : public Prefsum<SharePrefsumElement>
    {
    public:
        element_type& _make_element(element_type& element, const value_type &value) override
        {
            return element;
        }

        element_type& _none_element(element_type& element, const key_type& key) override
        {
            element.head = key;
            element.tail = key;
            return element;
        }

    public:
        uint256 get_work(uint256 hash)
        {
            return ArithToUint256(get_sum_to_last(hash).work);
        }
    };

    class VerifiedSharePrefsum2 : public SharePrefsum2
    {
    protected:
        SharePrefsum2 &_prefsum_share;

    public:
        VerifiedSharePrefsum2(SharePrefsum2 &prefsum_share) : SharePrefsum2(), _prefsum_share(prefsum_share)
        {
        }

        key_type get_nth_parent_key(key_type key, int32_t n) override
        {
            return _prefsum_share.get_nth_parent_key(key, n);
        }
    }
}