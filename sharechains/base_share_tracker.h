#pragma once
#include "tree_tracker/tracker.h"
#include "tree_tracker/rules.h"
#include "prefsum_weights.h"

class BaseTrackerElement : public BaseSumElement<ShareType, BaseTrackerElement, uint256>
{
public:
    value_type share;

    shares::TreeRulesElement rules;
    arith_uint288 work;
    arith_uint288 min_work;
    shares::weight::weight_data weight;
    uint64_t height;

public:

    hash_type hash() const override
    {
        return share ? share->hash : uint256::ZERO;
    }

    hash_type prev() const override
    {
        return share ? *share->previous_hash : uint256::ZERO;
    }

    BaseTrackerElement()
    {
        height = 0;
//        work = uint256::ZERO;
//        min_work = uint256::ZERO;
//        weight = {};
    }

    BaseTrackerElement(const value_type& _share) : share(_share)
    {
        height = 1;
        work = coind::data::target_to_average_attempts(_share->target);
        min_work = coind::data::target_to_average_attempts(_share->max_target);
        weight = shares::weight::weight_data(_share);
    }

    BaseTrackerElement(hash_type hash)
    {
        height = 0;
//        work = uint256::ZERO;
//        min_work = uint256::ZERO;
//        weight = {};
    }

    sum_element_type& add(const sum_element_type& value) override
    {
        height += value.height;
        work += value.work;
        min_work += value.min_work;
        weight += value.weight;
        rules += value.rules;
        return *this;
    }

    sum_element_type& sub(const sum_element_type& value) override
    {
        height -= value.height;
        work -= value.work;
        min_work -= value.min_work;
        weight -= value.weight;
        rules -= value.rules;
        return *this;
    }
};

class BaseShareTracker : public Tracker<BaseTrackerElement>
{
public:
    BaseShareTracker() : Tracker<BaseTrackerElement>() {}

    uint256 get_work(uint256 hash)
    {
        return ArithToUint256(get_sum_to_last(hash).sum.work);
    }
};

class VerifiedShareTracker : public BaseShareTracker
{
protected:
    BaseShareTracker &_share_tracker;
public:
    VerifiedShareTracker(BaseShareTracker &share_tracker) : BaseShareTracker(), _share_tracker(share_tracker)
    {
    }

    hash_type get_nth_parent_key(hash_type hash, int32_t n) const override
    {
        return _share_tracker.get_nth_parent_key(hash, n);
    }
};
