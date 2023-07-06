#pragma once

#include "metric.h"

#include <functional>

class MetricGetter : public Metric
{
    typedef std::function<void(nlohmann::json& j)> func_type;
private:
    func_type func_;
public:
    explicit MetricGetter(func_type func) : func_(std::move(func)){}

    nlohmann::json get() override
    {
        std::shared_lock lock(mutex_);
        if (func_)
            func_(j);
        return j;
    }
};