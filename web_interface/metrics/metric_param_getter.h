#pragma once

#include "metric.h"

#include <functional>

class MetricParamGetter : public Metric
{
    typedef std::function<void(nlohmann::json& j, const nlohmann::json &params)> func_type;
private:
    func_type func_;
public:
    explicit MetricParamGetter(func_type func) : func_(std::move(func)){}

    nlohmann::json get() override
    {
        std::shared_lock lock(mutex_);
        return j;
    }

    nlohmann::json get(const nlohmann::json& params)
    {
        std::shared_lock lock(mutex_);
        if (func_)
            func_(j, params);
        return j;
    }
};