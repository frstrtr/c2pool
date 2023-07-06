#pragma once
#include "metric.h"

class MetricValue : public Metric
{
public:
    MetricValue() = default;

    template <typename T>
    explicit MetricValue(const T& value)
    {
        set(value);
    }

    template <typename T>
    explicit MetricValue(T&& value)
    {
        set(value);
    }

    template<typename T>
    void set(T value)
    {
        std::unique_lock lock(mutex_);
        j = value;
    }
};

class MetricValues : public Metric
{
public:
    MetricValues() = default;

    explicit MetricValues(nlohmann::json&& json)
    {
        std::unique_lock lock(mutex_);
        j = json;
    }

    template<typename T>
    void set(const std::string& field_name, T value)
    {
        std::unique_lock lock(mutex_);
        j[field_name] = value;
    }
};
