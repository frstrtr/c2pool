#pragma once

#include "metric.h"

template <typename T, unsigned int Size = 0>
class MetricSum : public Metric
{
    static constexpr int max_size = Size;

    nlohmann::json& array;
    nlohmann::json& sum;

    T sum_value;
public:

    MetricSum() : array(j["array"] = std::vector<T>{}), sum_value(), sum(j["sum"] = sum_value)
    {
    }

    inline auto size_check() const
    {
        return (max_size != 0) && (array.size() == max_size);
    }

    void add(const T& value)
    {
        std::unique_lock lock(mutex_);
        if (size_check())
        {
            sum_value -= array.begin()->template get<T>();
            array.erase(array.begin());
        }

        sum_value += value;
        sum = sum_value;
        array.push_back(value);
    }

    void add(T&& value)
    {
        std::unique_lock lock(mutex_);
        if (size_check())
        {
            sum_value -= array.begin()->template get<T>();
            array.erase(array.begin());
        }

        sum_value += value;
        sum = sum_value;
        array.push_back(value);
    }

    //TODO: CAN BE OPTIMIZED!!!
    void add(std::vector<T>& arr)
    {
        for (auto& v : arr)
        {
            add(v);
        }
    }

    void add(std::vector<T>&& arr)
    {
        for (auto& v : arr)
        {
            add(v);
        }
    }

    auto size() const
    {
        std::shared_lock lock(mutex_);
        return j.size();
    }
};