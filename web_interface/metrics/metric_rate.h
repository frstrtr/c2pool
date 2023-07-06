#pragma once

#include "metric.h"
#include <list>


template <typename T, unsigned int Size = 0>
class MetricRateTime : public Metric
{
    static constexpr int max_size = Size;

    struct TimestampData
    {
        T data;
        int timestamp;
    };

    std::list<TimestampData> datas;
    T sum{};

public:
    inline auto size_check() const
    {
        return (max_size != 0) && (datas.size() == max_size);
    }

    void add(const T& value, int timestamp)
    {
        std::unique_lock lock(mutex_);
        if (size_check())
        {
            sum -= datas.front().data;
            datas.pop_front();
        }

        sum += value;
        datas.push_back({value, timestamp});

        auto _timestamp = timestamp - datas.front().timestamp;
        j = sum / (_timestamp > 0 ? _timestamp : 1);
    }

    void add(T&& value, int timestamp)
    {
        add(value, timestamp);
    }
};