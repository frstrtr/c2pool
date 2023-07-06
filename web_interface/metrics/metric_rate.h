#pragma once

#include "metric.h"
#include <list>


template <unsigned int Size, typename T>
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
    void add(const T& value, int timestamp)
    {
        std::unique_lock lock(mutex_);
        if (datas.size() == max_size)
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