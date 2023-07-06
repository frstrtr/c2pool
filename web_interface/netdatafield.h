#pragma once

#include <string>
#include <shared_mutex>
#include <unordered_map>

#include "webexcept.h"
#include "metrics/metric.h"
#include "metrics/metric_sum.h"
#include "metrics/metric_value.h"

#include <boost/format.hpp>

class NetDataField
{
    std::shared_mutex mutex_;

    std::unordered_map<std::string, Metric*> data; // key -- variable name; value -- json value
public:

    template <typename T>
    T get(const std::string& metric_name)
    {
        std::shared_lock lock(mutex_);
        if (data.count(metric_name))
            return data.at(metric_name)->get().get<T>();
        else
            throw WebServerError((boost::format("NetDataField try to get<%1%>(\"%2%)\"") % typeid(T).name() % metric_name).str());
    }

    nlohmann::json get(const std::string& metric_name)
    {
        std::shared_lock lock(mutex_);
        return data.count(metric_name) ? data.at(metric_name)->get() : nullptr;
    }

    Metric* get_metric(const std::string& metric_name)
    {
        std::shared_lock lock(mutex_);
        //TODO: throw WebNotFound?
        return data.count(metric_name) ? data.at(metric_name) : nullptr;
    }

    template <typename MetricType, typename... Args>
    MetricType* add(const std::string &metric_name, Args... args)
    {
        auto* metric = new MetricType(args...);
        {
            std::unique_lock lock(mutex_);
            data[metric_name] = metric;
        }
        return metric;
    }

    template <typename T>
    MetricValue* add(const std::string &metric_name, T&& value)
    {
        auto* metric = new MetricValue(value);
        {
            std::unique_lock lock(mutex_);
            data[metric_name] = metric;
        }
        return metric;
    }

    std::vector<std::string> fields()
    {
        std::vector<std::string> result;

        std::shared_lock lock(mutex_);
        result.reserve(data.size());
        for (const auto& field : data)
        {
            result.push_back(field.first);
        }
        return result;
    }
};