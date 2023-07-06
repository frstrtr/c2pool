#pragma once

#include <string>
#include <shared_mutex>
#include <mutex>
#include <nlohmann/json.hpp>

// Метрики изменяются только там, где они созданы и(или) там, куда их передали, после создания.
// Сам WebInterface использует базовый класс Metric, которого интересует лишь результат в виде json.

class Metric
{
protected:
    mutable std::shared_mutex mutex_;
    nlohmann::json j{};

public:
    virtual nlohmann::json get()
    {
        std::shared_lock lock(mutex_);
        return j;
    }
};