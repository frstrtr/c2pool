#pragma once

#include <string>
#include <shared_mutex>
#include <unordered_map>

class NetDataField
{
    std::shared_mutex mutex_;

    std::unordered_map<std::string, std::string> data; // key -- variable name; value -- json value
public:

    std::string get(const std::string& var_name)
    {
        std::shared_lock lock(mutex_);
        //TODO: throw WebNotFound?
        return data.count(var_name) ? data.at(var_name) : "";
    }

    void set(const std::string &var_name, const std::string &value)
    {
        std::unique_lock lock(mutex_);
        data[var_name] = value;
    }
};