#pragma once
#include <memory>
#include <map>
#include <tuple>
#include <optional>
#include <boost/asio.hpp>

template <typename Key, typename Value>
class expiring_dict
{
private:
    const boost::posix_time::time_duration expiry_time;
    boost::asio::io_context* context;
    std::map<Key, std::tuple<Value, std::shared_ptr<boost::asio::deadline_timer>>> values;
public:
    expiring_dict(boost::asio::io_context* _context, int32_t expiry_seconds) 
        : context(_context), expiry_time(boost::posix_time::seconds(expiry_seconds)) 
    {
    }

    ~expiring_dict()
    {
        for (auto& [key, value_] : values)
        {
            auto& [value, timer] = value_;
            timer->cancel();
        }
    }

    void add(Key key, Value value)
    {
        auto _timer = std::make_shared<boost::asio::deadline_timer>(*context);
        _timer->expires_from_now(expiry_time);
        _timer->async_wait(
            [&, _key = key](const boost::system::error_code &ec) 
            {
                values.erase(_key);
            }
        );

        values[key] = {value, _timer};
    }

    std::optional<Value> get(Key key)
    {
        if (values.count(key))
            return {std::get<0>(values.at(key))};
        else
            return std::nullopt;
    }

    bool exist(Key key) const
    {
        return values.count(key);
    }
};