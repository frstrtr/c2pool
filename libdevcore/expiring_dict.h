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
    std::shared_ptr<boost::asio::io_context> context;
    std::map<Key, std::tuple<Value, std::shared_ptr<boost::asio::deadline_timer>>> values;
public:
    expiring_dict(std::shared_ptr<boost::asio::io_context> _context, int32_t expiry_seconds) : context(_context), expiry_time(boost::posix_time::seconds(expiry_seconds)) { }

    void add(Key key, Value value)
    {
        auto _timer = std::make_shared<boost::asio::deadline_timer>(*context);
        _timer->expires_from_now(expiry_time);
        _timer->async_wait([&, _key = key](const boost::system::error_code &ec) {
            values.erase(_key);
        });

        values[key] = {value, _timer};
    }

    std::optional<Value> get(Key key)
    {
        if (values.count(key))
            return {values[key]};
        else
            return std::nullopt;
    }
};