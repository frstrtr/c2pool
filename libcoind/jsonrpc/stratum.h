#pragma once

#include <iostream>
#include "stratum_protocol.h"


class Stratum : public StratumProtocol
{
public:
    Stratum(boost::asio::io_context& context);

    boost::asio::deadline_timer _t_send_work;

public:
    // Server:
    json mining_subscribe(const json & _params)
    {
        std::vector<std::string> params = _params.get<std::vector<std::string>>();
        auto miner_info = params[0];
        std::cout << "mining.subscribe called: " << miner_info << std::endl;

        json res;
        //res = {{"mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f"}, "", 8};

        _t_send_work.expires_from_now(boost::posix_time::seconds(1));
        _t_send_work.async_wait([&](const boost::system::error_code &ec){
            mining_set_difficulty();
            mining_notify();
        });

        res = {{{"mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f"},{}}, "", 8};
        return res;
    }

    json mining_authorize(const std::string &username, const std::string &password)
    {
        std::cout << "Auth with [username: " << username << ", password: " << password << "]." << std::endl;
        return json({true});
    }

public:
    // Client:
    json mining_set_difficulty()
    {
        client.CallNotification("mining.set_difficulty", {0x1b0404cb});
        std::cout << "called mining_set_difficulty" << std::endl;
    }

    json mining_notify()
    {
        json notify_data = {
                // jobid
                "ae6812eb4cd7735a302a8a9dd95cf71f",
                // prevhash
                "4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000",
                // coinb1
                "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008",
                // coinb2
                "072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000",
                // merkle_branch
                json::array(),
                // version
                "00000002",
                // nbits
                "1c2ac4af",
                // ntime
                "504e86b9",
                // clean_jobs
                true
        };
        client.CallNotification("mining.notify", notify_data);
        std::cout << "called mining.notify" << std::endl;
    }
    
};