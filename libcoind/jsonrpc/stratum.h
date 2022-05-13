#pragma once

#include <iostream>
#include <memory>

#include "stratum_protocol.h"

#include <libnet/worker.h>
#include <libdevcore/logger.h>
#include <libdevcore/expiring_dict.h>

class Stratum : public StratumProtocol
{
    typedef double difficulty_type;
public:
    Stratum(std::shared_ptr<boost::asio::io_context> context, std::shared_ptr<c2pool::libnet::Worker> _worker);

    boost::asio::deadline_timer _t_send_work;
    std::shared_ptr<c2pool::libnet::Worker> worker;

private:
    std::string username;
    expiring_dict<std::string, c2pool::libnet::worker_get_work_result> handler_map;

public:
    void _send_work();

public:
    // Server:
    json mining_subscribe(const json & _params);
    json mining_authorize(const std::string &_username, const std::string &_password);

public:
    // Client:
    json mining_set_difficulty(difficulty_type difficulty);
    json mining_notify();
    
};