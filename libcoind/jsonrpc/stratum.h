#pragma once

#include <iostream>
#include <memory>

#include "stratum_protocol.h"

#include <libnet2/worker.h>
#include <libdevcore/logger.h>
#include <libdevcore/expiring_dict.h>

class Stratum : public StratumProtocol
{
    typedef double difficulty_type;
public:
    Stratum(std::shared_ptr<boost::asio::io_context> context, std::shared_ptr<ip::tcp::socket> socket, std::shared_ptr<Worker> worker, std::function<void(std::tuple<std::string, unsigned short>)> _disconnect_event);

    boost::asio::deadline_timer _t_send_work;
    std::shared_ptr<Worker> _worker;
private:
    std::string username;
    expiring_dict<std::string, worker_get_work_result> handler_map;

public:
    void _send_work();

public:
    // Server:
    json mining_subscribe(const json & _params);
    json mining_authorize(const std::string &_username, const std::string &_password, const std::string &_id);
    json mining_submit(const std::string &_worker_name, const std::string &_jobid, const std::string &_extranonce2, const std::string &_ntime, const std::string &_nonce, const std::string &_id);

public:
    // Client:
    json mining_set_difficulty(difficulty_type difficulty);
    json mining_notify(std::string jobid, std::string prevhash, std::string coinb1, std::string coinb2, json::array_t merkle_branch, std::string version, std::string nbits, std::string ntime, bool clean_jobs = true);
    
};