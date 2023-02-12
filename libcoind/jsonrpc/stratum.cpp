#include "stratum.h"

#include <libdevcore/random.h>
#include <libdevcore/common.h>
#include <libdevcore/stream.h>

#include <utility>

Stratum::Stratum(std::shared_ptr<boost::asio::io_context> context, std::shared_ptr<ip::tcp::socket> socket, std::shared_ptr<Worker> worker, std::function<void(std::tuple<std::string, unsigned short>)> _disconnect_event)
                : StratumProtocol(context, std::move(socket), std::move(_disconnect_event)), _worker(std::move(worker)), _t_send_work(*context), handler_map(_context, 300)
{
    server.Add("mining.subscribe", GetUncheckedHandle([&](const json &value)
                                                      {
                                                          return mining_subscribe(value);
                                                      }));

    server.Add("mining.authorize", GetHandle(&Stratum::mining_authorize, *this));

    server.Add("mining.submit", GetHandle(&Stratum::mining_submit, *this));

    _worker->new_work.subscribe([&](){ _send_work(); });

    std::cout << "Added methods to server" << std::endl;
}

void Stratum::_send_work()
{
    worker_get_work_result get_work_result;

    try
    {
        auto [user, pubkey_hash, desired_share_target, desired_pseudoshare_target] = _worker->preprocess_request(username);
        get_work_result = _worker->get_work(pubkey_hash, desired_share_target, desired_pseudoshare_target);
    } catch (const std::exception &ec)
    {
        LOG_ERROR << "Stratum disconnect " << ec.what();
        disconnect();
        return;
    }

    auto &[x, got_response] = get_work_result;

    auto jobid = HexStr(c2pool::random::random_bytes(16)); // random_bytes(16) = random(2**128)
    mining_set_difficulty(coind::data::target_to_difficulty(x.share_target)* _worker->_net->parent->DUMB_SCRYPT_DIFF);

    json::array_t merkle_branch;
    for (auto s : x.merkle_link.branch)
    {
        merkle_branch.emplace_back(HexStr(pack<IntType(256)>(s)));
    }

    mining_notify(
                jobid,
                HexStr(c2pool::dev::swap4(pack<IntType(256)>(x.previous_block))),
                HexStr(x.coinb1),
                HexStr(x.coinb2),
                merkle_branch,
                HexStr(c2pool::dev::swap4(pack<IntType(32)>(x.version))),
                HexStr(c2pool::dev::swap4(pack<IntType(32)>(x.bits))),
                HexStr(c2pool::dev::swap4(pack<IntType(32)>(x.timestamp)))
            );

    handler_map.add(jobid, get_work_result);
}

json Stratum::mining_subscribe(const json &_params)
{
    std::vector<std::string> params = _params.get<std::vector<std::string>>();
    std::cout << (_params.find("id") != _params.end()) << std::endl;
    auto miner_info = params[0];
    LOG_DEBUG << "mining.subscribe called: " << miner_info;// << " " << _params.get<std::string>() << std::endl;
    LOG_DEBUG << "params:";
    for (auto p : params)
    {
        LOG_DEBUG << p;
    }

    json res;
    //res = {{"mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f"}, "", 8};

//    _context->post([&](){_send_work();});
//    _t_send_work.expires_from_now(boost::posix_time::seconds(0));
//    _t_send_work.async_wait([&](const boost::system::error_code &ec){
//        _send_work();
//    });

//    _send_work();
    //TODO: sub id
    res = {{{"mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f"},{}}, "", 8};
    return res;
}

json Stratum::mining_authorize(const std::string &_username, const std::string &_password, const std::string &_id)
{
    username = _username;
    std::cout << "Auth with [username: " << _username << ", password: " << _password << "]." << std::endl;

    _context->post([&](){_send_work();});

    return json({true});
}

json Stratum::mining_set_difficulty(difficulty_type difficulty)
{
//    std::string diff_data = "{" + difficulty.ToString() + "}";
//    json diff_json = diff_data;
    client.CallNotification("mining.set_difficulty", {difficulty});
    std::cout << "called mining_set_difficulty" << std::endl;
}

json Stratum::mining_notify(std::string jobid, std::string prevhash, std::string coinb1, std::string coinb2, json::array_t merkle_branch, std::string version, std::string nbits, std::string ntime, bool clean_jobs)
{
//    json notify_data = {
//            // jobid
//            "ae6812eb4cd7735a302a8a9dd95cf71f",
//            // prevhash
//            "4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000",
//            // coinb1
//            "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008",
//            // coinb2
//            "072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000",
//            // merkle_branch
//            json::array(),
//            // version
//            "00000002",
//            // nbits
//            "1c2ac4af",
//            // ntime
//            "504e86b9",
//            // clean_jobs
//            true
//    };

    json notify_data = {
            // jobid
            jobid,
            // prevhash
            prevhash,
            // coinb1
            coinb1,
            // coinb2
            coinb2,
            // merkle_branch
            merkle_branch,
            // version
            version,
            // nbits
            nbits,
            // ntime
            ntime,
            // clean_jobs
            clean_jobs
    };

    client.CallNotification("mining.notify", notify_data);
    std::cout << "called mining.notify" << std::endl;
    return {};
}

json Stratum::mining_submit(const std::string &_worker_name, const std::string &_jobid, const std::string &_extranonce2, const std::string &_ntime, const std::string &_nonce, const std::string &_id)
{
//    json res = {false};

    if (!handler_map.exist(_jobid))
    {
        LOG_WARNING << "Couldn't link returned work's job id with its handler. This should only happen if this process was recently restarted!";
        return false;
    }

    auto map_obj = handler_map.get(_jobid);
    auto x = map_obj.value().ba;
    auto coinb_nonce = ParseHex(_extranonce2);
    assert(coinb_nonce.size() == _worker->COINBASE_NONCE_LENGTH);

    std::vector<unsigned char> new_packed_gentx {x.coinb1.begin(), x.coinb1.end()};
    new_packed_gentx.insert(new_packed_gentx.end(), coinb_nonce.begin(), coinb_nonce.end());
    new_packed_gentx.insert(new_packed_gentx.end(), x.coinb2.begin(), x.coinb2.end());

    uint32_t _timestamp = unpack<IntType(32)>(c2pool::dev::swap4(ParseHex(_ntime)));
    uint32_t nonce = unpack<IntType(32)>(c2pool::dev::swap4(ParseHex(_nonce)));
    auto merkle_root = coind::data::check_merkle_link(coind::data::hash256(new_packed_gentx, true), x.merkle_link);

    coind::data::types::BlockHeaderType header(x.version, x.previous_block, _timestamp, x.bits, nonce, merkle_root);

    //DEBUG
    std::cout << "coinb1: " << HexStr(x.coinb1) << std::endl;
    std::cout << "coinb_nonce: " << HexStr(coinb_nonce) << std::endl;
    std::cout << "coinb2: " << HexStr(x.coinb2) << std::endl;
    std::cout << "merkle_link: " << x.merkle_link.index << " ";
    for (auto br : x.merkle_link.branch)
    {
        std::cout << br.GetHex() << " ";
    }
    std::cout << ".\n";
    std::cout << "merkle_root: <" << merkle_root.ToString() << ">" << std::endl;
    //########

    // IN P2Pool -- coinb_nonce = bytes, c2pool -- IntType64
    return map_obj->get_response(header, _worker_name, unpack<IntType(64)>(coinb_nonce));



//    return {true};
}


