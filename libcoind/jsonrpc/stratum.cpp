#include "stratum.h"

#include <libdevcore/random.h>
#include <libdevcore/common.h>

Stratum::Stratum(std::shared_ptr<boost::asio::io_context> context, std::shared_ptr<Worker> _worker) : StratumProtocol(context), worker(_worker), _t_send_work(*context),
                                                                                                      handler_map(_context, 300)
{
    server.Add("mining.subscribe", GetUncheckedHandle([&](const json& value){
        return mining_subscribe(value);
    }));

    server.Add("mining.authorize", GetHandle(&Stratum::mining_authorize, *this));
    std::cout << "Added methods to server" << std::endl;
}

void Stratum::_send_work()
{
    worker_get_work_result get_work_result;

    try
    {
        auto [user, pubkey_hash, desired_share_target, desired_pseudoshare_target] = worker->preprocess_request(username);
        get_work_result = worker->get_work(pubkey_hash, desired_share_target, desired_pseudoshare_target);
    } catch (const std::exception &ec)
    {
        LOG_ERROR << "Stratum disconnect " << ec.what();
        disconnect();
        return;
    }

    auto &[x, got_response] = get_work_result;

    //TODO: test
    auto jobid = HexStr(c2pool::random::random_bytes(16)); // random_bytes(16) = random(2**128)
    mining_set_difficulty(coind::data::target_to_difficulty(x.share_target)* worker->_net->parent->DUMB_SCRYPT_DIFF);

    json::array_t merkle_branch;
    for (auto s : x.merkle_link.branch)
    {
        merkle_branch.push_back(HexStr(pack<IntType(256)>(s)));
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
    auto miner_info = params[0];
    std::cout << "mining.subscribe called: " << miner_info << std::endl;

    json res;
    //res = {{"mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f"}, "", 8};

    _t_send_work.expires_from_now(boost::posix_time::seconds(1));
    _t_send_work.async_wait([&](const boost::system::error_code &ec){
        _send_work();
    });

    res = {{{"mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f"},{}}, "", 8};
    return res;
}

json Stratum::mining_authorize(const std::string &_username, const std::string &_password)
{
    username = _username;
    std::cout << "Auth with [username: " << _username << ", password: " << _password << "]." << std::endl;
    return json({true});
}

// TODO: test
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
}
