#include "stratum.h"

#include <libdevcore/random.h>
#include <libdevcore/common.h>
#include <libdevcore/stream.h>

#include <utility>

Stratum::Stratum(std::shared_ptr<boost::asio::io_context> context, std::shared_ptr<ip::tcp::socket> socket, std::shared_ptr<Worker> worker, std::function<void(std::tuple<std::string, unsigned short>)> _disconnect_in_node_f)
                : StratumProtocol(context, std::move(socket), std::move(_disconnect_in_node_f)), _worker(std::move(worker)), _t_send_work(*context), handler_map(_context, 300)
{
    server.Add("mining.subscribe", GetUncheckedHandle([&](const json &value)
                                                      {
                                                          return mining_subscribe(value);
                                                      }));

    server.Add("mining.authorize", GetHandle(&Stratum::mining_authorize, *this));

    server.Add("mining.submit", GetHandle(&Stratum::mining_submit, *this));

    auto new_work_id = _worker->new_work.subscribe([&](){ _send_work(); });
    event_disconnect.subscribe([&, _new_work_id = new_work_id](){ _worker->new_work.unsubscribe(_new_work_id); });
}

void Stratum::_send_work()
{
    worker_get_work_result get_work_result;

    try
    {
        auto [user, pubkey_hash, desired_share_target, desired_pseudoshare_target] = _worker->preprocess_request(username);
        get_work_result = _worker->get_work(pubkey_hash, desired_share_target, desired_pseudoshare_target);
    } catch (const std::runtime_error &ec)
    {
        disconnect(ec.what());
        return;
    }

    auto &[x, got_response] = get_work_result;
    LOG_DEBUG_STRATUM << "X: " << x;

    auto jobid = HexStr(c2pool::random::random_bytes(16)); // random_bytes(16) = random(2**128)
    mining_set_difficulty(coind::data::target_to_difficulty(x.share_target)*_worker->_net->parent->DUMB_SCRYPT_DIFF.GetUint64(0));
    LOG_DEBUG_STRATUM << "mining diff: " << coind::data::target_to_difficulty(x.share_target)*_worker->_net->parent->DUMB_SCRYPT_DIFF.GetUint64(0) << "; target_to_diff = " << coind::data::target_to_difficulty(x.share_target) << "; DUMB_SCRYPT_DIFF = " << _worker->_net->parent->DUMB_SCRYPT_DIFF.GetUint64(0);

    json::array_t merkle_branch;
    for (auto s : x.merkle_link.branch)
    {
        merkle_branch.emplace_back(HexStr(pack<IntType(256)>(s)));
    }

    LOG_DEBUG_STRATUM << "x.bits = " << x.bits << ", swap4 = " << HexStr(c2pool::dev::swap4(pack<IntType(32)>(x.bits)));

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
    LOG_DEBUG_STRATUM << "mining.subscribe called: " << miner_info;// << " " << _params.get<std::string>() << std::endl;
    LOG_DEBUG_STRATUM << "params:";
    for (auto p : params)
    {
        LOG_DEBUG_STRATUM << p;
    }

    json res;

    //TODO: sub id
    res = {{{"mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f"},{}}, "", 8};
    return res;
}

json Stratum::mining_authorize(const std::string &_username, const std::string &_password, const std::string &_id)
{
    username = _username;
    LOG_DEBUG_STRATUM << "Auth with [username: " << _username << ", password: " << _password << "]";

    _context->post([&](){_send_work();});

    return json({true});
}

json Stratum::mining_set_difficulty(difficulty_type difficulty)
{
    client.CallNotification("mining.set_difficulty", {difficulty});
    LOG_DEBUG_STRATUM << "called mining_set_difficulty = " << difficulty;
    return {};
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
    return {};
}

json Stratum::mining_submit(const std::string &_worker_name, const std::string &_jobid, const std::string &_extranonce2, const std::string &_ntime, const std::string &_nonce, const std::string &_id)
{
//    json res = {false};
    LOG_TRACE << "MINING_SUBMIT_ARGS: " << _worker_name << "; " << _jobid << "; " << _extranonce2 << "; " << _ntime << "; " << _nonce << "; "  << _id << "; ";

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

    // IN P2Pool -- coinb_nonce = bytes, c2pool -- IntType64
    return map_obj->get_response(header, _worker_name, unpack<IntType(64)>(coinb_nonce));
}


