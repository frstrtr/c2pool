#pragma once

#include <vector>

#include "transaction.hpp"

#include <nlohmann/json.hpp>

namespace ltc
{

namespace coin
{
    
namespace rpc
{

struct WorkData
{
    nlohmann::json m_data;
    std::vector<Transaction> m_txs;
    std::vector<uint256> m_hashes; // transaction hashes
    time_t m_latency;

    WorkData() {}
    WorkData(nlohmann::json data, std::vector<Transaction> txs, std::vector<uint256> txhashes, time_t latency) 
        : m_data(data), m_txs(txs), m_hashes(txhashes), m_latency(latency)
    {

    }

    bool operator==(const WorkData& rhs) const { return m_data == rhs.m_data; }
    bool operator!=(const WorkData& rhs) const { return !(*this == rhs); }

/*

            
// version=work['version'],
// previous_block=int(work['previousblockhash'], 16),
// transactions=unpacked_transactions,
// transaction_hashes=txhashes,
// transaction_fees=[x.get('fee', None) if isinstance(x, dict) else None for x in work['transactions']],
// subsidy=work['coinbasevalue'],
// time=work['time'] if 'time' in work else work['curtime'],
// height=work['height'],
// rules=work.get('rules', []),
// last_update=time.time(),
// use_getblocktemplate=use_getblocktemplate,
// latency=end - start,

// bits=bitcoin_data.FloatingIntegerType().unpack(work['bits'].decode('hex')[::-1]) if isinstance(work['bits'], (str, unicode)) else bitcoin_data.FloatingInteger(work['bits']),
// coinbaseflags=work['coinbaseflags'].decode('hex') if 'coinbaseflags' in work else ''.join(x.decode('hex') for x in work['coinbaseaux'].itervalues()) if 'coinbaseaux' in work else '',

            version = work["version"].get<int>();
            previous_block = work["previousblockhash"].get<uint256>();
            transactions = unpacked_txs;
            transaction_hashes = txhashes;

            for (auto x : work["transactions"])
            {
                optional<uint64_t> fee;
                if (x.contains("fee"))
                    fee = x["fee"].get<int64_t>();

                transaction_fees.push_back(fee);
            }
            
            subsidy = work["coinbasevalue"].get<int64_t>();
            if (work.contains("time"))
                time = work["time"].get<int64_t>();
            else
                time = work["curtime"].get<int64_t>();

            if (work.contains("coinbaseflags"))
            {
                coinbaseflags = PackStream(ParseHex(work["coinbaseflags"].get<std::string>()));
            }
            else if (work.contains("coinbaseaux"))
            {
                for (auto x : work["coinbaseaux"])
                {
                    PackStream _x(ParseHex(x.get<std::string>()));
                    coinbaseflags << _x;
                }
            }

            if (work["bits"].is_string())
            {
                auto _bits_v = ParseHex(work["bits"].get<std::string>());
                std::reverse(_bits_v.begin(), _bits_v.end());
                PackStream _bits_stream(_bits_v);
                FloatingIntegerType _bits;
                _bits_stream >> _bits;
                bits = _bits.bits;
            }
            //TODO: ? else bitcoin_data.FloatingInteger(work['bits']),

            height = work["height"].get<int>();
            rules = work["rules"].get<std::vector<std::string>>();

            last_update = c2pool::dev::timestamp();
            latency = _latency;

            mweb = "01" + (work.contains("mweb") ? work["mweb"].get<std::string>() : "");
*/

};

} // namespace rpc

} // namespace coin

} // namespace ltc