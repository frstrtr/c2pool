#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <algorithm>

#include <univalue.h>
#include <btclibs/uint256.h>
#include <btclibs/util/strencodings.h>
#include <coind/transaction.h>
#include <util/stream_types.h>
#include <devcore/common.h>

namespace coind::jsonrpc::data
{
    struct getwork_result
    {
        int version;
        uint256 previous_block;
        vector<shared_ptr<coind::data::TransactionType>> transactions;
        vector<uint256> transaction_hashes;
        vector<optional<uint64_t>> transaction_fees;
        int64_t subsidy;
        time_t time;
        FloatingInteger bits;
        PackStream coinbaseflags;
        int32_t height;
        vector<string> rules;
        time_t last_update;
        bool use_getblocktemplate;
        time_t latency;

        getwork_result() {}

        getwork_result(UniValue work, vector<shared_ptr<coind::data::TransactionType>> unpacked_txs, vector<uint256> txhashes, bool _use_getblocktemplate, time_t _latency)
        {
            /*
                version=work['version'],
                previous_block=int(work['previousblockhash'], 16),
                transactions=unpacked_transactions,
                transaction_hashes=txhashes,
                transaction_fees=[x.get('fee', None) if isinstance(x, dict) else None for x in work['transactions']],
                subsidy=work['coinbasevalue'],
                time=work['time'] if 'time' in work else work['curtime'],
                height=work['height'],
                rules=work.get('rules', []),
                last_update=time.time(),
                use_getblocktemplate=use_getblocktemplate,
                latency=end - start,
                
                bits=bitcoin_data.FloatingIntegerType().unpack(work['bits'].decode('hex')[::-1]) if isinstance(work['bits'], (str, unicode)) else bitcoin_data.FloatingInteger(work['bits']),
                coinbaseflags=work['coinbaseflags'].decode('hex') if 'coinbaseflags' in work else ''.join(x.decode('hex') for x in work['coinbaseaux'].itervalues()) if 'coinbaseaux' in work else '',
            */
            version = work["version"].get_int();
            previous_block.SetHex(work["previousblockhash"].get_str());
            transactions = unpacked_txs;
            transaction_hashes = txhashes;

            for (auto x : work["transactions"].getValues())
            {
                optional<uint64_t> fee;
                if (x.exists("fee"))
                {
                    fee = x.get_uint64();
                }
                transaction_fees.push_back(fee);
            }
            subsidy = work["coinbasevalue"].get_int64();
            if (work.exists("time"))
            {
                time = work["time"].get_int64();
            }
            else
            {
                time = work["curtime"].get_int64();
            }

            if (work.exists("coinbaseflags"))
            {
                coinbaseflags = PackStream(ParseHex(work["coinbaseflags"].get_str()));
            }
            else
            {
                if (work.exists("coinbaseaux"))
                {
                    for (auto x : work["coinbaseaux"].getValues())
                    {
                        PackStream _x(ParseHex(x.get_str()));
                        coinbaseflags << _x;
                    }
                }
            }

            //TODO: test
            if (work["bits"].isStr())
            {
                auto _bits_v = ParseHex(work["bits"].get_str());
                std::reverse(_bits_v.begin(), _bits_v.end());
                PackStream _bits_stream(_bits_v);
                FloatingIntegerType _bits;
                _bits_stream >> _bits;
                bits = _bits.bits;
            }
            //TODO: ? else bitcoin_data.FloatingInteger(work['bits']),

            height = work["height"].get_int();
            for (auto rule : work["rules"].getValues())
            {
                rules.push_back(rule.get_str());
            }

            last_update = c2pool::dev::timestamp();
            use_getblocktemplate = _use_getblocktemplate;
            latency = _latency;
        }

        bool operator==(getwork_result const &val)
        {
            //TODO: for Events::Variable
            return false;
        }
        bool operator!=(getwork_result const &val)
        {
            //TODO: for Events::Variable
            return true;
        }
    };
} // namespace coind::jsonrpc::data