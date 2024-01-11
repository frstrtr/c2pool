#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <algorithm>

#include <nlohmann/json.hpp>
#include <btclibs/uint256.h>
#include <btclibs/util/strencodings.h>
#include <libcoind/transaction.h>
#include <libdevcore/stream_types.h>
#include <libdevcore/common.h>
#include <libdevcore/logger.h>

namespace coind
{
    struct getwork_result
    {
        int version;
        uint256 previous_block;
        vector<shared_ptr<coind::data::TransactionType>> transactions;
        vector<uint256> transaction_hashes;
        vector<std::optional<uint64_t>> transaction_fees;
        int64_t subsidy;
        time_t time;
        FloatingInteger bits;
        PackStream coinbaseflags;
        int32_t height;
        vector<string> rules;
        time_t last_update;
        time_t latency;
        std::string mweb;
		//use_getblocktemplate = true always

        getwork_result() {}

        getwork_result(nlohmann::json work, vector<shared_ptr<coind::data::TransactionType>> unpacked_txs, vector<uint256> txhashes, time_t _latency)
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
        }

        bool operator==(getwork_result const &val) const
        {
            return std::make_tuple(version, previous_block.GetHex(), transactions, transaction_hashes, subsidy, time, bits.get(), coinbaseflags.data, height, rules, last_update, latency, mweb) == std::make_tuple(val.version, val.previous_block.GetHex(), val.transactions, val.transaction_hashes, val.subsidy, val.time, val.bits.get(), val.coinbaseflags.data, val.height, val.rules, val.last_update, val.latency, val.mweb);
        }
        bool operator!=(getwork_result const &val) const
        {
            return !(*this == val);
        }

        friend std::ostream &operator<<(std::ostream &stream, const getwork_result &val)
        {
            stream << "(getwork_result: ";
            stream << "version = " << val.version;
            stream << ", previous_block = " << val.previous_block;
            stream << ", transactions = " << val.transactions;
            stream << ", transaction_hashes = " << val.transaction_hashes;
            stream << ", transaction_fees = " << val.transaction_fees;
            stream << ", subsidy = " << val.subsidy;
            stream << ", time = " << val.time;
            stream << ", bits = " << val.bits;
            stream << ", coinbaseflags = " << val.coinbaseflags;
            stream << ", height = " << val.height;
            stream << ", rules = " << val.rules;
            stream << ", last_update = " << val.last_update;
            stream << ", latency = " << val.latency;
            stream << ", mweb = " << val.mweb;
            stream << " )";

            return stream;
        }
    };
} // namespace coind::jsonrpc::data