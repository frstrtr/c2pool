#pragma once

#include <cstdio>
#include <cinttypes>
#include <functional>

#include <utility>
#include <btclibs/uint256.h>

#include <libcoind/jsonrpc/jsonrpc_coind.h>

//TODO: more error check
//TODO: rpc <-----> btc_p2p_protocol

namespace coind
{
    class HeightTrackerBase
    {
    protected:
        std::shared_ptr<JSONRPC_Coind> _jsonrpc_coind;
        std::function<uint256()> get_best_block_func;
        std::map<uint256, int32_t> cached_heights;

        int32_t best_height_cached{};

    public:
        HeightTrackerBase() { }

        void set_jsonrpc_coind(std::shared_ptr<JSONRPC_Coind> jsonrpc_coind)
        {
            _jsonrpc_coind = std::move(jsonrpc_coind);
        }

        void set_get_best_block_func(std::function<uint256()> _get_best_block_func)
        {
            get_best_block_func = std::move(_get_best_block_func);
        }

        virtual int64_t get_height(uint256 block_hash) = 0;
        virtual int32_t operator ()(uint256 block_hash) = 0;
    };

    class HeightTracker : public HeightTrackerBase
    {
    public:
        HeightTracker() : HeightTrackerBase() { }

        int64_t get_height(uint256 block_hash) override
        {
            if (cached_heights.find(block_hash) != cached_heights.end())
                return cached_heights[block_hash];

            UniValue x;
            try
            {
                x = _jsonrpc_coind->getblock(std::make_shared<GetBlockRequest>(get_best_block_func()));
            } catch (const std::exception &except)
            {
                throw except;
            }

            int32_t result = x.exists("blockcount") ? x["blockcount"].get_int64() : x["height"].get_int64();
            cached_heights[block_hash] = result;

            return result;
        }

        int32_t operator ()(uint256 block_hash) override
        {
            int32_t this_height = get_height(block_hash);
            int32_t best_height = get_height(get_best_block_func());
            best_height_cached = std::max({best_height_cached, this_height, best_height});

            return this_height - best_height_cached;
        }
    };
}