#pragma once

#include <cstdio>
#include <cinttypes>
#include <functional>

#include <utility>
#include <btclibs/uint256.h>

#include <libcoind/jsonrpc/coindrpc.h>

//TODO: more error check
//TODO: rpc <-----> btc_p2p_protocol

namespace coind
{
    class HeightTrackerBase
    {
    protected:
        CoindRPC* _jsonrpc_coind;
        std::function<uint256()> get_best_block_func;
        std::map<uint256, int32_t> cached_heights;

        int32_t best_height_cached{};

    public:
        HeightTrackerBase() { }
        HeightTrackerBase(const HeightTrackerBase& copy) = delete;

        void set_jsonrpc_coind(CoindRPC* jsonrpc_coind)
        {
            _jsonrpc_coind = jsonrpc_coind;
        }

        void set_get_best_block_func(std::function<uint256()> _get_best_block_func)
        {
            get_best_block_func = std::move(_get_best_block_func);
        }

        std::function<int32_t(uint256)> ref_func()
        {
            return [&](const uint256 &block_hash) { return this->operator()(block_hash); };
        }

        virtual int32_t get_height(uint256 block_hash) = 0;
        virtual int32_t operator ()(uint256 block_hash) = 0;
    };

    class HeightTracker : public HeightTrackerBase
    {
    public:
        HeightTracker() : HeightTrackerBase() { }
        HeightTracker(const HeightTracker& copy) = delete;

        int32_t get_height(uint256 block_hash) override
        {
            if (cached_heights.find(block_hash) != cached_heights.end())
                return cached_heights[block_hash];
                
            nlohmann::json x = _jsonrpc_coind->getblock(block_hash);

            int32_t result = x.contains("blockcount") ? x["blockcount"].get<int>() : x["height"].get<int>();
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