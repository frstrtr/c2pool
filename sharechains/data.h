#pragma once
#include <btclibs/uint256.h>
#include <networks/network.h>
#include "share_types.h"

#include "string"
using std::string;

namespace c2pool::shares
{
    bool is_segwit_activated(int version, shared_ptr<Network> net);

    uint256 check_hash_link(HashLinkType hash_link, unsigned char *data, string const_ending = "");
}