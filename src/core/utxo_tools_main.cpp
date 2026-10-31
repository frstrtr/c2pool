// c2pool-utxo: see utxo_tools.hpp.

#include "utxo_tools.hpp"

#include <btclibs/crypto/sha256.h>

#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv)
{
    // CPU-dispatched SHA256 (SSE4 / AVX2 / SHA-NI), as the node binaries do.
    SHA256AutoDetect();
    std::vector<std::string> args(argv + 1, argv + argc);
    return core::run_utxo_tool(args, std::cout, std::cerr);
}
