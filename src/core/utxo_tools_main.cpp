// c2pool-utxo: see utxo_tools.hpp.

#include "utxo_tools.hpp"

#include "sha256_init.hpp"

#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv)
{
    // CPU-dispatched SHA256 (SSE4 / AVX2 / SHA-NI), self-tested, as the node
    // binaries do (core/sha256_init.hpp).
    core::init_sha256();
    std::vector<std::string> args(argv + 1, argv + argc);
    return core::run_utxo_tool(args, std::cout, std::cerr);
}
