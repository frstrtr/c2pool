#include <iostream>

#include <core/filesystem.hpp>
#include <core/log.hpp>

#include <btclibs/uint256.h>
#include <nlohmann/json.hpp>

int main(int argc, char *argv[])
{
    c2pool::log::Logger::init();
    c2pool::log::Logger::add_category("all");

    std::cout << nlohmann::json::meta() << std::endl;
    std::cout << uint256S("ff").GetHex() << std::endl;
    std::cout << c2pool::filesystem::config_path() << std::endl;
    std::cout << c2pool::filesystem::current_path() << std::endl;
     
    std::cout << c2pool::log::Logger::check_category(c2pool::log::COIND_RPC) << std::endl;
    BOOST_LOG_TRIVIAL(info) << "hi";
    LOG_DEBUG_POOL << "DEBUG DATA";
}