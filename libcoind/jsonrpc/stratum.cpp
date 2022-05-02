#include "stratum.h"

Stratum::Stratum(boost::asio::io_context &context) : StratumProtocol(context), _t_send_work(context)
{
    server.Add("mining.subscribe", GetUncheckedHandle([&](const json& value){
        return mining_subscribe(value);
    }));

    server.Add("mining.authorize", GetHandle(&Stratum::mining_authorize, *this));
    std::cout << "Added methods to server" << std::endl;
}
