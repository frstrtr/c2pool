#include <iostream>
#include <memory>
#include <sstream>

#include <libnet2/worker.h>
#include <libnet2/coind_node.h>
#include <libnet2/pool_node.h>
#include <libnet2/pool_socket.h>
#include <networks/network.h>
#include <libdevcore/config.h>
#include <libdevcore/addr_store.h>
#include <libp2p/preset/p2p_node_interface.h>
#include <libp2p/node.h>
#include <libcoind/jsonrpc/jsonrpc_coind.h>
#include <libcoind/p2p/coind_socket.h>
#include <libcoind/jsonrpc/stratum.h>

#include <boost/asio.hpp>

int main(int ac, char *av[])
{
	switch (ac)
	{
		case 1:
			LOG_FATAL << "Enter coind ip!";
			return 1;
		case 2:
			LOG_FATAL << "Enter coind port!";
			return 2;
		case 3:
			LOG_FATAL << "Enter coind login [user:pass]!";
			return 3;
	}
	const char *coind_ip = av[1];
	const char *coind_port = av[2];
	const char *coind_login = av[3];

	// boost context
	auto context = std::make_shared<boost::asio::io_context>(0);

	// Network
	auto parent_net = std::make_shared<coind::DigibyteParentNetwork>();
	auto net = std::make_shared<c2pool::DigibyteNetwork>(parent_net);

	// Config
	auto config = std::make_shared<c2pool::dev::coind_config>();

	// JSONRPC Coind
	std::shared_ptr<coind::JSONRPC_Coind> coind = std::make_shared<coind::JSONRPC_Coind>(context, parent_net, coind_ip, coind_port, coind_login);
	coind->check();

	context->run();
}