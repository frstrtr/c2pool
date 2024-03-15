#include <iostream>
#include <memory>
#include <sstream>

#include <libnet/worker.h>
#include <libnet/coind_node.h>
#include <libnet/pool_node.h>
#include <libnet/pool_socket.h>
#include <networks/network.h>
#include <libdevcore/config.h>
#include <libdevcore/addr_store.h>
#include <libp2p/preset/p2p_node_interface.h>
#include <libp2p/node.h>
#include <libcoind/jsonrpc/jsonrpc_coind.h>
#include <libcoind/stratum/stratum.h>

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

	NodeMode pool_node_mode = both;
	if (ac >= 5)
	{
		std::stringstream ss;
		ss << av[4];
		int _pool_node_mode;
		ss >> _pool_node_mode;

		pool_node_mode = (NodeMode) _pool_node_mode;
		std::cout << pool_node_mode << std::endl;
	}


	// boost context
	auto context = std::make_shared<boost::asio::io_context>(0);

	// Network
	auto parent_net = std::make_shared<coind::DigibyteParentNetwork>();
	auto net = std::make_shared<c2pool::DigibyteNetwork>(parent_net);

	// Config
	auto config = std::make_shared<c2pool::dev::coind_config>();

	// AddrStore
	auto addr_store = std::make_shared<c2pool::dev::AddrStore>("only_pool_addrs	", net);

	// Pool Node
	std::shared_ptr<PoolNode> pool_node = std::make_shared<PoolNode>(context);
	pool_node
			->set_net(net)
			->set_config(config)
			->set_addr_store(addr_store);
	pool_node->run<PoolListener<PoolSocket>, P2PConnector<PoolSocket>>(pool_node_mode);

	// DEBUG
	boost::asio::steady_timer t(*context, 10s);
	t.async_wait([](const boost::system::error_code &ec) {
		LOG_DEBUG << "DEBUG TIMER";
	});

	// JSONRPC Coind
	std::shared_ptr<coind::JSONRPC_Coind> coind = std::make_shared<coind::JSONRPC_Coind>(context, parent_net, coind_ip, coind_port, coind_login);

	// ShareTracker
	std::shared_ptr<ShareTracker> tracker = std::make_shared<ShareTracker>(net);

	// CoindNode
	std::shared_ptr<CoindNode> coind_node = std::make_shared<CoindNode>(context);

	coind_node
		->set_parent_net(parent_net)
		->set_coind(coind)
		->set_tracker(tracker)
		->set_pool_node(pool_node);

	// Worker
	std::shared_ptr<Worker> worker = std::make_shared<Worker>(net, pool_node, coind_node, tracker);

	// Stratum: worker -> stratum
	std::shared_ptr<Stratum> stratum = std::make_shared<Stratum>(context, worker);

	context->run();
}