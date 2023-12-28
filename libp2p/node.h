#pragma once

#include <functional>
#include <memory>
#include <string>
#include <tuple>

#include "socket.h"

class Listener
{
public:
	Listener() = default;

	virtual void tick(std::function<void(std::shared_ptr<Socket>)> socket_handle, std::function<void()> finish) = 0;
};

class Connector
{
public:
	Connector() = default;

	virtual void tick(std::function<void(std::shared_ptr<Socket>)> socket_handle, NetAddress _addr) = 0;
};

enum NodeRunState
{
	onlyClient,
	onlyServer,
	both
};