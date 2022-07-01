#pragma once

#include <functional>
#include <memory>
#include <string>
#include <tuple>

#include "socket.h"

class Listener
{
public:
	Listener()
	{

	}

	virtual void operator()(std::function<void(std::shared_ptr<Socket>)> socket_handle, std::function<void()> finish) = 0;
};

class Connector
{
public:
	Connector()
	{

	}

	virtual void operator()(std::function<void(std::shared_ptr<Socket>)> socket_handle,
							std::tuple<std::string, std::string> _addr) = 0;
};