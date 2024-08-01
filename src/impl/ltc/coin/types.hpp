#pragma once

namespace ltc
{

namespace coin
{

struct RPCAuthData
{
	const char *ip;
	const char *port;
	char *authorization;
	char *host;

	RPCAuthData() = default;
	RPCAuthData(const char *_ip, const char *_port) : ip(_ip), port(_port)
	{
		
	}
};



} // namespace coin

} // namespace ltc