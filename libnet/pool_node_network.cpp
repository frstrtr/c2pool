#include "pool_node_interface.h"

std::vector<NetAddress> PoolNodeClient::get_good_peers(int max_count)
{
	int t = c2pool::dev::timestamp();

	std::vector<std::pair<float, NetAddress>> values;
	for (auto kv : addr_store->GetAll())
	{
		values.push_back(
				std::make_pair(
						-log(max(int64_t(3600), kv.second.last_seen - kv.second.first_seen)) / log(max(int64_t(3600), t - kv.second.last_seen)) * c2pool::random::Expovariate(1),
						kv.first));
	}

	std::sort(values.begin(), values.end(), [](const std::pair<float, NetAddress>& a, std::pair<float, NetAddress> b)
	{ return a.first < b.first; });

	values.resize(min((int)values.size(), max_count));
	std::vector<NetAddress> result;
	for (const auto& v : values)
	{
		result.push_back(v.second);
	}
	return result;
}