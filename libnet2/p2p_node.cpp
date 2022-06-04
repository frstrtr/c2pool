#include "p2p_node.h"

std::vector<addr_type> P2PNodeClient::get_good_peers(int max_count)
{
	int t = c2pool::dev::timestamp();

	std::vector<std::pair<float, addr_type>> values;
	for (auto kv : addr_store->GetAll())
	{
		values.push_back(
				std::make_pair(
						-log(max(int64_t(3600), kv.second.last_seen - kv.second.first_seen)) / log(max(int64_t(3600), t - kv.second.last_seen)) * c2pool::random::Expovariate(1),
						kv.first));
	}

	std::sort(values.begin(), values.end(), [](std::pair<float, addr_type> a, std::pair<float, addr_type> b)
	{ return a.first < b.first; });

	values.resize(min((int)values.size(), max_count));
	std::vector<addr_type> result;
	for (auto v : values)
	{
		result.push_back(v.second);
	}
	return result;
}