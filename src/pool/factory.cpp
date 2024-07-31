#include "factory.hpp"

#include <core/common.hpp>
#include <core/random.hpp>

namespace pool
{
    
void Factory::got_addr(NetService addr, uint64_t services, uint64_t timestamp)
{
	if (m_addrs.check(addr))
	{
		auto old = m_addrs.get(addr);
		m_addrs.update(addr, {services, old.m_first_seen, std::max(old.m_last_seen, timestamp)});
	}
	else
	{
		if (m_addrs.len() < 10000)
			m_addrs.add(addr, {services, timestamp, timestamp});
	}
}

std::vector<core::AddrStorePair> Factory::get_good_peers(size_t max_count)
{
	auto t = core::timestamp();

    std::vector<std::pair<float, core::AddrStorePair>> values;
	for (auto pair : m_addrs.get_all())
	{
		values.push_back(
				std::make_pair(
						-log(std::max(uint64_t(3600), pair.value.m_last_seen - pair.value.m_first_seen)) / log(std::max(uint64_t(3600), t - pair.value.m_last_seen)) * core::random::expovariate(1),
						pair)
        );
	}

	std::sort(values.begin(), values.end(), [](const auto& a, auto b)
	{ return a.first < b.first; });

	values.resize(std::min(values.size(), max_count));
	std::vector<core::AddrStorePair> result;
	for (const auto& v : values)
	{
		result.push_back(v.second);
	}
	return result;
}

} // namespace pool
