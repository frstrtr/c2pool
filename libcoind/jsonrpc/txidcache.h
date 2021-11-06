#ifndef C2POOL_TXIDCACHE_H
#define C2POOL_TXIDCACHE_H

#include <string>
#include <map>
using std::map, std::string;

#include <uint256.h>
#include <libdevcore/common.h>

namespace coind{
	class TXIDCache
	{
	public:
		map<string, uint256> cache; //getblocktemplate.transacions[].data; hash256(packed data)
	private:
		bool _started = false;

		time_t time_started = 0;

	public:
		bool is_started() const
		{
			return _started;
		}

		bool exist(const string &key)
		{
			return (cache.find(key) != cache.end());
		}

		uint256 operator[](const string &key)
		{
			if (exist(key))
			{
				return cache[key];
			}
			else
			{
				uint256 null_value;
				null_value.SetNull();
				return null_value;
			}
		}

		void add(const string &key, const uint256 &value)
		{
			cache[key] = value;
		}

		void add(map<string, uint256> v)
		{
			for (auto _v : v)
			{
				cache[_v.first] = _v.second;
			}
		}

		void clear()
		{
			cache.clear();
		}

		void start()
		{
			time_started = c2pool::dev::timestamp();
			_started = true;
		}

		time_t time()
		{
			return time_started;
		}
	};
}

#endif //C2POOL_TXIDCACHE_H
