#pragma once
#include <memory>
#include <map>
#include <list>
#include <vector>

#include <btclibs/uint256.h>

#include "share.h"
#include <libcoind/data.h>

class ShareTracker;

namespace shares::weight
{
	class element_type
	{
	public:
		std::map<uint256, element_type>::iterator prev;
		std::list<std::map<uint256, element_type>::iterator> nexts;
		ShareType element;

		int32_t share_count;
		std::map<std::vector<unsigned char>, arith_uint256> weights;
		arith_uint256 total_weight;
		arith_uint256 total_donation_weight;

	public:
		element_type() = default;

		element_type(ShareType _share)
		{
			element = _share;
			auto att = UintToArith256(coind::data::target_to_average_attempts(element->target));

			share_count = 1;
			weights[element->new_script.data] = att * (65535 - *element->donation);
			total_weight = att * 65535;
			total_donation_weight = att * (*element->donation);
		}

		uint256 hash()
		{
			return element->hash;
		}

		uint256 prev_hash()
		{
			if (element == nullptr)
			{
				uint256 res;
				res.SetNull();
				return res;
			}
			return *element->previous_hash;
		}

		element_type operator+(const element_type &element)
		{
			element_type res = *this;

			res.share_count += element.share_count;

			std::map<std::vector<unsigned char>, arith_uint256> _weights;
			_weights.insert(res.weights.begin(), res.weights.end());
			for (auto v : element.weights)
			{
				if (_weights.find(v.first) != _weights.end())
				{
					_weights[v.first] += v.second;
				} else
				{
					_weights[v.first] = v.second;
				}
			}
			res.weights.swap(_weights);

			res.total_weight += element.total_weight;
			res.total_donation_weight += element.total_donation_weight;

			return res;
		}

		element_type operator-(const element_type &element)
		{
			element_type res = *this;

			res.share_count -= element.share_count;

			std::map<std::vector<unsigned char>, arith_uint256> _weights;
			_weights.insert(res.weights.begin(), res.weights.end());
			for (auto v : element.weights)
			{
				if (_weights.find(v.first) != _weights.end())
				{
					_weights[v.first] -= v.second;
					if (_weights[v.first] == 0)
					{
						_weights.erase(v.first);
					}
				}
			}
			res.weights.swap(_weights);

			res.total_weight -= element.total_weight;
			res.total_donation_weight -= element.total_donation_weight;

			return res;
		}

		element_type &operator+=(const element_type &element)
		{
			this->share_count += element.share_count;

			for (auto v : element.weights)
			{
				if (this->weights.find(v.first) != this->weights.end())
				{
					this->weights[v.first] += v.second;
				} else
				{
					this->weights[v.first] = v.second;
				}
			}

			this->total_weight += element.total_weight;
			this->total_donation_weight += element.total_donation_weight;

			return *this;
		}

		element_type &operator-=(const element_type &element)
		{
			this->share_count -= element.share_count;

			for (auto v : element.weights)
			{
				if (this->weights.find(v.first) != this->weights.end())
				{
					this->weights[v.first] -= v.second;
					if (this->weights[v.first] == 0)
					{
						this->weights.erase(v.first);
					}
				}
			}

			this->total_weight -= element.total_weight;
			this->total_donation_weight -= element.total_donation_weight;

			return *this;
		}
	};

	class element_delta_type
	{
	private:
		bool _none;

	public:
		uint256 head;
		uint256 tail;

		int32_t share_count;
		std::map<std::vector<unsigned char>, arith_uint256> weights;
		arith_uint256 total_weight;
		arith_uint256 total_donation_weight;

		element_delta_type(bool none = true)
		{
			_none = none;
		}

		element_delta_type(element_type &el)
		{
			head = el.hash();
			tail = el.prev_hash();

			share_count = el.share_count;
			weights = el.weights;
			total_weight = el.total_weight;
			total_donation_weight = el.total_donation_weight;
		}

		element_delta_type operator-(const element_delta_type &el) const
		{
			element_delta_type res = *this;
			res.tail = el.head;

			res.share_count -= el.share_count;

			std::map<std::vector<unsigned char>, arith_uint256> _weights;
			_weights.insert(res.weights.begin(), res.weights.end());
			for (auto v : el.weights)
			{
				if (_weights.find(v.first) != _weights.end())
				{
					_weights[v.first] -= v.second;
					if (_weights[v.first] == 0)
					{
						_weights.erase(v.first);
					}
				}
			}
			res.weights.swap(_weights);

			res.total_weight -= el.total_weight;
			res.total_donation_weight -= el.total_donation_weight;

			return res;
		}

		void operator-=(const element_delta_type &el)
		{
			tail = el.head;

			this->share_count -= el.share_count;

			for (auto v : el.weights)
			{
				if (this->weights.find(v.first) != this->weights.end())
				{
					this->weights[v.first] -= v.second;
					if (this->weights[v.first] == 0)
					{
						this->weights.erase(v.first);
					}
				}
			}

			this->total_weight -= el.total_weight;
			this->total_donation_weight -= el.total_donation_weight;
		}

		bool is_none()
		{
			return _none;
		}

		void set_none(bool none = true)
		{
			_none = none;
		}
	};

	class PrefsumWeights
	{
		std::shared_ptr<ShareTracker> _tracker;
		map<uint256, element_type> sum;

	protected:
		element_type make_element(ShareType _share)
		{
			element_type element(_share);
			element.prev = sum.find(*_share->previous_hash);
			return element;
		}

	public:
		PrefsumWeights(std::shared_ptr<ShareTracker> tracker);
// a = (desired_weight - total_weight1)
// b = (total_weight2//65535)
// (a * weights2[script]) // (b * 65535)
	};
}