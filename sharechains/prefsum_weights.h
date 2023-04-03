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
    // TODO: хранить без умножения на 65535 и лишь в конце вычислений, результат, как сумму, умножать на 65535*n;
    // TODO: Оптимизировать память для amount.
    class weight_data
    {
    public:
        std::map<std::vector<unsigned char>, arith_uint288> amount; //weight, not sum, just element! //TODO: может быть тоже суммировать?
        arith_uint288 total_weight;
        arith_uint288 total_donation_weight;

        weight_data()
        {
            amount = {};
            total_weight = 0;
            total_donation_weight = 0;
        }

        weight_data(const ShareType& share)
        {
            auto att = coind::data::target_to_average_attempts(share->target);

            amount = {{share->new_script.data, att * (65535 - *share->donation)}};
            total_weight = att*65535;
            total_donation_weight = att * (*share->donation);
        }

        void operator+=(const weight_data &element)
        {
/*            for (auto el : element.amount)
            {
                if (amount.find(el.first) != amount.end())
                    amount[el.first] += el.second;
                else
                    amount[el.first] = el.second;
            }*/

            total_weight += element.total_weight;
            total_donation_weight += element.total_donation_weight;
        }

        void operator-=(const weight_data &element)
        {
            for (auto el : element.amount)
            {
                //TODO: сделать проверку на существование script в словаре?
                amount[el.first] -= el.second;

                if (amount[el.first].IsNull())
                {
                    amount.erase(el.first);
                }
            }

            total_weight -= element.total_weight;
            total_donation_weight -= element.total_donation_weight;
        }
    };
//	class weight_element;
//	typedef std::shared_ptr<weight_element> weight_element_ptr;
//
//	class weight_element : public enable_shared_from_this<weight_element>
//	{
//	public:
//		weight_element_ptr prev;
//		std::pair<std::vector<unsigned char>, arith_uint288> amount;
//
//		weight_element(std::vector<unsigned char> _key, arith_uint288 _value)
//		{
//			amount = std::make_pair(_key, _value);
//		}
//
//		std::map<std::vector<unsigned char>, arith_uint288> get_map()
//		{
//			std::map<std::vector<unsigned char>, arith_uint288> result;
//			auto it = shared_from_this();
//
//			while (it)
//			{
//				if (result.find(it->amount.first) != result.end())
//				{
//					result[it->amount.first] += it->amount.second;
//				} else
//				{
//					result[it->amount.first] = it->amount.second;
//				}
//
//				it = it->prev;
//			}
//
//			return result;
//		}
//
//		//best+last
////		weight_element_ptr operator+(weight_element_ptr element);
//		weight_element_ptr operator+=(const weight_element_ptr &element);
//
//		//best-last
////		weight_element_ptr operator-(weight_element_ptr element);
//		weight_element_ptr operator-=(const weight_element_ptr &element);
//	};
//
//	class weight_element_type
//	{
//	public:
//		weight_element_ptr weights;
//		arith_uint288 total_weight;
//		arith_uint288 total_donation_weight;
//
//	public:
//		weight_element_type() = default;
//
//		weight_element_type(ShareType share)
//		{
//			auto att = coind::data::target_to_average_attempts(share->target);
//
//			weights = std::make_shared<weight_element>(share->new_script.data, att * (65535 - *share->donation));
//			total_weight = att * 65535;
//			total_donation_weight = att * (*share->donation);
//		}
//
//		weight_element_type(weight_element_ptr _weights, arith_uint288 _total_weight, arith_uint288 _total_donation_weight)
//		{
//			weights = _weights;
//			total_weight = _total_weight;
//			total_donation_weight = _total_donation_weight;
//		}
//
//		weight_element_type operator+(const weight_element_type &element)
//		{
//			weight_element_type res = *this;
//
//			*res.weights += element.weights;
//
////			std::map<std::vector<unsigned char>, arith_uint256> _weights;
////			_weights.insert(res.weights.begin(), res.weights.end());
////			for (auto v : element.weights)
////			{
////				if (_weights.find(v.first) != _weights.end())
////				{
////					_weights[v.first] += v.second;
////				} else
////				{
////					_weights[v.first] = v.second;
////				}
////			}
////			res.weights.swap(_weights);
//
//			res.total_weight += element.total_weight;
//			res.total_donation_weight += element.total_donation_weight;
//
//			return res;
//		}
//
//		weight_element_type operator-(const weight_element_type &element)
//		{
//			weight_element_type res = *this;
//
//			*res.weights -= element.weights;
//
////			std::map<std::vector<unsigned char>, arith_uint256> _weights;
////			_weights.insert(res.weights.begin(), res.weights.end());
////			for (auto v : element.weights)
////			{
////				if (_weights.find(v.first) != _weights.end())
////				{
////					_weights[v.first] -= v.second;
////					if (_weights[v.first] == 0)
////					{
////						_weights.erase(v.first);
////					}
////				}
////			}
////			res.weights.swap(_weights);
//
//			res.total_weight -= element.total_weight;
//			res.total_donation_weight -= element.total_donation_weight;
//
//			return res;
//		}
//
//		weight_element_type &operator+=(const weight_element_type &element)
//		{
//			*this->weights += element.weights;
////			for (auto v : element.weights)
////			{
////				if (this->weights.find(v.first) != this->weights.end())
////				{
////					this->weights[v.first] += v.second;
////				} else
////				{
////					this->weights[v.first] = v.second;
////				}
////			}
//
//			this->total_weight += element.total_weight;
//			this->total_donation_weight += element.total_donation_weight;
//
//			return *this;
//		}
//
//		weight_element_type &operator-=(const weight_element_type &element)
//		{
//			*this->weights -= element.weights;
////			for (auto v : element.weights)
////			{
////				if (this->weights.find(v.first) != this->weights.end())
////				{
////					this->weights[v.first] -= v.second;
////					if (this->weights[v.first] == 0)
////					{
////						this->weights.erase(v.first);
////					}
////				}
////			}
//
//			this->total_weight -= element.total_weight;
//			this->total_donation_weight -= element.total_donation_weight;
//
//			return *this;
//		}
//	};
//
////	class element_delta_type
////	{
////	private:
////		bool _none;
////
////	public:
////		uint256 head;
////		uint256 tail;
////
////		int32_t share_count;
////		weight_element_ptr weights;
////		arith_uint256 total_weight;
////		arith_uint256 total_donation_weight;
////
////		element_delta_type(bool none = true)
////		{
////			_none = none;
////		}
////
////		element_delta_type(weight_element_type &el)
////		{
////			head = el.hash();
////			tail = el.prev_hash();
////
////			share_count = el.share_count;
////			weights = el.weights;
////			total_weight = el.total_weight;
////			total_donation_weight = el.total_donation_weight;
////		}
////
////		element_delta_type operator-(const element_delta_type &el) const
////		{
////			element_delta_type res = *this;
////			res.tail = el.head;
////
////			res.share_count -= el.share_count;
////
////			*res.weights -= el.weights;
//////			std::map<std::vector<unsigned char>, arith_uint256> _weights;
//////			_weights.insert(res.weights.begin(), res.weights.end());
//////			for (auto v : el.weights)
//////			{
//////				if (_weights.find(v.first) != _weights.end())
//////				{
//////					_weights[v.first] -= v.second;
//////					if (_weights[v.first] == 0)
//////					{
//////						_weights.erase(v.first);
//////					}
//////				}
//////			}
//////			res.weights.swap(_weights);
////
////			res.total_weight -= el.total_weight;
////			res.total_donation_weight -= el.total_donation_weight;
////
////			return res;
////		}
////
////		void operator-=(const element_delta_type &el)
////		{
////			tail = el.head;
////
////			this->share_count -= el.share_count;
////
////			*this->weights -= el.weights;
//////			for (auto v : el.weights)
//////			{
//////				if (this->weights.find(v.first) != this->weights.end())
//////				{
//////					this->weights[v.first] -= v.second;
//////					if (this->weights[v.first] == 0)
//////					{
//////						this->weights.erase(v.first);
//////					}
//////				}
//////			}
////
////			this->total_weight -= el.total_weight;
////			this->total_donation_weight -= el.total_donation_weight;
////		}
////
////		bool is_none()
////		{
////			return _none;
////		}
////
////		void set_none(bool none = true)
////		{
////			_none = none;
////		}
////	};
////
////	class PrefsumWeights
////	{
////		std::shared_ptr<ShareTracker> _tracker;
////		map<uint256, weight_element_type> sum;
////
////	protected:
////		weight_element_type make_element(ShareType _share)
////		{
////			weight_element_type element(_share);
////			element.prev = sum.find(*_share->previous_hash);
////			return element;
////		}
////
////	public:
////		PrefsumWeights(std::shared_ptr<ShareTracker> tracker);
////// a = (desired_weight - total_weight1)
////// b = (total_weight2//65535)
////// (a * weights2[script]) // (b * 65535)
////	};
}