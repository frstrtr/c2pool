#pragma once

#include <util/prefsum.h>

#include <univalue.h>
#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <devcore/logger.h>
#include <coind/data.h>

#include <vector>
#include <tuple>
#include <string>
#include <memory>
using namespace std;

namespace c2pool::shares
{
    struct PrefsumShareElement
    {
        uint256 hash; //head
        //TODO: ? uint256 previous_hash; //tail

        arith_uint256 work;
        arith_uint256 min_work;
        int height;

        uint256 reverse_key()
        {
            return hash;
        }

        PrefsumShareElement &operator+=(const PrefsumShareElement &rhs)
        {
            work += rhs.work;
            min_work += rhs.min_work;
            height += rhs.height;
            return *this;
        }

        PrefsumShareElement &operator-=(const PrefsumShareElement &rhs)
        {
            work -= rhs.work;
            min_work -= rhs.min_work;
            height -= rhs.height;
            return *this;
        }

        friend PrefsumShareElement operator-(PrefsumShareElement lhs, const PrefsumShareElement &rhs)
        {
            lhs.work -= rhs.work;
            lhs.min_work -= rhs.min_work;
            lhs.height -= rhs.height;
            return lhs;
        }

        friend PrefsumShareElement operator+(PrefsumShareElement lhs, const PrefsumShareElement &rhs)
        {
            lhs.work += rhs.work;
            lhs.min_work += rhs.min_work;
            lhs.height += rhs.height;
            return lhs;
        }
    };

    //https://en.wikipedia.org/wiki/Prefix_sum
    class PrefsumShare : public Prefsum<PrefsumShareElement, uint256>
    {
    public:
        int get_height(uint256 hash)
        {
            return _reverse[hash]->height;
        }

        uint256 get_work(uint256 hash)
        {
            //TODO:
        }

        uint256 get_last(uint256 hash)
        {
            //TODO:
        }

        virtual uint256 get_nth_parent_hash(int32_t n)
        {
            if (n >= size())
            {
                //TODO: throw
            }
            return (_sum.begin() - (n + 1))->hash;
        }

        tuple<int, uint256> get_height_and_last(uint256 hash)
        {
            //TODO:
        }

    public:
        PrefsumShare(int _max_size) : Prefsum(_max_size) {}
    };

    class PrefsumVerifiedShare : public PrefsumShare
    {
    protected:
        PrefsumShare &prefsum_share;

    public:
        PrefsumVerifiedShare(int _max_size, PrefsumShare &_prefsum_share) : PrefsumShare(_max_size), prefsum_share(_prefsum_share)
        {
        }

        uint256 get_nth_parent_hash(int32_t n) override
        {
            return prefsum_share.get_nth_parent_hash(n);
        }
    };
}

//========================Weights========================
namespace c2pool::shares
{
    struct PrefsumWeightsElement
    {
        uint256 hash;

        std::map<char *, arith_uint256> weights;
        arith_uint256 total_weight;
        arith_uint256 total_donation_weight;

        std::map<char *, arith_uint256> my_weights;
        arith_uint256 my_total_weight;
        arith_uint256 my_total_donation_weight;

        uint256 reverse_key()
        {
            return hash;
        }

        PrefsumWeightsElement()
        {
            hash.SetNull();
        }

        PrefsumWeightsElement(uint256 hash, uint256 target, char *new_script, uint256 donation);

        PrefsumWeightsElement(std::map<char *, arith_uint256> &_weights, arith_uint256 &_total_weight, arith_uint256 &_total_donation_weight)
        {
            weights = _weights;
            total_weight = _total_weight;
            total_donation_weight = _total_donation_weight;
        }

        PrefsumWeightsElement my()
        {
            return PrefsumWeightsElement(my_weights, my_total_weight, my_total_donation_weight);
        }

        PrefsumWeightsElement &operator+=(const PrefsumWeightsElement &rhs)
        {
            auto _weights = rhs.weights;
            weights.merge(_weights);
            for (auto weight_value : _weights)
            {
                weights[weight_value.first] += weight_value.second;
            }

            total_weight += rhs.total_weight;
            total_donation_weight += rhs.total_donation_weight;
            return *this;
        }

        PrefsumWeightsElement &operator-=(const PrefsumWeightsElement &rhs)
        {
            auto _weights = rhs.weights;
            _weights.merge(weights);
            for (auto vk : weights)
            {
                weights[vk.first] -= _weights[vk.first];
            }

            total_weight -= rhs.total_weight;
            total_donation_weight -= rhs.total_donation_weight;
            return *this;
        }

        friend PrefsumWeightsElement operator-(PrefsumWeightsElement lhs, const PrefsumWeightsElement &rhs)
        {
            lhs -= rhs;
            return lhs;
        }

        friend PrefsumWeightsElement operator+(PrefsumWeightsElement lhs, const PrefsumWeightsElement &rhs)
        {
            lhs += rhs;
            return lhs;
        }
    };

    struct CumulativeWeights
    {
        std::map<char *, arith_uint256> weights;
        arith_uint256 total_weight;
        arith_uint256 donation_weight;
    };

    class PrefsumWeights : public Prefsum<PrefsumWeightsElement, uint256>
    {
    public:
        CumulativeWeights get_cumulative_weights(uint256 start_hash, int32_t max_shares, arith_uint256 desired_weight)
        {
            PrefsumWeightsElement result_element;

            //Если шары имеются.
            if (!_sum.empty())
            {
                auto _it = _reverse[start_hash];
                result_element = *_it;

                //Если шар в трекере за заданной шарой, меньше или равен максимальному.
                if (distance(_sum.begin(), _it) <= max_shares)
                {
                    if (_it->total_weight > desired_weight)
                    {
                        // Случай, если вес больше ожидаемого
                        auto req_weight_delta = _it->total_weight + desired_weight;

                        for (auto check_it = _sum.begin(); check_it < _it; check_it++)
                        {
                            req_weight_delta -= check_it->total_weight;

                            if (req_weight_delta == desired_weight)
                            {
                                result_element -= *check_it;
                                result_element += check_it->my();
                                break;
                            }

                            if (req_weight_delta < desired_weight)
                            {
                                result_element -= *check_it;
                                auto just_my = check_it->my();
                                auto new_script = just_my.weights.begin()->first;
                                auto new_weight = (desired_weight - result_element.total_weight) / 65535 * just_my.weights[new_script] / (just_my.total_weight / 65535);
                                std::map<char *, arith_uint256> new_weights = {{new_script, new_weight}};

                                arith_uint256 new_total_donation_weight = (desired_weight - result_element.total_weight) / 65535 * just_my.my_total_donation_weight / (just_my.total_weight / 65535);
                                arith_uint256 new_total_weight = desired_weight - req_weight_delta;
                                //total_donation_weight1 + (desired_weight - total_weight1)//65535*total_donation_weight2//(total_weight2//65535)
                                result_element += PrefsumWeightsElement(new_weights, new_total_weight, new_total_donation_weight);
                                break;
                            }
                        }
                    }
                }
                else
                {
                    //TODO: Случаи, когда количество шар в трекере больше, чем нужно в запросе.
                }
            }

            return CumulativeWeights(result_element.weights, result_element.total_weight, result_element.total_donation_weight);
        }

    public:
        PrefsumWeights(int _max_size) : Prefsum(_max_size) {}
    };
}
