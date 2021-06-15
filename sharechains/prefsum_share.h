#include <univalue.h>
#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <devcore/logger.h>
#include <coind/data.h>

#include <map>
#include <vector>
#include <set>
#include <tuple>
#include <string>
#include <memory>
#include <deque>
using namespace std;

namespace c2pool::shares::tracker
{
    struct PrefixSumShareElement
    {
        uint256 hash; //head
        //TODO: ? uint256 previous_hash; //tail

        arith_uint256 work;
        arith_uint256 min_work;
        int height;

        PrefixSumShareElement &operator+=(const PrefixSumShareElement &rhs)
        {
            work += rhs.work;
            min_work += rhs.min_work;
            height += rhs.height;
            return *this;
        }

        PrefixSumShareElement &operator-=(const PrefixSumShareElement &rhs)
        {
            work -= rhs.work;
            min_work -= rhs.min_work;
            height -= rhs.height;
            return *this;
        }

        friend PrefixSumShareElement operator-(PrefixSumShareElement lhs, const PrefixSumShareElement &rhs)
        {
            lhs.work -= rhs.work;
            lhs.min_work -= rhs.min_work;
            lhs.height -= rhs.height;
            return lhs;
        }

        friend PrefixSumShareElement operator+(PrefixSumShareElement lhs, const PrefixSumShareElement &rhs)
        {
            lhs.work += rhs.work;
            lhs.min_work += rhs.min_work;
            lhs.height += rhs.height;
            return lhs;
        }
    };

    //https://en.wikipedia.org/wiki/Prefix_sum
    class PrefixSumShare
    {
    protected:
        deque<PrefixSumShareElement> _sum;
        map<uint256, deque<PrefixSumShareElement>::iterator> _reverse;
        int max_size;
        int real_max_size;

    public:
        int get_height(uint256 hash)
        {
            return _reverse[hash]->height;
        }

        tuple<int, uint256> get_height_and_last(uint256 hash)
        {
            //TODO:
        }

        uint256 get_work(uint256 hash)
        {
            //TODO:
        }

        uint256 get_last(uint256 hash)
        {
            //TODO:
        }

    private:
        void resize()
        {
            auto delta = _sum[max_size - 1];
            for (int i = 0; i < max_size; i++)
            {
                reverse_remove(_sum.front().hash);
                _sum.pop_front();
            }
            for (auto &item : _sum)
            {
                item -= delta;
            }
        }

        void reverse_add(uint256 hash, deque<PrefixSumShareElement>::iterator _it);

        void reverse_remove(uint256 hash);

    public:
        PrefixSumShare(int _max_size)
        {
            max_size = _max_size;
            real_max_size = max_size * 4;
        }

        void init(vector<PrefixSumShareElement> a)
        {
            for (auto item : a)
            {
                add(item);
            }
        }

        void add(PrefixSumShareElement v)
        {
            if (_sum.size() >= real_max_size)
            {
                resize();
            }
            if (!_sum.empty())
            {
                v += _sum.back();
            }

            _sum.push_back(v);
            reverse_add(v.hash, _sum.end() - 1);
        }

        void remove(int index)
        {
            if ((_sum.size() <= index) && (index < 0))
            {
                throw std::out_of_range("size of sum < index in prefix_sum.remove");
            }
            if (_sum.size() - 1 == index)
            {
                reverse_remove(_sum.back().hash);
                _sum.pop_back();
            }
            else
            {
                PrefixSumShareElement v;
                if (index - 1 < 0)
                {
                    v = _sum[index];
                }
                else
                {
                    v = _sum[index] - _sum[index - 1];
                }
                for (auto item = _sum.begin() + index + 1; item != _sum.end(); item++)
                {
                    *item -= v;
                }

                auto it_for_remove = _sum.begin() + index;
                reverse_remove(it_for_remove->hash);
                _sum.erase(it_for_remove);
            }
        }

        size_t size()
        {
            return _sum.size();
        }
    };

    //Weights

    struct PrefixSumWeightsElement
    {
        uint256 hash;

        std::map<char *, arith_uint256> weights;
        arith_uint256 total_weight;
        arith_uint256 total_donation_weight;

        std::map<char *, arith_uint256> my_weights;
        arith_uint256 my_total_weight;
        arith_uint256 my_total_donation_weight;

        PrefixSumWeightsElement()
        {
            hash.SetNull();
        }

        PrefixSumWeightsElement(uint256 hash, uint256 target, char* new_script, uint256 donation);

        PrefixSumWeightsElement(std::map<char *, arith_uint256>& _weights, arith_uint256& _total_weight, arith_uint256& _total_donation_weight){
            weights = _weights;
            total_weight = _total_weight;
            total_donation_weight = _total_donation_weight;
        }

        PrefixSumWeightsElement my(){
            return PrefixSumWeightsElement(my_weights, my_total_weight, my_total_donation_weight);
        }

        PrefixSumWeightsElement &operator+=(const PrefixSumWeightsElement &rhs)
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

        PrefixSumWeightsElement &operator-=(const PrefixSumWeightsElement &rhs)
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

        friend PrefixSumWeightsElement operator-(PrefixSumWeightsElement lhs, const PrefixSumWeightsElement &rhs)
        {
            lhs -= rhs;
            return lhs;
        }

        friend PrefixSumWeightsElement operator+(PrefixSumWeightsElement lhs, const PrefixSumWeightsElement &rhs)
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

    class PrefixSumWeights
    {
    protected:
        deque<PrefixSumWeightsElement> _sum;
        map<uint256, deque<PrefixSumWeightsElement>::iterator> _reverse;

        int max_size;
        int real_max_size;

    public:
        CumulativeWeights get_cumulative_weights(uint256 start_hash, int32_t max_shares, arith_uint256 desired_weight)
        {
            PrefixSumWeightsElement result_element;

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
                                result_element += PrefixSumWeightsElement(new_weights, new_total_weight, new_total_donation_weight);
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

    private:
        void resize()
        {
            auto delta = _sum[max_size - 1];
            for (int i = 0; i < max_size; i++)
            {
                reverse_remove(_sum.front().hash);
                _sum.pop_front();
            }
            for (auto &item : _sum)
            {
                item -= delta;
            }
        }

        void reverse_add(uint256 hash, deque<PrefixSumWeightsElement>::iterator _it);

        void reverse_remove(uint256 hash);

    public:
        PrefixSumWeights(int _max_size)
        {
            max_size = _max_size;
            real_max_size = max_size * 4;
        }

        void init(vector<PrefixSumWeightsElement> a)
        {
            for (auto item : a)
            {
                add(item);
            }
        }

        void add(PrefixSumWeightsElement v)
        {
            if (_sum.size() >= real_max_size)
            {
                resize();
            }
            if (!_sum.empty())
            {
                v += _sum.back();
            }

            _sum.push_back(v);
            reverse_add(v.hash, _sum.end() - 1);
        }

        void remove(int index)
        {
            if ((_sum.size() <= index) && (index < 0))
            {
                throw std::out_of_range("size of sum < index in prefix_sum.remove");
            }
            if (_sum.size() - 1 == index)
            {
                reverse_remove(_sum.back().hash);
                _sum.pop_back();
            }
            else
            {
                PrefixSumWeightsElement v;
                if (index - 1 < 0)
                {
                    v = _sum[index];
                }
                else
                {
                    v = _sum[index] - _sum[index - 1];
                }
                for (auto item = _sum.begin() + index + 1; item != _sum.end(); item++)
                {
                    *item -= v;
                }

                auto it_for_remove = _sum.begin() + index;
                reverse_remove(it_for_remove->hash);
                _sum.erase(it_for_remove);
            }
        }

        size_t size()
        {
            return _sum.size();
        }
    };
}
