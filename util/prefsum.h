#pragma once
#include <deque>
#include <map>

using namespace std;

//https://en.wikipedia.org/wiki/Prefix_sum
template <typename element_type, typename reverse_key>
class Prefsum
{
public:
    typedef typename deque<element_type>::iterator it_type;

protected:
    deque<element_type> _sum;
    map<reverse_key, it_type> _reverse;
    const size_t max_size;
    const size_t real_max_size;

private:
    void reverse_add(reverse_key reverse_k, it_type _it)
    {
        _reverse[reverse_k] = _it;
    }

    void reverse_remove(reverse_key reverse_k)
    {
        _reverse.erase(reverse_k);
    }

    virtual void resize()
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

public:
    Prefsum(int32_t _max_size) : max_size(_max_size), real_max_size(_max_size * 4)
    {
    }

    size_t size() const
    {
        return _sum.size();
    }

    size_t max_size() const
    {
        return max_size;
    }

    virtual void add(element_type v)
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

    void add_range(vector<element_type> items)
    {
        for (auto &item : items)
        {
            add(item);
        }
    }

    virtual void remove(int32_t index)
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
            element_type v;
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
            reverse_remove(it_for_remove->reverse_key()); //? it_for_remove->template reverse_key
            _sum.erase(it_for_remove);
        }
    }

    void remove_from_key(reverse_key key)
    {
        auto index_it = _reverse[key];
        remove(distance(_sum.begin(), index_it));
    }
};