#include <map>
#include <queue>
#include <list>
#include <memory>
#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include "share.h"
using namespace std;

class element_type
{
public:
    map<uint256, element_type>::iterator prev;
    list<map<uint256 element_type>::iterator> nexts;
    shared_ptr<BaseShare> element;

    int32_t height;
    uint256 work;

public:
    element_type() {}
    element_type(shared_ptr<BaseShare> _share)
    {
        element = _share;
        work = _share->work;
        height = 1;
    }

    int hash()
    {
        return element->hash;
    }
    int prev_hash()
    {
        if (element == nullptr)
        {
            cout << prev->second.hash() << endl;
            return 0;
        }
        return element->prev_hash;
    }

    element_type operator+(const element_type &element)
    {
        element_type res = *this;
        res.work += element.work;
        res.height += element.height;
        return res;
    }

    element_type operator-(const element_type &element)
    {
        element_type res = *this;
        res.work -= element.work;
        res.height -= element.height;
        return res;
    }

    element_type operator+=(const element_type &element)
    {
        this->work += element.work;
        this->height += element.height;
        return *this;
    }

    element_type operator-=(const element_type &element)
    {
        this->work -= element.work;
        this->height -= element.height;
        return *this;
    }

    // static element_type get_null(){}
};

class element_delta_type
{
private:
    bool _none;

public:
    uint256 head;
    uint256 tail;
    int32_t height;
    arith_uint256 work;

    element_delta_type(bool none = true)
    {
        _none = none;
    }

    element_delta_type(element_type &el)
    {
        head = el.hash();
        tail = el.prev_hash();
        height = el.height;
        work = el.work;
    }

    element_delta_type operator-(const element_delta_type &el) const
    {
        element_delta_type res = *this;
        res.tail = el.head;
        res.height -= el.height;
        res.work -= el.work;
        return res;
    }

    void operator-=(const element_delta_type &el)
    {
        tail = el.head;
        height -= el.height;
        work -= el.work;
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

class PrefsumShare
{
public:
    map<uint256, shared_ptr<BaseShare>> items;
    map<uint256, element_type> sum;

protected:
    element_type make_element(shared_ptr<BaseShare> _share)
    {
        element_type element(_share);
        element.prev = sum.find(_share->prev_hash);
        return element;
    }

public:
    void add(shared_ptr<BaseShare> _share)
    {
        //TODO: throw if share exists in items;
        items[_share->hash] = _share;

        element_type new_sum_element = make_element(_share); //only this element
        if (new_sum_element.prev != sum.end())
        {
            new_sum_element += new_sum_element.prev->second;
            sum[_share->hash] = new_sum_element;
            new_sum_element.prev->second.nexts.push_back(sum.find(_share->hash));
        }
        else
        {
            sum[_share->hash] = new_sum_element;
        }
    }

#define set_cur_it(new_value) \
    cur_it = new_value;       \
    cur_it_nexts = cur_it->second.nexts

#define get_q() \
    q.front();  \
    q.pop()

    void remove(uint256 hash)
    {
        //TODO: throw if hash not exists in items;
        auto _share = items[hash];
        items.erase(hash);

        queue<map<uint256, element_type>::iterator> q;
        auto remover = sum[hash];

        auto cur_it = sum.find(hash);
        auto &cur_it_nexts = cur_it->second.nexts;

        if (remover.nexts.empty())
        {
            cur_it = sum.end();
        }
        else
        {
            for (auto item : cur_it_nexts)
            {
                item->second.prev = sum.end(); //remover.prev;
                q.push(item);
            }
            auto new_it = get_q();
            set_cur_it(new_it);
        }
        //добавлять все nexts в текущей cur_it в q и проходить их.
        while (!q.empty() || (cur_it != sum.end()))
        {
            if (cur_it != sum.end())
            {
                cur_it->second -= remover;
                for (auto item : cur_it_nexts)
                {
                    q.push(item);
                }
            }
            if (!q.empty())
            {
                auto new_it = get_q();
                set_cur_it(new_it);
            }
            else
            {
                break;
            }
        }
        sum.erase(hash);
    }
#undef set_cur_it
#undef get_q

    bool is_child_of(uint256 item_hash, uint256 possible_child_hash)
    {
        auto _it = sum.find(item_hash);
        if (sum.find(possible_child_hash) == sum.end())
        {
            throw invalid_argument("is_child_of: possible_child_hash existn't in tracker");
        }
        while (_it != sum.end())
        {
            if (_it->second.prev->first == possible_child_hash)
                return true;
            else
                _it = _it->second.prev;
        }
        return false;
    }

    element_delta_type get_delta(uint256 first_hash, uint256 second_hash)
    {
        if (sum.find(first_hash) == sum.end())
        {
            throw invalid_argument("first_hash in get_delta existn't in sum!");
        }
        if (sum.find(second_hash) == sum.end())
        {
            throw invalid_argument("second in get_delta existn't in sum!");
        }

        if (!is_child_of(first_hash, second_hash))
        {
            throw invalid_argument("get_delta: second_hash is not child for first_hash!");
            //return element_delta_type();
        }

        element_delta_type fir(sum[first_hash]);
        element_delta_type sec(sum[second_hash]);
        return fir - sec;
    }

    //todo: create optimization like get_last_iterator
    int get_last(uint256 hash)
    {
        auto _it = sum.find(hash);
        if (_it == sum.end())
        {
            throw invalid_argument("[get_last] hash not exists in sum");
        }
        //cout << _it->second.element;
        auto last = _it->second.prev_hash();
        while (_it != sum.end())
        {
            last = _it->second.prev_hash();
            _it = _it->second.prev;
            // this_thread::sleep_for(chrono::milliseconds(1));
        }
        return last;
    }

    element_delta_type get_delta_to_last(int hash)
    {
        auto el = sum.find(hash);
        if (el == sum.end())
        {
            throw invalid_argument("[get_delta_to_last] hash not exists in sum");
        }
        element_delta_type delta(el->second);
        delta.tail = get_last(hash);
        return delta;
    }

    int get_test_best()
    {
        if (items.empty())
        {
            return 0;
        }
        auto best = items.begin()->second->hash;
        for (auto item : items)
        {
            if (item.second->hash > best)
                best = item.second->hash;
        }
        return best;
    }

    //todo: remove range
};