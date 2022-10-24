#pragma once

//#include <deque>
#include <map>
#include <vector>

#include "events.h"

using namespace std;

template <typename Key, typename Value, typename SubElement>
class BasePrefsumElement
{
public:
    typedef Key key_type;
    typedef Value value_type;
    typedef SubElement sub_element_type;
    typedef typename std::map<key_type, sub_element_type>::iterator it_element;
public:
    it_element prev;
    std::vector<it_element> next;

    key_type head;
    key_type tail;
public:
    virtual bool is_none() = 0;

    virtual void set_value(value_type value) = 0;
//    virtual it_element get_prev() = 0;
//    virtual std::vector<it_element> get_next() = 0;

//    virtual key_type get_head(value_type value) = 0;
//    virtual key_type get_tail(value_type value) = 0;

public:
    virtual sub_element_type& push(sub_element_type sub) = 0;

    BasePrefsumElement() {}
};

template <typename PrefsumElementType>
class Prefsum
{
public:
    typedef PrefsumElementType element_type;
    typedef typename element_type::key_type key_type;
    typedef typename element_type::value_type value_type;
public:
    std::map<key_type, value_type> items;
    std::map<key_type, element_type> sum;

    Event<value_type> added;
    Event<value_type> removed;
public:
    virtual element_type make_element(value_type value) = 0;

    virtual void add(value_type _value)
    {
        // Make PrefsumElement from value_type
        auto value = make_element(_value);

        if (value.is_none())
            throw std::invalid_argument("value is none!");

        // Check for exist value in items
        if (items.find(value.head) != items.end())
            throw std::invalid_argument("item already present!");

        // Add value to items
        items[value.head] = _value;

        // Add value to sum
        if (value.prev != sum.end())
        {
            value.push(value.prev->second);
            auto &it = sum[value.head];
            it = std::move(value);
            it.prev->second.next.push_back(sum.find(it.head));
        } else
        {
            sum[value.head] = std::move(value);
        }



        // Call event ADDED
        added.happened(_value);
    }

    virtual void remove(key_type key)
    {
        if (items.find(key) == items.end())
            throw std::invalid_argument("item not exist!");

        auto item = items[key];
        items.erase(key);


    }
};


/*
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

    size_t get_max_size() const
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

    bool exists(reverse_key k)
    {
        if (_reverse.find(k) != _reverse.end())
            return true;
        else
            return false;
    }
};
 */