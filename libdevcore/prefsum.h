#pragma once

//#include <deque>
#include <map>
#include <vector>
#include <set>

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

    int32_t height;
    key_type head;
    key_type tail;
public:
    virtual bool is_none() = 0;

    virtual void set_value(value_type value) = 0;
protected:
    virtual sub_element_type& _push(const sub_element_type &sub) = 0;
    virtual sub_element_type& _erase(const sub_element_type &sub) = 0;
public:
    virtual sub_element_type& push(const sub_element_type &sub)
    {
        if (tail != sub.head)
            throw std::invalid_argument("tail != sub.head");

        tail = sub.tail;
        height += sub.height;

        return _push(sub);
    }

    virtual sub_element_type& erase(const sub_element_type &sub)
    {
        std::cout << head << " " << tail << std::endl;
        std::cout << sub.head << " " << sub.tail << std::endl;
        if (head == sub.head)
        {
            head = sub.tail;
            next = sub.next;
        } else if (tail == sub.tail)
        {
            tail = sub.head;
            prev = sub.prev;
        } else
        {
            throw std::invalid_argument("incorrect sub element in erase()!");
        }
        height -= sub.height;
        return _erase(sub);
    }

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

    //heads[head] -> tail
    std::map<key_type, key_type> heads;

    //tails[tail] -> set(head)
    std::map<key_type, std::set<key_type>> tails;

    Event<value_type> added;
    Event<value_type> removed;
protected:
    virtual element_type& _make_element(element_type& element, const value_type &value) = 0;
    virtual element_type& _none_element(element_type& element, const key_type& key) = 0;

public:
    virtual element_type make_element(value_type value)
    {
        element_type element {value};
        element.prev = sum.find(element.tail);
        element.height = 1;

        return _make_element(element, value);
    }

    virtual element_type none_element(key_type key)
    {
        element_type element;
        element.height = 0;

        return _none_element(element, key);
    }

    virtual void add(value_type _value)
    {
        //--Make PrefsumElement from value_type
        auto value = make_element(_value);

        if (value.is_none())
            throw std::invalid_argument("value is none!");

        //--Check for exist value in items
        if (items.find(value.head) != items.end())
            throw std::invalid_argument("item already present!");

        //--Add value to items
        items[value.head] = _value;

        //--Add value to sum
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

        //--update heads and tails

        // проверка на то, что новый элемент не является началом уже существующей части,
        // т.е. head нового элемента -- tail уже существующего в prefsum.
        std::set<key_type> _heads;
        if (tails.find(value.head) != tails.end())
        {
            _heads = tails[value.head];
            tails.erase(value.head); // TODO: optimize
        } else
        {
            _heads = {value.head};
        }

        // Проверка на то, что новый элемент не является ли продолжением уже существующей части,
        // т.е. tail нового элемента -- head уже существующего в prefsum.
        key_type _tail;
        if (heads.find(value.tail) != heads.end())
        {
            _tail = heads[value.tail];
            heads.erase(value.tail);
        } else
        {
            _tail = get_last(value.tail);
        }

        if (tails.count(_tail))
            tails[_tail].insert(_heads.begin(), _heads.end());
        else
            tails[_tail] = _heads;
        if (tails.empty() && (tails[_tail].find(value.tail) != tails[_tail].end()))
            tails[value.tail].erase(value.tail);

        for (auto _head : _heads)
        {
            heads[_head] = _tail;
        }

        //--Call event ADDED
        added.happened(_value);
    }

    virtual void remove(key_type key)
    {
        if (items.find(key) == items.end())
            throw std::invalid_argument("item not exist!");

        auto item = items[key];
        items.erase(key);

        //TODO:

    }

    bool exists(key_type key)
    {
        return (items.find(key) != items.end());
    }

    int32_t get_height(key_type item)
    {
        return get_sum_to_last(item).height;
    }

    key_type get_last(key_type item)
    {
        return get_sum_to_last(item).tail;
    }

    // get_delta_to_last in p2pool
    element_type get_sum_to_last(key_type item)
    {
        auto result = none_element(item);

        if (items.find(result.tail) != items.end())
            result = sum[result.tail];

        return result;
    }

    std::tuple<int32_t, key_type> get_height_and_last(key_type item)
    {
        auto _sum = get_sum_to_last(item);
        return {_sum.height, _sum.tail};
    }

    virtual key_type get_nth_parent_key(key_type key, int32_t n)
    {
        auto it = sum.find(key);
        key_type result = key;
        int32_t dist = 0;

        while((dist < n) && (it != sum.end()))
        {
            dist++;
            if (it->second.prev != sum.end())
            {
                it = it->second.prev;
                result = it->first;
            } else
            {
                result = it->second.tail;
                it = it->second.prev;
            }
        }
//        if (it == sum.end())
//            throw std::invalid_argument("get_nth_parent_key n < len_chain");

        if (dist != n)
            throw std::invalid_argument("dist != n");

        return result;
    }

    // last------item------child---best->
    bool is_child_of(key_type item, key_type possible_child)
    {
        auto [height, last] = get_height_and_last(item);
        auto [child_height, child_last] = get_height_and_last(possible_child);

        if (last != child_last)
            return false;

        auto height_up = child_height - height;
        return height_up != 0 && get_nth_parent_key(possible_child, height_up) == item;
    }

    // last------[ancestor------item]--->best
    element_type get_sum(key_type item, key_type ancestor)
    {
        if (!is_child_of(ancestor, item))
            throw std::invalid_argument("get_sum item not child for ancestor");

        auto result = get_sum_to_last(item);
        auto ances = get_sum_to_last(ancestor);
        return result.erase(ances);
    }

    std::function<bool(key_type&)> get_chain(key_type key, int32_t n)
    {
        if (n > get_height(key))
        {
            throw std::invalid_argument("n > height for this key in get_chain!");
        }
        return [&, this]()
        {
            auto cur_it = sum.find(key);
            auto cur_pos = n; //exclusive 0
            auto &_sum = this->sum;

            return [=, &_sum](key_type &ref_key) mutable
            {
                if ((cur_it != _sum.end()) && (cur_pos > 0))
                {
                    ref_key = cur_it->first;
                    cur_it = cur_it->second.prev;
                    cur_pos -= 1;
                    return true;
                } else
                {
                    return false;
                }
            };
        }();
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