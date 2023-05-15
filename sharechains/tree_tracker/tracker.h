#pragma once
#include <set>
#include <functional>
#include <optional>

#include <btclibs/uint256.h>

#include "fork.h"
#include "rules.h"
#include "../share.h"
#include <libdevcore/events.h>


template <typename TrackerElement>
class Tracker
{
public:
    typedef uint256 hash_type;
    typedef ShareType item_type;
    typedef typename std::map<hash_type , item_type>::iterator it_items;

    typedef Fork<TrackerElement, 8192> fork_type;
    typedef std::shared_ptr<fork_type> fork_ptr;
    typedef typename fork_type::value_type value_type;
    typedef typename fork_type::sum_element sum_element;

public:
    std::map<hash_type, item_type> items;
    std::map<hash_type, std::vector<it_items>> reverse;

    std::vector<fork_ptr> forks;
    std::map<hash_type, fork_ptr> fork_by_key;

    //heads[head] -> tail
    std::map<hash_type, fork_ptr> heads;

    //tails[tail] -> set(head)
    std::map<hash_type, std::set<fork_ptr>> tails;

    // manager for rules
    shares::PrefsumRules<value_type> rules;

    Event<value_type> added;
    Event<value_type> removed;
public:
    Tracker()
    {
        rules.new_rule_event.subscribe([&](const std::vector<std::string> &k_rules)
                                       {
                                           new_rules_calculate(k_rules);
                                       });
    }

    void add(value_type _value)
    {
        if (!_value)
            throw std::invalid_argument("value is none");

        auto value = make_element(_value);

        if (items.find(value.hash()) != items.end())
            throw std::invalid_argument("item already present!");

        //--Add value to items
        items[value.hash()] = _value;

        //--Add to reverse
        reverse[value.prev()].push_back(items.find(value.hash()));

        //--Add to forks

        //----forks by head
        if (heads.find(value.prev()) != heads.end())
        {
            auto head_fork = heads.extract(value.prev());
            head_fork.mapped()->insert(value);
            head_fork.key() = value.hash();
            heads.insert(std::move(head_fork));

            fork_by_key[value.hash()] = heads[value.hash()];
        }
        //----forks by tail
        else if (tails.find(value.hash()) != tails.end())
        {
            auto tail_forks = tails.find(value.hash());
            if (tail_forks->second.size() > 1)
            {
                // make new fork
                auto new_fork = make_fork();
                new_fork->insert(value);

                // add new fork to head forks
                for (auto &_fork :tail_forks->second)
                {
                    _fork->insert_fork(new_fork);
                }
                fork_by_key[value.hash()] = new_fork;
            } else
            {
                // add value in head fork
                for (auto &_fork :tail_forks->second)
                {
                    _fork->insert(value);
                    fork_by_key[value.hash()] = _fork;
                }
            }
        } else
        {
            // make new fork
            auto new_fork = make_fork();
            new_fork->insert(value);
            heads[new_fork->head] = new_fork;
            tails[new_fork->tail].insert(new_fork);
            fork_by_key[value.hash()] = new_fork;
        }

        //--Call event ADDED
        added.happened(_value);
    }

    bool exist(hash_type hash)
    {
        return (items.find(hash) != items.end());
    }

    sum_element get_sum_to_last(hash_type hash)
    {
        sum_element result;

        if (items.find(hash) != items.end())
        {
            auto fork = fork_by_key[hash];
            result += fork->get_sum(hash);
            fork = fork->prev_fork;

            while (fork)
            {
                result += fork->get_sum_all();
                fork = fork->prev_fork;
            }
        } else
            return sum_element(hash);

        return result;
    }

    int32_t get_height(hash_type hash)
    {
        return get_sum_to_last(hash).height;
    }

    int32_t get_last(hash_type hash)
    {
        auto fork = fork_by_key.find(hash);
        // TODO: NULL HASH RETURN!
        return fork != fork_by_key.end() ? fork->second->tail : hash;
    }

    std::tuple<int32_t, hash_type> get_height_and_last(hash_type item)
    {
        return {get_height(item), get_last(item)};
    }

    bool is_child_of(hash_type item, hash_type possible_child)
    {
        // item = possible_child -> объект сам себе дочерний, true.
        if (item == possible_child)
            return true;

        auto [height, last] = get_height_and_last(item);
        auto [child_height, child_last] = get_height_and_last(possible_child);

        if (last != child_last)
            return false;

        auto height_up = child_height - height;
        return height_up >= 0 && get_nth_parent_key(possible_child, height_up) == item;
    }

    virtual hash_type get_nth_parent_key(hash_type hash, int32_t n) const
    {
        for (int i = 0; i < n; i++)
        {
            hash = *items.at(hash)->previous_hash;
        }
        return hash;
    }

    std::function<bool(hash_type&)> get_chain(hash_type hash, int32_t n)
    {
        if (n > get_height(hash))
        {
            throw std::invalid_argument("n > height for this hash in get_chain!");
        }

        return [&, this]()
        {
            auto cur_it = items.find(hash);
            auto cur_pos = n; //exclusive 0
            auto &_items = this->items;

            return [=, &_items](hash_type &ref_key) mutable
            {
                if (cur_it != _items.end() && (cur_pos > 0))
                {
                    ref_key = cur_it->first;
                    cur_it = _items.find(*cur_it->second->previous_hash);
                    cur_pos -= 1;
                    return true;
                } else
                {
                    return false;
                }
            };
        }();
    }

private:
    fork_ptr make_fork()
    {
        auto new_fork = std::make_shared<fork_type>();
        forks.push_back(new_fork);
        return new_fork;
    }

    virtual sum_element make_element(value_type _value)
    {
        sum_element element(_value);
        element.rules = rules.make_rules(_value);

        return element;
    }

    void new_rules_calculate(std::vector<std::string> k_rules)
    {
        //TODO:
    }
};