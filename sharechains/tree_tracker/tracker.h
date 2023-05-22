#pragma once
#include <set>
#include <functional>
#include <optional>

#include <btclibs/uint256.h>

#include "fork.h"
#include "rules.h"
#include "../share.h"
#include <libdevcore/events.h>

template <typename T>
class PrepareNode
{
public:
    T value;

    std::shared_ptr<PrepareNode> prev;
    std::shared_ptr<PrepareNode> next;

    PrepareNode() {};
    PrepareNode(T& _value)
    {
        value = _value;
    }
};

//class TestData
//{
//public:
//    int hash;
//    int previous_hash;
//
//    int value;
//
//    TestData() {};
//    TestData(int _v, int _hash, int _prev)
//    {
//        value = _v;
//        hash = _hash;
//        previous_hash = _prev;
//    }
//};



template <typename T>
class PrepareFork
{
public:
    typedef T data_type;
    typedef std::shared_ptr<Node<T>> ptr_node;

    ptr_node head;
    ptr_node tail;

    PrepareFork(ptr_node _node)
    {
        head = _node;
        tail = _node;
    }
};

template <typename T>
class PreparedList
{
private:
    typedef std::shared_ptr<PrepareFork<T>> ptr_fork;
    typedef typename PrepareFork<T>::ptr_node ptr_node;
    typedef typename PrepareFork<T>::data_type data_type;
private:
    std::map<int, ptr_node> nodes;

    ptr_node make_node(data_type &value)
    {
        auto v = std::make_shared<Node<data_type>>(value);
        nodes[value.hash] = v;

        return v;
    }

    // Метод создаёт пару из двух нод
    void make_pair(ptr_node left, ptr_node right)
    {
        left->next = right;
        right->prev = left;
    }

    ptr_fork merge_fork(ptr_fork left, ptr_fork right)
    {
        make_pair(left->head, right->tail);
        left->head = right->head;
        return left;
    }
public:
    std::vector<ptr_fork> forks;

    PreparedList(std::vector<data_type> data)
    {
        // Prepare data
        // -- map hashes
        std::map<int, typename std::vector<data_type>::iterator> hashes;
        for (auto it = data.begin(); it != data.end(); it++)
        {
            hashes[it->hash] = it;
        }

        // -- heads/tails

        std::map<int, ptr_fork> heads;
        std::map<int, ptr_fork> tails;

        while (!hashes.empty())
        {
            auto node = make_node(*hashes.begin()->second);
            hashes.erase(node->value.hash);

            if (!heads.count(node->value.previous_hash) && !tails.count(node->value.hash))
            {
                typename std::map<int, typename std::vector<data_type>::iterator>::iterator it;
                // make new fork
                {
                    auto new_fork = std::make_shared<PrepareFork>(node);
                    heads[node->value.hash] = new_fork;
                    tails[node->value.previous_hash] = new_fork;
                }

                while ((it = hashes.find(node->value.previous_hash)) != hashes.end())
                {
                    auto new_node = make_node(*it->second);
                    make_pair(new_node, node);

                    auto _fork = tails.extract(node->value.previous_hash);
                    _fork.mapped()->tail = new_node;
                    _fork.key() = new_node->value.previous_hash;
                    tails.insert(std::move(_fork));

                    node = new_node;
                }
                continue;
            }

            // Проверка на продолжение форка спереди
            if (heads.find(node->value.previous_hash) != heads.end())
            {
                auto _fork = heads.extract(node->value.previous_hash);
                make_pair(_fork.mapped()->head, node);

                _fork.mapped()->head = node;
                _fork.key() = node->value.hash;
                heads.insert(std::move(_fork));

                hashes.erase(node->value.hash);
            }

            // Проверка на merge форков.
            if (tails.find(node->value.hash) != tails.end())
            {
                auto left_fork = heads.extract(node->value.hash);
                auto right_fork = tails.extract(node->value.hash);

                auto new_fork = merge_fork(left_fork.mapped(), right_fork.mapped());
                heads[new_fork->head->value.hash] = new_fork;
                tails[new_fork->tail->value.previous_hash] = new_fork;
            }
        }

        // set forks
        for (auto &_forks : heads)
        {
            forks.push_back(_forks.second);
        }
    }
};


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

    virtual void add(value_type _value)
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

        //--Add to forks

        enum fork_state
        {
            new_fork = 0,
            only_heads = 1,
            only_tails = 1 << 1,
            both = only_heads | only_tails
        };

        int state = new_fork;
        if (heads.count(value.prev()))
            state |= only_heads;
        if (tails.count(value.hash()))
            state |= only_tails;

        switch (state)
        {
            case new_fork:
                //создание нового форка
            {
                // make new fork
                auto new_fork = make_fork();
                new_fork->insert(value);
                heads[new_fork->head] = new_fork;
                tails[new_fork->tail].insert(new_fork);
                fork_by_key[value.hash()] = new_fork;
            }
                break;
            case both:
                // объединение двух форков на стыке нового элемента
            {
                auto left_fork = heads.extract(value.prev());
                auto right_fork = tails.extract(value.hash());

                tails[left_fork.mapped()->get_chain_tail()].clear();
                for (auto &_fork : right_fork.mapped())
                {
                    _fork->insert_fork(left_fork.mapped());

                    tails[left_fork.mapped()->get_chain_tail()].insert(_fork);

                }
                for (int i = 0; i < forks.size(); i++)
                {
                    if (forks[i] == left_fork.mapped())
                    {
                        forks.erase(forks.begin() + i);
                    }
                }
//                    std::remove(forks.begin(), forks.end(), )
//                    forks.erase(forks.find(left_fork.mapped()));
            }
                break;
            case only_heads:
                // продолжение форка спереди
            {
                auto head_fork = heads.extract(value.prev());
                head_fork.mapped()->insert(value);
                head_fork.key() = value.hash();
                heads.insert(std::move(head_fork));
                fork_by_key[value.hash()] = heads[value.hash()];
            }
                break;
            case only_tails:
                // продолжение форка сзади
            {
                auto tail_forks = tails.find(value.hash());
                if (tail_forks->second.size() > 1)
                {
                    // make new fork
                    auto new_fork = make_fork();
                    new_fork->insert(value);

                    // add new fork to head forks
                    for (auto &_fork: tail_forks->second)
                    {
                        _fork->insert_fork(new_fork);
                    }
                    fork_by_key[value.hash()] = new_fork;
                } else
                {
                    // add value in head fork
                    for (auto &_fork: tail_forks->second)
                    {
                        _fork->insert(value);
                        fork_by_key[value.hash()] = _fork;
                    }
                }
            }
                break;
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

    hash_type get_last(hash_type hash)
    {
        auto fork = fork_by_key.find(hash);
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
            if (items.find(hash) != items.end())
                hash = *items.at(hash)->previous_hash;
            else
                throw std::invalid_argument("get_nth_parent_key: items not exis't hash");
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

    // last------(ancestor------item]--->best
    sum_element get_sum(hash_type item, hash_type ancestor)
    {
        if (!is_child_of(ancestor, item))
            throw std::invalid_argument("get_sum item not child for ancestor");

        auto result = get_sum_to_last(item);
        auto ances = get_sum_to_last(ancestor);

        return result.sub(ances);
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

    //TODO: Реализовать, если понадобится создавать новые правила прямо во время работы пулла.
    void new_rules_calculate(std::vector<std::string> k_rules)
    {
        // legacy code:
        /*for (const auto &tail : tails)
        {
            std::queue<it_sums> next_tree;
            for (auto v: reverse[tail.first])
                next_tree.push(sum.find(v->first));

            while (!next_tree.empty())
            {
                auto v = next_tree.front();
                next_tree.pop();

                for (auto v_next: v->second.next)
                {
                    next_tree.push(v_next);
                }

                // new calculate
                for (auto k : k_rules)
                {
                    Rule new_rule = rules.make_rule(k, v->second.pvalue->second);
                    if (v->second.prev != sum.end())
                        new_rule += v->second.prev->second.rules.get_rule(k);
                    v->second.rules.add(k, new_rule);
                }
            }
        }*/
    }
};