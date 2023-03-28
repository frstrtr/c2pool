#pragma once

//#include <deque>
#include <map>
#include <utility>
#include <vector>
#include <set>
#include <queue>
#include <any>
#include <boost/format.hpp>

#include "events.h"

class Rule
{
public:
    std::any value;
private:
    typedef std::function<void(Rule&, const Rule&)> func_type;
    /// addition function
    func_type *_add;
    /// subtraction function
    func_type *_sub;
public:
    Rule() : _add(nullptr), _sub(nullptr)
    {

    }

    Rule(std::any v, func_type *additionF, func_type *subtractionF) : _add(additionF), _sub(subtractionF)
    {
        value = std::move(v);
    }

    Rule operator+(const Rule& r) const
    {
        auto copy_rule = Rule(*this);
        (*_add)(copy_rule, r);
        return copy_rule;
    }

    Rule operator-(const Rule& r) const
    {
        auto copy_rule = Rule(*this);
        (*_sub)(copy_rule, r);
        return copy_rule;
    }

    Rule &operator+=(const Rule& r)
    {
        (*_add)(*this, r);
        return *this;
    }

    Rule &operator-=(const Rule& r)
    {
        (*_sub)(*this, r);
        return *this;
    }
};

class PrefsumRulesElement
{
    std::map<std::string, Rule> rules;
public:
    PrefsumRulesElement() = default;

    void add(const std::string& key, Rule& value)
    {
        rules[key] = std::move(value);
    }

    template <typename TypeValue>
    TypeValue* get(std::string key)
    {
        if (rules.find(key) == rules.end())
            throw std::invalid_argument((boost::format("PrefsumRulesElement::get[key = [%1%]]: key not exist in PrefsumRulesElement") % key).str());

        if (rules.at(key).value.type() != typeid(TypeValue))
            throw std::invalid_argument((boost::format("PrefsumRulesElement::get[key = [%1%]]: %2% != %3%  in PrefsumRulesElement") % key % typeid(TypeValue).name() % rules.at(key).value.type().name()).str());

        TypeValue* result = std::any_cast<TypeValue>(&rules[key].value);
        return result;
    }

    Rule get_rule(std::string key)
    {
        if (rules.find(key) == rules.end())
            throw std::invalid_argument((boost::format("PrefsumRulesElement::get_rule[key = [%1%]]: key not exist in PrefsumRulesElement") % key).str());

        return rules[key];
    }

    PrefsumRulesElement &operator+=(const PrefsumRulesElement &r)
    {
        for (const auto &[k, rule] : r.rules)
        {
            rules[k] += rule;
        }
        return *this;
    }

    PrefsumRulesElement &operator-=(const PrefsumRulesElement &r)
    {
        for (const auto &[k, rule] : r.rules)
        {
            rules[k] -= rule;
        }
        return *this;
    }
};

template <typename ValueType>
class PrefsumRules
{
    struct RuleFunc
    {
        // Словарь с функциями для инициализации (расчёта) новых значений правил.
        std::function<std::any(const ValueType&)> make;
        //
        std::function<void(Rule&, const Rule&)> add;
        //
        std::function<void(Rule&, const Rule&)> sub;
    };

    std::map<std::string, RuleFunc> funcs;

public:
    Event<std::vector<std::string>> new_rule_event;

    void add(std::string k, std::function<std::any(const ValueType&)> _make, std::function<void(Rule&, const Rule&)> _add, std::function<void(Rule&, const Rule&)> _sub)
    {
        funcs[k] = {std::move(_make), std::move(_add), std::move(_sub)};

        std::vector<std::string> new_rule_list{k};
        new_rule_event.happened(new_rule_list);
    }

    Rule make_rule(const std::string &key, const ValueType &value)
    {
        if (funcs.find(key) == funcs.end())
            throw std::invalid_argument((boost::format("%1% not exist in funcs!") % key).str());

        auto &f = funcs[key];
        return {f.make(value), &f.add, &f.sub};
    }

    PrefsumRulesElement make_rules(const ValueType &value)
    {
        PrefsumRulesElement rules;
        for (auto kv : funcs)
        {
            auto _rule = make_rule(kv.first, value);
            rules.add(kv.first, _rule);
        }
        return rules;
    }
};

template <typename Key, typename Value, typename SubElement>
class BasePrefsumElement
{
public:
    typedef Key key_type;
    typedef Value value_type;
    typedef SubElement sub_element_type;
    typedef typename std::map<key_type, sub_element_type>::iterator it_element;
    typedef typename std::map<key_type, value_type>::iterator it_value;
public:
    it_value pvalue;
    it_element prev;
    std::vector<it_element> next;

    PrefsumRulesElement rules;
    int32_t height;
    key_type head;
    key_type tail;
public:
    virtual bool is_none() = 0;

    virtual bool is_none_tail() = 0;

    virtual void set_value(value_type value) = 0;
    // return head value
    virtual value_type get_value()
    {
        return pvalue->second;
    }
protected:
    virtual sub_element_type& _push(const sub_element_type &sub) = 0;
    virtual sub_element_type& _erase(const sub_element_type &sub) = 0;
public:
    virtual sub_element_type& push(const sub_element_type &sub)
    {
        if (tail != sub.head)
            throw std::invalid_argument((boost::format("tail [%1%] != sub.head [%2%].") % tail % sub.head).str());

        tail = sub.tail;
        height += sub.height;
        rules += sub.rules;

        return _push(sub);
    }

    virtual sub_element_type& erase(const sub_element_type &sub)
    {
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
        rules -= sub.rules;
        return _erase(sub);
    }

    BasePrefsumElement() {}
};

//https://en.wikipedia.org/wiki/Prefix_sum
template <typename PrefsumElementType>
class Prefsum
{
public:
    typedef PrefsumElementType element_type;
    typedef typename element_type::key_type key_type;
    typedef typename element_type::value_type value_type;
    typedef typename std::map<key_type, value_type>::iterator it_items;
    typedef typename std::map<key_type, element_type>::iterator it_sums;
public:
    std::map<key_type, value_type> items;
    std::map<key_type, element_type> sum;
    std::map<key_type, std::vector<it_items>> reverse;

    //heads[head] -> tail
    std::map<key_type, key_type> heads;

    //tails[tail] -> set(head)
    std::map<key_type, std::set<key_type>> tails;

    // manager for rules
    PrefsumRules<value_type> rules;

    Event<value_type> added;
    Event<value_type> removed;
protected:
    virtual element_type& _make_element(element_type& element, const value_type &value) = 0;
    virtual element_type& _none_element(element_type& element, const key_type& key) = 0;

    void new_rules_calculate(std::vector<std::string> k_rules)
    {
        for (const auto &tail : tails)
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
        }
    }
public:
    Prefsum()
    {
        rules.new_rule_event.subscribe([&](const std::vector<std::string>& k_rules)
        {
            new_rules_calculate(k_rules);
        });
    }

    virtual element_type make_element(value_type value)
    {
        element_type element {value};
        element.rules = rules.make_rules(value);
        element.pvalue = items.end();
        element.prev = sum.find(element.tail);
        element.height = 1;

        if (reverse.find(element.head) != reverse.end())
        {
            for (auto v : reverse[element.head])
            {
                element.next.push_back(sum.find(v->first));
            }
        }

        return _make_element(element, value);
    }

    virtual element_type none_element(key_type key)
    {
        element_type element;
        element.pvalue = items.end();
        element.height = 0;

        return _none_element(element, key);
    }

    virtual void add(value_type _value)
    {
        //--Make PrefsumElement from value_type
        auto value = make_element(_value);
        auto delta = value;

        if (value.is_none())
            throw std::invalid_argument("value is none!");

        //--Check for exist value in items
        if (items.find(value.head) != items.end())
            throw std::invalid_argument("item already present!");

        //--Add value to items
        items[value.head] = _value;
        value.pvalue = items.find(value.head);

        //--Add to reverse
        reverse[value.tail].push_back(items.find(value.head));

        //--Add value to sum
        auto &it = sum[value.head];
        it = std::move(value);

        if (it.prev != sum.end())
        {
            it.push(it.prev->second);
            it.prev->second.next.push_back(sum.find(it.head));
        }

        //--Add this value to next sum's
        // TODO: can be optimize: оптимизация памяти в процессе обхода дерева, путем прибавления ко всем элементам одного и того же значения, а не предыдущего к нему.
        // TODO: оптимизация с помощью изменения сразу на сумму значений, а не для каждого add в диапазоне новых добавленных. (add_range)
        std::queue<it_sums> next_tree;
        for (auto v : it.next)
            next_tree.push(v);

        while (!next_tree.empty())
        {
            auto v = next_tree.front();
            next_tree.pop();

            for (auto v_next : v->second.next)
            {
                next_tree.push(v_next);
            }

            // new calculate
            auto new_value = make_element((v->second.pvalue)->second);
            new_value.pvalue = v->second.pvalue;
            new_value.push(new_value.prev->second);
            sum[v->first] = new_value;
        }

        //--update heads and tails

        // проверка на то, что новый элемент не является началом уже существующей части,
        // т.е. head нового элемента -- tail уже существующего в prefsum.
        std::set<key_type> _heads;
        if (tails.find(delta.head) != tails.end())
        {
            _heads = tails[delta.head];
            tails.erase(delta.head);
        } else
        {
            _heads = {delta.head};
        }

        // Проверка на то, что новый элемент не является ли продолжением уже существующей части,
        // т.е. tail нового элемента -- head уже существующего в prefsum.
        key_type _tail;
        if (heads.find(delta.tail) != heads.end())
        {
            _tail = heads[delta.tail];
            heads.erase(delta.tail);
        } else
        {
            _tail = get_last(delta.tail);
        }

        if (tails.count(_tail))
            tails[_tail].insert(_heads.begin(), _heads.end());
        else
            tails[_tail] = _heads;

        if (!tails.empty() && (tails[_tail].find(delta.tail) != tails[_tail].end()))
            tails[_tail].erase(delta.tail);

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
        {
            result = sum[result.tail];
        }

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
        return height_up >= 0 && get_nth_parent_key(possible_child, height_up) == item;
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