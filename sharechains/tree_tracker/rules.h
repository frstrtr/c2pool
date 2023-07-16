#pragma once

#include <any>
#include <functional>
#include <map>

#include <libdevcore/events.h>

#include <boost/format.hpp>

namespace shares
{
    class Rule
    {
    public:
        std::any value;
    private:
        typedef std::function<void(Rule &, const Rule &)> func_type;
        /// addition function
        func_type *_add;
        /// subtraction function
        func_type *_sub;
        /// make empty Rule obj
        std::function<std::any()> *_make_none;
    public:
        Rule() : _add(nullptr), _sub(nullptr)
        {

        }

        Rule(std::any v, func_type *additionF, func_type *subtractionF, auto *make_noneF) : _add(additionF), _sub(subtractionF), _make_none(make_noneF)
        {
            value = std::move(v);
        }

        Rule operator+(const Rule &r) const
        {
            auto copy_rule = Rule(*this);
            if (_add)
                (*_add)(copy_rule, r);
            else if (r._add)
                (*r._add)(copy_rule, r);
            else
                throw std::runtime_error("Rule::operator+ without add functors");
            return copy_rule;
        }

        Rule operator-(const Rule &r) const
        {
            auto copy_rule = Rule(*this);
            if (_sub)
                (*_sub)(copy_rule, r);
            else if (r._sub)
                (*r._sub)(copy_rule, r);
            else
                throw std::runtime_error("Rule::operator- without sub functors");
            return copy_rule;
        }

        Rule &operator+=(const Rule &r)
        {
            if (_add)
                (*_add)(*this, r);
            else if (r._add)
                (*r._add)(*this, r);
            else
                throw std::runtime_error("Rule::operator+= without add functors");
            return *this;
        }

        Rule &operator-=(const Rule &r)
        {
            if (_sub)
                (*_sub)(*this, r);
            else if (r._sub)
                (*r._sub)(*this, r);
            else
                throw std::runtime_error("Rule::operator-= without sub functors");
            return *this;
        }

        Rule make_none() const
        {
            return Rule{(*_make_none)(), _add, _sub, _make_none};
        }
    };

    class PrefsumRulesElement
    {
        std::map<std::string, Rule> rules;
    public:
        PrefsumRulesElement() = default;

        void add(const std::string &key, Rule &value)
        {
            rules[key] = std::move(value);
        }

        template<typename TypeValue>
        TypeValue *get(std::string key)
        {
            if (rules.find(key) == rules.end())
                throw std::invalid_argument(
                        (boost::format("PrefsumRulesElement::get[key = [%1%]]: key not exist in PrefsumRulesElement") %
                         key).str());

            if (rules.at(key).value.type() != typeid(TypeValue))
                throw std::invalid_argument(
                        (boost::format("PrefsumRulesElement::get[key = [%1%]]: %2% != %3%  in PrefsumRulesElement") %
                         key % typeid(TypeValue).name() % rules.at(key).value.type().name()).str());

            TypeValue *result = std::any_cast<TypeValue>(&rules[key].value);
            return result;
        }

        Rule get_rule(std::string key)
        {
            if (rules.find(key) == rules.end())
                throw std::invalid_argument((boost::format(
                        "PrefsumRulesElement::get_rule[key = [%1%]]: key not exist in PrefsumRulesElement") %
                                             key).str());

            return rules[key];
        }

        PrefsumRulesElement &operator+=(const PrefsumRulesElement &r)
        {
            for (const auto &[k, rule]: r.rules)
            {
                if (!rules.count(k))
                    rules[k] = rule.make_none();

                rules[k] += rule;
            }
            return *this;
        }

        PrefsumRulesElement &operator-=(const PrefsumRulesElement &r)
        {
            for (const auto &[k, rule]: r.rules)
            {
                if (!rules.count(k))
                    rules[k] = rule.make_none();

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
            std::function<std::any()> make_none;
            //
            std::function<void(Rule&, const Rule&)> add;
            //
            std::function<void(Rule&, const Rule&)> sub;
        };

        std::map<std::string, RuleFunc> funcs{};

    public:
        Event<std::vector<std::string>> new_rule_event;

        explicit PrefsumRules()
        {
            new_rule_event = make_event<std::vector<std::string>>();
        }

        ~PrefsumRules()
        {
            delete new_rule_event;
        }

        void add(std::string k, std::function<std::any(const ValueType&)> _make, std::function<std::any()> _make_none, std::function<void(Rule&, const Rule&)> _add, std::function<void(Rule&, const Rule&)> _sub)
        {
            funcs[k] = {std::move(_make), std::move(_make_none) , std::move(_add), std::move(_sub)};

            std::vector<std::string> new_rule_list{k};
            new_rule_event->happened(new_rule_list);
        }

        Rule make_rule(const std::string &key, const ValueType &value)
        {
            if (funcs.find(key) == funcs.end())
                throw std::invalid_argument((boost::format("%1% not exist in funcs!") % key).str());

            auto &f = funcs[key];
            return {f.make(value), &f.add, &f.sub, &f.make_none};
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
}