#include <gtest/gtest.h>
#include <libdevcore/prefsum.h>

struct TestData
{
    int head;
    int tail;

    int value;

    TestData() {};
    TestData(int h, int t, int v) : head(h), tail(t), value(v) {}
};

class TestPrefsumElement : public BasePrefsumElement<int, TestData, TestPrefsumElement>
{
protected:
    TestPrefsumElement& _push(const TestPrefsumElement &sub) override
    {
        i += sub.i;
        return *this;
    }

    TestPrefsumElement& _erase(const TestPrefsumElement &sub) override
    {
        i -= sub.i;
        return *this;
    }
public:
    int i;

    TestPrefsumElement() : BasePrefsumElement<int, TestData, TestPrefsumElement>(), i(0) {}
    TestPrefsumElement(TestData data) { set_value(data); }

    bool is_none() override
    {
        return i == 0;
    }

    bool is_none_tail() override
    {
        return tail == -876;
    }

    void set_value(value_type value) override
    {
        head = value.head;
        tail = value.tail;
        i = value.value;
    }
};

class TestPrefsum : public Prefsum<TestPrefsumElement>
{
public:
    element_type& _make_element(element_type& element, const value_type &value) override
    {
        return element;
    }

    element_type& _none_element(element_type& element, const key_type& key) override
    {
        element.head = key;
        element.tail = key;
        return element;
    }
};

void print_element(TestPrefsum::element_type &element)
{
    std::cout << element.i << " " << element.height << " " << element.head << " " << element.tail << std::endl;
}

void print_get_sum_to_last(TestPrefsum &prefsum, TestPrefsum::key_type key)
{
    auto v = prefsum.get_sum_to_last(key);
    std::cout << "TEST get_sum_to_last(" << key << ")\n";
    std::cout << "get_sum_to_last(" << key << ").i = " << v.i << std::endl;
    std::cout << "get_sum_to_last(" << key << ").head = " << v.head << std::endl;
    std::cout << "get_sum_to_last(" << key << ").tail = " << v.tail << std::endl;
    std::cout << "get_sum_to_last(" << key << ").height = " << v.height << std::endl;
    std::cout << std::endl;
}

void print_get_height_and_last(TestPrefsum &prefsum, TestPrefsum::key_type key)
{
    auto [height, last] = prefsum.get_height_and_last(key);
    std::cout << "TEST get_height_and_last(" << key << ")\n";
    std::cout << "height = " << height << ", last = " << last << "\n\n";
}

std::vector<int> test_reverse(TestPrefsum &prefsum, TestPrefsum::key_type key_tail)
{
    std::vector<TestPrefsum::key_type> res;
    for (auto v : prefsum.reverse[key_tail])
    {
        res.push_back(v->first);
    }
    return res;
}

TEST(Prefsum_test, main_test)
{
    TestPrefsum prefsum;
    TestData first{2,1, 100};
    TestData second{3, 2, 200};
    TestData second2{33, 2, 233};
    TestData second22{44, 33, 67};
    // (1->2->33->44]; (1->2->3]; (9->10]
    TestData first2{10, 9, 900};

    prefsum.add(first);
    prefsum.add(second);
    prefsum.add(second2);
    prefsum.add(first2);
    prefsum.add(second22);

    auto sum3 = prefsum.sum[3];
    std::cout << sum3.i << " " << sum3.head << " " << sum3.tail << std::endl;

    sum3 = prefsum.sum[44];
    std::cout << sum3.i << " " << sum3.head << " " << sum3.tail << std::endl;

    auto sum9 = prefsum.sum[9];
    ASSERT_EQ(sum9.i, 0);
    ASSERT_EQ(sum9.head, 0);
    ASSERT_EQ(sum9.tail, 0);


    std::cout << "TAILS: " << std::endl;
    for (auto tails : prefsum.tails)
    {
        std::cout << tails.first << ": ";
        for (auto v2 : tails.second)
        {
            std::cout << v2 << " ";
        }
        std::cout << std::endl;
    }

    std::cout << "HEADS: " << std::endl;
    for (auto head : prefsum.heads)
    {
        std::cout << head.first << ":" << head.second << std::endl;
    }
    std::cout << std::endl;

    std::cout << "get_last for " << 44 << " = " << prefsum.get_last(44) << std::endl;
    std::cout << "get_last for " << 33 << " = " << prefsum.get_last(33) << std::endl;
    std::cout << "get_last for " << 22 << " = " << prefsum.get_last(22) << std::endl;
    std::cout << "get_last for " << 10 << " = " << prefsum.get_last(10) << std::endl;
    std::cout << std::endl;

    print_get_sum_to_last(prefsum, 44);
    print_get_sum_to_last(prefsum, 33);
    print_get_sum_to_last(prefsum, 22);
    print_get_sum_to_last(prefsum, 10);
    print_get_sum_to_last(prefsum, 3);

    print_get_height_and_last(prefsum, 44);
    print_get_height_and_last(prefsum, 33);
    print_get_height_and_last(prefsum, 22);
    print_get_height_and_last(prefsum, 10);
    print_get_height_and_last(prefsum, 3);

    ASSERT_TRUE(prefsum.is_child_of(1, 44));
    ASSERT_FALSE(prefsum.is_child_of(44,1));
    ASSERT_TRUE(prefsum.is_child_of(33, 44));
    ASSERT_TRUE(prefsum.is_child_of(1, 3));
    ASSERT_FALSE(prefsum.is_child_of(22, 1));
    ASSERT_FALSE(prefsum.is_child_of(1, 22));

    // TEST for get_sum
    // for (33->44]
    {
        auto get_sum_res = prefsum.get_sum(44, 33);
        print_element(get_sum_res);
        ASSERT_EQ(get_sum_res.i, 67);
        ASSERT_EQ(get_sum_res.height, 1);
        ASSERT_EQ(get_sum_res.head, 44);
        ASSERT_EQ(get_sum_res.tail, 33);
    }
    // for (2->44]
    {
        auto get_sum_res = prefsum.get_sum(44, 2);
        print_element(get_sum_res);
        ASSERT_EQ(get_sum_res.i, 300);
        ASSERT_EQ(get_sum_res.height, 2);
        ASSERT_EQ(get_sum_res.head, 44);
        ASSERT_EQ(get_sum_res.tail, 2);
        {
            // test for erase#1
            auto erase_res = prefsum.get_sum_to_last(44).erase(get_sum_res);
            print_element(erase_res);
            ASSERT_EQ(erase_res.i, 100);
            ASSERT_EQ(erase_res.height, 1);
            ASSERT_EQ(erase_res.head, 2);
            ASSERT_EQ(erase_res.tail, 1);
        }
    }


    // TEST get_chain
    {
        auto get_chain_f = prefsum.get_chain(44, 3);
        TestPrefsum::key_type chain_k;
        std::cout << "\nCHAIN#1: " << std::endl;
        while (get_chain_f(chain_k))
        {
            auto chain_v = prefsum.sum[chain_k].get_value();
            std::cout << chain_v.head << " " << chain_v.tail << " " << chain_v.value << std::endl;
        }
    }

    // TEST reverse
    using List = std::vector<int>;
    {
        List comp{2};
        ASSERT_EQ(test_reverse(prefsum, 1), comp);
    }
    {
        List comp{3,33};
        ASSERT_EQ(test_reverse(prefsum, 2), comp);
    }
    {
        List comp{44};
        ASSERT_EQ(test_reverse(prefsum, 33), comp);
    }
    {
        List comp{10};
        ASSERT_EQ(test_reverse(prefsum, 9), comp);
    }
}

void write_head_n_tails(TestPrefsum& prefsum)
{
    //HEADS
    std::cout << "HEADS: [  ";
    for (auto head : prefsum.heads)
    {
        std::cout << "(" << head.first << ": " << head.second << "), ";
    }
    std::cout << "\b\b].\n";

    //TAILS
    std::cout << "TAILS: [  ";
    for (const auto& tail : prefsum.tails)
    {
        std::cout << "(" << tail.first << ": [";
        for (auto _h : tail.second)
        {
            std::cout << _h << ", ";
        }
        std::cout << "\b\b]), ";
    }
    std::cout << "\b\b].\n";
}

TEST(Prefsum_test, head_tails_test)
{
    TestPrefsum prefsum;
    TestData first{1, 0, 100};
    TestData second{3, 2, 300};
    TestData third{2, 1, 200};
    TestData new_end{-2, 3, -200};
    TestData fork{-4, 2, -400};
    TestData zero{0, -1, 1};


    write_head_n_tails(prefsum);

    prefsum.add(first);
    std::cout << "added first" << std::endl;
    write_head_n_tails(prefsum);

    prefsum.add(second);
    std::cout << "added second" << std::endl;
    write_head_n_tails(prefsum);

    prefsum.add(third);
    std::cout << "added third" << std::endl;
    write_head_n_tails(prefsum);

    prefsum.add(new_end);
    std::cout << "added new_end" << std::endl;
    write_head_n_tails(prefsum);

    prefsum.add(fork);
    std::cout << "added fork" << std::endl;
    write_head_n_tails(prefsum);

    prefsum.add(zero);
    std::cout << "added zero" << std::endl;
    write_head_n_tails(prefsum);


    std::cout << "height: " << prefsum.get_sum_to_last(3).height << std::endl;

    for (auto v : prefsum.sum)
    {
        std::cout << "nexts for " << v.first << ": ";
        for (auto vv : v.second.next)
        {
            std::cout << vv->first << " ";
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;

    for (const auto& v: prefsum.sum)
    {
        std::cout << v.first << "\n" << v.second.head << "->" << (v.second.prev == prefsum.sum.end() ? "NULL" : std::to_string(v.second.prev->second.head)) << ": " << v.second.i << " " << v.second.height << std::endl;
    }
}

TEST(Prefsum_test, rules_test)
{
    TestPrefsum prefsum;
    TestData first{2, 1, 100};
    TestData second{3, 2, 200};
    TestData second2{33, 2, 233};
    TestData second22{44, 33, 67};
    // (1->2->33->44]; (1->2->3]; (9->10]
    TestData first2{10, 9, 900};

    std::vector<int> check_rules_value {100, 233, 900, 300};

    // (1->2->33->44]; (1->2->3->4]; (9->10]
    TestData third{4, 3, 300};

    prefsum.add(first);
    prefsum.add(second);
    prefsum.add(second2);
    prefsum.add(first2);
    prefsum.add(second22);
    prefsum.add(third);

    prefsum.rules.add("test_rule", [&](const TestData& v)
    {
        std::cout << "MAKE: " << v.head << std::endl;
        if (std::count(check_rules_value.begin(), check_rules_value.end(), v.value))
            return 1;
        return 0;
    }, [](Rule& l, const Rule& r)
    {
        auto _l = std::any_cast<int>(&l.value);
        auto _r = std::any_cast<int>(&r.value);
        std::cout << "ADD: " << *_l << "+" << *_r << std::endl;
        *_l += *_r;
    }, [](Rule& l, const Rule& r)
    {
        auto _l = std::any_cast<int>(&l.value);
        auto _r = std::any_cast<int>(&r.value);
        std::cout << "REMOVE" << std::endl;
        *_l -= *_r;
    });

    write_head_n_tails(prefsum);

    for (auto& v: prefsum.sum)
    {
        auto _rule = v.second.rules.get<int>("test_rule");
        std::cout << v.first << "\n" << v.second.head << "->" << (v.second.prev == prefsum.sum.end() ? "NULL" : std::to_string(v.second.prev->second.head)) << ": " << v.second.i << " " << v.second.height << ", test_rule = " << *_rule << std::endl;
    }

    ASSERT_EQ(*prefsum.get_sum_to_last(44).rules.get<int>("test_rule"), 2);

    // Test for solo element
//    prefsum.get_height_and_last()
    {
        auto _v = prefsum.get_sum_to_last(3);
        std::cout << _v.tail;
    }
}

TEST(Prefsum_test, none_tail_test)
{
    TestPrefsum prefsum; // none_tail = -876
    TestData first{2, 0, 100};
    TestData second{3, 2, 200};
    TestData second2{33, 2, 233};
    TestData second22{44, 33, 67};
    // (1->2->33->44]; (1->2->3]; (9->10]
    TestData first2{10, 9, 900};

    std::vector<int> check_rules_value {100, 67, 233, 900, 300};

    // (0->2->33->44]; (0->2->3->4]; (9->10]; ({None=-876}->678->679]
    TestData third{4, 3, 300};

    prefsum.add(first);
    prefsum.add(second);
    prefsum.add(second2);
    prefsum.add(first2);
    prefsum.add(second22);
    prefsum.add(third);

    prefsum.rules.add("test_rule",
                      [&](const TestData& v)
                      {
                          std::cout << "MAKE: " << v.head << std::endl;
                          if (std::count(check_rules_value.begin(), check_rules_value.end(), v.value))
                              return 1;
                          return 0;
                      }, [](Rule& l, const Rule& r)
                      {
                          auto _l = std::any_cast<int>(&l.value);
                          auto _r = std::any_cast<int>(&r.value);
                          std::cout << "ADD: " << *_l << " + " << *_r << std::endl;
                          *_l += *_r;
                      }, [](Rule& l, const Rule& r)
                      {
                          auto _l = std::any_cast<int>(&l.value);
                          auto _r = std::any_cast<int>(&r.value);
                          std::cout << "REMOVE: " << *_l << " - " << *_r << std::endl;
                          *_l -= *_r;
                      }
    );

    TestData testNoneTail{678, -876, 1000};
    prefsum.add(testNoneTail);

    TestData testNoneTail2{679, 678, 1000};
    prefsum.add(testNoneTail2);

    write_head_n_tails(prefsum);

    for (auto& v: prefsum.sum)
    {
        auto _rule = v.second.rules.get<int>("test_rule");
        std::cout << v.first << "\n" << v.second.head << "->" << (v.second.prev == prefsum.sum.end() ? "NULL" : std::to_string(v.second.prev->second.head)) << ": " << v.second.i << " " << v.second.height << ", test_rule = " << *_rule << std::endl;
    }

    ASSERT_EQ(*prefsum.get_sum_to_last(44).rules.get<int>("test_rule"), 3);


    // 1
    std::cout << "is_child_of: " << (prefsum.is_child_of(2, 2) ? "true" : "false") << std::endl;
    ASSERT_EQ(prefsum.is_child_of(2, 2), true);
    // 2
    std::cout << "get_nth_parent_hash: " << prefsum.get_nth_parent_key(2, 0) << std::endl;
    ASSERT_EQ(prefsum.get_nth_parent_key(2, 0), 2);
    // 3.1
    {
        auto get_chain_f = prefsum.get_chain(2, 0);
        std::cout << "get_chain: [";
        std::vector<int> chain;
        int i;
        while(get_chain_f(i))
        {
            std::cout << i << ", ";
            chain.push_back(i);
        }
        std::cout << "]" << std::endl;
        ASSERT_EQ(chain, std::vector<int>());
    }
    // 3.2
    {
        auto get_chain_f = prefsum.get_chain(33, 0);
        std::cout << "get_chain: [";
        std::vector<int> chain;
        int i;
        while(get_chain_f(i))
        {
            std::cout << i << ", ";
            chain.push_back(i);
        }
        std::cout << "]" << std::endl;
        ASSERT_EQ(chain, std::vector<int>());
    }
    // 3.3
    {
        auto get_chain_f = prefsum.get_chain(33, 2);
        std::cout << "get_chain: [";
        std::vector<int> chain;
        int i;
        while(get_chain_f(i))
        {
            std::cout << i << ", ";
            chain.push_back(i);
        }
        std::cout << "]" << std::endl;
        ASSERT_EQ(chain, std::vector<int>({33,2}));
    }
    // 4.1
    {
        std::cout << "4.1" << std::endl;
        auto res = prefsum.get_sum(2, 2);
        std::cout << "head = " << res.head << ", tail = " << res.tail << ", height = " << res.height << ", test_rule = " << *res.rules.get<int>("test_rule") << ", i = " << res.i << std::endl;
        ASSERT_EQ(res.head, 0);
        ASSERT_EQ(res.tail, 0);
        ASSERT_EQ(*res.rules.get<int>("test_rule"), 0);
        ASSERT_EQ(res.height, 0);
        ASSERT_EQ(res.i, 0);
    }
    // 4.2
    {
        std::cout << "4.2" << std::endl;
        auto res = prefsum.get_sum(10, 10);
        std::cout << "head = " << res.head << ", tail = " << res.tail << ", height = " << res.height << ", test_rule = " << *res.rules.get<int>("test_rule") << ", i = " << res.i << std::endl;
        ASSERT_EQ(res.head, 9);
        ASSERT_EQ(res.tail, 9);
        ASSERT_EQ(*res.rules.get<int>("test_rule"), 0);
        ASSERT_EQ(res.height, 0);
        ASSERT_EQ(res.i, 0);
    }
    // 4.3
    {
        std::cout << "4.3" << std::endl;
        auto res = prefsum.get_sum(44, 2);
        std::cout << "head = " << res.head << ", tail = " << res.tail << ", height = " << res.height << ", test_rule = " << *res.rules.get<int>("test_rule") << ", i = " << res.i << std::endl;
        ASSERT_EQ(res.head, 44);
        ASSERT_EQ(res.tail, 2);
        ASSERT_EQ(*res.rules.get<int>("test_rule"), 2);
        ASSERT_EQ(res.height, 2);
        ASSERT_EQ(res.i, 300);
    }
    // 4.4
    {
        std::cout << "4.4" << std::endl;
        auto res = prefsum.get_sum(44, 0);
        std::cout << "head = " << res.head << ", tail = " << res.tail << ", height = " << res.height << ", test_rule = " << *res.rules.get<int>("test_rule") << ", i = " << res.i << std::endl;
        ASSERT_EQ(res.head, 44);
        ASSERT_EQ(res.tail, 0);
        ASSERT_EQ(*res.rules.get<int>("test_rule"), 3);
        ASSERT_EQ(res.height, 3);
        ASSERT_EQ(res.i, 400);
    }
    // 4.5.1
    {
        std::cout << "4.5.1" << std::endl;
        auto res = prefsum.get_sum(678, -876);
        std::cout << "head = " << res.head << ", tail = " << res.tail << ", height = " << res.height << ", test_rule = " << *res.rules.get<int>("test_rule") << ", i = " << res.i << std::endl;
/*        ASSERT_EQ(res.head, 44);
        ASSERT_EQ(res.tail, 0);
        ASSERT_EQ(*res.rules.get<int>("test_rule"), 3);
        ASSERT_EQ(res.height, 3);
        ASSERT_EQ(res.i, 400);*/
    }
    // 4.5.2
    {
        std::cout << "4.5.2" << std::endl;
        auto res = prefsum.get_sum(679, -876);
        std::cout << "head = " << res.head << ", tail = " << res.tail << ", height = " << res.height << ", test_rule = " << *res.rules.get<int>("test_rule") << ", i = " << res.i << std::endl;
/*        ASSERT_EQ(res.head, 44);
        ASSERT_EQ(res.tail, 0);
        ASSERT_EQ(*res.rules.get<int>("test_rule"), 3);
        ASSERT_EQ(res.height, 3);
        ASSERT_EQ(res.i, 400);*/
    }
    // 4.5.3
    {
        std::cout << "4.5.3" << std::endl;
        auto res = prefsum.get_sum(679, 678);
        std::cout << "head = " << res.head << ", tail = " << res.tail << ", height = " << res.height << ", test_rule = " << *res.rules.get<int>("test_rule") << ", i = " << res.i << std::endl;
/*        ASSERT_EQ(res.head, 44);
        ASSERT_EQ(res.tail, 0);
        ASSERT_EQ(*res.rules.get<int>("test_rule"), 3);
        ASSERT_EQ(res.height, 3);
        ASSERT_EQ(res.i, 400);*/
    }
    // 4.6
    {
        std::cout << "4.6" << std::endl;
        auto res = prefsum.get_sum(10, 9);
        std::cout << "head = " << res.head << ", tail = " << res.tail << ", height = " << res.height << ", test_rule = " << *res.rules.get<int>("test_rule") << ", i = " << res.i << std::endl;
        ASSERT_EQ(res.head, 10);
        ASSERT_EQ(res.tail, 9);
        ASSERT_EQ(*res.rules.get<int>("test_rule"), 1);
        ASSERT_EQ(res.height, 1);
        ASSERT_EQ(res.i, 900);
    }
    // 5.1
    {
        std::cout << "5.1" << std::endl;
        auto res = prefsum.get_sum_to_last(10);
        std::cout << "head = " << res.head << ", tail = " << res.tail << ", height = " << res.height << ", test_rule = " << *res.rules.get<int>("test_rule") << ", i = " << res.i << std::endl;
        ASSERT_EQ(res.head, 10);
        ASSERT_EQ(res.tail, 9);
        ASSERT_EQ(*res.rules.get<int>("test_rule"), 1);
        ASSERT_EQ(res.height, 1);
        ASSERT_EQ(res.i, 900);
    }
    // 5.2
    {
        std::cout << "5.2" << std::endl;
        auto res = prefsum.get_sum_to_last(44);
        std::cout << "head = " << res.head << ", tail = " << res.tail << ", height = " << res.height << ", test_rule = " << *res.rules.get<int>("test_rule") << ", i = " << res.i << std::endl;
        ASSERT_EQ(res.head, 44);
        ASSERT_EQ(res.tail, 0);
        ASSERT_EQ(*res.rules.get<int>("test_rule"), 3);
        ASSERT_EQ(res.height, 3);
        ASSERT_EQ(res.i, 400);
    }
    // 5.3
    {
        std::cout << "5.3" << std::endl;
        auto res = prefsum.get_sum_to_last(678);
        std::cout << "head = " << res.head << ", tail = " << res.tail << ", height = " << res.height << ", i = " << res.i << std::endl;
//        ASSERT_EQ(res.head, 44);
//        ASSERT_EQ(res.tail, 0);
//        ASSERT_EQ(*res.rules.get<int>("test_rule"), 3);
//        ASSERT_EQ(res.height, 3);
//        ASSERT_EQ(res.i, 400);
    }
}