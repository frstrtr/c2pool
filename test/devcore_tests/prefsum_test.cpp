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

TEST(Prefsum_test, main_test)
{
    TestPrefsum prefsum;
    TestData first{2,1, 100};
    TestData second{3, 2, 200};
    TestData second2{33, 2, 233};
    TestData second22{44, 33, 67};

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
    ASSERT_ANY_THROW(prefsum.is_child_of(44,1));
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

}