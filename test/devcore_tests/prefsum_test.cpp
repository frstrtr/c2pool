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

    TestPrefsumElement& push(TestPrefsumElement sub) override
    {
        if (tail != sub.head)
            throw std::invalid_argument("tail != sub.head");

        tail = sub.tail;
        i += sub.i;
        return *this;
    }
};

class TestPrefsum : public Prefsum<TestPrefsumElement>
{
public:
    element_type make_element(value_type value) override
    {
        element_type element {value};
        element.prev = sum.find(value.tail);
        return element;
    }

    element_type none_element(key_type value) override
    {
        element_type element;
        element.head = value;
        element.tail = value;
        return element;
    }
};


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
}