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
    TestPrefsumElement(TestData data) : BasePrefsumElement<int, TestData, TestPrefsumElement>(), i(data.value)  {}

    bool is_none() override
    {
        return i == 0;
    }

    key_type get_head() override
    {

    }

    key_type get_tail() override
    {

    }


};

class TestPrefsum : public Prefsum<TestPrefsumElement>
{
public:
    element_type& make_element(value_type value) override
    {
        return sum[1];
    }
};


TEST(Prefsum_test, one_element)
{

}