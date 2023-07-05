#include <iostream>
#include "metric.h"
#include "metric_value.h"
#include "metric_sum.h"

void MetricValuesTest()
{
    MetricValue metricValues;

    metricValues.set("first_int", 123);
    metricValues.set("second_str",  "asdasd");
    metricValues.set("third_array", std::vector<int>{1,2,3,4,5,6,1000});

    std::cout << "values: " << metricValues.get().dump() << std::endl;
}

void MetricSumTest()
{
    MetricSum<5, int> metric;

    metric.add(1);
    metric.add(2);
    metric.add(3);
    metric.add(4);
    metric.add(5);
    std::cout << "max_size[=15]: " << metric.get().dump() << std::endl;

    metric.add(100);
    std::cout << "overload#1[=114]: " << metric.get().dump() << std::endl;
    metric.add(100);
    std::cout << "overload#2[=212]: " << metric.get().dump() << std::endl;

    metric.add(std::vector<int>{200});
    std::cout << "overload_range#1[=409]: " << metric.get().dump() << std::endl;
    metric.add(std::vector<int>{0, 0, 1000});
    std::cout << "overload_range#3[=1300]: " << metric.get().dump() << std::endl;
}

struct a{
    int i = 0;

    a() = default;
    explicit a(int _i) : i(_i) {}

    a operator +(const a& r)
    {
        i += r.i;
        return *this;
    }

    a& operator -=(const a& v)
    {
        i -= v.i;
        return *this;
    }

    a& operator +=(const a& v)
    {
        i += v.i;
        return *this;
    }

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(a, i);

//    void to_json(nlohmann::json& j, const a& p) {
//        j = nlohmann::json{ {"i", p.i}};
//    }
//
//    void from_json(const nlohmann::json& j, a& p) {
//        j.at("i").get_to(p.i);
//    }
};

void MetricSumCustomTypeTest()
{
    MetricSum<5, a> metric;

    metric.add(a{1});
    metric.add(a{2});
    metric.add(a{3});
    metric.add(a{4});
    metric.add(a{5});
    std::cout << "max_size[=15]: " << metric.get().dump() << std::endl;

    metric.add(a{100});
    std::cout << "overload#1[=114]: " << metric.get().dump() << std::endl;
    metric.add(a{100});
    std::cout << "overload#2[=112]: " << metric.get().dump() << std::endl;

    metric.add(std::vector<a>{a{200}});
    std::cout << "overload_range#1[=409]: " << metric.get().dump() << std::endl;
    metric.add(std::vector<a>{a{0}, a{0}, a{1000}});
    std::cout << "overload_range#3[=1300]: " << metric.get().dump() << std::endl;
}

#define TEST(test_f) \
                std::cout << "\t\t\t" << #test_f << "\n" << std::endl; \
                test_f();                           \
                std::cout << "\n";\

int main()
{
    TEST(MetricValuesTest);
    TEST(MetricSumTest);
    TEST(MetricSumCustomTypeTest);
}


#undef TEST