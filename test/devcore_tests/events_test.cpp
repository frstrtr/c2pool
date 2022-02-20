#include <gtest/gtest.h>
#include <libdevcore/events.h>
#include <iostream>

template <typename Key, typename Value>
bool eq_maps(const std::map<Key, Value> &m1, const std::map<Key, Value> &m2)
{
    for (auto val: m1)
    {
        if (m2.find(val.first) == m2.end())
            return false;
        if (val.second != m2.find(val.first)->second)
            return false;
    }
    return true;
}

TEST(DevcoreEvents, event_lambda)
{
	int res = 0;
	Event<int> event;
	event.subscribe([&res](int value)
					{
						std::cout << value << std::endl;
						res = value;
					});

	event.happened(500);
	ASSERT_EQ(500, res);
}

TEST(DevcoreEvents, event_void)
{
    Event event;
    event.happened();

    bool result = false;
    event.subscribe([&result](){result = true;});
    event.happened();
    ASSERT_TRUE(result);
}

class TestEvent
{
public:
	int res = 0;

	void testF(int value)
	{
		res = value;
		std::cout << value << std::endl;
	}
};

TEST(DevcoreEvents, event_class_method)
{
	Event<int> event;
	TestEvent *obj = new TestEvent();
	//event.subscribe(&TestEvent::testF, obj);
	event.subscribe([&](int value)
					{ obj->testF(value); });
	event.happened(1337);

	ASSERT_EQ(1337, obj->res);
	delete obj;
}

TEST(DevcoreEvents, event_many_args)
{
	int res = 0;
	double res2 = 0;

	Event<int, double> event;
	event.subscribe([&res, &res2](int value, double value2)
					{
						std::cout << value << std::endl;
						std::cout << value2 << std::endl;
						res = value;
						res2 = value2;
					});

	event.happened(500, 10.5);
	ASSERT_EQ(500, res);
	ASSERT_EQ(10.5, res2);
}

TEST(DevcoreEvents, variable_lambda)
{
	Variable<int> var(10);
	var.changed->subscribe([](int val)
						  {
							  std::cout << "changed to: " << val << std::endl;
							  ASSERT_EQ(100, val);
						  });

	var.changed->subscribe([](int val)
						  {
							  std::cout << "changed to_2(value+100): " << val + 100 << std::endl;
							  ASSERT_EQ(100, val);
						  });

	var.transitioned->subscribe([](int valFrom, int valTo)
							   {
								   std::cout << "From: " << valFrom << ", To: " << valTo << std::endl;
								   ASSERT_EQ(valFrom, 10);
								   ASSERT_EQ(valTo, 100);
							   });
	var = 100;
	ASSERT_EQ(100, var.value());
}

TEST(DevcoreEvents, variabledict_lambda)
{
	VariableDict<int, std::shared_ptr<int>> var;
	var.added->subscribe([](VariableDict<int, std::shared_ptr<int>>::MapType new_items){
        for (auto it : new_items){
			std::cout << "added: " << it.first << ":" << *it.second << std::endl;
		}
	});
    var.removed->subscribe([](VariableDict<int, std::shared_ptr<int>>::MapType gone_items){
        for (auto it : gone_items){
            std::cout << "removed: " <<it.first << ":" << *it.second << std::endl;
        }
    });

    var.add(0, std::make_shared<int>(0));


    VariableDict<int, std::shared_ptr<int>>::MapType newVals = {{1, std::make_shared<int>(112)}, {2, std::make_shared<int>(222)}, {3, std::make_shared<int>(333)}};
	var.add(newVals);

    std::cout << "Check duplicate (wanna be empty):" << std::endl;
    var.add(newVals);
    std::cout << "Check finished." << std::endl;

    std::cout << "Check change in duplicate (wanna be not empty):" << std::endl;
    newVals[1] = std::make_shared<int>(111);
    var.add(newVals);
    std::cout << "Check finished." << std::endl;

    auto var_copy = var;

    var_copy.remove(1);
}

TEST(DevcoreEvents, variabledict_varinheritance)
{
    VariableDict<int, int> var({{1,2},{2,3}, {5,6}});

    var.changed->subscribe([](std::map<int,int> _new){
        std::cout << "changed:" << std::endl;
        for (auto item : _new)
        {
            std::cout << item.first << ":" << item.second << std::endl;
        }

        std::map<int,int> true_result = {{1,2}, {5,6}};
        ASSERT_EQ(true_result, _new);
    });

    var.transitioned->subscribe([](std::map<int,int> _old, std::map<int,int> _new){
        std::map<int,int> true_old = {{1,2},{2,3}, {5,6}};
        std::map<int,int> true_result = {{1,2}, {5,6}};

        ASSERT_EQ(true_old, _old);
        ASSERT_EQ(true_result, _new);

    });

    var.remove(2);

    std::map<int, int> empty_map;
    var.add(empty_map);

    std::vector<int> empty_keys;
    var.remove(empty_keys);

    var.add(5,6);
}

TEST(DevcoreEvents, variabledict_set)
{
    VariableDict<int, int> var({{1,2}, {3,5}});

    var.changed->subscribe([](std::map<int,int> val){
        std::cout << "changed" << std::endl;
        std::map<int, int> new_var_value = {{0,2}, {2,3}};
        ASSERT_TRUE(eq_maps(val, new_var_value));
    });

    std::map<int, int> new_var_value = {{0,1}, {2,3}};
    var = new_var_value;
}