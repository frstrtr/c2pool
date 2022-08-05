#include <gtest/gtest.h>
#include <libdevcore/events.h>
#include <iostream>

TEST(DevcoreEvents, event_lambda)
{
	int res = 0;
	Event<int> event;
	event.subscribe([&res](int value)
					{
						std::cout << value << std::endl;
						res = value;
					});

	int v = 500;
	event.happened(v);
	ASSERT_EQ(500, res);
}

TEST(DevcoreEvents, event_run_and_subscribe)
{
    int res = 0;

    Event<int> event;
    event.run_and_subscribe([&res](){
        res = 99;
    });

    ASSERT_EQ(res, 99);

    res = 0;

	auto v = 199;
    event.happened(v);
    ASSERT_EQ(res, 99);

    res = 0;
    int res2 = 0;
    event.subscribe([&](const int &value){
        res2 = value;
    });
	auto v2 = 511;
    event.happened(v2);

    ASSERT_EQ(res, 99);
    ASSERT_EQ(res2, 511);

}

TEST(DevcoreEvents, event_copy)
{
    int res = 0;
    Event<int> event;
    event.subscribe([&res](const int &value){
        res = value;
    });

	auto v = 123;
    event.happened(v);
    ASSERT_EQ(res, 123);

    int res2 = res;

    Event<int> event_copy;
    event_copy = event;
    event_copy.subscribe([&res2] (const int &value){
        res2 += 127;
    });

	auto v2 = 50;
    event_copy.happened(v2);

    ASSERT_EQ(res, 50);
    ASSERT_EQ(res2, 250);
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
	auto v = 1337;
	event.happened(v);

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

	auto v = 500;
	auto v2 = 10.5;
	event.happened(v, v2);
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
        std::map<int, int> new_var_value = {{0,1}, {2,3}};
        ASSERT_EQ(val, new_var_value);
    });

    std::map<int, int> new_var_value = {{0,1}, {2,3}};
    var = new_var_value;
}

TEST(DevcoreEvents, variabledict2_set)
{
	VariableDict<int, std::shared_ptr<int>> var({{1, std::make_shared<int>(2)}, {3,std::make_shared<int>(5)}});

	var.changed->subscribe([](std::map<int, std::shared_ptr<int>> val){
		std::cout << "changed" << std::endl;
		std::map<int, std::shared_ptr<int>> new_var_value = {{0,std::make_shared<int>(1)}, {2,std::make_shared<int>(3)}};
		ASSERT_EQ(val, new_var_value);
	});

	std::map<int, std::shared_ptr<int>> new_var_value = {{0,std::make_shared<int>(1)}, {2,std::make_shared<int>(3)}};
	var = new_var_value;
}