#include <gtest/gtest.h>
#include <libdevcore/events.h>
#include <iostream>

TEST(DevcoreEvents, event_lambda)
{
    int res = 0;
	Event<int> event;
	event.subscribe([&res](int value){
		std::cout << value << std::endl;
        res = value;
	});

	event.happened(500);
    ASSERT_EQ(500, res);
}

class TestEvent{
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
	TestEvent* obj = new TestEvent();
	//event.subscribe(&TestEvent::testF, obj);
	event.subscribe([&](int value){obj->testF(value);});
	event.happened(1337);

	ASSERT_EQ(1337, obj->res);
	delete obj;
}

TEST(DevcoreEvents, event_many_args){
    int res = 0;
    double res2 = 0;

    Event<int, double> event;
    event.subscribe([&res, &res2](int value, double value2){
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
    Variable<int> var;
    var.changed.subscribe([](int val) { std::cout << "changed to: " << val << std::endl;});
    var.changed.subscribe([](int val) { std::cout << "changed to_2(value+100): " << val+100 << std::endl;});

    var.transitioned.subscribe([](int valFrom, int valTo){ std::cout << "From: " << valFrom << ", To: " << valTo << std::endl;});
    
}