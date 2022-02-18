#include <gtest/gtest.h>
#include <libdevcore/events.h>
#include <iostream>

TEST(DevcoreEvents, event_lambda)
{
	Event<int> event;
	event.subscribe([](int value){
		std::cout << value << std::endl;
	});

	event.happened(500);
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
	using namespace boost::placeholders;
	Event<int> event;
	TestEvent* obj = new TestEvent();
	//event.subscribe(&TestEvent::testF, obj);
	event.subscribe([&](int value){obj->testF(value);});
	event.happened(1337);

	ASSERT_EQ(1337, obj->res);
	delete obj;
}