#include <gtest/gtest.h>
#include <iostream>
#include <core/events.hpp>

TEST(EventTests, SubscribeOnce_FiresExactlyOnce)
{
	Event<int> ev;
	int count = 0;
	ev.subscribe_once([&](int v){ count += v; });

	ev.happened(10);  // fires: count = 10
	ev.happened(10);  // should NOT fire again
	ev.happened(10);

	EXPECT_EQ(count, 10);
}

TEST(EventTests, SubscribeOnce_CoexistsWithRegularSubscribe)
{
	Event<int> ev;
	int once_count = 0, reg_count = 0;
	ev.subscribe_once([&](int v){ once_count += v; });
	ev.subscribe([&](int v){ reg_count += v; });

	ev.happened(5);
	ev.happened(5);

	EXPECT_EQ(once_count, 5);   // once: only first
	EXPECT_EQ(reg_count, 10);   // regular: both
}

TEST(EventTests, SubscribeOnce_NoArgsEvent)
{
	Event<> ev;
	int count = 0;
	ev.subscribe_once([&](){ ++count; });
	ev.happened();
	ev.happened();
	EXPECT_EQ(count, 1);
}

TEST(VariableTests, IsNull_DefaultVar_IsNull)
{
	Variable<int> v;
	EXPECT_TRUE(v.is_null());
}

TEST(VariableTests, IsNull_AfterSet_NotNull)
{
	Variable<int> v;
	v.set(42);
	EXPECT_FALSE(v.is_null());
}

TEST(VariableTests, IsNull_ConstructedWithValue_NotNull)
{
	Variable<int> v(99);
	EXPECT_FALSE(v.is_null());
}

TEST(VariableTests, Changed_FiredOnSet)
{
	Variable<int> v;
	int last = -1;
	v.changed.subscribe([&](int x){ last = x; });
	v.set(7);
	EXPECT_EQ(last, 7);
}

TEST(VariableTests, Changed_NotFiredOnSameValue)
{
	Variable<int> v(3);
	int count = 0;
	v.changed.subscribe([&](int){ ++count; });
	v.set(3); // same value — no fire
	EXPECT_EQ(count, 0);
}

TEST(VariableTests, Transitioned_CarriesOldAndNew)
{
	Variable<int> v(1);
	int old_val = -1, new_val = -1;
	v.transitioned.subscribe([&](int o, int n){ old_val = o; new_val = n; });
	v.set(2);
	EXPECT_EQ(old_val, 1);
	EXPECT_EQ(new_val, 2);
}
