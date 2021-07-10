#include <gtest/gtest.h>
#include <iostream>
#include <util/pystruct.h>
using namespace std;

TEST(Py, TestWorkPyPackTypes)
{
    ASSERT_EQ(c2pool::python::PyPackTypes::is_worked(), true);
    cout << "PyPackTypes is worked" << endl;
}
