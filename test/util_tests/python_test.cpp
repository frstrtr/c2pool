#include <gtest/gtest.h>
#include <iostream>
#include <memory>
using namespace std;

TEST(Py, TestWitoutPy)
{
    cout << "Work" << endl;
}

// TEST(Py, TestSharedPtr)
// {
//     shared_ptr<int> p1 = make_shared<int>(100);
//     vector<shared_ptr<int>> vp;
//     vp.push_back(p1);
//     *p1 = 101;
//     cout << p1.use_count() << " " << *p1 << " | " << *vp[0] << endl;
//     //p1 = make_shared<int>(200);
//     p1.reset();
//     cout << p1.use_count() << " " << *p1 << " | " << *vp[0] << endl;
//     int* p2 = vp[0].get();
//     vp.pop_back();
//     cout << vp.size() << endl;
//     cout << vp[0].use_count() << endl;
//     cout << *p2 << " | " << *vp[0] << endl;
// }