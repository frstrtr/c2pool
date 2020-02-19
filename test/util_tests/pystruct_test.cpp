#include <gtest/gtest.h>
#include <pystruct.h>
using namespace std;

TEST(PyCode, PyStructPack){
    Py::Initialize();

    stringstream ss;

    ss << 321 << ", " << 1337;
    string res = pystruct::pack("<II", ss);
    ASSERT_EQ(res, "b\'A\\x01\\x00\\x009\\x05\\x00\\x00\'");
    ss.clear();
    ss << "bzz" << ", " << 1337 << ", " << 321;
    res = pystruct::pack("<3sII", ss);
    ASSERT_EQ(res,"b\'bzz9\\x05\\x00\\x00A\\x01\\x00\\x00\'");

    Py::Finalize();
}

TEST(PyCode, PyStructUnpack){
    string r;
    int a, b;
    stringstream s = pystruct::unpack("<3sII", "b\'bzz9\\x05\\x00\\x00A\\x01\\x00\\x00\'");

    s >> r >> a >> b;
    ASSERT_EQ(r, "bzz");
    ASSERT_EQ(a, 1337);
    ASSERT_EQ(b, 321);
}

TEST(PyCode, PyStructPackUnpack){
    char* types = "<I2I10s";
    int i11 = 1, i12 = 12, i13 = 31;
    string s1 = "zerone.bit";

    stringstream _pack;

    _pack << i11 << ", " << i12 << ", " << i13 << ", " << s1;
    char* res = pystruct::pack(types, _pack);

    stringstream _unpack = pystruct::unpack(types, res);

    int i21, i22, i23;
    string s2;
    _unpack >> i21 >> i22 >> i23 >> s2;
    ASSERT_EQ(i21, i11);
    ASSERT_EQ(i22, i12);
    ASSERT_EQ(i23, i13);
    ASSERT_EQ(s2, s1);
}