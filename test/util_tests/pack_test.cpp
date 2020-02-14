#include <gtest/gtest.h>
//#include "pack.h"
#include "pystruct.h"
#include <sstream>
#include "Python.h"
using namespace std;
/*class PackTypeTest : public testing::Test{
public:
    virtual ~PackTypeTest(){

    }

protected:
    virtual void SetUp(){

    }
};

TEST_F(PackTypeTest, equal_type){

}*/


TEST(PyCode, PyStruct){
    Py_Initialize();
    //strct.read();

    pystruct strct;

    cout << strct.pack("<II", "123, 13371488");



    Py_Finalize();
}