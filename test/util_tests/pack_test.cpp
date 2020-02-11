#include <gtest/gtest.h>
//#include "pack.h"
#include "pystruct.h"
#include "Python.h"
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
    pystruct strct;
    Py_Initialize();
    //strct.read();

    


    Py_Finalize();

    std::tuple<int, int> t;
    //strct.pack("asd", t);
    //strct.unpack("1","1");
}