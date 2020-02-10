#include <gtest/gtest.h>
//#include "pack.h"
#include "pystruct.h"

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
    strct.read();
    std::tuple<int, int> t;
    strct.pack("asd", t);
}