#include <gtest/gtest.h>
#include "pack.h"

class PackTypeTest : public testing::Test{
public:
    virtual ~PackTypeTest(){

    }
    Type First;
    Type Second;
protected:
    virtual void SetUp(){
        First = Type(1,2);
        Second = Type(1,2);
    }
};

TEST_F(PackTypeTest, equal_type){
    ASSERT_EQ(First, Second);
}