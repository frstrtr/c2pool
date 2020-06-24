#include <gtest/gtest.h>
#include <pystruct.h>
using namespace std;

TEST(PyCode, PyReceiveLength){
    int first_num = 10;

    char* first_num_chr = c2pool::messages::python::for_test::pymessage::get_packed_int(first_num);

    int second_num = c2pool::messages::python::pymessage::receive_length(first_num_chr);

    ASSERT_EQ(first_num, second_num);
}