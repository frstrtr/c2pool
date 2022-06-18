#include <gtest/gtest.h>
#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>

TEST(stream_types_test, int_type)
{
    IntType(64) num(1231);

    PackStream stream;
    stream << num;

    IntType(32) num_res;
    int32_t res = num_res.get();

    ASSERT_EQ(12312312, res);
}