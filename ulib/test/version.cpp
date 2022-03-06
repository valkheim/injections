#include <gtest/gtest.h>
#include "ulib.h"

TEST(version, test_version)
{
    ASSERT_EQ(ul::getVersion(), "1.0.0");
}