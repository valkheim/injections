#include <gtest/gtest.h>
#include <windows.h>
#include "ulib.h"

TEST(processes, test_using_enumprocess)
{
    auto pids = ul::get_processes_ids_using_enumprocess();
    ASSERT_FALSE(pids.empty());
    ASSERT_TRUE(std::find(pids.begin(), pids.end(), GetCurrentProcessId()) != pids.end());
}

TEST(processes, test_using_toolhelp)
{
    auto pids = ul::get_processes_ids_using_toolhelp();
    ASSERT_FALSE(pids.empty());
    ASSERT_TRUE(std::find(pids.begin(), pids.end(), GetCurrentProcessId()) != pids.end());
}

TEST(processes, test_using_wts)
{
    auto pids = ul::get_processes_ids_using_wts();
    ASSERT_FALSE(pids.empty());
    ASSERT_TRUE(std::find(pids.begin(), pids.end(), GetCurrentProcessId()) != pids.end());
}

TEST(processes, test_compatibility)
{
    auto pids_using_enumprocess = ul::get_processes_ids_using_enumprocess();
    auto pids_using_toolhelp = ul::get_processes_ids_using_toolhelp();
    auto pids_using_wts = ul::get_processes_ids_using_wts();
    ASSERT_EQ(pids_using_enumprocess.size(), pids_using_toolhelp.size());
    ASSERT_EQ(pids_using_enumprocess.size(), pids_using_wts.size());
}