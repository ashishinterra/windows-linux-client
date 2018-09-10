#pragma once

#include "ta/OsUserInfo.h"
#include "cxxtest/TestSuite.h"
#include <string>

class OsUserInfoTest : public CxxTest::TestSuite
{
public:
    void testGetUserSID()
    {
        std::string myUserSID = ta::OsUserInfo::getCurrentUserSID();
        TS_ASSERT(!myUserSID.empty());
    }

    void testGetCurrentUserLogonId()
    {
        ta::OsUserInfo::UserLogonId myCurrentLogonId = ta::OsUserInfo::getCurrentUserLogonId();
        TS_ASSERT(myCurrentLogonId.lowPart > 0);
    }
};
