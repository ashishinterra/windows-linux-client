#pragma once

# ifdef _WIN32

#include <string>

namespace ta
{
    namespace OsUserInfo
    {
        struct UserLogonId
        {
            UserLogonId() : highPart(0), lowPart(0) {}
            UserLogonId(long aHighPart, int aLowPart) : highPart(aHighPart), lowPart(aLowPart) {};
            /**
            HighPart of LUID
            */
            long highPart;
            /**
            LowPart of LUID
            */
            long lowPart;
        };

        /**
         Retrieve Security Identifier (SID) associated with the user of the current process
         */
        std::string getCurrentUserSID();

        /**
         Retrieve the Logon ID used in Kerberos
        */
        UserLogonId getCurrentUserLogonId();
    }
}
# endif
