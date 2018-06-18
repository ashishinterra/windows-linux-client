#pragma once

#include <string>

namespace ta
{
    namespace OsInfoUtils
    {
        struct OsVersion
        {
            std::string name;
            std::string ver;
        };
        inline std::string str(const OsVersion& aVersion) { return aVersion.name + " " + aVersion.ver; }

        // Retrieve OS version
        OsVersion getVersion();

        // Return short platform name such as "Windows", "Linux" or "OpenBSD"
        //@nothrow
        std::string getPlatformShortName();


#ifdef __linux__
        // No more than an educated guess
        bool isRaspberryPi();

        bool isLinuxDebian(); // Debian or Ubuntu
        bool isLinuxCentOS();
        bool isLinuxRHEL();
#endif
    }
}
