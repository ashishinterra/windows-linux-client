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

        // Retrieve OS version
        OsVersion getVersion();

        // Return short platform name such as "Windows", "Linux" or "OpenBSD"
        //@nothrow
        std::string getPlatformShortName();

        // The educated guess whether we run Raspberry Pi
        bool isRaspberryPi();
    }
}
