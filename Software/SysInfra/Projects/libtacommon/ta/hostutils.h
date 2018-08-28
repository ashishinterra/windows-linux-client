#pragma once

#ifdef _WIN32
#error "Unsupported platform"
#else
#include <string>

//
// API to retrieve and set Unix/Linux hostname
//
namespace ta
{
    namespace HostUtils
    {
        namespace hostname
        {
            std::string get();
            void set(const std::string& aHostName);
        }
    }
}
#endif
