#pragma once

#include <string>

namespace ta
{
    namespace SysInfo
    {
#ifdef _WIN32
        /**
         Determines whether the current process is running under WOW64.

         @throw std::runtime_error
         */
        bool isWow64();

        /**
          Retrieves Windows product ID

          @throw std::runtime_error
          */
        std::string getWinProductId();

        /**
          Retrieves Windows registered owner

          @throw std::runtime_error
          */
        std::string getWinRegisteredOwner();

        /**
          Whether SNI is supported by the installed IIS version
          Background: SNI is supported from IIS 8 and up.
          The IIS version is bound to a Windows version.
          IIS 8 belongs to Windows 8 (and server 2012) which have NT version 6.2
        */
        bool isIisSniSupported();

        std::string getLastErrorStr();

        /**
          Scoped class initialize COM using CoInitialize()
        */
        class ScopedComInitializer
        {
        public:
            ScopedComInitializer();
            ~ScopedComInitializer();
        private:
            bool isComInitialized;
        };
#endif //_WIN32
        /**
          Retrieves the serial number from BIOS. When BIOS is not available (e.g. on RaspberryPi) return CPU serial number

          @throw std::runtime_error
          */
        std::string getSerialNumber();


        /**
          Get the unique hardware representation text

          @nothrow
        */
        std::string getHardwareDescription();

        bool isUserPasswordExpiring(size_t aRemainingPasswordValidityInSeconds);
    }
}
