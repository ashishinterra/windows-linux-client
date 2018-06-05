#pragma once
#ifdef _WIN32
#include <string>
#include "resept/common.h"

namespace ta
{
    struct WinSmartCardUtilNoSmartCardError : std::runtime_error
    {
        explicit WinSmartCardUtilNoSmartCardError(const std::string& aMessage = "") : std::runtime_error(aMessage) {}
    };

    namespace WinSmartCardUtil
    {
        bool hasSmartCard();
        std::string requestCsr(const std::string& aCn,
                               const std::string& aC,
                               const std::string& aSt,
                               const std::string& anL,
                               const std::string& anO,
                               const std::string& anOu,
                               const std::string& anE,
                               const unsigned int aKeySize,
                               const ta::SignUtils::Digest aSigningAlg = ta::SignUtils::digestSha256);
        std::string requestCsr(const resept::CsrRequirements& aCsrRequirements);

        // Automated creation of a vsc, commented for future purposes, because of it's complexity
#if 0
        void createVsc();
#endif
    } // end WinSmartCardUtil namespace
} // end ta namespace
#else
// Only for Windows
#endif
