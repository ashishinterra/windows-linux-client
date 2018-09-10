#pragma once

#include "ta/utils.h"
#include <string>
#include <stdexcept>
#include <vector>
#include <utility>

class QWidget;

namespace rclient
{
    struct AuthRequirements;

    struct UserLockedError : std::exception
    {};
    struct AuthCancelledException : std::exception
    {};
#ifdef _WIN32
    struct KerberosAuthSuccessException : std::exception
    {
        KerberosAuthSuccessException(QWidget* aParent);
    };
#endif

    struct LoggerInitError : std::runtime_error
    {
        explicit LoggerInitError(const std::string& aMessage = "") : std::runtime_error(aMessage) {}
    };


    // RAII-class for logger.
    struct LoggerInitializer
    {
        //@throw LoggerInitError
        LoggerInitializer();
        ~LoggerInitializer();
    };

    ta::StringArrayDict resolveURIs(const AuthRequirements& anAuthReqs);
    ta::StringDict calcDigests(const AuthRequirements& anAuthReqs);
    //@nothrow
    std::string calcHwsig(const std::string& aFormula);
}
