#pragma once

#include "rclient/QtExclusiveApp.h"
#include "rclient/CommonUtils.h"
#include "ta/opensslapp.h"
#include <stdexcept>
#include <string>
#include <memory>

struct ReseptDesktopClientAppError : std::runtime_error
{
    ReseptDesktopClientAppError(const std::string& aMessage = "")	: std::runtime_error(aMessage) {}
};

class ReseptDesktopClientApp
{
public:
    /**
     Construct RESEPT desktop application and performs some basic initializations
     @throw ReseptDesktopClientAppError
    */
    ReseptDesktopClientApp(int& argc, char** argv);
    ~ReseptDesktopClientApp();

    /**
    Start RESEPT desktop application
    @throw ReseptDesktopClientAppError
    */
    void execute();
private:
    static void checkReseptCustomized();
    void initQt();
    void initLogger();
    void initOpenSSL();
private:
    TA_UNIQUE_PTR<rclient::QtExclusiveApp> theQtAppPtr;
    TA_UNIQUE_PTR<rclient::LoggerInitializer> theLoggerInitializer;
    TA_UNIQUE_PTR<ta::OpenSSLApp> theOpenSSLAppPtr;
};
