#include "LogInitializer.h"
#include "rclient/Common.h"
#include "rclient/CommonUtils.h"

#include "ta/process.h"
#include "ta/version.h"
#include "ta/logconfiguration.h"
#include "ta/logger.h"
#include "ta/common.h"

using std::string;

LogInitializer::LogInitializer()
{
    string myAppName;
    try { myAppName = ta::Process::getSelfShortName(); }
    catch (...) {}

    const string myLogFilePath = ta::Process::getTempDir() + rclient::PrGeneratorLogName;
    string myEnvInfo = str(boost::format("%s Client-%s Problem Report Generator") % resept::ProductName % toStr(rclient::ClientVersion));

    ta::LogConfiguration::Config myMemConfig;
    myMemConfig.fileAppender = true;
    myMemConfig.fileAppenderLogThreshold = ta::LogLevel::Debug;
    myMemConfig.fileAppenderLogFileName = myLogFilePath;
    ta::LogConfiguration::instance().load(myMemConfig);
    PROLOG(myEnvInfo);
    logOsInfo();
}

void LogInitializer::logOsInfo()
{
    using namespace ta;
    try
    {
        const OsInfoUtils::OsVersion myVersion = OsInfoUtils::getVersion();
        DEBUGLOG(boost::format("\nOS info:\nName: %s\nVersion: %s") % myVersion.name % myVersion.ver);

        DEBUGLOG("\nEnvironment variables:");
        foreach (const string& myEnvVar, Process::getEnvVars())
        {
            DEBUGLOG(myEnvVar);
        }
    }
    catch (std::exception& e)
    {
        WARNLOG2("Failed to get OS info.", boost::format("Failed to get OS info. %s. Ignoring the error...") % e.what());
    }
}
