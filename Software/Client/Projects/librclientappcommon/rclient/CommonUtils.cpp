#include "CommonUtils.h"
#ifdef _WIN32
#include "QtExclusiveApp.h"
#include "AuthenticationWizard.h"
#include "TimedNotificationBox.h"
#endif
#include "rclient/NativeCertStore.h"
#include "rclient/Settings.h"
#include "rclient/RcdpHandler.h"
#include "rclient/Common.h"
#include "resept/computeruuid.h"
#include "ta/WinSmartCardUtil.h"
#include "ta/url.h"
#include "ta/version.h"
#include "ta/logappender.h"
#include "ta/logconfiguration.h"
#include "ta/logger.h"
#include "ta/netutils.h"
#include "ta/strings.h"
#include "ta/hashutils.h"
#include "ta/process.h"
#include "ta/dnsutils.h"
#include "ta/timeutils.h"
#include "ta/assert.h"
#include "ta/utils.h"
#include "ta/common.h"

#include <memory>
#include "boost/algorithm/string.hpp"

using std::string;
using namespace ta;

namespace rclient
{
    namespace
    {
        void initLogger()
        {
            try
            {
                string myEnvInfo = str(boost::format("%s Client-%s") % resept::ProductName % toStr(rclient::ClientVersion));
                string myLogLevelStr = rclient::Settings::getLogLevel();
                ta::LogLevel::val myLogLevel;
                if (!LogLevel::parse(myLogLevelStr.c_str(), myLogLevel))
                    TA_THROW_MSG(LoggerInitError, "Failed to parse logging level " + myLogLevelStr);
                const string myLogFilePath = rclient::getLogDir() + ta::getDirSep() + rclient::LogName;

                ta::LogConfiguration::Config myMemConfig;
                myMemConfig.fileAppender = true;
                myMemConfig.fileAppenderLogThreshold = myLogLevel;
                myMemConfig.fileAppenderLogFileName = myLogFilePath;
                ta::LogConfiguration::instance().load(myMemConfig);

                PROLOG(myEnvInfo);
            }
            catch (LoggerInitError&)
            {
                throw;
            }
            catch (std::exception& e)
            {
                TA_THROW_MSG(LoggerInitError, e.what());
            }
        }

        void deinitLogger()
        {
            EPILOG(resept::ProductName + " Client-" + toStr(rclient::ClientVersion));
        }
    }

    //
    // Public API
    //

#ifdef _WIN32
    KerberosAuthSuccessException::KerberosAuthSuccessException(QWidget* aParent)
    {
        static const int myTimerTtlSec = 3;
        TimedNotificationBox::show(aParent, myTimerTtlSec, "Authenticated successfully", "Kerberos authentication succeeded.");
    }
#endif

    LoggerInitializer::LoggerInitializer()
    {
        initLogger();
    }

    LoggerInitializer::~LoggerInitializer()
    {
        deinitLogger();
    }


    ta::StringArrayDict resolveURIs(const AuthRequirements& anAuthReqs)
    {
        ta::StringArrayDict myResolvedURIs;
        if (anAuthReqs.resolve_service_uris)
        {
            foreach(const string& uri, anAuthReqs.service_uris)
            {
                const string myHost = ta::url::parse(uri).authority_parts.host;
                DEBUGLOG("Resolving " + myHost);
                ta::StringArray myIps;
                foreach(const ta::NetUtils::IP& ip, ta::DnsUtils::resolveIpsByName(myHost))
                {
                    if (!ip.ipv4.empty())
                    {
                        myIps.push_back(ip.ipv4);
                    }
                    if (!ip.ipv6.empty())
                    {
                        myIps.push_back(ip.ipv6);
                    }
                }
                DEBUGLOG("Resolved IPs of " + myHost + ": " + ta::Strings::join(myIps, ","));
                myResolvedURIs[uri] = myIps;
            }
        }
        return myResolvedURIs;
    }

    ta::StringDict calcDigests(const AuthRequirements& anAuthReqs)
    {
        ta::StringDict myCalculatedDigests;
        if (anAuthReqs.calc_service_uris_digest)
        {
            foreach(const string& uri, anAuthReqs.service_uris)
            {
                const string myExecutableNativePath = ta::Process::expandEnvVars(ta::url::makeNativePath(uri));
                const string myDigest = ta::HashUtils::getSha256HexFile(myExecutableNativePath);
                DEBUGLOG("Digest of " + myExecutableNativePath + "  is " + myDigest);
                myCalculatedDigests[uri] = myDigest;
            }
        }
        return myCalculatedDigests;
    }

    //@nothrow
    string calcHwsig(const string& aFormula)
    {
        string myParsedFormula;
        const string myHwSig = resept::ComputerUuid::calcCs(aFormula, &myParsedFormula);
        DEBUGLOG(boost::format("Calculated HWSIG: %s (parsed formula: %s)") % myHwSig % myParsedFormula);
        return myHwSig;
    }

}
