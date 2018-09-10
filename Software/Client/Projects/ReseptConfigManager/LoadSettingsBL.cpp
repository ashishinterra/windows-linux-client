#include "LoadSettingsBL.h"
#ifdef _WIN32
#include "rclient/IReseptBrokerService.h"
#include "rclient/NativeCertStore.h"
#endif
#include "rclient/ContentConfig.h"
#include "rclient/Settings.h"
#include "ta/Zip.h"
#include "ta/url.h"
#include "ta/utils.h"
#include "ta/dnsutils.h"
#include "ta/signutils.h"
#include "ta/process.h"
#include "ta/proto.hpp"
#include "ta/scopedresource.hpp"
#include "ta/tcpclient.h"
#include "ta/logger.h"
#include "ta/common.h"

#include "boost/filesystem/operations.hpp"
#include "boost/filesystem/convenience.hpp"
#include "boost/algorithm/string.hpp"
#include "boost/cstdint.hpp"

using std::string;
using std::vector;

//
// Private API
//
namespace
{
#ifdef _WIN32
    enum ServiceStatus
    {
        serviceStatusRunning,
        serviceStatusStopped,
        serviceStatusPending,
        serviceStatusNotFound
    };

    ServiceStatus getReseptBrokerServiceStatus()
    {
        SC_HANDLE myScHandle = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ENUMERATE_SERVICE);
        if (!myScHandle)
            TA_THROW_MSG(std::runtime_error, boost::format("OpenSCManager failed. Last error: %d") % ::GetLastError());
        ENUM_SERVICE_STATUS myServices[1024] = {};
        DWORD cbBytesNeeded, myNumServices;
        if (!EnumServicesStatus(myScHandle, SERVICE_WIN32, SERVICE_STATE_ALL, myServices, sizeof(myServices), &cbBytesNeeded, &myNumServices, 0))
            TA_THROW_MSG(std::runtime_error, boost::format("EnumServicesStatus failed. Last error: %d") % ::GetLastError());
        for (DWORD i=0; i<myNumServices; ++i)
        {
            if (string(myServices[i].lpServiceName) == rclient::BrokerServiceName)
            {
                switch (myServices[i].ServiceStatus.dwCurrentState)
                {
                case SERVICE_RUNNING:
                    return serviceStatusRunning;
                case SERVICE_STOPPED:
                case SERVICE_PAUSED:
                    return serviceStatusStopped;
                case SERVICE_CONTINUE_PENDING:
                case SERVICE_PAUSE_PENDING:
                case SERVICE_START_PENDING:
                case SERVICE_STOP_PENDING:
                    return serviceStatusPending;
                default:
                    TA_THROW_MSG(std::runtime_error, boost::format("Unsupported service status %d") % myServices[i].ServiceStatus.dwCurrentState);
                }
            }
        }
        return serviceStatusNotFound;
    }

    bool checkBrokerServiceStatusRunning(string& anErrorMsg)
    {
        using namespace rclient::ReseptBrokerService;

        const ServiceStatus myBrokerServiceStatus = getReseptBrokerServiceStatus();

        if (myBrokerServiceStatus == serviceStatusNotFound)
            return anErrorMsg = resept::ProductName + " Broker Service is not installed. Please reinstall " + resept::ProductName + " and try again or contact " + resept::ProductName + " administrator.", false;
        if (myBrokerServiceStatus == serviceStatusPending)
            return anErrorMsg = resept::ProductName + " Broker Service is in pending state. Please try again.", false;
        if (myBrokerServiceStatus == serviceStatusStopped)
            return anErrorMsg = resept::ProductName + " Broker Service is stopped. Please start the service and try again or contact " + resept::ProductName + " administrator.", false;
        if (myBrokerServiceStatus != serviceStatusRunning)
            TA_THROW_MSG(std::runtime_error, boost::format("Unsupported service status %d") % myBrokerServiceStatus);

        return true;
    }

    bool installSettingsWithBrokerService(const rclient::ContentConfig::Config& aContentConfig,
                                          LoadSettingsBL::ConfirmationPromptCallback aConfirmationPromptCb,
                                          void* aConfirmationPromptCbCookie,
                                          string& anErrorMsg)
    {
        using namespace rclient::ReseptBrokerService;

        if (!checkBrokerServiceStatusRunning(anErrorMsg))
        {
            return false;
        }

        const unsigned int myReseptBrokerServicePort = rclient::Settings::getReseptBrokerServicePort();
        DEBUGLOG(boost::format("Connecting to RESEPT Broker Service at 127.0.0.1:%u") % myReseptBrokerServicePort);
        ta::TcpClient myBrokerServiceConnection;
        myBrokerServiceConnection.open("127.0.0.1", myReseptBrokerServicePort);

        DEBUGLOG("Connected");
        const string myUserConfigPath = rclient::Settings::getUserConfigPath();
        ta::proto::send(myBrokerServiceConnection, requestInstallSettings);
        ta::proto::send(myBrokerServiceConnection, InstallSettingsRequest(aContentConfig, myUserConfigPath));
        DEBUGLOG("Installation request sent");

        Response myResponse = ta::proto::receive<Response>(myBrokerServiceConnection);

        switch (myResponse.status)
        {
        case responseStatusOk:
            DEBUGLOG("Settings have been successfully installed");
            return true;
        case responseStatusConfirmation:
        {
            DEBUGLOG("Confirmation prompt received from the service");

            if (!aConfirmationPromptCb)
            {
                TA_THROW_MSG(std::invalid_argument, "Confirmation prompt received from the service but prompt callback routine is not specified");
            }

            if (!aConfirmationPromptCb(myResponse.text, aConfirmationPromptCbCookie))
            {
                anErrorMsg = "Loading settings is cancelled by the user";
                WARNLOG("Loading settings is cancelled by the user (no downgrade desired for provider " + aContentConfig.getProviderName() + ")");
                ta::proto::send(myBrokerServiceConnection, false);
                myResponse = ta::proto::receive<Response>(myBrokerServiceConnection);
                switch (myResponse.status)
                {
                case responseStatusOk:
                    return false;
                case responseStatusUserError:
                    anErrorMsg = myResponse.text;
                    WARNLOG(anErrorMsg);
                    return false;
                case responseStatusError:
                    TA_THROW_MSG(std::runtime_error, myResponse.text);
                default:
                    TA_THROW_MSG(std::runtime_error, boost::format("Unexpected status %d received from RESEPT Broker Service") % myResponse.status);
                }
            }

            ta::proto::send(myBrokerServiceConnection, true);
            myResponse = ta::proto::receive<Response>(myBrokerServiceConnection);

            switch (myResponse.status)
            {
            case responseStatusOk:
                DEBUGLOG("Settings have been successfully installed");
                return true;
            case responseStatusUserError:
                anErrorMsg = myResponse.text;
                WARNLOG(anErrorMsg);
                return false;
            case responseStatusError:
                TA_THROW_MSG(std::runtime_error, myResponse.text);
            default:
                TA_THROW_MSG(std::runtime_error, boost::format("Unexpected status %d received from RESEPT Broker Service") % myResponse.status);
            }
        }
        case responseStatusUserError:
            anErrorMsg = myResponse.text;
            WARNLOG(anErrorMsg);
            return false;
        case responseStatusError:
            TA_THROW_MSG(std::runtime_error, myResponse.text);
        default:
            TA_THROW_MSG(std::runtime_error, boost::format("Unexpected status %d received from RESEPT Broker Service") % myResponse.status);
        }
    }
#else
    //
    // Linux
    //



    void fixUserHomeDirOwner()
    {
        if (!ta::isUserRoot()) // don't bother when we are called by root
        {
            //note: just executing "chown -R" in a shell does not work because the shell will be spawn with real uid i.o. effective uid which has all the power

            const string myHomeDir = ta::Process::getUserAppDataDir();
            const string myUserTempDir = myHomeDir + "/tmp";
            const string myKeyTalkUserConfigDir = rclient::Settings::getUserConfigDir();

            ta::chownDir(myHomeDir, ta::recursiveNo);
            ta::chownDir(myUserTempDir, ta::recursiveYes);
            ta::chownDir(myKeyTalkUserConfigDir, ta::recursiveYes);
        }
    }

    bool installSettingsDirectly(const rclient::ContentConfig::Config& aContentConfig,
                                 LoadSettingsBL::ConfirmationPromptCallback aConfirmationPromptCb,
                                 void* aConfirmationPromptCbCookie,
                                 string& anErrorMsg)
    {
        const string myNewProviderName = aContentConfig.getProviderName();

        // Ask for confirmation when downgrading settings
        if (rclient::Settings::isCustomized() && ta::isElemExist(myNewProviderName, rclient::Settings::getProviders()))
        {
            if (rclient::Settings::getProviderContentVersion(myNewProviderName) > aContentConfig.getContentVersion())
            {
                const string myUserPrompt = "The version of the settings being installed for provider " + myNewProviderName + " is older than the version of the settings already installed. Are you sure you want to proceed? [y/n]";
                DEBUGLOG("The version of the settings being installed for provider " + myNewProviderName + " is older than the version of the settings already installed. Asking the user for confirmation");

                if (!aConfirmationPromptCb)
                {
                    TA_THROW_MSG(std::invalid_argument, "Downgrade confirmation required but confirmation callback routine is not specified");
                }
                if (!aConfirmationPromptCb(myUserPrompt, aConfirmationPromptCbCookie))
                {
                    anErrorMsg = "Loading settings is canceled by the user (no downgrade desired for provider " + aContentConfig.getProviderName() + ")";
                    return false;
                }
            }
        }

        rclient::ContentConfig::install(aContentConfig);

        // It is likely that a just created KeyTalk user profile directory maybe along with user home directory use effective uid (root), so they do not belong to a real user.
        // Make sure these directories belong to the real owner.
        fixUserHomeDirOwner();

        // Record user name we customized for.
        // We can later use this this knowledge to remove KeyTalk settings for all customized users during uninstallation
        const string myUserName = ta::getUserName();
        DEBUGLOG("Adding customized user " + myUserName);
        rclient::Settings::addCustomizedUser(myUserName);

        return true;
    }
#endif // _WIN32


    enum HttpReqStatus
    {
        http200Resp, reqError
    };


    //@nothrow
    //@return success flag. If return value is false, anErrorMsg contains user-oriented error message.
    //                      If the function return true, anErrorMsg is not affected
    bool installSettings(const string& anExtractedSettingsDir,
                         LoadSettingsBL::ConfirmationPromptCallback aConfirmationPromptCb,
                         void* aConfirmationPromptCbCookie,
                         string& anErrorMsg)
    {
        try
        {
            const string myIndexFilePath = anExtractedSettingsDir + ta::getDirSep() + rclient::ContentConfig::IndexFileName;

            if (ta::isFileExist(myIndexFilePath))
            {
                DEBUGLOG(boost::format("Loading RCCDv2 index from '%s'") % myIndexFilePath);
            }
            else
            {
                const string myV1IndexFilePath = anExtractedSettingsDir + ta::getDirSep() + rclient::ContentConfig::v1::IndexFileName;
                DEBUGLOG(boost::format("Loading RCCDv1 index from '%s'") % myV1IndexFilePath);
                // we do not verify RCCD index file signature any more
                ta::writeData(myIndexFilePath, ta::SignUtils::loadNotVerifyPKCS7WithSMIME(myV1IndexFilePath));
            }

            const rclient::ContentConfig::Config myContentConfig(myIndexFilePath);
#ifdef _WIN32
            return installSettingsWithBrokerService(myContentConfig, aConfirmationPromptCb, aConfirmationPromptCbCookie, anErrorMsg);
#else
            return installSettingsDirectly(myContentConfig, aConfirmationPromptCb, aConfirmationPromptCbCookie, anErrorMsg);
#endif
        }
        catch (std::exception& e)
        {
            anErrorMsg = "Error installing " + resept::ProductName + " Client Customization File. Please contact " + resept::ProductName + " support.";
            ERRORLOG2(anErrorMsg, e.what());
        }
        return false;
    }

    string fixRccdUrl(string& anUrl)
    {
        string myUrl = boost::trim_copy(anUrl);

        if (!ta::url::hasScheme(myUrl))
        {
            INFOLOG("Adding http:// to " + myUrl);
            myUrl = "http://" + myUrl;
        }
        if (!boost::ends_with(myUrl, ".rccd"))
        {
            INFOLOG("Appending .rccd to " + myUrl);
            myUrl += ".rccd";
        }

        return myUrl;

    }

#ifdef _WIN32
    bool uninstallUserSettingsForProvider(const string& aProvider, string& anErrorMsg)
    {
        using namespace rclient::ReseptBrokerService;

        try
        {
            DEBUGLOG(boost::format("Uninstalling user settings for provider '%s'") % aProvider);

            bool myFromMasterConfig;
            rclient::Settings::getProviderContentVersion(aProvider, myFromMasterConfig);
            if (myFromMasterConfig)
            {
                TA_THROW_MSG(std::invalid_argument, "Cannot remove master settings for provider " + aProvider + ". Only users settings can be removed.");
            }

            if (!checkBrokerServiceStatusRunning(anErrorMsg))
            {
                return false;
            }

            const string myIssuer = rclient::Settings::getUserCaName(aProvider);// grab cert issuer before uninstalling settings

            const unsigned int myReseptBrokerServicePort = rclient::Settings::getReseptBrokerServicePort();
            DEBUGLOG(boost::format("Connecting to RESEPT Broker Service at 127.0.0.1:%u") % myReseptBrokerServicePort);
            ta::TcpClient myBrokerServiceConnection;
            myBrokerServiceConnection.open("127.0.0.1", myReseptBrokerServicePort);

            DEBUGLOG("Connected");
            const string myUserConfigPath = rclient::Settings::getUserConfigPath();
            ta::proto::send(myBrokerServiceConnection, requestUninstallSettings);
            ta::proto::send(myBrokerServiceConnection, UninstallSettingsRequest(aProvider, myUserConfigPath));
            DEBUGLOG("Settings uninstallation request sent");

            const Response myResponse = ta::proto::receive<Response>(myBrokerServiceConnection);

            switch (myResponse.status)
            {
            case responseStatusOk:
                // remove user certs ourselves because broker service running as system could not access user personal cert store
                rclient::NativeCertStore::deleteUserCertsForIssuerCN(myIssuer, rclient::NativeCertStore::failOnError);
                DEBUGLOG("Settings have been successfully uninstalled");
                return true;
            case responseStatusUserError:
                anErrorMsg = myResponse.text;
                WARNLOG(anErrorMsg);
                return false;
            case responseStatusError:
                TA_THROW_MSG(std::runtime_error, myResponse.text);
            default:
                TA_THROW_MSG(std::runtime_error, boost::format("Unexpected status %d received from BrokerService trying to uninstall settings for provider %s") % myResponse.status % aProvider);
            }
        }
        catch (std::exception& e)
        {
            anErrorMsg = "Error uninstalling settings for provider " + aProvider + ". Please contact " + resept::ProductName + " support.";
            ERRORLOG2(anErrorMsg, e.what());
            return false;
        }
    }
#endif

} // end private API


//
// Public API
//

namespace LoadSettingsBL
{
    bool loadRccdFromUrl(const string& anUrl, vector<unsigned char>& aBlob, string& anErrorMsg)
    {
        string myUrl = boost::trim_copy(anUrl);
        if (myUrl.empty())
        {
            anErrorMsg = "Please specify URL to " + resept::ProductName + " Client Customization File";
            return false;
        }
        myUrl = fixRccdUrl(myUrl);

        DEBUGLOG(boost::format("Loading RCCD from URL '%s'") % myUrl);

        try
        {
            aBlob = ta::NetUtils::fetchHttpUrl(myUrl);
            return true;
        }
        catch (ta::UrlFetchError &e)
        {
            anErrorMsg = e.friendlyMsg;
            ERRORLOG2(anErrorMsg, e.what());
            return false;
        }
        catch (std::exception &e)
        {
            anErrorMsg = "Failed to download Client Customization File from " + myUrl;
            ERRORLOG2(anErrorMsg, e.what());
            return false;
        }
    }

    bool loadRccdFromFile(const string& aPath, vector<unsigned char>& aBlob, string& anErrorMsg)
    {
        DEBUGLOG(boost::format("Loading RCCD from file '%s'") % aPath);
        if (aPath.empty())
            return anErrorMsg = "Please specify location of " + resept::ProductName + " Client Customization File", false;
        try
        {
            aBlob = ta::readData(aPath);
            return true;
        }
        catch(std::exception&)
        {
            return anErrorMsg = "Cannot read " + resept::ProductName + " Client Customization File from " + aPath, false;
        }
    }

    bool installRccd(const vector<unsigned char>& anRccdBlob, const string& anUrlHint, ConfirmationPromptCallback aConfirmationPromptCb, void* aConfirmationPromptCbCookie, string& anErrorMsg)
    {
        FUNCLOG;

        string myDownloadedRccdFilePath, myExtractedDir;
        try
        {
            myDownloadedRccdFilePath = ta::Process::genTempPath("rccd_");
            ta::writeData(myDownloadedRccdFilePath, anRccdBlob);
            myExtractedDir = ta::Zip::extract(myDownloadedRccdFilePath, ta::Process::getTempDir());
            if (!myDownloadedRccdFilePath.empty())
            {
                remove(myDownloadedRccdFilePath.c_str());
            }
        }
        catch (std::exception& e)
        {
            anErrorMsg = "Incorrect " + resept::ProductName + " Client Customization File received from " + anUrlHint;
            ERRORLOG2(anErrorMsg, e.what());
            if (!myDownloadedRccdFilePath.empty())
            {
                remove(myDownloadedRccdFilePath.c_str());
            }
            return false;
        }

        const bool myRetVal = installSettings(myExtractedDir, aConfirmationPromptCb, aConfirmationPromptCbCookie, anErrorMsg);

        try {
            boost::filesystem::remove_all(myExtractedDir);
        } catch (std::exception& e) {
            WARNLOG2("Failed to remove extraction directory", boost::format("Failed to remove directory %s. %s") % myExtractedDir % e.what());
        }
        return myRetVal;
    }

#ifdef _WIN32
    bool uninstallUserSettings(const string& aProvider, string& anErrorMsg)
    {
        FUNCLOG;

        foreach(const string& provider, rclient::Settings::getProviders())
        {
            if (boost::iequals(provider, aProvider))
            {
                if (!uninstallUserSettingsForProvider(provider, anErrorMsg))
                {
                    return false; // exit on the first error.
                    // given the fact that we disallow installing multiple providers which differ in letter case only, we will not end up with partially uninstalled settings when provider "KPN" is successfully uninstalled but uninstallation for provider "kpn" fails
                }
            }
        }
        return true;
    }
#endif

}
