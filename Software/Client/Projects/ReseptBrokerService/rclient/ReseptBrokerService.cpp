#include "rclient/IReseptBrokerService.h"
#include "rclient/ContentConfig.h"
#include "rclient/Settings.h"
#include "rclient/Common.h"
#include "resept/util.h"
#include "ta/utils.h"
#include "ta/timeutils.h"
#include "ta/process.h"
#include "ta/scopedresource.hpp"
#include "ta/logappender.h"
#include "ta/logconfiguration.h"
#include "ta/logger.h"
#include "ta/tcpserver.h"
#include "ta/proto.hpp"

#include "boost/filesystem/operations.hpp"
#include "boost/filesystem/convenience.hpp"
#include <windows.h>
#include <ntsecapi.h>
#include <string>
#include <sstream>
#include <vector>
#include <list>
#include <memory>

using std::string;
namespace fs = boost::filesystem;

SERVICE_STATUS theServiceStatus = { 0 };
SERVICE_STATUS_HANDLE theServiceStatusHandle = NULL;
static const unsigned int AcceptTimeout = 1000;

// @note When the user imports CA cert by hand (say, PCA) its default location will be (as viewed from mmc certificates snap-in):
// 'Certificates - Current User' =>  'Trusted Root Certificate Authorities' ('ROOT') logical store => 'Registry' ('.Default') physical store
//
// When the service running in the context of LocalSystem account imports this PCA cert, the cert will go to (as viewed from mmc certificates snap-in):
// 'Certificates (Local Computer)' =>  'Trusted Root Certificate Authorities' ('ROOT') logical store => 'Registry' ('.Default') physical store
// and it will be also accessible from:
// 'Certificates - Current User' =>  'Trusted Root Certificate Authorities' ('ROOT') logical store => 'Local Computer' ('.LocalMachine') physical store
//
// To see physical store via mmc Certificates snap-in right-click in "Certificates (Local Computer)" => View => Options => check "Physical Store nodes"
// Additional info: http://www.mail-archive.com/wix-users@lists.sourceforge.net/msg22330.html


namespace rclient
{

    namespace ReseptBrokerService
    {
        // @nothrow
        void initLogger()
        {
            string myLogDir;
            try
            {
                myLogDir = ta::Process::getCommonAppDataDir() + "\\" + resept::CompanyName;
                if (!ta::isDirExist(myLogDir))
                    fs::create_directories(myLogDir);

                const string myLogFileName = str(boost::format("%s\\%s") % myLogDir % BrokerServiceLogName);
                const string myEnvInfo = str(boost::format("%s Client-%s %s (user: %s)") % resept::ProductName % toStr(rclient::ClientVersion) % BrokerServiceName % ta::getUserName());
                ta::LogConfiguration::Config myMemConfig;
                myMemConfig.fileAppender = true;
                myMemConfig.fileAppenderLogThreshold = ta::LogLevel::Debug;
                myMemConfig.fileAppenderLogFileName = myLogFileName;
                ta::LogConfiguration::instance().load(myMemConfig);
                PROLOG(myEnvInfo);
            }
            catch (...)
            {}
        }

        void deInitLogger()
        {
            EPILOG(boost::format("RESEPT Client-%s %s") % toStr(rclient::ClientVersion) % BrokerServiceName);
        }

        void tryRestoreFile(const string& aFrom, const string& aTo)
        {
            try
            {
                DEBUGLOG("Restoring " + aFrom + " to " + aTo);
                fs::copy_file(aFrom, aTo, fs::copy_option::overwrite_if_exists);
            }
            catch (std::exception& e)
            {
                WARNLOG2("Failed to restore " + aFrom + " to " + aTo + ". Tolerating.", e.what());
            }
        }

        void tryRestoreDir(const string& aFrom, const string& aTo)
        {
            try
            {
                WARNLOG("Restoring directory " + aFrom + " to " + aTo);
                fs::remove_all(aTo);
                ta::copyDir(aFrom, aTo);
            }
            catch (std::exception& e)
            {
                WARNLOG2("Failed to restore " + aFrom + " to " + aTo + ". Tolerating.", e.what());
            }
        }

        void tryRemoveProviderDirectoryWithRestore(const string& aProviderDir, const string& aProviderName)
        {
            ta::Process::ScopedDir providerDataBackupDir(ta::Process::genTempPath());
            ta::copyDir(aProviderDir, providerDataBackupDir.path + ta::getDirSep() + aProviderName);
            try
            {
                DEBUGLOG("Removing provider data at " + aProviderDir);
                fs::remove_all(aProviderDir);
            }
            catch (std::exception& e)
            {
                ERRORLOG2("Error occurred uninstalling configuration at " + aProviderDir + ". Restoring the original provider data", e.what());
                tryRestoreDir(providerDataBackupDir.path + ta::getDirSep() + aProviderName, aProviderDir);
                throw;
            }
        }

        // Try removing provider data from the specified dir, without removing the directory itself
        // tolerate all errors occurred during removal
        void tryRemoveProviderData(const string& aProviderDir)
        {
            DEBUGLOG("Remove provider data from " + aProviderDir + " without removing the directory itself");

            if (ta::isDirExist(aProviderDir))
            {
                fs::path dir(aProviderDir);
                for (fs::directory_iterator end_dir_it, it(dir); it!=end_dir_it; ++it)
                {
                    try
                    {
                        fs::remove_all(it->path());
                    }
                    catch (std::exception& e)
                    {
                        WARNLOG2("Failed to remove " + it->path().string() + ". Tolerating.", e.what());
                    }
                }
            }
        }

        //
        // Purpose:
        //   Sets the current service status and reports it to the SCM.
        //
        // Parameters:
        //   dwCurrentState - The current state (see SERVICE_STATUS)
        //   dwWin32ExitCode - The system error code
        //   dwWaitHint - Estimated time for pending operation, in milliseconds
        //
        // Return value:
        //   None
        //
        void reportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
        {
            static DWORD dwCheckPoint = 1;

            theServiceStatus.dwCurrentState = dwCurrentState;
            theServiceStatus.dwWin32ExitCode = dwWin32ExitCode;
            theServiceStatus.dwWaitHint = dwWaitHint;

            if (dwCurrentState == SERVICE_START_PENDING)
                theServiceStatus.dwControlsAccepted = 0;
            else
                theServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

            if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
                theServiceStatus.dwCheckPoint = 0;
            else
                theServiceStatus.dwCheckPoint = dwCheckPoint++;

            // Report the status of the service to the SCM.
            SetServiceStatus(theServiceStatusHandle, &theServiceStatus);
        }


        // Control handler function
        void ControlHandler(DWORD request)
        {
            switch (request)
            {
            case SERVICE_CONTROL_STOP:
                DEBUGLOG("Stopping due to stop request");
                reportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
                return;
            case SERVICE_CONTROL_SHUTDOWN:
                DEBUGLOG("Stopping due to shutdown");
                reportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
                return;
            default:
                break;
            }
        }

        TA_UNIQUE_PTR<ta::TcpServer> initService()
        {
            DEBUGLOG("Initializing...");
            TA_UNIQUE_PTR<ta::TcpServer> mySvr(new ta::TcpServer());
            unsigned int myListenPort = mySvr->listen("127.0.0.1");
            DEBUGLOG(boost::format("Listening on 127.0.0.1:%u") % myListenPort);
            rclient::Settings::setReseptBrokerServicePort(myListenPort);
            return mySvr;
        }

        bool findProviderForNameDifferInCaseOnly(const string& aProviderName, string& aProviderWithDifferentCaseName)
        {
            foreach(const string& provider, rclient::Settings::getProviders())
            {
                if (boost::iequals(provider, aProviderName) && provider != aProviderName)
                {
                    aProviderWithDifferentCaseName = provider;
                    return true;
                }
            }
            return false;
        }

        void installSettings(const InstallSettingsRequest& aRequest, ta::TcpClient& aConnection)
        {
            // Become user context-aware because broker service runs as system
            rclient::Settings::setUserConfigPath(aRequest.userConfigPath);

            const string myNewProviderName = aRequest.contentConfig.getProviderName();
            const int myNewContentVersion = aRequest.contentConfig.getContentVersion();

            // disallow messing up with reserved directories
            foreach(const std::string& reservedProviderName, resept::ReservedProviderNames)
            {
                if (boost::iequals(myNewProviderName, reservedProviderName))
                {
                    const string myUserErrorResponse = "Cannot install settings for provider " + myNewProviderName + " because this name is used by " + resept::ProductName + " for internal purposes.";
                    WARNLOG(myUserErrorResponse);
                    ta::proto::send(aConnection, Response(responseStatusUserError, myUserErrorResponse));
                    return;
                }
            }

            if (rclient::Settings::isCustomized())
            {
                string myProviderForNameDifferInCaseOnly;
                if (findProviderForNameDifferInCaseOnly(myNewProviderName, myProviderForNameDifferInCaseOnly))
                {
                    const string myUserErrorResponse = "Cannot install settings for provider " + myNewProviderName + " because it differs from the already installed settings for provider " + myProviderForNameDifferInCaseOnly + " in character case only.";
                    WARNLOG(myUserErrorResponse);
                    ta::proto::send(aConnection, Response(responseStatusUserError, myUserErrorResponse));
                    return;
                }

                // Ask for confirmation when downgrading settings
                if (ta::isElemExist(myNewProviderName, rclient::Settings::getProviders()))
                {
                    if (rclient::Settings::getProviderContentVersion(myNewProviderName) > myNewContentVersion)
                    {
                        const string myUserPrompt = "The version of the settings being installed for provider " + myNewProviderName + " is older than the version of the settings already installed. Are you sure you want to proceed?";
                        DEBUGLOG("The version of the settings being installed for provider " + myNewProviderName + " is older than the version of the settings already installed. Asking user for confirmation");
                        ta::proto::send(aConnection, Response(responseStatusConfirmation, myUserPrompt));
                        const bool myIsConfirmed = ta::proto::receive<bool>(aConnection);
                        DEBUGLOG(boost::format("User confirmed %s to overwrite settings with the older version") % (myIsConfirmed ? "" : "not"));
                        if (!myIsConfirmed)
                        {
                            return;
                        }
                    }
                }
            }

            ContentConfig::install(aRequest.contentConfig, aRequest.username);
        }

        void uninstallUserSettings(const UninstallSettingsRequest& aRequest)
        {
            DEBUGLOG("Uninstalling user settings for provider " + aRequest.provider);

            // Become user context-aware because broker service runs as system
            rclient::Settings::setUserConfigPath(aRequest.userConfigPath);

            if (!ta::isElemExist(aRequest.provider, rclient::Settings::getProviders()))
            {
                WARNLOG("Cannot uninstall settings for provider " + aRequest.provider + " because no such a provider installed.");
                return;
            }

            const string myReseptConfigPath = rclient::Settings::getReseptConfigPath();
            const string myProviderInstallDir = rclient::Settings::getProviderInstallDir(aRequest.provider);

            // Uninstall settings in transaction. Backup files first.
            //
            ta::Process::ScopedDir configBackupDir(ta::Process::genTempPath());
            fs::copy_file(aRequest.userConfigPath, configBackupDir.path + ta::getDirSep() + "user.ini", fs::copy_option::overwrite_if_exists);
            fs::copy_file(myReseptConfigPath, configBackupDir.path + ta::getDirSep() + "resept.ini", fs::copy_option::overwrite_if_exists);

            try
            {
                DEBUGLOG("Removing user settings for provider " + aRequest.provider + " at " + aRequest.userConfigPath);
                rclient::Settings::removeProviderFromUserConfig(aRequest.provider);

                try
                {
                    DEBUGLOG("Removing reference to the installed provider " + aRequest.provider + " from the installation registry at " + myReseptConfigPath);
                    rclient::Settings::removeInstalledProvider(aRequest.provider);

                    if (fs::exists(myProviderInstallDir))
                    {
                        foreach (const std::string& reservedProviderName, resept::ReservedProviderNames)
                        {
                            if (!boost::iequals(aRequest.provider, reservedProviderName))
                            {
                                tryRemoveProviderDirectoryWithRestore(myProviderInstallDir, aRequest.provider);
                            }
                            else
                            {
                                tryRemoveProviderData(myProviderInstallDir);
                            }
                        }
                    }
                    else
                    {
                        // We can land up here when e.g. pre-4.4.2 client installed two or more providers which names differ in character case only and then removed one of these providers. See #415
                        WARNLOG("Skip removal provider data because provider directory " + myProviderInstallDir + " does not exist");
                    }
                }
                catch (std::exception& e)
                {
                    ERRORLOG2("Error occurred uninstalling configuration. Restoring the original reference to the installed provider" + aRequest.provider, e.what());
                    tryRestoreFile(configBackupDir.path + ta::getDirSep() + "resept.ini", myReseptConfigPath);
                    throw;
                }
            }
            catch (std::exception& e)
            {
                ERRORLOG2("Error occurred uninstalling configuration. Restoring the original user settings for provider " + aRequest.provider, e.what());
                tryRestoreFile(configBackupDir.path + ta::getDirSep() + "user.ini", aRequest.userConfigPath);
                throw;
            }

            // success!

            //@note we do not remove CAs because they can be used by other users. They will be removed during uninstall anyway.
        }

#ifdef _WIN32
        time_t FileTimeToUnixTime(const LARGE_INTEGER &ltime)
        {
            FILETIME filetime, localfiletime;
            SYSTEMTIME systime;
            struct tm utime;
            filetime.dwLowDateTime = ltime.LowPart;
            filetime.dwHighDateTime = ltime.HighPart;
            FileTimeToLocalFileTime(&filetime, &localfiletime);
            FileTimeToSystemTime(&localfiletime, &systime);
            utime.tm_sec = systime.wSecond;
            utime.tm_min = systime.wMinute;
            utime.tm_hour = systime.wHour;
            utime.tm_mday = systime.wDay;
            utime.tm_mon = systime.wMonth - 1;
            utime.tm_year = systime.wYear - 1900;
            utime.tm_isdst = -1;
            return(mktime(&utime));
        }

        std::string toMbyte(const UNICODE_STRING& aWstr)
        {
            const std::wstring wstr(aWstr.Buffer, aWstr.Length / sizeof(WCHAR));
            return ta::Strings::toMbyte(wstr);
        }

        KerberosExternalTicket::KerberosExternalName makeKerberosExternalName(const PKERB_EXTERNAL_NAME anExternalName)
        {
            if (!anExternalName)
            {
                TA_THROW_MSG(std::invalid_argument, "KERB_EXTERNAL_NAME is NULL");
            }
            KerberosExternalTicket::KerberosExternalName myExternalNameStruct;
            myExternalNameStruct.nameType = anExternalName->NameType;
            myExternalNameStruct.nameCount = anExternalName->NameCount;
            for (int iName = 0; iName < anExternalName->NameCount; ++iName)
            {
                myExternalNameStruct.names.push_back(toMbyte(anExternalName->Names[iName]));
            }
            return myExternalNameStruct;
        }

        void validateKerberosExternalTicket(const KERB_EXTERNAL_TICKET& aTicket)
        {
            if (!aTicket.ServiceName)
            {
                TA_THROW_MSG(std::runtime_error, " Mandatory ServiceName is missing in Kerberos External Ticket");
            }
            if (!aTicket.ClientName)
            {
                TA_THROW_MSG(std::runtime_error, "Mandatory ClientName is missing in Kerberos External Ticket");
            }
            if (aTicket.SessionKey.Length == 0)
            {
                TA_THROW_MSG(std::runtime_error, "Kerberos External Ticket Session Key is empty");
            }
            else
            {
                bool myAllZeroSessionKey = true;
                for (size_t i = 0; i < aTicket.SessionKey.Length; ++i)
                {
                    if (aTicket.SessionKey.Value[i] != '\x0')
                    {
                        myAllZeroSessionKey = false;
                        break;
                    }
                }
                if (myAllZeroSessionKey)
                {
                    TA_THROW_MSG(std::runtime_error, "Kerberos External Ticket Session key is all-zero. Possible cause: TGT was retrieved without SSPI permissions");
                }
            }
        }

        KerberosExternalTicket makeKerberosExternalTicket(const KERB_EXTERNAL_TICKET& aTicket)
        {
            KerberosExternalTicket myTicket;
            myTicket.serviceNames = makeKerberosExternalName(aTicket.ServiceName);
            myTicket.clientNames = makeKerberosExternalName(aTicket.ClientName);
            if (aTicket.TargetName)
                myTicket.targetNames = makeKerberosExternalName(aTicket.TargetName);

            myTicket.domainName = toMbyte(aTicket.DomainName);
            myTicket.targetDomainName = toMbyte(aTicket.TargetDomainName);
            myTicket.altTargetDomainName = toMbyte(aTicket.AltTargetDomainName);

            KerberosExternalTicket::KerberosCryptoKey myCryptoKey;
            myCryptoKey.keyType = aTicket.SessionKey.KeyType;
            myCryptoKey.length = aTicket.SessionKey.Length;
            myCryptoKey.value = std::vector<unsigned char>(aTicket.SessionKey.Value, aTicket.SessionKey.Value + aTicket.SessionKey.Length);
            myTicket.sessionKey = myCryptoKey;

            myTicket.ticketFlags = aTicket.TicketFlags;
            myTicket.flags = aTicket.Flags;
            myTicket.keyExpirationTime = FileTimeToUnixTime(aTicket.KeyExpirationTime);
            myTicket.startTime = FileTimeToUnixTime(aTicket.StartTime);
            myTicket.endTime = FileTimeToUnixTime(aTicket.EndTime);
            myTicket.renewUntil = FileTimeToUnixTime(aTicket.RenewUntil);
            myTicket.timeSkew = FileTimeToUnixTime(aTicket.TimeSkew);
            myTicket.encodedTicketSize = aTicket.EncodedTicketSize;
            if (aTicket.EncodedTicket)
                myTicket.encodedTicket = std::vector<unsigned char>(aTicket.EncodedTicket, aTicket.EncodedTicket + aTicket.EncodedTicketSize);

            return myTicket;
        }

        PKERB_RETRIEVE_TKT_RESPONSE requestKerberosTkt(const LUID& aLogonId)
        {
            HANDLE logon_handle = NULL;
            NTSTATUS status = LsaConnectUntrusted(&logon_handle);
            if (FAILED(status)) {
                TA_THROW_MSG(std::runtime_error, boost::format("LsaConnectUntrusted failed with %d") % status);
            }

            LSA_STRING lsa_name;
            lsa_name.Buffer = MICROSOFT_KERBEROS_NAME_A;
            lsa_name.Length = (unsigned short)strlen(lsa_name.Buffer);
            lsa_name.MaximumLength = lsa_name.Length + 1;

            ULONG package_id = 0;
            status = LsaLookupAuthenticationPackage(
                         logon_handle,
                         &lsa_name,
                         &package_id
                     );
            if (FAILED(status)) {
                TA_THROW_MSG(std::runtime_error, boost::format("LsaLookupAuthenticationPackage failed with %d") % status);
            }

            NTSTATUS sub_status = 0;
            KERB_RETRIEVE_TKT_REQUEST req = {};
            PKERB_RETRIEVE_TKT_RESPONSE pTicketResponse = NULL;
            req.MessageType = KerbRetrieveTicketMessage;
            req.LogonId = aLogonId;
            req.TargetName.Buffer = L"";
            req.TargetName.Length = 0;
            req.TargetName.MaximumLength = req.TargetName.Length;
            req.TicketFlags = 0;
            req.CacheOptions = 0;
            req.EncryptionType = KERB_ETYPE_NULL;
            ULONG ReturnBufferLength = 0;

            status = LsaCallAuthenticationPackage(
                         logon_handle,
                         package_id,
                         &req,
                         sizeof(req),
                         (PVOID*)&pTicketResponse,
                         &ReturnBufferLength,
                         &sub_status
                     );

            if (FAILED(status) || FAILED(sub_status))
            {
                TA_THROW_MSG(std::runtime_error, boost::format("LsaCallAuthenticationPackage failed with status %d and substatus: 0x%x") % status % sub_status);
            }
            return pTicketResponse;
        }

        KerberosExternalTicket getKerberosTgt(const KerberosTgtRequest& aRequest)
        {
            LUID myLogonId = { 0 };
            myLogonId.HighPart = aRequest.logonIdHighPart;
            myLogonId.LowPart = aRequest.logonIdLowPart;

            PKERB_RETRIEVE_TKT_RESPONSE myTicketResponse = requestKerberosTkt(myLogonId);
            if (!myTicketResponse)
            {
                TA_THROW_MSG(std::runtime_error, "Failed to get Ticket Response from requestKerberosTkt, reason: Ticket Response is NULL");
            }
            ta::ScopedResource<PKERB_RETRIEVE_TKT_RESPONSE> myScopedTicketResponse(myTicketResponse, LsaFreeReturnBuffer);

            const KERB_EXTERNAL_TICKET ticket = myTicketResponse->Ticket;
            validateKerberosExternalTicket(ticket);
            return makeKerberosExternalTicket(ticket);
        }
#else
        KerberosExternalTicket getKerberosTgt(const KerberosTgtRequest& aRequest)
        {
            TA_THROW_MSG(std::runtime_error, "getKerberosTgt is not supported on Linux");
        }
#endif

        void doServiceMain(int UNUSED(argc), char** UNUSED(argv))
        {
            theServiceStatusHandle = ::RegisterServiceCtrlHandler(BrokerServiceName.c_str(), (LPHANDLER_FUNCTION)ControlHandler);
            if (theServiceStatusHandle == (SERVICE_STATUS_HANDLE)0)
            {
                ERRORLOG2("Error registering service", boost::format("RegisterServiceCtrlHandler failed. LastError: %d") % ::GetLastError());
                return;
            }

            theServiceStatus.dwServiceType = SERVICE_WIN32;
            theServiceStatus.dwCurrentState = SERVICE_START_PENDING;
            theServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
            theServiceStatus.dwWin32ExitCode = 0;
            theServiceStatus.dwServiceSpecificExitCode = 0;
            theServiceStatus.dwCheckPoint = 0;
            theServiceStatus.dwWaitHint = 0;

            reportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 50);

            try
            {
                TA_UNIQUE_PTR<ta::TcpServer> mySvr = initService();
                reportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);

                // The worker loop
                while (theServiceStatus.dwCurrentState == SERVICE_RUNNING)
                {
                    TA_UNIQUE_PTR<ta::TcpClient> myConnection;
                    try
                    {
                        myConnection = mySvr->accept(AcceptTimeout);
                        DEBUGLOG("Incoming connection");
                        const RequestType myReqType = ta::proto::receive<RequestType>(*myConnection);
                        switch (myReqType)
                        {
                        case requestInstallSettings:
                        {
                            DEBUGLOG("Incoming request to install settings");
                            const InstallSettingsRequest myRequest = ta::proto::receive<InstallSettingsRequest>(*myConnection);
                            installSettings(myRequest, *myConnection);
                            ta::proto::send(*myConnection, Response(responseStatusOk));
                            break;
                        }
                        case requestUninstallSettings:
                        {
                            DEBUGLOG("Incoming request to uninstall user settings");
                            const UninstallSettingsRequest myRequest = ta::proto::receive<UninstallSettingsRequest>(*myConnection);
                            uninstallUserSettings(myRequest);
                            ta::proto::send(*myConnection, Response(responseStatusOk));
                            break;
                        }
                        case requestKerberosTgt:
                        {
                            DEBUGLOG("Incoming request to get Kerberos Ticket Granting Ticket (TGT)");
                            const KerberosTgtRequest myRequest = ta::proto::receive<KerberosTgtRequest>(*myConnection);
                            try
                            {
                                const KerberosExternalTicket tgt = getKerberosTgt(myRequest);
                                DEBUGLOG(boost::format("Got Kerberos TGT with tgt %s") % str(tgt));
                                ta::proto::send(*myConnection, KerberosTgtResponse(responseStatusOk, tgt));
                                break;
                            }
                            catch (std::exception& ex)
                            {
                                DEBUGLOG(boost::format("Unable to get Kerberos TGT with exception: %s") % ex.what());
                                ta::proto::send(*myConnection, KerberosTgtResponse(responseStatusError, KerberosExternalTicket()));
                                break;
                            }
                        }
                        default:
                            WARNLOG(boost::format("Unsupported request %d") % myReqType);
                            break;
                        }
                    }
                    catch (ta::TcpServerConnectionTimedOut&)
                    {
                        // just check if we need to stop and go on
                        continue;
                    }
                    catch (std::exception& e)
                    {
                        ERRORLOG2("ReseptBrokerService error", e.what());
                        if (myConnection.get())
                        {
                            try { ta::proto::send(*myConnection, Response(responseStatusError, e.what())); }
                            catch (std::exception& e) { ERRORLOG2("ReseptBrokerService error", e.what()); }
                        }
                    }
                    DEBUGLOG("Done with this connection");
                } // worker loop

                reportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
            }
            catch (std::exception& e)
            {
                ERRORLOG2("ReseptBrokerService error", e.what());
            }
            catch (...)
            {
                ERRORLOG("Unexpected error");
            }
            reportSvcStatus(SERVICE_STOPPED, (DWORD)-1, 0);
        }


        void ServiceMain(int argc, char** argv)
        {
            initLogger();
            doServiceMain(argc, argv);
            deInitLogger();
        }

    }
}

void main()
{
    static std::vector<char> myReseptBrokerServiceName(rclient::BrokerServiceName.length()+ 1);
    strcpy(&myReseptBrokerServiceName[0], rclient::BrokerServiceName.c_str());
    SERVICE_TABLE_ENTRY DispatchTable[] =
    {
        { &myReseptBrokerServiceName[0], (LPSERVICE_MAIN_FUNCTION)rclient::ReseptBrokerService::ServiceMain },
        { NULL, NULL }
    };
    StartServiceCtrlDispatcher(DispatchTable);
}



