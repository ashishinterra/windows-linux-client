#ifdef _WIN32
#include "KerberosAuthenticator.h"
#include "CommonUtils.h"
#include "rclient/IReseptBrokerService.h"
#include "rclient/Settings.h"
#include "rclient/RcdpHandler.h"
#include "rclient/NativeCertStore.h"
#include "resept/util.h"
#include "ta/logger.h"
#include "ta/url.h"
#include "ta/encodingutils.h"
#include "ta/timeutils.h"
#include "ta/proto.hpp"
#include "ta/osuserinfo.h"
#include "ta/process.h"
#include "boost/filesystem/operations.hpp"

using std::string;
using namespace resept::rcdpv2;
using boost::assign::map_list_of;

namespace rclient
{
    namespace KerberosAuthenticator
    {
        using namespace ReseptBrokerService;
        namespace
        {
            static const string TicketPath = ta::Process::getTempDir() + "\\tgt.ticket";

            /**
            *   We're cachcing the TGT to attempt to prevent the client from showing up when the TGT is temporarily inaccessible.
            *   We noticed the TGT becoming inaccessible at various points during testing and do not know what causes it.
            *   Caching the ticket would make it possible to bridge the gaps in time where the TGT is unavailable through the Windows API.
            */
            bool getCachedTicket(KerberosExternalTicket& aTicket)
            {
                WARNDEVLOG("Attempting to acquire cached TGT");
                try
                {
                    if (!ta::isFileExist(TicketPath))
                    {
                        return false;
                    }
                    const KerberosExternalTicket myTicket = ta::boost_deserialize<KerberosExternalTicket>(ta::readData(TicketPath));
                    if (myTicket.endTime > time(NULL))
                    {
                        WARNDEVLOG("Returning a valid cached TGT (valid based on expiration)");
                        aTicket = myTicket;
                        return true;
                    }
                }
                catch (const std::exception& ex)
                {
                    WARNDEVLOG(boost::format("Getting cached ticket failed with error: %s") % ex.what());
                }
                return false;
            }

            void cacheTicket(const KerberosExternalTicket& aTicket)
            {
                try
                {
                    ta::writeData(TicketPath, ta::boost_serialize(aTicket));
                }
                catch (const std::exception& ex)
                {
                    WARNDEVLOG(boost::format("Caching ticket failed with error: %s") % ex.what());
                }
            }

            void removeCacheTicket()
            {
                try
                {
                    if (ta::isFileExist(TicketPath))
                    {
                        boost::filesystem::remove(TicketPath);
                    }
                }
                catch (const std::exception& ex)
                {
                    WARNDEVLOG(boost::format("Removing cached ticket failed with error: %s") % ex.what());
                }
            }

            resept::Credentials makeCredentials(const AuthRequirements& anAuthReqs, const string& aClientName)
            {
                resept::Credentials myRetVal;

                foreach(const resept::CredentialType cred_type, anAuthReqs.cred_types)
                {
                    if (cred_type == resept::credUserId)
                    {
                        myRetVal.push_back(resept::Credential(resept::credUserId, aClientName));
                    }
                    else if (cred_type == resept::credHwSig)
                    {
                        const string myHwsig = calcHwsig(anAuthReqs.hwsig_formula);
                        myRetVal.push_back(resept::Credential(resept::credHwSig, myHwsig));
                    }
                }

                return myRetVal;
            }

            // Create server compatible version of ClientName in format [clientNames@domainName]
            string createClientPrincipal(const KerberosExternalTicket& aTicket)
            {
                return str(boost::format("%s@%s") % str(aTicket.clientNames) % aTicket.domainName);
            }

            string createRequestJson(const KerberosExternalTicket& aTicket)
            {
                ta::StringDict myKerberosTicket =
                    map_list_of(requestParamNameKerberosTicketClientPrincipal, createClientPrincipal(aTicket))
                    (requestParamNameKerberosTicketSessionKey, ta::EncodingUtils::toBase64(aTicket.sessionKey.value, true))
                    (requestParamNameKerberosTicketSessionKeyEncoding, boost::lexical_cast<std::string>(aTicket.sessionKey.keyType))
                    (requestParamNameKerberosTicketTgt, ta::EncodingUtils::toBase64(aTicket.encodedTicket, true))
                    (requestParamNameKerberosTicketTgtFlags, boost::lexical_cast<std::string>(aTicket.ticketFlags))
                    (requestParamNameKerberosTicketStartTime, ta::TimeUtils::timestampToIso8601(aTicket.startTime))
                    (requestParamNameKerberosTicketEndTime, ta::TimeUtils::timestampToIso8601(aTicket.endTime))
                    (requestParamNameKerberosTicketRenewTill, ta::TimeUtils::timestampToIso8601(aTicket.renewUntil));
                return ta::EncodingUtils::toJson(myKerberosTicket);
            }


            bool requestCertificate(RcdpHandler& anRdcpClient)
            {
                const resept::CertFormat myCertFormat = Settings::getCertFormat();
                const bool myWithChain = Settings::isCertChain();
                const CertResponse myCertResponse = anRdcpClient.getCert(myCertFormat, myWithChain);

                // Import/save certificate
                if (myCertFormat == resept::certformatP12)
                {
                    const Pfx myPfx(myCertResponse.cert, myCertResponse.password);
                    NativeCertStore::importPfx(myPfx);
                    return true;
                }
                else if (myCertFormat == resept::certformatPem)
                {
                    const string mySavedPemPath = ta::Process::getTempDir() + SavedPemName;
                    const string mySavedPemKeyPasswdPath = ta::Process::getTempDir() + SavedPemKeyPasswdName;
                    ta::writeData(mySavedPemPath, myCertResponse.cert);
                    ta::writeData(mySavedPemKeyPasswdPath, myCertResponse.password);
                    DEBUGLOG(boost::format("PEM has been saved to %s, private key password has been saved to %s") % mySavedPemPath % mySavedPemKeyPasswdPath);
                    return true;
                }
                else
                {
                    ERRORLOG(boost::format("Unsupported certificate format in settings: %d") % myCertFormat);
                }
                return false;
            }
        }

        AuthResponse authenticate(const KerberosExternalTicket& aTicket, RcdpHandler& anRcdpClient)
        {
            const string myService = Settings::getLatestService();
            const AuthRequirements myAuthReqs = anRcdpClient.getAuthRequirements(myService);
            return anRcdpClient.authenticate(myService,
                                             makeCredentials(myAuthReqs, str(aTicket.clientNames)),
                                             resolveURIs(myAuthReqs),
                                             calcDigests(myAuthReqs),
                                             createRequestJson(aTicket));
        }

        /**
        * Authenticate using Kerberos and request & install certificate after successful authentication
        * TGT is requested from the ReseptBrokerService
        * Results are divided in successful process (success), Kerberos related issues (kerberosFailure) and other server related issues (auth***) and 'other' (defaultFailure)
        * Catching exceptions is the responsibility of the caller
        */
        Result authenticateAndInstall(int& aDelaySec)
        {
            // Get LogonId
            const ta::OsUserInfo::UserLogonId myLogonId = ta::OsUserInfo::getCurrentUserLogonId();
            if (myLogonId.lowPart <= 0)
            {
                ERRORLOG(boost::format("User Logon Id is invalid with Higher part %i and Lower part %i") % myLogonId.highPart % myLogonId.lowPart);
                return Result::kerberosFailure;
            }

            const unsigned int myReseptBrokerServicePort = rclient::Settings::getReseptBrokerServicePort();
            ta::TcpClient myBrokerServiceConnection;
            myBrokerServiceConnection.open("127.0.0.1", myReseptBrokerServicePort);

            // Request TGT from ReseptBrokerService
            const string myUserConfigPath = rclient::Settings::getUserConfigPath();
            ta::proto::send(myBrokerServiceConnection, requestKerberosTgt);
            ta::proto::send(myBrokerServiceConnection, KerberosTgtRequest(myLogonId.highPart, myLogonId.lowPart));

            KerberosExternalTicket myTgt;
            const KerberosTgtResponse myResponse = ta::proto::receive<KerberosTgtResponse>(myBrokerServiceConnection);
            switch (myResponse.status)
            {
            case responseStatusOk:
                DEBUGDEVLOG("Successfully got TGT");
                myTgt = myResponse.tgt;
                break;
            case responseStatusConfirmation:
            case responseStatusUserError:
            case responseStatusError:
                if (!getCachedTicket(myTgt))
                {
                    WARNLOG("Could not get TGT");
                    return Result::kerberosFailure;
                }
            default:
                TA_THROW_MSG(std::exception, boost::format("Unsupported response status for status %d") % myResponse.status);
                break;
            }

            // Authenticate using acquired TGT
            const ta::NetUtils::RemoteAddress mySvr = Settings::getReseptSvrAddress();
            RcdpHandler myRcdpClient = RcdpHandler(mySvr);
            myRcdpClient.hello();
            myRcdpClient.handshake();
            const AuthResponse myAuthResponse = authenticate(myTgt, myRcdpClient);

            switch (myAuthResponse.auth_result.type)
            {
            case resept::AuthResult::Ok:
                cacheTicket(myTgt);
                break;
            case resept::AuthResult::KerberosAuthNok:
                ERRORLOG(boost::format("Could not authenticate using Kerberos TGT: %s") % str(myTgt));
                removeCacheTicket();
                return Result::kerberosFailure;
            case resept::AuthResult::Locked:
                if (myAuthResponse.auth_result.delay > 0)
                {
                    aDelaySec = myAuthResponse.auth_result.delay;
                    WARNLOG(boost::format("Kerberos Authentication locked for another %i seconds") % aDelaySec);
                    return Result::authLockedWithDelay;
                }
                else
                {
                    ERRORLOG("Could not authenticate using Kerberos because the user account is locked");
                    return Result::authPermanentlyLocked;
                }
            case resept::AuthResult::Delay:
                ERRORLOG(boost::format("User account is delayed because of invalid credentials for %i seconds.") % myAuthResponse.auth_result.delay);
                return Result::authDelay;
            default:
                ERRORLOG(boost::format("Could not authenticate using Kerberos for unspecified reasons with authResponse: %s") % str(myAuthResponse.auth_result.type));
                return Result::defaultFailure;
            }

            // Request & install certificate
            if (!requestCertificate(myRcdpClient))
            {
                ERRORLOG("Could not request certificate with Kerberos authenticated RcdpClient");
                return Result::defaultFailure;
            }
            return Result::success;
        }
    } // end KerberosAuthenticator
} // end rclient
#endif
