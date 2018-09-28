#pragma once

#include "rclient/ContentConfig.h"
#include "ta/utils.h"
#include "ta/timeutils.h"
#include <string>
#include <vector>
#include <sstream>

namespace rclient
{
    namespace ReseptBrokerService
    {
        struct KerberosExternalTicket
        {
            struct KerberosCryptoKey
            {
                KerberosCryptoKey() : keyType(0), length(0) {};
                KerberosCryptoKey(
                    const long aKeyType,
                    const unsigned long aLength,
                    const std::vector<unsigned char>& aValue
                ) :
                    keyType(aKeyType),
                    length(aLength),
                    value(aValue)
                {};

                long keyType;
                unsigned long length;
                std::vector<unsigned char> value;
            };

            struct KerberosExternalName
            {
                KerberosExternalName() : nameType(0), nameCount(0) {};
                KerberosExternalName(
                    const short aNameType,
                    const unsigned short aNameCount,
                    const std::vector<std::string>& aNames
                ) :
                    nameType(aNameType),
                    nameCount(aNameCount),
                    names(aNames) {};

                short nameType;
                unsigned short nameCount;
                std::vector<std::string> names;
            };

            KerberosExternalTicket() :
                ticketFlags(0),
                flags(0),
                keyExpirationTime(0),
                startTime(0),
                endTime(0),
                renewUntil(0),
                timeSkew(0),
                encodedTicketSize(0)
            {};
            KerberosExternalTicket(
                const KerberosExternalName& aServiceNames,
                const KerberosExternalName& aTargetNames,
                const KerberosExternalName& aClientNames,
                const std::string& aDomainName,
                const std::string& aTargetDomainName,
                const std::string& anAltTargetDomainName,
                const KerberosCryptoKey& aSessionKey,
                const unsigned long aTicketFlags,
                const unsigned long aFlags,
                const time_t aKeyExpirationTime,
                const time_t aStartTime,
                const time_t anEndTime,
                const time_t aRenewUntil,
                const time_t aTimeSkew,
                const unsigned long anEncodedTicketSize,
                const std::vector<unsigned char>& anEncodedTicket
            ) :
                serviceNames(aServiceNames),
                targetNames(aTargetNames),
                clientNames(aClientNames),
                domainName(aDomainName),
                targetDomainName(aTargetDomainName),
                altTargetDomainName(anAltTargetDomainName),
                sessionKey(aSessionKey),
                ticketFlags(aTicketFlags),
                flags(aFlags),
                keyExpirationTime(aKeyExpirationTime),
                startTime(aStartTime),
                endTime(anEndTime),
                renewUntil(aRenewUntil),
                timeSkew(aTimeSkew),
                encodedTicketSize(anEncodedTicketSize),
                encodedTicket(anEncodedTicket)
            {};

            KerberosExternalName serviceNames;
            KerberosExternalName targetNames;
            KerberosExternalName clientNames;
            std::string domainName;
            std::string targetDomainName;
            std::string altTargetDomainName;

            KerberosCryptoKey sessionKey;

            unsigned long ticketFlags;
            unsigned long flags;
            time_t keyExpirationTime;
            time_t startTime;
            time_t endTime;
            time_t renewUntil;
            time_t timeSkew;
            unsigned long encodedTicketSize;
            std::vector<unsigned char> encodedTicket;
        };

        inline std::string str(const KerberosExternalTicket::KerberosCryptoKey& aKey)
        {
            return str(boost::format("CryptoKey with size %i") % aKey.length);
        }
        inline std::string str(const KerberosExternalTicket::KerberosExternalName& aName)
        {
            return boost::algorithm::join(aName.names, "/");
        }
        inline std::string str(const KerberosExternalTicket& aTicket)
        {
            return str(boost::format("Kerberos External Ticket for user %s for service %s with Ticket Size %i StartTime %s and EndTime %s")
                       % str(aTicket.clientNames)
                       % str(aTicket.serviceNames)
                       % aTicket.encodedTicketSize
                       % ta::TimeUtils::timestampToIso8601(aTicket.startTime)
                       % ta::TimeUtils::timestampToIso8601(aTicket.endTime));
        }

        enum RequestType
        {
            requestInstallSettings,
            requestUninstallSettings,
            requestKerberosTgt
        };
        struct InstallSettingsRequest
        {
            InstallSettingsRequest() {}
            InstallSettingsRequest(const rclient::ContentConfig::Config& aContentConfig, const std::string& aUserConfigPath, const std::string& aUsername):
                contentConfig(aContentConfig), userConfigPath(aUserConfigPath), username(aUsername) {};
            rclient::ContentConfig::Config contentConfig;
            std::string userConfigPath;
            std::string username;
        };

        struct UninstallSettingsRequest
        {
            UninstallSettingsRequest() {}
            UninstallSettingsRequest(const std::string& aProvider, const std::string& aUserConfigPath): provider(aProvider), userConfigPath(aUserConfigPath) {};
            std::string provider;
            std::string userConfigPath;
        };

        struct KerberosTgtRequest
        {
            KerberosTgtRequest() {}
            KerberosTgtRequest(const long aLogonIdHighPart, const long aLogonIdLowPart) : logonIdHighPart(aLogonIdHighPart), logonIdLowPart(aLogonIdLowPart) {};
            long logonIdHighPart;
            long logonIdLowPart;
        };

        enum ResponseStatus
        {
            responseStatusOk,
            responseStatusError,
            responseStatusUserError,
            responseStatusConfirmation
        };
        struct Response
        {
            Response(): status(responseStatusOk) {}
            Response(ResponseStatus aStatus, const std::string& aText = ""): status(aStatus), text(aText) {}
            ResponseStatus status;
            std::string text; // if status is statusError, text is a developer-oriented error message. if status is statusConfirmation, text is a user confirmation prompt
        };

        struct KerberosTgtResponse
        {
            KerberosTgtResponse(): status(responseStatusOk) {}
            KerberosTgtResponse(ResponseStatus aStatus, const KerberosExternalTicket& aTgt) : status(aStatus), tgt(aTgt) {};
            ResponseStatus status;
            KerberosExternalTicket tgt;
        };
    }
}

namespace boost
{
    namespace serialization
    {
        template<class Archive>
        void serialize(Archive& ar, rclient::ReseptBrokerService::KerberosExternalTicket::KerberosCryptoKey& aKey, const unsigned int UNUSED(version))
        {
            ar & aKey.keyType;
            ar & aKey.length;
            ar & aKey.value;
        }
        template<class Archive>
        void serialize(Archive& ar, rclient::ReseptBrokerService::KerberosExternalTicket::KerberosExternalName& aName, const unsigned int UNUSED(version))
        {
            ar & aName.nameType;
            ar & aName.nameCount;
            ar & aName.names;
        }
        template<class Archive>
        void serialize(Archive& ar, rclient::ReseptBrokerService::KerberosExternalTicket& aTicket, const unsigned int UNUSED(version))
        {
            ar & aTicket.serviceNames;
            ar & aTicket.targetNames;
            ar & aTicket.clientNames;

            ar & aTicket.domainName;
            ar & aTicket.targetDomainName;
            ar & aTicket.altTargetDomainName;

            ar & aTicket.sessionKey;

            ar & aTicket.ticketFlags;
            ar & aTicket.flags;
            ar & aTicket.keyExpirationTime;
            ar & aTicket.startTime;
            ar & aTicket.endTime;
            ar & aTicket.renewUntil;
            ar & aTicket.timeSkew;
            ar & aTicket.encodedTicketSize;
            ar & aTicket.encodedTicket;
        }

        template<class Archive>
        void serialize(Archive& ar, rclient::ReseptBrokerService::InstallSettingsRequest& aRequest, const unsigned int UNUSED(version))
        {
            ar & aRequest.contentConfig;
            ar & aRequest.userConfigPath;
            ar & aRequest.username;
        }

        template<class Archive>
        void serialize(Archive& ar, rclient::ReseptBrokerService::UninstallSettingsRequest& aRequest, const unsigned int UNUSED(version))
        {
            ar & aRequest.provider;
            ar & aRequest.userConfigPath;
        }

        template<class Archive>
        void serialize(Archive& ar, rclient::ReseptBrokerService::KerberosTgtRequest& aRequest, const unsigned int UNUSED(version))
        {
            ar & aRequest.logonIdHighPart;
            ar & aRequest.logonIdLowPart;
        }

        template<class Archive>
        void serialize(Archive& ar, rclient::ReseptBrokerService::Response& aResponse, const unsigned int UNUSED(version))
        {
            ar & aResponse.status;
            ar & aResponse.text;
        }

        template<class Archive>
        void serialize(Archive& ar, rclient::ReseptBrokerService::KerberosTgtResponse& aResponse, const unsigned int UNUSED(version))
        {
            ar & aResponse.status;
            ar & aResponse.tgt;
        }
    }
}
