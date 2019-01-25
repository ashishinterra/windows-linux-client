#pragma once

#include "resept/common.h"
#include "ta/logger.h"
#include "ta/logconfiguration.h"
#include "ta/netutils.h"
#include "ta/certutils.h"

#include <string>
#include <vector>
#include <stdexcept>

namespace rclient
{
    struct SettingsError : std::runtime_error
    {
        explicit SettingsError(const std::string& aMessage = "") : std::runtime_error(aMessage) {}
    };

    struct SettingsOpenError : SettingsError
    {
        explicit SettingsOpenError(const std::string& aMessage = "") : SettingsError(aMessage) {}
    };

    struct SettingsOpenParseError : SettingsOpenError
    {
    public:
        SettingsOpenParseError(const std::string& aMessage, int aLineNumber) : SettingsOpenError(aMessage)
        {
            lineNumber = aLineNumber;
        }

        int getLineNumber() const
        {
            return lineNumber;
        }

    private:
        int lineNumber;
    };

    struct SettingsSaveError : SettingsError
    {
        explicit SettingsSaveError(const std::string& aMessage = "") : SettingsError(aMessage) {}
    };

    namespace Settings
    {
        static const char ReseptConfigFileName[]  =        "resept.ini";
        static const char MasterConfigFileName[]  =        "master.ini";
        static const char MasterYamlConfigFileName[] =     "master.yaml";
        static const char UserConfigFileName[]    =        "user.ini";
        static const char UserYamlConfigFileName[] =       "user.yaml";

        enum CertificateValidityType
        {
            _firstCertValidityType = 0,
            certValidityTypePercentage = _firstCertValidityType,
            certValidityTypeDuration,
            _lastCertValidityType = certValidityTypeDuration
        };
        // Mapped pair contains <name, suffix>
        const std::map<CertificateValidityType, boost::tuple<std::string, std::string> > CertValidityTypeStrings = boost::assign::map_list_of
                (certValidityTypePercentage, boost::make_tuple(std::string("Percentage"), std::string("%")))
                (certValidityTypeDuration, boost::make_tuple(std::string("Duration"), std::string("s")));

        inline bool isCertValidityType(int aVal)
        {
            return (aVal >= _firstCertValidityType && aVal <= _lastCertValidityType);
        }
        inline std::string name(CertificateValidityType aCertValidityType)
        {
            if (!isCertValidityType(static_cast<int>(aCertValidityType)))
            {
                TA_THROW_MSG(std::invalid_argument, str(boost::format("Cannot get name for unknown CertValidityType %d") % aCertValidityType));
            }
            return ta::getValueByKey(aCertValidityType, CertValidityTypeStrings).get<0>();
        }
        inline std::string suffix(CertificateValidityType aCertValidityType)
        {
            if (!isCertValidityType(static_cast<int>(aCertValidityType)))
            {
                TA_THROW_MSG(std::invalid_argument, str(boost::format("Cannot get suffix for unknown CertValidityType %d") % aCertValidityType));
            }
            return ta::getValueByKey(aCertValidityType, CertValidityTypeStrings).get<1>();
        }
        inline bool nameToCertificateValidityType(const std::string& aCertValidityTypeStr, CertificateValidityType& aCertValidityType)
        {
            for (int typ = _firstCertValidityType; typ <= _lastCertValidityType; ++typ)
            {
                CertificateValidityType myType = static_cast<CertificateValidityType>(typ);
                if (name(myType) == aCertValidityTypeStr)
                {
                    aCertValidityType = myType;
                    return true;
                }
            }
            return false;
        }

        typedef std::vector<std::string> Users;

        // Setting defaults
        static const unsigned int DefRcdpV1Port        = 80;
        static const unsigned int DefRcdpV2Port        = 443;
        static const CertificateValidityType DefCertValidityType = certValidityTypeDuration;
        static const unsigned int DefCertValidPercent  = 10; // @todo tim To be fased out
        static const unsigned int DefCertValidityPercentage = 10;
        static const bool DefIsCertChain               = false;
        static const resept::CertFormat DefCertFormat  = resept::certformatP12;
        static const std::string DefLogLevel           = str(ta::LogLevel::Debug); // it is important to have some default for log level in order KeyTalk app can start&complain regardless messed up configuration
        static const bool DefServiceDisplayName       = true;
        static const bool DefServiceCleanupUserCert   = false;
        static const bool DefServiceUseClientOsLogonUser = true;

        struct CertValidity
        {
            CertValidity() : type(DefCertValidityType), value(DefCertValidityType == certValidityTypeDuration ? 0 : DefCertValidityPercentage)
            {}
            CertValidity(const CertificateValidityType aType, const unsigned int aValue)
                : type(aType), value(aValue)
            {}

            inline std::string str() const {
                return boost::str(boost::format("%d%s") % value % suffix(type));
            }

            inline bool operator==(const CertValidity& rhs)
            {
                return (type == rhs.type && value == rhs.value);
            }

            CertificateValidityType type;
            unsigned int value;
        };

        CertValidity parseCertValidity(const std::string& aValidityStr);


        //
        // All getters may throw SettingsError or SettingsOpenError
        // All setters may additionally throw SettingsSaveError
        // All strings are in UTF-8

        // Global RESEPT settings

        std::string getReseptInstallDir();
        void setReseptInstallDir(const std::string& anInstallDir);

        unsigned int getReseptBrokerServicePort();
        void setReseptBrokerServicePort(unsigned int aPort);

        std::vector<std::string> getInstalledProviders();
        void addInstalledProvider(const std::string& aProviderName);
        void removeInstalledProvider(const std::string& aProviderName);

        std::vector<std::string> getInstalledUserCaCNs();
        std::vector<std::string> getInstalledServerCaCNs();
        std::vector<std::string> getInstalledPrimaryCaCNs();
        std::vector<std::string> getInstalledRootCaCNs();
        std::vector<std::string> getInstalledExtraSigningIntCaSha1Fingerprints();
        std::vector<std::string> getInstalledExtraSigningRootCaSha1Fingerprints();
        void addInstalledUserCA(const std::string& aCN);
        void addInstalledServerCA(const std::string& aCN);
        void addInstalledPrimaryCA(const std::string& aCN);
        void addInstalledRootCA(const std::string& aCA);
        void addInstalledExtraSigningIntCA(const std::string& aSha1Fingerprint);
        void addInstalledExtraSigningRootCA(const std::string& aSha1Fingerprint);

        std::vector<std::string> getCustomizedUsers();
        void addCustomizedUser(const std::string& aUserName);

        std::string getCertValidityParamName();


        //
        // Global user settings
        //

        // @post the returned provider exists
        std::string getLatestProvider();
        // @post the returned service exists for the latest provider
        std::string getLatestService();
        void setLatestProviderService(const std::string& aProviderName, const std::string& aServiceName);

        // Return a list of (provider, service) pairs which the given requested URL matches service uri using the given match criteria
        typedef bool (*IsServiceUriFunc)(const std::string& aRequestedUrl, const std::string& aServiceUri);
        std::vector<std::pair<std::string, std::string> > getProviderServiceForRequestedUri(const std::string& aRequestedUrl, IsServiceUriFunc anIsServiceUri);

        //
        // Provider settings
        // Functions without aProviderName argument use the latest provider
        //
        std::vector<std::string> getProviders();
        // @return whether the function had effect (provider is removed)
        bool removeProviderFromUserConfig(const std::string& aProviderName);

        // No check performed whether the given provider or directory exists
        std::string getProviderInstallDir();
        std::string getProviderInstallDir(const std::string& aProviderName);

        int getProviderContentVersion(const std::string& aProviderName);
        int getProviderContentVersion(const std::string& aProviderName, bool& aFromMasterConfig);

        ta::NetUtils::RemoteAddress getReseptSvrAddress();
        ta::NetUtils::RemoteAddress getReseptSvrAddress(bool& aFromMasterConfig);
        ta::NetUtils::RemoteAddress getReseptSvrAddress(const std::string& aProviderName);
        ta::NetUtils::RemoteAddress getReseptSvrAddress(const std::string& aProviderName, bool& aFromMasterConfig);
        void setReseptSvrAddress(const std::string& aProviderName, const ta::NetUtils::RemoteAddress& anAddr);

        std::string getUserCaName();
        std::string getUserCaName(const std::string& aProviderName);
        std::string getServerCaName();
        std::string getServerCaName(const std::string& aProviderName);
        std::string getPrimaryCaName();
        std::string getPrimaryCaName(const std::string& aProviderName);
        bool isRootCaExist();
        bool isRootCaExist(const std::string& aProviderName);
        std::string getRootCaName();
        std::string getRootCaName(const std::string& aProviderName);

        std::string getLogLevel();
        std::string getLogLevel(bool& aFromMasterConfig);
        std::string getLogLevel(const std::string& aProviderName);
        std::string getLogLevel(const std::string& aProviderName, bool& aFromMasterConfig);
        //@ note no check is performed on the log level validity
        void setLogLevel(const std::string& aProviderName, const std::string& aLogLevel);

        bool isLastUserMsgUtcExist();
        bool isLastUserMsgUtcExist(const std::string& aProviderName);
        std::string getLastUserMsgUtc();
        std::string getLastUserMsgUtc(const std::string& aProviderName);
        void setLastUserMsgUtc(const std::string& anUtc);
        void setLastUserMsgUtc(const std::string& aProviderName, const std::string& anUtc);

        //
        // Service settings
        // Functions without aProviderName/aServiceName arguments use latest provider/service
        //
        std::vector<std::string> getServices();
        std::vector<std::string> getServices(const std::string& aProviderName);

        bool isDisplayServiceName();

        bool isCleanupUserCert();

        bool isCertChain();
        bool isCertChain(const std::string& aProviderName, const std::string& aServiceName);

        CertValidity getCertValidity();
        CertValidity getCertValidity(const std::string& aProviderName, const std::string& aServiceName);
        CertValidity getCertValidity(const std::string& aProviderName, const std::string& aServiceName, bool& aFromMasterConfig);

        resept::CertFormat getCertFormat();
        resept::CertFormat getCertFormat(const std::string& aProviderName, const std::string& aServiceName);
        void setCertFormat(const std::string& aProviderName, const std::string& aServiceName, resept::CertFormat aCertFormat);

        std::string getServiceUri();
        std::string getServiceUri(const std::string& aProviderName, const std::string& aServiceName);
        void setServiceUri(const std::string& aServiceUri);

        std::vector<std::string> getImportedUserCertFingerprints();
        std::vector<std::string> getImportedUserCertFingerprints(const std::string& aProviderName, const std::string& aServiceName);
        void addImportedUserCertFingerprint(const std::string& aFingerprint);
        void removeImportedUserCertFingerprints(const std::vector<std::string>& aFingerprints);

        //
        // User settings
        // Functions without aProviderName/aServiceName arguments use latest provider/service
        //
        //@param [out] aFromMasterConfig set to whether the users go from the master config and therefore cannot be altered using addUser() and removeUser()
        Users getUsers();
        Users getUsers(bool& aFromMasterConfig);
        Users getUsers(const std::string& aProviderName, const std::string& aServiceName);
        Users getUsers(const std::string& aProviderName, const std::string& aServiceName, bool& aFromMasterConfig);
        // @pre the given user does not exist
        void addUser(const std::string& aUserName);
        // @pre the given user does not exist
        void addUser(const std::string& aProviderName, const std::string& aServiceName, const std::string& aUserName);
        void removeUsers();
        void removeUsers(const std::string& aProviderName, const std::string& aServiceName);

        std::string getReseptConfigDir();
        std::string getReseptConfigPath();
        std::string getUserConfigDir();
        std::string getUserConfigPath();
        std::string getMasterConfigDir();
        std::string getMasterConfigPath();
        bool isCustomized();

        // Explicitly specify the location of the configuration files.
        // This function can be helpful when called from the subsystem running in another user's context or for test purposes.
        void setConfigsPath(const std::string& aReseptConfigPath, const std::string& aUserConfigPath, const std::string& aMasterConfigPath);
        void setUserConfigPath(const std::string& aUserConfigPath);
        // Reset to the default behavior
        void resetConfigsPath();


        //
        // Generate admin or user config based on allowOverwriteXXX flags supplied in aReq
        //

        struct RccdRequestData
        {
            RccdRequestData(): allowOverwriteSvrAddress(true)
            {}

            inline bool isAdminRccd() const
            {
                if (!allowOverwriteSvrAddress)
                {
                    return true;
                }
                foreach (const Service& service, services)
                {
                    if (!service.allowOverwriteCertValidity)
                    {
                        return true;
                    }
                }
                return false;
            }

            inline std::vector<std::string> getServiceNames() const
            {
                std::vector<std::string> myServiceNames;
                foreach (const Service& service, services)
                {
                    myServiceNames.push_back(service.name);
                }
                return myServiceNames;
            }



            struct Service
            {
                Service() // default c'tor is required by boost::serialize
                    : allowOverwriteCertValidity(true)
                    , useClientOsLogonUser(DefServiceUseClientOsLogonUser)
                {}
                Service(const std::string& aName, const std::string& aUri, const unsigned int aDefaultValidity)
                    : name(aName)
                    , uri(aUri)
                    , certValidity(DefCertValidityType, aDefaultValidity)
                    , allowOverwriteCertValidity(true)
                    , useClientOsLogonUser(DefServiceUseClientOsLogonUser)
                {}
                // this c'tor is for testing only
                Service(const std::string& aName,
                        const std::string& aUri,
                        const CertificateValidityType aCertValidityType,
                        const unsigned int aCertValidity,
                        const bool anAllowOverwriteCertValidity,
                        const bool aUseClientOsLogonUser,
                        const std::vector<std::string>& aUsers = std::vector<std::string>())
                    : name(aName)
                    , uri(aUri)
                    , certValidity(aCertValidityType, aCertValidity)
                    , allowOverwriteCertValidity(anAllowOverwriteCertValidity)
                    , useClientOsLogonUser(aUseClientOsLogonUser)
                    , users(aUsers)
                {}

                std::string name;
                std::string uri;
                CertValidity certValidity;
                // CertificateValidityType certValidityType;
                // unsigned int certValidity;
                bool allowOverwriteCertValidity;
                bool useClientOsLogonUser;
                std::vector<std::string> users;
            };

            std::string providerName;
            int contentVersion;
            ta::NetUtils::RemoteAddress svrAddress;
            bool allowOverwriteSvrAddress;
            std::vector<unsigned char> signingCaPem;
            std::vector<unsigned char> commCaPem;
            std::vector<unsigned char> pcaPem;
            std::vector<unsigned char> rcaPem;
            std::vector<unsigned char> logo; // binary BLOB
            std::vector<Service> services;
        };

        //
        // Generate user and optionally master client configuration files
        //
        // User config is always created
        // For each aReq.allowOverwriteXXX flag set to false, a master config will be created with the corresponding setting XXX
        // YAML output configs contain the same information as their libconfig counterparts; needed to support clients that prefer YAML-formatted configs
        //@return true if admin configs are generated, false if user configs are generated
        bool generateConfigs(const RccdRequestData& aReq,
                             const std::string& anOutUserLibConfigConfPath,
                             const std::string& anOutUserYamlConfPath,
                             const std::string& anOutMasterLibConfigConfPath = "",
                             const std::string& anOutMasterYamlConfPath = "");

        // Performs administration installation of the provider from the config files.
        // The provider settings are added, if new, otherwise overwrite the existing ones.
        void adminInstallProvider(const std::string& aUserConfigPath, const std::string& aMasterConfigPath, const std::string& aUsername);

        // Performs user installation of the provider from the config file.
        // The provider settings are added, if new, otherwise overwrite the existing ones.
        void userInstallProvider(const std::string& aUserConfigPath, const std::string& aUsername);
    }
}

namespace boost
{
    namespace serialization
    {
        template<class Archive>
        void serialize(Archive& ar, rclient::Settings::CertValidity& aCertValidity, const unsigned int UNUSED(version))
        {
            ar & aCertValidity.type;
            ar & aCertValidity.value;
        }

        template<class Archive>
        void serialize(Archive& ar, rclient::Settings::RccdRequestData::Service& aService, const unsigned int UNUSED(version))
        {
            ar & aService.name;
            ar & aService.uri;
            ar & aService.certValidity;
            ar & aService.allowOverwriteCertValidity;
            ar & aService.users;
            ar & aService.useClientOsLogonUser;
        }

        template<class Archive>
        void serialize(Archive& ar, rclient::Settings::RccdRequestData& aReq, const unsigned int UNUSED(version))
        {
            ar & aReq.providerName;
            ar & aReq.contentVersion;
            ar & aReq.svrAddress;
            ar & aReq.allowOverwriteSvrAddress;
            ar & aReq.signingCaPem;
            ar & aReq.commCaPem;
            ar & aReq.pcaPem;
            ar & aReq.rcaPem;
            ar & aReq.logo;
            ar & aReq.services;
        }
    }
}
