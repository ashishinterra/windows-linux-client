#include "RcdpResponse.h"
#include "resept/common.h"
#include "rclient/Common.h"
#include "ta/version.h"
#include "ta/encodingutils.h"
#include "ta/strings.h"
#include "ta/timeutils.h"
#include "ta/logger.h"
#include "ta/common.h"

#include <sstream>
#include "boost/property_tree/ptree.hpp"

using std::string;
using std::vector;
using boost::property_tree::ptree;
using namespace ta::EncodingUtils;

namespace rclient
{
    namespace rcdpv2response
    {
        // internal API
        namespace
        {

            resept::CredentialTypes parseCredentialTypes(const std::vector<string>& aCredTypes)
            {
                resept::CredentialTypes myRetVal;

                foreach (const string& credTypeStr, aCredTypes)
                {
                    myRetVal.push_back(resept::parseCredentialType(credTypeStr));
                }

                return myRetVal;
            }

            template<class T>
            bool isScalarParamExist(const ptree& aResponseTree, const string& aParamName)
            {
                return !!aResponseTree.get_optional<T>(aParamName);
            }
            bool isTreeParamExist(const ptree& aResponseTree, const string& aParamName)
            {
                return !!aResponseTree.get_child_optional(aParamName);
            }

            resept::rcdpv2::Response parseResponseStatusFromTree(const ptree& aResponseTree)
            {
                const std::string myResponseStatusStr = parseStringVal(aResponseTree, resept::rcdpv2::responseParamNameStatus);
                resept::rcdpv2::Response myParsedResponseType;
                if (!parseResponse(myResponseStatusStr, myParsedResponseType))
                {
                    TA_THROW_MSG(std::invalid_argument, "Cannot parse response status from " + myResponseStatusStr);
                }
                return myParsedResponseType;
            }

            ta::StringDict parseChallenges(const ptree& aResponse)
            {
                using namespace resept::rcdpv2;

                const ta::StringDictArray myChallenges = parseStringDictArray(aResponse, responseParamNameChallenges);

                ta::StringDict myParsedChallenges;
                foreach (const ta::StringDict& challenge, myChallenges)
                {
                    const string myChallengeName = ta::getValueByKey(responseParamNameName, challenge);
                    const string myChallengeValue = ta::getValueByKey(responseParamNameValue, challenge);
                    myParsedChallenges[myChallengeName] = myChallengeValue;
                }
                return myParsedChallenges;
            }

            ta::StringArray parseResponseNames(const ptree& aResponse)
            {
                using namespace resept::rcdpv2;

                if (isTreeParamExist(aResponse, responseParamNameResponseNames))
                {
                    return parseStringArray(aResponse, responseParamNameResponseNames);
                }
                else
                {
                    return ta::StringArray();
                }
            }

            ptree parseResponseTree(const string& aResponse, const resept::rcdpv2::Response anExpectedResponseType)
            {
                const ptree myResponseTree = ta::EncodingUtils::jsonToTree(aResponse);
                const  resept::rcdpv2::Response myActualResponseType = parseResponseStatusFromTree(myResponseTree);
                if (myActualResponseType != anExpectedResponseType)
                {
                    TA_THROW_MSG(ParseError, boost::format("Unexpected response type received. Actual: %s, expected %s") % str(myActualResponseType) % str(anExpectedResponseType));
                }
                return myResponseTree;
            }

            AddressBookConfig parseAddressBookConfig(const ptree& aResponseTree)
            {
                using namespace resept::rcdpv2;

                resept::AddressBooks myAddressBooks;
                const ta::StringDictArray myAddressBooksStr = parseStringDictArray(aResponseTree, responseParamNameAddressBooks);
                foreach(const ta::StringDict& address_book, myAddressBooksStr)
                {
                    const string myLdapSvrUrl = ta::getValueByKey(responseParamNameLdapSvrUrl, address_book);
                    const string mySearchBase = ta::getValueByKey(responseParamNameSearchBase, address_book);
                    const string myVerificationCas = ta::getValueByKeyWithDefault(responseParamNameVerificationCa, address_book, "");
                    resept::AddressBook myAddressBook(myLdapSvrUrl, mySearchBase, myVerificationCas);
                    myAddressBooks.push_back(myAddressBook);
                }
                const bool myApplyAddressBooks = parseBoolVal(aResponseTree, responseParamNameApplyAddressBooks);
                return AddressBookConfig(myAddressBooks, myApplyAddressBooks);
            }
        }


        //
        // Public API
        //

        resept::rcdpv2::Response parseResponseStatus(const string& aResponse)
        {
            const ptree myResponseTree = ta::EncodingUtils::jsonToTree(aResponse);
            return parseResponseStatusFromTree(myResponseTree);
        }

        string parseEoc(const string& aResponse)
        {
            using namespace resept::rcdpv2;

            const ptree myResponseTree = parseResponseTree(aResponse, respEOC);

            string myReason;
            if (isScalarParamExist<string>(myResponseTree, responseParamNameReason))
            {
                myReason = parseStringVal(myResponseTree, responseParamNameReason);
            }
            return myReason;
        }

        int parseError(const std::string& aResponse, std::string& anErrorDescription)
        {
            using namespace resept::rcdpv2;

            const Response myExpectedResponseType = respError;
            const ptree myResponseTree = parseResponseTree(aResponse, myExpectedResponseType);

            if (!isScalarParamExist<int>(myResponseTree, responseParamNameErrorCode))
            {
                TA_THROW_MSG(ParseError, boost::format("No error code found in %s response: '%s'") % str(myExpectedResponseType) % aResponse);
            }
            const int myErrorCode = parseIntVal(myResponseTree, responseParamNameErrorCode);

            if (isScalarParamExist<string>(myResponseTree, responseParamNameErrorDescription))
            {
                anErrorDescription = parseStringVal(myResponseTree, responseParamNameErrorDescription);
            }
            return myErrorCode;
        }

        ta::version::Version parseHello(const std::string& aResponse)
        {
            using namespace resept::rcdpv2;

            const Response myExpectedResponseType = respHello;
            const ptree myResponseTree = parseResponseTree(aResponse, myExpectedResponseType);

            try
            {
                return ta::version::parse(parseStringVal(myResponseTree, responseParamNameVersion));
            }
            catch (std::exception& e)
            {
                TA_THROW_MSG(ParseError, boost::format("Cannot parse server proposed version from %s response: '%s'. %s") % str(myExpectedResponseType) % aResponse % e.what());
            }
        }

        time_t parseHandshake(const string& aResponse)
        {
            using namespace resept::rcdpv2;

            const Response myExpectedResponseType = respHandshake;
            const ptree myResponseTree = parseResponseTree(aResponse, myExpectedResponseType);

            try
            {
                return ta::TimeUtils::parseIso8601ToUtc(parseStringVal(myResponseTree, responseParamNameServerUtc));
            }
            catch (std::exception& e)
            {
                TA_THROW_MSG(ParseError, boost::format("Cannot parse server UTC from %s response: '%s'. %s") % str(myExpectedResponseType) % aResponse % e.what());
            }
        }

        AuthRequirements parseAuthRequirements(const string& aResponse)
        {
            using namespace resept::rcdpv2;

            const Response myExpectedResponseType = respAuthRequirements;
            const ptree myResponseTree = parseResponseTree(aResponse, myExpectedResponseType);

            AuthRequirements myAuthRequirements;
            try
            {
                myAuthRequirements.cred_types = parseCredentialTypes(parseStringArray(myResponseTree, responseParamNameCredTypes));
            }
            catch (std::exception& e)
            {
                TA_THROW_MSG(ParseError, boost::format("Cannot parse required credential types from %s response: '%s'. %s") % str(myExpectedResponseType) % aResponse % e.what());
            }

            if (isScalarParamExist<string>(myResponseTree, responseParamNameHwsigFormula))
            {
                myAuthRequirements.hwsig_formula = parseStringVal(myResponseTree, responseParamNameHwsigFormula);
            }
            if (isScalarParamExist<string>(myResponseTree, responseParamNamePasswordPrompt))
            {
                myAuthRequirements.password_prompt = parseStringVal(myResponseTree, responseParamNamePasswordPrompt);
            }
            if (isTreeParamExist(myResponseTree, responseParamNameServiceUris))
            {
                myAuthRequirements.service_uris = parseStringArray(myResponseTree, responseParamNameServiceUris);
            }
            if (isScalarParamExist<bool>(myResponseTree, responseParamNameResolveServiceUris))
            {
                myAuthRequirements.resolve_service_uris = parseBoolVal(myResponseTree, responseParamNameResolveServiceUris);
            }
            if (isScalarParamExist<bool>(myResponseTree, responseParamNameCalcServiceUrisDigest))
            {
                myAuthRequirements.calc_service_uris_digest = parseBoolVal(myResponseTree, responseParamNameCalcServiceUrisDigest);
            }
            if (isScalarParamExist<bool>(myResponseTree, responseParamNameUseTpmVscAuthentication))
            {
                myAuthRequirements.use_tpm_vsc = parseBoolVal(myResponseTree, responseParamNameUseTpmVscAuthentication);
            }
            if (isScalarParamExist<bool>(myResponseTree, responseParamNameUseKerberosAuthentication))
            {
                myAuthRequirements.use_kerberos_authentication = parseBoolVal(myResponseTree, responseParamNameUseKerberosAuthentication);
            }

            return myAuthRequirements;
        }

        AuthResponse parseAuthResponse(const std::string& aResponse)
        {
            using namespace resept::rcdpv2;
            using resept::PasswordValidity;

            const Response myExpectedResponseType = respAuthResult;
            const ptree myResponseTree = parseResponseTree(aResponse, myExpectedResponseType);


            const string myAuthResultTypeStr = parseStringVal(myResponseTree, responseParamNameAuthStatus);
            resept::AuthResult::Type myAuthResultType;
            if (!parseAuthResult(myAuthResultTypeStr, myAuthResultType))
            {
                TA_THROW_MSG(ParseError, boost::format("Cannot parse authentication result from %s in response %s") % myAuthResultTypeStr % aResponse);
            }

            switch (myAuthResultType)
            {
            case resept::AuthResult::Ok:
            {
                if (isScalarParamExist<int>(myResponseTree, responseParamNamePasswordValidity))
                {
                    const int myPasswordValidity = parseIntVal(myResponseTree, responseParamNamePasswordValidity);
                    if (myPasswordValidity == resept::rcdp::PasswordNeverExpires)
                    {
                        return AuthResponse(resept::AuthResult(resept::AuthResult::Ok,
                                                               PasswordValidity(PasswordValidity::neverExpires)));
                    }
                    else if (myPasswordValidity > 0)
                    {
                        return AuthResponse(resept::AuthResult(resept::AuthResult::Ok,
                                                               PasswordValidity(PasswordValidity::notExpired, myPasswordValidity)));
                    }
                    else
                    {
                        TA_THROW_MSG(ParseError, boost::format("Non-positive password validity %d parsed from successful authentication response '%s'") % myPasswordValidity % aResponse);
                    }
                }
                else
                {
                    return AuthResponse(resept::AuthResult(resept::AuthResult::Ok));
                }
            }
            case resept::AuthResult::Delay:
            {
                return AuthResponse(resept::AuthResult(resept::AuthResult::Delay,
                                                       parseIntVal(myResponseTree, responseParamNameDelay)));
            }
            case resept::AuthResult::Locked:
            {
                if (myResponseTree.count(responseParamNameDelay) > 0)
                {

                    int myDelay = parseIntVal(myResponseTree, responseParamNameDelay);
                    if (myDelay > 0)
                    {
                        return AuthResponse(resept::AuthResult(resept::AuthResult::Locked, myDelay));
                    }
                }
                return AuthResponse(resept::AuthResult(resept::AuthResult::Locked));
            }
            case resept::AuthResult::Expired:
            {
                return AuthResponse(resept::AuthResult(resept::AuthResult::Expired,
                                                       PasswordValidity(PasswordValidity::expired)));
            }
            case resept::AuthResult::KerberosAuthNok:
            {
                return AuthResponse(resept::AuthResult(resept::AuthResult::KerberosAuthNok));
            }
            case resept::AuthResult::Challenge:
            {
                return AuthResponse(resept::AuthResult(resept::AuthResult::Challenge),
                                    parseChallenges(myResponseTree),
                                    parseResponseNames(myResponseTree));
            }
            default:
            {
                TA_THROW_MSG(ParseError, boost::format("Unsupported authentication result type %s in response %s") % myAuthResultTypeStr % aResponse);
            }
            }
        }

        Messages parseLastMessages(const std::string& aResponse)
        {
            using namespace resept::rcdpv2;

            const Response myExpectedResponseType = respLastMessages;
            const ptree myResponseTree = parseResponseTree(aResponse, myExpectedResponseType);

            try
            {
                Messages myMessages;
                foreach (const ta::StringDict& msg, parseStringDictArray(myResponseTree, responseParamNameLastMessages))
                {
                    const time_t myUtc = ta::TimeUtils::parseIso8601ToUtc(ta::getValueByKey(responseParamNameMessageUtc, msg));
                    const string myText = ta::getValueByKey(responseParamNameMessageText, msg);
                    myMessages.push_back(Message(myUtc, myText));
                }
                return myMessages;
            }
            catch (std::exception& e)
            {
                TA_THROW_MSG(ParseError, boost::format("Cannot parse last messages from %s response: '%s'. %s") % str(myExpectedResponseType) % aResponse % e.what());
            }
        }

        resept::CsrRequirements parseCsrRequirements(const string& aResponse)
        {
            using namespace resept::rcdpv2;

            const Response myExpectedResponseType = respCsrRequirements;
            const ptree myResponseTree = parseResponseTree(aResponse, myExpectedResponseType);

            try
            {
                const unsigned int myKeySize = parseIntVal(myResponseTree, responseParamNameKeySize);
                const ta::SignUtils::Digest mySigningAlgo = ta::SignUtils::parseDigest(parseStringVal(myResponseTree, responseParamNameSigningAlgo));
                const ta::CertUtils::Subject mySubject(myResponseTree.get_child(responseParamNameSubject));
                return resept::CsrRequirements(myKeySize, mySigningAlgo, mySubject);
            }
            catch (std::exception& e)
            {
                TA_THROW_MSG(ParseError, boost::format("Cannot parse CSR requirements from %s response: '%s'. %s") % str(myExpectedResponseType) % aResponse % e.what());
            }
        }

        CertResponse parseCertWithKey(const string& aResponse, const resept::CertFormat aCertFormat, const string& aSessionId)
        {
            using namespace resept::rcdpv2;

            const Response myExpectedResponseType = respCert;
            const ptree myResponseTree = parseResponseTree(aResponse, myExpectedResponseType);

            try
            {
                CertResponse myCertResponse;

                const string myCert = parseStringVal(myResponseTree, responseParamNameCert);
                myCertResponse.cert = (aCertFormat == resept::certformatP12)
                                      ? ta::EncodingUtils::fromBase64(myCert, true)
                                      : ta::str2Vec<unsigned char>(myCert);
                myCertResponse.password = aSessionId.substr(0, resept::rcdp::PackagedCertExportPasswdSize);
                myCertResponse.execute_sync = (isScalarParamExist<bool>(myResponseTree, responseParamNameExecuteSync))
                                              ? parseBoolVal(myResponseTree, responseParamNameExecuteSync)
                                              : false;
                myCertResponse.address_book_config = parseAddressBookConfig(myResponseTree);

                return myCertResponse;
            }
            catch (std::exception& e)
            {
                TA_THROW_MSG(ParseError, boost::format("Cannot parse certificate&key from %s response: '%s'. %s") % str(myExpectedResponseType) % aResponse % e.what());
            }
        }

        CertResponse parsePemCert(const string& aResponse)
        {
            using namespace resept::rcdpv2;

            const Response myExpectedResponseType = respCert;
            const ptree myResponseTree = parseResponseTree(aResponse, myExpectedResponseType);

            try
            {
                CertResponse myCertResponse;

                myCertResponse.cert = ta::str2Vec<unsigned char>(parseStringVal(myResponseTree, responseParamNameCert));
                myCertResponse.execute_sync = (isScalarParamExist<bool>(myResponseTree, responseParamNameExecuteSync))
                                              ? parseBoolVal(myResponseTree, responseParamNameExecuteSync)
                                              : false;
                myCertResponse.address_book_config = parseAddressBookConfig(myResponseTree);

                return myCertResponse;
            }
            catch (std::exception& e)
            {
                TA_THROW_MSG(ParseError, boost::format("Cannot parse PEM certificate from %s response: '%s'. %s") % str(myExpectedResponseType) % aResponse % e.what());
            }
        }

    } // rcdpv2response
} // rclient
