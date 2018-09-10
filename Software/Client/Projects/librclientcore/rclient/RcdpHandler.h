#pragma once

#include "resept/common.h"
#include "rclient/Common.h"
#include "ta/netutils.h"
#include "ta/certutils.h"

#include "boost/utility.hpp"
#include <string>
#include <vector>

namespace rclient
{
    struct EocError : std::runtime_error
    {
        explicit EocError(const std::string& aMessage)
            : std::runtime_error(aMessage) {}
    };

    struct ErrError : std::runtime_error
    {
        explicit ErrError(const int anErrorNum, const std::string& aDescription, const std::string& aMessage)
            : std::runtime_error(aMessage), errnum(anErrorNum), description(aDescription) {}
        ~ErrError() throw() {}
        int errnum;
        std::string description;
    };

    struct HttpRequestError: std::runtime_error
    {
        explicit HttpRequestError(const std::string& aMessage = "") : std::runtime_error(aMessage) {}
    };


    class RcdpHandler: boost::noncopyable
    {
    public:
        RcdpHandler(const ta::NetUtils::RemoteAddress& aServer);
        virtual ~RcdpHandler();

        //
        // Any phase messages
        //
        void eoc(const std::string& aReason = "");
        void error(const int aCode, const std::string& aDescription = "");

        //
        // Phase 1 messages (handshake)
        //
        void hello();
        void handshake();

        //
        // Phase 2 messages (authentication)
        //
        AuthRequirements getAuthRequirements(const std::string& aServiceName);
        AuthResponse authenticate(const std::string& aServiceName,
                                  const resept::Credentials& aCredentials,
                                  const ta::StringArrayDict& aResolvedURIs = ta::StringArrayDict(),
                                  const ta::StringDict& aCalculatedDigests = ta::StringDict(),
                                  const boost::optional<std::string>& aKerberosTicket = boost::none);

        //
        // Phase 2 messages after at least one authentication attempt ended with expired or expiring password
        //
        AuthResponse changePassword(const std::string& anOldPassword, const std::string& aNewPassword);

        //
        // Phase 3 messages (service)
        //
        Messages getLastMessages(const time_t* aFromUtc = NULL);
        resept::CsrRequirements getCsrRequirements();
        CertResponse getCert(const resept::CertFormat aCertFormat, const bool anIncludeChain);
        CertResponse signCSR(const std::string& aCsrPem, const bool anIncludeChain);

        //
        // Helpers
        //
        UserRcdpSessionData userSessionData() const;
    private:
        void handleErrors(const std::string& aResponse, const resept::rcdpv2::Request aReqTypeHint);
        void setState(const resept::rcdpv2::State aState);
    private:
        struct RcdpHandlerImpl;
        RcdpHandlerImpl* pImpl;
    };
}
