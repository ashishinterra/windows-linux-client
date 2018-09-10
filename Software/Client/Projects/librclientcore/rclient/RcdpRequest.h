#pragma once

#include "resept/common.h"
#include "ta/common.h"
#include <string>

namespace rclient
{
    namespace rcdpv2request
    {
        ta::StringDict makeAuthenticateRequestParams(const std::string& aServiceName,
                const resept::Credentials& aCredentials,
                const ta::StringArrayDict& aResolvedURIs,
                const ta::StringDict& aCalculatedDigests,
                const boost::optional<std::string>& aKerberosTicket = boost::none);

        ta::StringDict makeCertRequestParams(const resept::CertFormat aCertFormat,
                                             const bool anIncludeChain);
        ta::StringDict makeCertRequestParams(const std::string& aCsrPem,
                                             const bool anIncludeChain);
    }
}
