#pragma once



#include <string>
#include <vector>
#include "boost/optional.hpp"

namespace ta
{
    namespace NetUtils  { struct RemoteAddress; }

    namespace HttpProxy
    {
#ifdef _WIN32
        //@param [in] aDestUrl http:// or https:// destination URL to look up HTTP proxy for
        //@return HTTP proxy address for manually-configured proxy or boost::none when no proxy is in use
        //@note This function should not be used in a service process that does not impersonate a logged-on user.
        //@note Only http:// locations are supported for PAC scripts
        //Because Internet Explorer settings are likely not configured for these system accounts (such as local service or the network service), the function will most likely fail.
        boost::optional<NetUtils::RemoteAddress> getProxy(const std::string& aDestUrl);
#else
        // Retrieves HTTP and HTTPS proxy
        boost::optional<ta::NetUtils::RemoteAddress> getProxy();
        // Effectuates HTTP and HTTPS proxy settings rebooting the system, making the changes persistent across reboots
        //@param aSaveFilePath, aReboot are for test only, do NOT change them in production environment!
        void enableProxy(const ta::NetUtils::RemoteAddress& aProxy, const bool aReboot = true, const std::string& aSaveFilePath = "/etc/environment");
        void disableProxy(const bool aReboot = true, const std::string& aSaveFilePath = "/etc/environment");
#endif
        //
        // Auxiliary functions
        //

        // Parse the list of proxies from the string given as "DIRECT" or "PROXY proxy:1234[;PROXY proxy2:1234]" or "proxy:1234[;proxy2:1234]")
        // Port defauls to 8080
        std::vector<ta::NetUtils::RemoteAddress> parseProxiesFromPacProxyString(const std::string& aProxyString);

    }
}

