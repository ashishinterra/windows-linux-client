#include "httpproxy.h"
#include "netutils.h"
#include "strings.h"
#include "process.h"
#include "utils.h"
#include "url.h"
#include "scopedresource.hpp"
#include "common.h"
#include "ta/logger.h"

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <winhttp.h>
#endif

using std::string;
using std::wstring;
using std::vector;

namespace ta
{
    namespace HttpProxy
    {
        //
        // Private API
        //
        namespace
        {
#ifdef _WIN32
            bool isHostInProxyBypassList(const string& aHostName, const string& aBypassList)
            {
                // The proxy bypass list contains one or more server names separated by ; or whitespace.
                // The proxy bypass list can also contain the string "<local>" to indicate that all local Intranet sites are bypassed.

                const string myHostName = boost::trim_copy(aHostName);

                if (myHostName.empty())
                {
                    return false;
                }

                if (ta::NetUtils::isValidIpv4(myHostName) && ta::NetUtils::isLoopbackIpv4(myHostName))
                {
                    return true;
                }
                if  (ta::NetUtils::isValidIpv6(myHostName) && ta::NetUtils::isLoopbackIpv6(myHostName))
                {
                    return true;
                }

                static const vector<char> mySeps = boost::assign::list_of(' ')('\t')('\r')('\n')(';');
                foreach(const string& bypassTempl, ta::Strings::split(aBypassList, mySeps))
                {
                    if (!bypassTempl.empty())
                    {
                        if (boost::iequals(bypassTempl, "<local>"))
                        {
                            // exclude local hostname
                            if (myHostName.find('.') == std::string::npos && myHostName.find(':') == std::string::npos)
                            {
                                return true;
                            }
                            //@todo also check we're in subnet, as in http://cep.xray.aps.anl.gov/software/qt4-x11-4.8.6-browser/de/dfe/qnetworkproxy__win_8cpp_source.html
                        }

                        if (boost::istarts_with(myHostName, bypassTempl))
                        {
                            return true;
                        }
                        if (ta::Strings::wildcardMatch(boost::to_lower_copy(myHostName), boost::to_lower_copy(bypassTempl)))
                        {
                            return true;
                        }
                    }
                }

                // bypassing not applicable
                return false;
            }

            boost::optional<NetUtils::RemoteAddress> extractManualProxy(const string& aProxies, const string& aDestHost, const string& aBypassAddresses)
            {
                DEBUGDEVLOG(boost::format("Determining HTTP proxy for host '%s' from manual configuration. Proxy list: '%s'. Proxy bypass list: '%s'") % aDestHost % aProxies % aBypassAddresses);
                if (isHostInProxyBypassList(aDestHost, aBypassAddresses))
                {
                    DEBUGDEVLOG(boost::format("No proxy for '%s' (overruled by proxy bypass list)") % aDestHost);
                    return boost::none;
                }

                // Expect: "http=localhost3:8083[;https=localhost1:8081]" or just "localhost1:8081"
                string myHttpProxySvr;
                foreach(const string& proxy, ta::Strings::split(aProxies, ';'))
                {
                    const ta::StringArray myParsedProxy = ta::Strings::split(proxy, '=');
                    if (myParsedProxy.size() == 1)
                    {
                        myHttpProxySvr = boost::trim_copy(myParsedProxy[0]);
                        break;
                    }
                    else if (myParsedProxy.size() == 2 && myParsedProxy[0] == "http")
                    {
                        myHttpProxySvr = boost::trim_copy(myParsedProxy[1]);
                        break;
                    }
                }
                if (myHttpProxySvr.empty())
                {
                    DEBUGDEVLOG(boost::format("No proxy for '%s' (no HTTP proxy defined)") % aDestHost);
                    return boost::none;
                }

                const ta::url::Authority::Parts myHttpProxyParts = ta::url::Authority::parse(myHttpProxySvr);
                NetUtils::RemoteAddress myRetVal;
                if (!NetUtils::isValidPort(myHttpProxyParts.port, (unsigned int*)&myRetVal.port))
                {
                    TA_THROW_MSG(std::runtime_error, boost::format("%s is not a valid port number in HTTP proxy %s") % myHttpProxyParts.port % myHttpProxySvr);
                }
                myRetVal.host = myHttpProxyParts.host;
                DEBUGDEVLOG(boost::format("'%s' will be used as HTTP proxy for '%s'") % str(myRetVal) % aDestHost);

                return myRetVal;
            }

            string fmtPacInfo(const string& aPacUrl)
            {
                return aPacUrl.empty() ? "automatically discovered PAC" : "PAC at " + aPacUrl;
            }

            // @param [in] aPacUrl when empty implies PAC location should be determined by the system
            // The function tries to be tolerant to system errors falling back to "no proxy" in order to stay consistent with IE behavior
            boost::optional <NetUtils::RemoteAddress> extractProxyFromPac(const string& aDestUrl, const string& aPacUrl = "")
            {
                DEBUGDEVLOG(boost::format("Determining HTTP proxy for URL '%s' from %s.") % aDestUrl % fmtPacInfo(aPacUrl));

                ScopedResource<HINTERNET> myHttpSession(::WinHttpOpen(L"RESEPT Proxy Extractor", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0),
                                                        ::WinHttpCloseHandle);
                if (!myHttpSession)
                {
                    const DWORD myError = ::GetLastError();
                    WARNDEVLOG(boost::format("No proxy for '%s' from %s. ::WinHttpOpen() failed with %d.") % aDestUrl % fmtPacInfo(aPacUrl) % myError);
                    return boost::none;
                }

                WINHTTP_AUTOPROXY_OPTIONS myAutoProxyOptions = { 0 };
                const wstring myPacUrlW = aPacUrl.empty() ? L"" : ta::Strings::toWide(aPacUrl);
                if (aPacUrl.empty())
                {
                    myAutoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
                    myAutoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
                }
                else
                {
                    myAutoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
                    myAutoProxyOptions.lpszAutoConfigUrl = myPacUrlW.c_str();
                }

                // If obtaining the PAC script requires NTLM/Negotiate authentication, automatically supply the domain credentials of the client.
                myAutoProxyOptions.fAutoLogonIfChallenged = TRUE;
                wstring myDestUrlW = ta::Strings::toWide(aDestUrl);
                WINHTTP_PROXY_INFO myProxyInfo = { 0 };

                if (!::WinHttpGetProxyForUrl(myHttpSession, myDestUrlW.c_str(), &myAutoProxyOptions, &myProxyInfo))
                {
                    const DWORD myError = ::GetLastError();
                    WARNDEVLOG(boost::format("No proxy for '%s' from %s. ::WinHttpGetProxyForUrl() failed with %d (hint: indicate WINHTTP module when looking up for the error description)") % aDestUrl % fmtPacInfo(aPacUrl) % myError);
                    return boost::none;
                }

                // Tackle RAII
                ta::ScopedResource<LPWSTR> myScopedProxy(myProxyInfo.lpszProxy, ::GlobalFree);
                ta::ScopedResource<LPWSTR> myScopedProxyBypass(myProxyInfo.lpszProxyBypass, ::GlobalFree);

                if (myProxyInfo.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY)
                {
                    DEBUGDEVLOG(boost::format("No proxy for '%s' from %s.") % aDestUrl % fmtPacInfo(aPacUrl));
                    return boost::none;
                }
                if (myProxyInfo.dwAccessType != WINHTTP_ACCESS_TYPE_NAMED_PROXY)
                {
                    WARNDEVLOG(boost::format("No proxy for '%s' from %s. ::WinHttpGetProxyForUrl returned unrecognized myProxyInfo.dwAccessType (%d)") % aDestUrl % fmtPacInfo(aPacUrl) % myProxyInfo.dwAccessType);
                    return boost::none;
                }
                if (!myProxyInfo.lpszProxy)
                {
                    WARNDEVLOG(boost::format("No proxy for '%s' from %s. ::WinHttpGetProxyForUrl succeeded but proxy is NULL") % aDestUrl % fmtPacInfo(aPacUrl));
                    return boost::none;
                }

                const string myProxyString = ta::Strings::toMbyte(myProxyInfo.lpszProxy);
                DEBUGDEVLOG(boost::format("Parsed proxy string '%s' for '%s' from %s") % myProxyString % aDestUrl % fmtPacInfo(aPacUrl));

                vector<NetUtils::RemoteAddress> myProxies;
                try {
                    myProxies = parseProxiesFromPacProxyString(myProxyString);
                }
                catch (std::exception& e) {
                    WARNDEVLOG(boost::format("Failed to parse proxy for '%s' from proxy string '%s' extracted from %s. %s. Falling back to no proxy.") % aDestUrl % myProxyString % fmtPacInfo(aPacUrl) % e.what());
                    return boost::none;
                }

                if (myProxies.empty())
                {
                    DEBUGDEVLOG(boost::format("No proxy for '%s' extracted from %s (parsed proxy string: '%s')") % aDestUrl % fmtPacInfo(aPacUrl) % myProxyString);
                    return boost::none;
                }
                else
                {
                    const NetUtils::RemoteAddress myProxy = myProxies[0];
                    DEBUGDEVLOG(boost::format("Use proxy '%s' for '%s' extracted from %s (parsed proxy string: '%s')") % str(myProxy) % aDestUrl % fmtPacInfo(aPacUrl) % myProxyString);
                    return myProxy;
                }
            }
#else // non-Windows

            const ta::StringArray HttpProxyEnvVariableNames = boost::assign::list_of("http_proxy")
                    ("HTTP_PROXY")
                    ("https_proxy")
                    ("HTTPS_PROXY");

            bool isLineContainsHttpProxyEnvVar(const string& aLine)
            {
                const string myLine = boost::trim_copy(aLine);

                foreach (const string& env_var, HttpProxyEnvVariableNames)
                {
                    if (boost::starts_with(myLine, env_var + "="))
                    {
                        return true;
                    }
                }
                return false;
            }

            void applyProxy(const ta::NetUtils::RemoteAddress& aProxy, const bool aReboot, const string& aSaveFilePath)
            {
                ta::StringArray myLines;

                if (ta::isFileExist(aSaveFilePath))
                {
                    std::ifstream myFile(aSaveFilePath.c_str());
                    if (!myFile.is_open() || myFile.fail())
                    {
                        TA_THROW_MSG(std::runtime_error, boost::format("Failed to open %s for reading") % aSaveFilePath);
                    }
                    string myLine;
                    while (std::getline(myFile, myLine))
                    {
                        if (!isLineContainsHttpProxyEnvVar(myLine))
                        {
                            myLines.push_back(boost::trim_copy(myLine));
                        }
                    }// getline
                }

                const string myHost = boost::trim_copy(aProxy.host);
                if (!myHost.empty())
                {
                    foreach (const string& proxy_var_name, HttpProxyEnvVariableNames)
                    {
                        myLines.push_back(str(boost::format("%s=http://%s:%d/") % proxy_var_name % myHost % aProxy.port));
                    }
                }

                ta::writeData(aSaveFilePath, ta::Strings::join(myLines, "\n") + "\n");

                if (aReboot)
                {
                    ta::Process::checkedShellExecSync("sudo reboot");
                }
            }

#endif // _WIN32

        }
        //
        // end of private API
        //


#ifdef _WIN32
        //
        // Public API
        //
        boost::optional<ta::NetUtils::RemoteAddress> getProxy(const string& aDestUrl)
        {
            const ta::url::Scheme myDestScheme = ta::url::getScheme(aDestUrl);
            if (myDestScheme != ta::url::Http && myDestScheme != ta::url::Https)
            {
                TA_THROW_MSG(std::invalid_argument, boost::format("Cannot detect HTTP proxy for %s. Only http and https schemes are supported for destination URL.") % aDestUrl);
            }
            const string myDestHost = ta::url::parse(aDestUrl).authority_parts.host;

            WINHTTP_CURRENT_USER_IE_PROXY_CONFIG myProxyCfg;
            if (!::WinHttpGetIEProxyConfigForCurrentUser(&myProxyCfg))
            {
                const DWORD myLastError = ::GetLastError();
                if (myLastError == ERROR_FILE_NOT_FOUND)
                {
                    // The most possible explanation is that no IE profile created yet, treat is as no proxy
                    // @todo this might also indicate we get called from non-user account e.g. local service or the network service. In this case this should probably be treated as error
                    DEBUGDEVLOG("No IE profile exists. Consider it as no HTTP proxy configured for " + aDestUrl);
                    return boost::none;
                }
                TA_THROW_MSG(std::runtime_error, boost::format("Failed to retrieve IE proxy settings. WinHttpGetIEProxyConfigForCurrentUser() failed. Last error is %d") % myLastError);
            }

            // Tackle RAII
            ta::ScopedResource<LPWSTR> myScopedAutoConfigUrl(myProxyCfg.lpszAutoConfigUrl, ::GlobalFree);
            ta::ScopedResource<LPWSTR> myScopedProxy(myProxyCfg.lpszProxy, ::GlobalFree);
            ta::ScopedResource<LPWSTR> myScopedProxyBypass(myProxyCfg.lpszProxyBypass, ::GlobalFree);

            if (myProxyCfg.fAutoDetect)
            {
                // Proxy goes from PAC script which location is detected by the system
                return extractProxyFromPac(aDestUrl);
            }
            else if (myProxyCfg.lpszAutoConfigUrl)
            {
                // Proxy goes from PAC script which location is set manually
                return extractProxyFromPac(aDestUrl, ta::Strings::toMbyte(myProxyCfg.lpszAutoConfigUrl));
            }
            else if (myProxyCfg.lpszProxy)
            {
                // Proxy location is manually configured
                return extractManualProxy(ta::Strings::toMbyte(myProxyCfg.lpszProxy),
                                          myDestHost,
                                          myProxyCfg.lpszProxyBypass ? ta::Strings::toMbyte(myProxyCfg.lpszProxyBypass) : "");
            }
            else
            {
                // No proxy
                DEBUGDEVLOG("No HTTP proxy configured for " + aDestUrl);
                return boost::none;
            }
        }
#else // non-windows
        boost::optional<ta::NetUtils::RemoteAddress> getProxy()
        {
            foreach (const string& kv, ta::Process::getEnvVars())
            {
                if (isLineContainsHttpProxyEnvVar(kv))
                {
                    const string myProxyUrl = boost::trim_copy_if(
                                                  ta::Strings::split(kv, '=').at(1),
                                                  boost::is_any_of(" \t\""));
                    const url::Authority::Parts myParsedProxy = url::parse(myProxyUrl).authority_parts;
                    unsigned int myPort = 80;
                    if (myParsedProxy.port.empty() || ta::NetUtils::isValidPort(myParsedProxy.port, &myPort))
                    {
                        return ta::NetUtils::RemoteAddress(myParsedProxy.host, myPort);
                    }
                }
            }
            return boost::none;
        }

        void enableProxy(const ta::NetUtils::RemoteAddress& aProxy, const bool aReboot, const string& aSaveFilePath)
        {
            applyProxy(aProxy, aReboot, aSaveFilePath);
        }

        void disableProxy(const bool aReboot, const string& aSaveFilePath)
        {
            applyProxy(ta::NetUtils::RemoteAddress(), aReboot, aSaveFilePath);
        }
#endif //_WIN32

        vector<ta::NetUtils::RemoteAddress> parseProxiesFromPacProxyString(const string& aProxyString)
        {
            if (aProxyString == "DIRECT" || aProxyString.empty())
            {
                return vector<ta::NetUtils::RemoteAddress>();
            }

            vector<ta::NetUtils::RemoteAddress> myProxies;
            foreach(string proxy, ta::Strings::split(aProxyString, ';'))
            {
                static const string ProxyPrefix = "PROXY ";
                if (boost::starts_with(proxy, ProxyPrefix))
                {
                    proxy.erase(0, ProxyPrefix.size());
                }
                myProxies.push_back(ta::NetUtils::parseHost(proxy, 8080));
            }
            return myProxies;
        }


    }// HttpProxy
}// ta
