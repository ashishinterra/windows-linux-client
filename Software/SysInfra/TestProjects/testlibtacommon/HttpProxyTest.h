#pragma once

#include "ta/httpproxy.h"
#include "ta/netutils.h"
#include "cxxtest/TestSuite.h"

class HttpProxyTest : public CxxTest::TestSuite
{
public:
    void testHttpProxy()
    {
#ifdef _WIN32
        {
            const std::string myDestUrl = "http://google.com";
            if (const boost::optional<ta::NetUtils::RemoteAddress> myProxy = ta::HttpProxy::getProxy(myDestUrl))
            {
                TS_TRACE(str(boost::format("HTTP Proxy for %s is %s") % myDestUrl % str(*myProxy)).c_str());
            }
            else
            {
                TS_TRACE(("No HTTP Proxy for " + myDestUrl).c_str());
            }
        }

        // quite unlikely a proxy is configured for local urls
        TS_ASSERT(!ta::HttpProxy::getProxy("http://localhost:8080"));
        TS_ASSERT(!ta::HttpProxy::getProxy("http://127.0.0.1:8081"));

        // invalid URL
        TS_ASSERT_THROWS(ta::HttpProxy::getProxy("ftp://google.com"), std::exception);
        TS_ASSERT_THROWS(ta::HttpProxy::getProxy("invalid-url"), std::exception);
        TS_ASSERT_THROWS(ta::HttpProxy::getProxy(""), std::exception);

#else // non-Windows

    {
        // when-then
        if (const boost::optional<ta::NetUtils::RemoteAddress> myProxy = ta::HttpProxy::getProxy())
        {
            TS_TRACE(str("HTTP Proxy: " + str(*myProxy)).c_str());
        }
        else
        {
            TS_TRACE("No HTTP Proxy defined");
        }
    }

    // given
    const std::string mySaveFilePath = "./etc.environment.local";
    const bool myRebootNo = false;

    {
        // given
        ta::writeData(mySaveFilePath, std::string("name1=val1\n"));
        // when
        ta::HttpProxy::enableProxy(ta::NetUtils::RemoteAddress("proxy.com", 8080), myRebootNo, mySaveFilePath);
        // then
        TS_ASSERT_EQUALS((std::string)ta::readData(mySaveFilePath), "name1=val1\nhttp_proxy=http://proxy.com:8080/\nHTTP_PROXY=http://proxy.com:8080/\nhttps_proxy=http://proxy.com:8080/\nHTTPS_PROXY=http://proxy.com:8080/\n");

        // when
        ta::HttpProxy::enableProxy(ta::NetUtils::RemoteAddress("proxy2.com", 80), myRebootNo, mySaveFilePath);
        // then
        TS_ASSERT_EQUALS((std::string)ta::readData(mySaveFilePath), "name1=val1\nhttp_proxy=http://proxy2.com:80/\nHTTP_PROXY=http://proxy2.com:80/\nhttps_proxy=http://proxy2.com:80/\nHTTPS_PROXY=http://proxy2.com:80/\n");
    }

    {
        // given
        std::remove(mySaveFilePath.c_str());
        // when
        ta::HttpProxy::enableProxy(ta::NetUtils::RemoteAddress("proxy2.com", 80), myRebootNo, mySaveFilePath);
        // then
        TS_ASSERT_EQUALS((std::string)ta::readData(mySaveFilePath), "http_proxy=http://proxy2.com:80/\nHTTP_PROXY=http://proxy2.com:80/\nhttps_proxy=http://proxy2.com:80/\nHTTPS_PROXY=http://proxy2.com:80/\n");

        // when
        ta::HttpProxy::disableProxy(myRebootNo, mySaveFilePath);
        // then
        TS_ASSERT_EQUALS((std::string)ta::readData(mySaveFilePath), "\n");
    }

    {
        // given
        ta::writeData(mySaveFilePath, std::string("name1=val1\n"));
        // when
        ta::HttpProxy::disableProxy(myRebootNo, mySaveFilePath);
        // then
        TS_ASSERT_EQUALS((std::string)ta::readData(mySaveFilePath), "name1=val1\n");
    }
#endif // _WIN32
    }

    void testParseProxiesFromPacProxyString()
    {
        std::vector<ta::NetUtils::RemoteAddress> myAddresses;
        using ta::HttpProxy::parseProxiesFromPacProxyString;

        myAddresses = parseProxiesFromPacProxyString("");
        TS_ASSERT(myAddresses.empty());

        myAddresses = parseProxiesFromPacProxyString("DIRECT");
        TS_ASSERT(myAddresses.empty());

        myAddresses = parseProxiesFromPacProxyString("PROXY 127.0.0.1:80");
        TS_ASSERT_EQUALS(myAddresses.size(), 1);
        TS_ASSERT_EQUALS(myAddresses[0].host, "127.0.0.1");
        TS_ASSERT_EQUALS(myAddresses[0].port, 80);

        myAddresses = parseProxiesFromPacProxyString("PROXY 127.0.0.1");
        TS_ASSERT_EQUALS(myAddresses.size(), 1);
        TS_ASSERT_EQUALS(myAddresses[0].host, "127.0.0.1");
        TS_ASSERT_EQUALS(myAddresses[0].port, 8080);

        myAddresses = parseProxiesFromPacProxyString("PROXY 127.0.0.1:80;PROXY proxy:1234;PROXY 192.168.0.1");
        TS_ASSERT_EQUALS(myAddresses.size(), 3);
        TS_ASSERT_EQUALS(myAddresses[0].host, "127.0.0.1");
        TS_ASSERT_EQUALS(myAddresses[0].port, 80);
        TS_ASSERT_EQUALS(myAddresses[1].host, "proxy");
        TS_ASSERT_EQUALS(myAddresses[1].port, 1234);
        TS_ASSERT_EQUALS(myAddresses[2].host, "192.168.0.1");
        TS_ASSERT_EQUALS(myAddresses[2].port, 8080);

        myAddresses = parseProxiesFromPacProxyString("127.0.0.1:80;proxy:1234");
        TS_ASSERT_EQUALS(myAddresses.size(), 2);
        TS_ASSERT_EQUALS(myAddresses[0].host, "127.0.0.1");
        TS_ASSERT_EQUALS(myAddresses[0].port, 80);
        TS_ASSERT_EQUALS(myAddresses[1].host, "proxy");
        TS_ASSERT_EQUALS(myAddresses[1].port, 1234);
    }

};
