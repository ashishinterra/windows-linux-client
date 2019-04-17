#pragma once

// Test for Kerberos Authentication

#include "rclient/KerberosAuthenticator.h"
#include "rclient/IReseptBrokerService.h"
#include "rclient/NativeCertStore.h"
#include "rclient/RcdpHandler.h"

#include <cxxtest/TestSuite.h>
#include <string>
#include <vector>

using std::string;
using std::vector;

class KerberosTest : public CxxTest::TestSuite
{
private:
    std::string thePreviousService;

public:
    static KerberosTest *createSuite()
    {
        return new KerberosTest();
    }

    static void destroySuite(KerberosTest *suite)
    {
        delete suite;
    }

    KerberosTest()
    {
        CxxTest::setAbortTestOnFail(true);
    }

    void setUp()
    {
        ta::Process::shellExecSync("../../Projects/ReseptBrokerService/install_service.cmd");
        thePreviousService = rclient::Settings::getLatestService();
        rclient::Settings::setLatestProviderService(rclient::Settings::getLatestProvider(), "CUST_KERBEROS_AD");
    }

    void tearDown()
    {
        ta::Process::shellExecSync("../../Projects/ReseptBrokerService/uninstall_service.cmd");
        rclient::Settings::setLatestProviderService(rclient::Settings::getLatestProvider(), thePreviousService);
        foreach(const std::string& issuer, rclient::Settings::getInstalledUserCaCNs())
        {
            rclient::NativeCertStore::deleteUserCertsForIssuerCN(issuer, rclient::NativeCertStore::proceedOnError);
        }
    }

    void test_correct_ticket()
    {
        TS_SKIP("Skip until server is setup correctly for Kerberos");
        int myDelay = 0;
        rclient::AddressBookConfig myAddressBookConfig; // UNUSED
        TS_ASSERT_EQUALS(rclient::KerberosAuthenticator::authenticateAndInstall(myDelay, myAddressBookConfig), rclient::KerberosAuthenticator::Result::success);
    }

    void test_incorrect_ticket()
    {
        const rclient::ReseptBrokerService::KerberosExternalTicket myEmptyTicket = rclient::ReseptBrokerService::KerberosExternalTicket();
        rclient::RcdpHandler myRcdp(rclient::Settings::getReseptSvrAddress());
        myRcdp.hello();
        myRcdp.handshake();
        rclient::AuthResponse myResponse = rclient::KerberosAuthenticator::authenticate(myEmptyTicket, myRcdp);
        TS_ASSERT_EQUALS(myResponse.auth_result.type, resept::AuthResult::KerberosAuthNok);
    }
};
