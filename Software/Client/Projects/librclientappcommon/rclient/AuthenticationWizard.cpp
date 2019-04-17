#include "AuthenticationWizard.h"
#include "ChooseProviderServicePage.h"
#include "ConfigUsersDialog.h"
#include "AuthenticatePage.h"
#include "AuthDelayedMessageBox.h"
#include "EmailUtils.h"
#include "rclient/KerberosAuthenticator.h"
#include "rclient/Settings.h"
#include "rclient/NativeCertStore.h"
#include "rclient/CommonUtils.h"
#include "ta/common.h"
#include "ta/logger.h"

#include <QtWidgets>
#include <vector>

using namespace ta;
using std::string;
using std::vector;

namespace
{
    /**
      Checks client settings that at least one provider exists and for each provider at least one service exist
    */
    void verifyExistProviderService()
    {
        std::vector<string> myProviders = rclient::Settings::getProviders();
        if (myProviders.empty())
            TA_THROW_MSG(std::runtime_error, "No providers exist in the client settings");
        foreach (string provider, myProviders)
        {
            if (rclient::Settings::getServices(provider).empty())
                TA_THROW_MSG(std::runtime_error, boost::format("No services exist in the client settings for provider %s") % provider);
        }
    }
}


namespace rclient
{
    AuthenticationWizard::AuthenticationWizard(QWidget* parent)
        : QWizard(parent)
        , theAuthenticatePage(NULL)
    {
        verifyExistProviderService();

        Page myStartPage = pageAuthenticate;
        if (rclient::Settings::getProviders().size() == 1 && rclient::Settings::getServices().size() == 1)
        {
            const string mySelectedProvider = rclient::Settings::getProviders()[0];
            const string mySelectedService = rclient::Settings::getServices()[0];

            rclient::Settings::setLatestProviderService(mySelectedProvider, mySelectedService);
            rclient::NativeCertStore::deleteReseptUserCerts();
            if (authenticateWithKerberos())
            {
                throw KerberosAuthSuccessException(this);
            }

            myStartPage = pageAuthenticate;

            if (!selectUser(mySelectedProvider, mySelectedService, NULL /* NULL because we call from c'tor */))
            {
                WARNLOG(boost::format("No user selected for provider %s, service %s, cancelling authentication") % mySelectedProvider % mySelectedService);
                throw AuthCancelledException();
            }
        }
        else
        {
            myStartPage = pageSelectProviderService;
        }

        init(myStartPage);
    }

    bool AuthenticationWizard::authenticateWithKerberos()
    {
        const ta::NetUtils::RemoteAddress mySvr = rclient::Settings::getReseptSvrAddress();

        DEBUGLOG(boost::format("Connecting to %s server at %s") % resept::ProductName % toString(mySvr));
        rclient::RcdpHandler myRcdpClient(mySvr);
        myRcdpClient.hello();
        myRcdpClient.handshake();
        rclient::AuthRequirements myAuthReqs = myRcdpClient.getAuthRequirements(rclient::Settings::getLatestService());
        if (!myAuthReqs.use_kerberos_authentication)
        {
            return false;
        }
        int myDelay = 0;
        AddressBookConfig myAddressBookConfig;
        const rclient::KerberosAuthenticator::Result myAuthResult = rclient::KerberosAuthenticator::authenticateAndInstall(myDelay, myAddressBookConfig);
        // Only fallback to normal flow when authentication fails because of Kerberos. Exit if it fails for other reasons
        // And of course allow the user to retry when account is Locked with a set delay
        switch (myAuthResult)
        {
        case rclient::KerberosAuthenticator::Result::success:
            DEBUGLOG("Got TGT alright, skipping the rest of the app");
            EmailUtils::applyAddressBooks(myAddressBookConfig);
            return true;
        case rclient::KerberosAuthenticator::kerberosFailure:
            // Failure related to Kerberos. Fall back to normal use flow
            return false;
        case rclient::KerberosAuthenticator::authDelay:
        // Exit because Delay is caused (only when using Kerberos) by incorrect Hwsig
        case rclient::KerberosAuthenticator::defaultFailure:
        {
            const string msg = "Kerberos authentication unsuccessful.";
            QMessageBox::warning(this, "Authentication failed", msg.c_str(), QMessageBox::Ok);
            throw AuthCancelledException();
        }
        case rclient::KerberosAuthenticator::Result::authPermanentlyLocked:
        {
            const string msg = "This account is locked. Please contact " + resept::ProductName + " administrator.";
            QMessageBox::warning(this, "Account locked", msg.c_str(), QMessageBox::Ok);
            throw AuthCancelledException();
        }
        case rclient::KerberosAuthenticator::Result::authLockedWithDelay:
            if (AuthDelayedMessageBox::show(this, "The account is still locked. Please try again later.", true, myDelay))
            {
                return authenticateWithKerberos();
            }
            else
            {
                throw AuthCancelledException();
            }
        default:
            // Otherwise unknown result, throw exception
            TA_THROW_MSG(std::exception, boost::format("Unknown Kerberos authentication result with result: %i") % myAuthResult);
        }
    }

    void AuthenticationWizard::init(Page aStartPage)
    {
        setPage(pageSelectProviderService, new rclient::ChooseProviderServicePage(&theCurrentUser, this));
        theAuthenticatePage = new rclient::AuthenticatePage(&theCurrentUser, this);
        setPage(pageAuthenticate, theAuthenticatePage);
        setStartId(aStartPage);

        setWizardStyle(ModernStyle);
        setWindowIcon(QIcon(":/RClientAppCommon/logo.png"));
        setPixmap(QWizard::LogoPixmap, QPixmap(":/RClientAppCommon/logo.png"));
        setWindowTitle("Authentication Agent");

        setButtonText(FinishButton, "Connect");
    }

    string AuthenticationWizard::getServiceUri() const
    {
        if (!theAuthenticatePage)
            TA_THROW_MSG(std::logic_error, "Authentication page has not been initialized yet");
        return theAuthenticatePage->getServiceUri();
    }

    bool AuthenticationWizard::getExecuteSync() const
    {
        if (!theAuthenticatePage)
            TA_THROW_MSG(std::logic_error, "Authentication page has not been initialized yet");
        return theAuthenticatePage->getExecuteSync();
    }

    bool AuthenticationWizard::selectUser(const string& aProvider, const string& aService, QWidget* aParent)
    {
        if (rclient::Settings::getUsers().size() == 1)
        {
            theCurrentUser.select(rclient::Settings::getUsers()[0]);
            return true;
        }

        string mySelectedUser;
        if (showConfigUserDialog(aProvider, aService, mySelectedUser, aParent) == dlgAcceptedUserSelected)
        {
            theCurrentUser.select(mySelectedUser);
            return true;
        }
        theCurrentUser.unselect();
        return false;
    }
}
