#include "ChooseProviderServicePage.h"
#include "AuthenticationWizard.h"
#include "TimedNotificationBox.h"
#include "AboutDialog.h"
#include "ConfigUsersDialog.h"
#include "CommonUtils.h"
#include "AuthDelayedMessageBox.h"
#include "rclient/Settings.h"
#include "rclient/NativeCertStore.h"
#include "rclient/KerberosAuthenticator.h"
#include "rclient/RcdpHandler.h"
#include "ta/logger.h"
#include "ta/common.h"

#include <QtWidgets>

using std::string;

namespace rclient
{
    ChooseProviderServicePage::ChooseProviderServicePage(CurrentUser* aCurrentUser, AuthenticationWizard* anAuthenticationWizard)
        : QWizardPage(NULL)
        , theCurrentUser(aCurrentUser)
        , theAuthenticationWizard(anAuthenticationWizard)
    {
        if (!aCurrentUser)
            TA_THROW_MSG(std::invalid_argument, "CurrentUser is NULL");

        QLabel* providerLabel = new QLabel("Provider:");
        theProvidersCombo = new QComboBox;

        QLabel* serviceLabel = new QLabel("Service:");
        theServicesCombo = new QComboBox;

        QFormLayout* mainLayout = new QFormLayout;
        mainLayout->addRow(providerLabel, theProvidersCombo);
        mainLayout->addRow(serviceLabel, theServicesCombo);
        setLayout(mainLayout);

        connect(theProvidersCombo, SIGNAL(activated(const QString&)), this, SLOT(onProviderSelected(const QString&)) );
        connect(theServicesCombo, SIGNAL(activated(const QString&)), this, SLOT(onServiceSelected(const QString&)) );
    }


    bool ChooseProviderServicePage::validatePage()
    {
        const string mySelectedProvider = theProvidersCombo->currentText().toUtf8();
        const string mySelectedService = theServicesCombo->currentText().toUtf8();

        rclient::Settings::setLatestProviderService(mySelectedProvider, mySelectedService);
        rclient::NativeCertStore::deleteReseptUserCerts();

        // Before we select a user, we may want to start Kerberos if required.
        try
        {
            const ta::NetUtils::RemoteAddress mySvr = rclient::Settings::getReseptSvrAddress(mySelectedProvider);
            std::auto_ptr<rclient::RcdpHandler> myRcdpClient(new rclient::RcdpHandler(mySvr));
            myRcdpClient->hello();
            myRcdpClient->handshake();
            const rclient::AuthRequirements myAuthReqs = myRcdpClient->getAuthRequirements(mySelectedService);
            myRcdpClient->eoc();

            if (myAuthReqs.use_kerberos_authentication)
            {
                int myDelay = 0;
                const rclient::KerberosAuthenticator::Result myAuthResult = rclient::KerberosAuthenticator::authenticateAndInstall(myDelay);
                // Only fallback to normal flow when authentication fails because of Kerberos. Exit if it fails for other reasons
                // And of course allow the user to retry when account is Locked with a set delay
                switch (myAuthResult)
                {
                case rclient::KerberosAuthenticator::Result::success:
                {
                    DEBUGLOG("Got TGT alright, skipping the rest of the app");
                    throw KerberosAuthSuccessException(this);
                }
                case rclient::KerberosAuthenticator::kerberosFailure:
                    // Failure related to Kerberos. Fall back to normal use flow
                {
                    const string msg = "Kerberos automatic authentication failed. Continue to enter credentials.";
                    QMessageBox::warning(this, "Continue", msg.c_str(), QMessageBox::Ok);
                    break;
                }
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
                    const string msg = "Your account is locked. Please contact " + resept::ProductName + " administrator.";
                    QMessageBox::warning(this, "Account locked", msg.c_str(), QMessageBox::Ok);
                    throw AuthCancelledException();
                }
                case rclient::KerberosAuthenticator::Result::authLockedWithDelay:
                {
                    if (!AuthDelayedMessageBox::show(this, "The account is still locked. Please try again later.", true, myDelay))
                    {
                        throw AuthCancelledException();
                    }
                    updateUi(mySelectedProvider, mySelectedService);
                    return false;
                }
                default:
                    // Otherwise unknown result, throw exception
                    TA_THROW_MSG(std::exception, boost::format("Unknown Kerberos authentication result with result: %i") % myAuthResult);
                }
            }
        }
        catch (AuthCancelledException&)
        {
            throw AuthCancelledException();
        }
        catch (KerberosAuthSuccessException&)
        {
            throw KerberosAuthSuccessException(this);
        }
        catch (std::exception& ex)
        {
            WARNLOG(boost::format("Skipping Kerberos authentication because if failed with error: %s") % ex.what());
        }

        //select user
        const rclient::Settings::Users myUsers = rclient::Settings::getUsers(mySelectedProvider, mySelectedService);
        if (myUsers.size() == 1)
        {
            theCurrentUser->select(myUsers[0]);
            return true;
        }

        string mySelectedUser;
        if (showConfigUserDialog(mySelectedProvider, mySelectedService, mySelectedUser, this) == dlgAcceptedUserSelected)
        {
            theCurrentUser->select(mySelectedUser);
            return true;
        }

        theCurrentUser->unselect();
        return false;
    }

    int ChooseProviderServicePage::nextId() const
    {
        return AuthenticationWizard::pageAuthenticate;
    }

    void ChooseProviderServicePage::initializePage()
    {
        setTitle("Select Provider and Service");
        setSubTitle("Please select an Application Service Provider and a Service");

        const string mySelectedProvider = rclient::Settings::getLatestProvider();
        const string mySelectedService = rclient::Settings::getLatestService();
        updateUi(mySelectedProvider, mySelectedService);
    }

    void ChooseProviderServicePage::onProviderSelected(const QString& aSelectedProvider)
    {
        const string mySelectedProvider = aSelectedProvider.toStdString();
        const string mySelectedService = rclient::Settings::getServices(theProvidersCombo->currentText().toStdString()).at(0);
        updateUi(mySelectedProvider, mySelectedService);
    }

    void ChooseProviderServicePage::onServiceSelected(const QString& aSelectedService)
    {
        updateUi(theProvidersCombo->currentText().toStdString(), aSelectedService.toStdString());
    }

    void ChooseProviderServicePage::updateUi(const string& aSelectedProvider, const string& aSelectedService)
    {
        // Fill in providers
        theProvidersCombo->clear();
        std::list<string> mySortedProviders;
        foreach (const string& provider, rclient::Settings::getProviders())
        {
            mySortedProviders.push_back(provider);
        }
        mySortedProviders.sort();

        foreach (const string& provider, mySortedProviders)
        {
            theProvidersCombo->addItem(provider.c_str());
        }
        theProvidersCombo->setCurrentIndex(theProvidersCombo->findText(aSelectedProvider.c_str()));

        // Fill in services
        theServicesCombo->clear();
        std::list<string> mySortedServices;
        foreach (const string& service, rclient::Settings::getServices(aSelectedProvider))
        {
            mySortedServices.push_back(service);
        }
        mySortedServices.sort();

        foreach (const string& service, mySortedServices)
        {
            theServicesCombo->addItem(service.c_str());
        }
        theServicesCombo->setCurrentIndex(theServicesCombo->findText(aSelectedService.c_str()));
    }

    void ChooseProviderServicePage::setVisible(bool visible)
    {
        QWizardPage::setVisible(visible);

        if (visible)
        {
            wizard()->setButtonText(QWizard::CustomButton1, "");
            wizard()->setOption(QWizard::HaveCustomButton1, true);

            const QIcon aboutIcon(":/RClientAppCommon/info_ico.png");
            wizard()->button(QWizard::CustomButton1)->setIcon(aboutIcon);
            connect(wizard(), SIGNAL(customButtonClicked(int)), this, SLOT(customButtonClicked(int)));
        }
        else
        {
            wizard()->setOption(QWizard::HaveCustomButton1, false);
            disconnect(wizard(), SIGNAL(customButtonClicked(int)), this, SLOT(customButtonClicked(int)));
        }
    }

    void ChooseProviderServicePage::customButtonClicked(int button)
    {
        if (button == QWizard::CustomButton1)
        {
            AboutDialog about(this);
            about.exec();
            if (about.clickedButton() == about.reportProblemButton)
            {
                about.reportProblem();
            }
        }
    }

}
