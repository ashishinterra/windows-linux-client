//----------------------------------------------------------------------------
//
//  Name          AuthenticationWizard.h
//  Description : Provider/Service selection wizard for a user
//
//----------------------------------------------------------------------------
#pragma once

#include <string>
#include <stdexcept>
#include <vector>
#include <QWizard>

namespace rclient
{
    class CurrentUser
    {
    public:
        CurrentUser() : selected(false) {}
        inline std::string name() const  { return user;}
        inline bool isSelected() const  { return selected;}
        inline void select(const std::string& aUser) { user = aUser; selected = true;}
        inline void unselect() { user = ""; selected = false;}
    private:
        std::string user;
        bool selected;
    };

    class AuthenticatePage;

    class AuthenticationWizard : public QWizard
    {
        Q_OBJECT
    public:
        enum Page { pageSelectProviderService, pageAuthenticate};

        AuthenticationWizard(QWidget* parent = NULL);

        std::string getServiceUri() const;
        bool getExecuteSync() const;
    private:
        void init(Page aStartPage);
        bool selectUser(const std::string& aProvider, const std::string& aService, QWidget* parent);
        bool authenticateWithKerberos();
    private:
        CurrentUser theCurrentUser;
        AuthenticatePage* theAuthenticatePage;
        static const QSize theDefaultSize;
    };
}
