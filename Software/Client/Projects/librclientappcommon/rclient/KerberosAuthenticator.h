#ifdef _WIN32
#pragma once

#ifdef TEST_KERBEROS
#include "rclient/RcdpHandler.h"
#endif
#include <string>

namespace rclient
{
    struct AddressBookConfig;
    namespace ReseptBrokerService
    {
        struct KerberosExternalTicket;
    }

    namespace KerberosAuthenticator
    {
        enum Result
        {
            success,
            kerberosFailure,
            authDelay,
            authPermanentlyLocked,
            authLockedWithDelay,
            defaultFailure
        };

        Result authenticateAndInstall(int& aDelaySec, AddressBookConfig& anAddressBookConfig);

#ifdef TEST_KERBEROS
        AuthResponse authenticate(const ReseptBrokerService::KerberosExternalTicket& aTicket, RcdpHandler& anRcdpClient);
#endif
    }
} // end rclient
#endif