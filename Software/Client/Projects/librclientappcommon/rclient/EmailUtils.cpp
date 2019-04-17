#include "EmailUtils.h"

#ifdef _WIN32
#include "WinMailClientManager.h"
#else
#include "ta/logger.h"
#include "ta/common.h"
#endif

namespace rclient
{
    namespace EmailUtils
    {
#ifdef _WIN32
        void applyAddressBooks(const AddressBookConfig& anAddressBookConfig)
        {
            WinMailClientManager::winApplyAddressBooks(anAddressBookConfig);
        }
#else
        void applyAddressBooks(const AddressBookConfig& UNUSED(anAddressBookConfig))
        {
            WARNLOG("Skipping applyAddressBooks. It is only implemented on Windows");
        }
#endif
    }
}
