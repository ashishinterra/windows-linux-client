#ifdef _WIN32
#pragma once

namespace rclient
{
    struct AddressBookConfig;
    namespace WinMailClientManager
    {
        void winApplyAddressBooks(const AddressBookConfig& anAddressBookConfig);
    }
}
#endif // _WIN32
