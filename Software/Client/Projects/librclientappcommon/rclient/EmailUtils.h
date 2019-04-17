#pragma once

namespace rclient
{
    struct AddressBookConfig;
    namespace EmailUtils
    {
        void applyAddressBooks(const AddressBookConfig& anAddressBookConfig);
    }
}
