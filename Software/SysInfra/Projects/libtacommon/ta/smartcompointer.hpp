//----------------------------------------------------------------------------
//
//  Name          SmartComPointer.hpp
//  Description : Smart Pointer to COM object
//  MAPI API Usage example:
//  ...
//  {
//    LPPROFADMIN myProfAdminPtr = NULL;
//    MAPIAdminProfiles(0, &myProfAdminPtr);
//    SmartComPointer<LPPROFADMIN> myProfAdminSmartPtr;
//    ...
//  }
//  // At this point Release() has already been called on myProfAdminPtr if it is not NULL
//
//----------------------------------------------------------------------------
#pragma once
#include "boost/utility.hpp"

namespace ta
{
    template <class T>
    class SmartComPointer: boost::noncopyable
    {
    public:
        SmartComPointer(T *aPtr)
            : comPtr(aPtr)
        {}

        ~SmartComPointer()
        {
            if (comPtr)
            {
                comPtr->Release();
            }
        }
    private:
        T* comPtr;
    };
}
