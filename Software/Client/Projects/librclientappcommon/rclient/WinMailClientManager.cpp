#ifdef _WIN32
#pragma once
#include "WinMailClientManager.h"
#include "rclient/Settings.h"
#include "rclient/Common.h"
#include "CommonUtils.h"
#include "resept/common.h"
#include "ta/smartcompointer.hpp"
#include "ta/scopedresource.hpp"
#include "ta/logger.h"
#include "ta/sysinfo.h"
#include "ta/strings.h"
#include "ta/url.h"
#include "boost/format.hpp"

#include <string>
#include <vector>
#include <iostream>
#include <MAPIX.h>
#include <MAPIUtil.h>

#define USES_IID_IMsgServiceAdmin2
#include <initguid.h>
#include <MAPIAux.h>

#define MAPI_FORCE_ACCESS 0x00080000

#define AB_PROVIDER_BASE_ID                     0x6600  // Look at the comments in MAPITAGS.H
#define PROP_AB_PROVIDER_DISPLAY_NAME           PR_DISPLAY_NAME
#define PROP_AB_PROVIDER_SERVER_NAME            PROP_TAG (PT_TSTRING,   (AB_PROVIDER_BASE_ID + 0x0000)) // "example.contoso.com"
#define PROP_AB_PROVIDER_SERVER_PORT            PROP_TAG (PT_TSTRING,   (AB_PROVIDER_BASE_ID + 0x0001)) // "389"
#define PROP_AB_PROVIDER_USER_NAME              PROP_TAG (PT_TSTRING,   (AB_PROVIDER_BASE_ID + 0x0002)) // contoso\administrator
#define PROP_AB_PROVIDER_SEARCH_BASE            PROP_TAG (PT_TSTRING,   (AB_PROVIDER_BASE_ID + 0x0003)) // SEARCH_FILTER_VALUE
#define PROP_AB_PROVIDER_SEARCH_TIMEOUT         PROP_TAG (PT_TSTRING,   (AB_PROVIDER_BASE_ID + 0x0007)) // "60"
#define PROP_AB_PROVIDER_MAX_ENTRIES            PROP_TAG (PT_TSTRING,   (AB_PROVIDER_BASE_ID + 0x0008)) // "100"
#define PROP_AB_PROVIDER_USE_SSL                PROP_TAG (PT_BOOLEAN,   (AB_PROVIDER_BASE_ID + 0x0013)) // False
#define PROP_AB_PROVIDER_SERVER_SPA             PROP_TAG (PT_BOOLEAN,   (AB_PROVIDER_BASE_ID + 0x0015)) // False
#define PROP_AB_PROVIDER_USER_PASSWORD_ENCODED  PROP_TAG (PT_BINARY,    (AB_PROVIDER_BASE_ID + 0x0017)) // ENCODED_PWD
#define PROP_AB_PROVIDER_ENABLE_BROWSING        PROP_TAG(PT_BOOLEAN,    (AB_PROVIDER_BASE_ID + 0x0022)) // False
#define PROP_AB_PROVIDER_SEARCH_BASE_DEFAULT    PROP_TAG(PT_LONG,       (AB_PROVIDER_BASE_ID + 0x0023)) // 0 or 1

using std::string;

namespace rclient
{
    namespace WinMailClientManager
    {
        // Private functions
        namespace
        {
            string parseFqdn(const resept::AddressBook& anAddressBook)
            {
                return ta::url::parse(anAddressBook.ldap_svr_url).authority_parts.host;
            }

            string getDisplayName(const resept::AddressBook& anAddressBook, std::map<string, int>& anFqdnCounts)
            {
                const string myFqdn = parseFqdn(anAddressBook);
                ++anFqdnCounts[myFqdn];
                // Add numbering if address is not the first with this FQDN
                const string myNrString = anFqdnCounts[myFqdn] > 1 ? str(boost::format(" #%d") % anFqdnCounts[myFqdn]) : "";
                return str(boost::format("%s %s%s") % resept::ProductName % myFqdn % myNrString);
            }

            std::string getMsgServiceLastErrorStr(LPSERVICEADMIN2 aSvcAdmin, const HRESULT& aRes)
            {
                LPMAPIERROR myMAPIError = NULL;
                HRESULT myRes = aSvcAdmin->GetLastError(
                                    aRes,
                                    0, // ANSI i/o Unicode. For Unicode use MAPI_UNICODE flag
                                    &myMAPIError
                                );
                ta::ScopedResource<LPMAPIERROR> myScopedMAPIError(myMAPIError, MAPIFreeBuffer);
                if (FAILED(myRes))
                {
                    return str(boost::format("Unknown error occurred. Could not retrieve Extended Error Data for HRESULT=%d") % aRes);
                }
                return string(myMAPIError->lpszError); // Only possible if the 2nd argument of GetLastError is not unicode
            }

            void CHECK_HR(HRESULT hr, const string& aFunctionName, const string& anObjectName = "")
            {
                if (FAILED(hr))
                {
                    const string myForObject = anObjectName.empty() ? "" : str(boost::format(" for %s") % anObjectName);
                    TA_THROW_MSG(std::runtime_error, boost::format("Error calling %s%s. HRESULT=%d") % aFunctionName % myForObject % hr);
                }
            }

            // Retrieves the name of the default profile or an empty string if no default profile set
            string getDefaultProfileName()
            {
                // Create a profile administration object.
                LPPROFADMIN myProfAdminPtr = NULL;     // Profile Admin pointer
                CHECK_HR(MAPIAdminProfiles(0, &myProfAdminPtr), "MAPIAdminProfiles");
                ta::SmartComPointer<IProfAdmin> myProfAdminSmartPtr(myProfAdminPtr);

                // Get access to the profile table, a table that contains information about all of the available profiles.
                LPMAPITABLE myProfTablePtr = NULL;
                CHECK_HR(myProfAdminPtr->GetProfileTable(0, &myProfTablePtr), "GetProfileTable");
                ta::SmartComPointer<IMAPITable> myProfTableSmartPtr(myProfTablePtr);

                // Allocate memory for the restriction
                LPSRestriction myProfResPtr = NULL;
                CHECK_HR(MAPIAllocateBuffer(sizeof(SRestriction), (LPVOID*)&myProfResPtr), "MAPIAllocateBuffer", "myProfResPtr");
                ta::ScopedResource<LPSRestriction> myScopedProfResPtr(myProfResPtr, MAPIFreeBuffer);

                LPSRestriction myProfResLvl1Ptr = NULL;
                CHECK_HR(MAPIAllocateBuffer(sizeof(SRestriction) * 2, (LPVOID*)&myProfResLvl1Ptr), "MAPIAllocateBuffer", "myProfResLvl1Ptr");
                ta::ScopedResource<LPSRestriction> myScopedProfResLvl1Ptr(myProfResLvl1Ptr, MAPIFreeBuffer);

                LPSPropValue myProfPropValPtr = NULL;
                CHECK_HR(MAPIAllocateBuffer(sizeof(SPropValue), (LPVOID*)&myProfPropValPtr), "MAPIAllocateBuffer", "myProfPropValPtr");
                ta::ScopedResource<LPSPropValue> myScopedProfPropValPtr(myProfPropValPtr, MAPIFreeBuffer);

                // Set up restriction to query the profile table for the default profile
                myProfResPtr->rt = RES_AND;
                myProfResPtr->res.resAnd.cRes = 0x00000002;
                myProfResPtr->res.resAnd.lpRes = myProfResLvl1Ptr;

                myProfResLvl1Ptr[0].rt = RES_EXIST;
                myProfResLvl1Ptr[0].res.resExist.ulPropTag = PR_DEFAULT_PROFILE;
                myProfResLvl1Ptr[0].res.resExist.ulReserved1 = 0x00000000;
                myProfResLvl1Ptr[0].res.resExist.ulReserved2 = 0x00000000;
                myProfResLvl1Ptr[1].rt = RES_PROPERTY;
                myProfResLvl1Ptr[1].res.resProperty.relop = RELOP_EQ;
                myProfResLvl1Ptr[1].res.resProperty.ulPropTag = PR_DEFAULT_PROFILE;
                myProfResLvl1Ptr[1].res.resProperty.lpProp = myProfPropValPtr;

                myProfPropValPtr->ulPropTag = PR_DEFAULT_PROFILE;
                myProfPropValPtr->Value.b = true;

                // Query the table to get the the default profile only
                enum { iDisplayName, cptaProps };
                SizedSPropTagArray(cptaProps, sptaProps) = { cptaProps, PR_DISPLAY_NAME };

                // Retrieves all rows of the table.
                LPSRowSet myProfRowsPtr = NULL;
                CHECK_HR(HrQueryAllRows(myProfTablePtr, (LPSPropTagArray)&sptaProps, myProfResPtr, NULL, 0, &myProfRowsPtr), "HrQueryAllRows");
                ta::ScopedResource<LPSRowSet> myScopedProfRowsPtr(myProfRowsPtr, FreeProws);

                if (myProfRowsPtr->cRows == 0)
                {
                    WARNLOG("No default profile set");
                    return ""; // Return empty profile name, let the caller handle this
                }
                else if (myProfRowsPtr->cRows == 1)
                {
                    // If 1 row then return the multibyte display name value
                    return std::string(myProfRowsPtr->aRow->lpProps[iDisplayName].Value.lpszA);
                }
                else
                {
                    WARNLOG("Query resulted in incosinstent results. More than one default profiles found!");
                    return ""; // Return empty profile name, let the caller handle this
                }
            }

            bool doesABServiceExist(LPSERVICEADMIN aSvcAdminPtr, const resept::AddressBook& anAddressBook)
            {
                enum { iServiceUid, iAbServerName, iAbSearchBase, cptaProps };
                SizedSPropTagArray(cptaProps, sptaProps) = { cptaProps, PR_SERVICE_UID, PROP_AB_PROVIDER_SERVER_NAME, PROP_AB_PROVIDER_SEARCH_BASE };

                // Get access to the message service table, a list of the message services in the profile.
                LPMAPITABLE myMsgSvcTablePtr = NULL;
                CHECK_HR(aSvcAdminPtr->GetMsgServiceTable(0, &myMsgSvcTablePtr), "GetMsgServiceTable");
                ta::SmartComPointer<IMAPITable> myMsgSvcTableSmartPtr(myMsgSvcTablePtr);

                // Allocate and create the SRestriction
                LPSRestriction myResPtr = NULL;
                CHECK_HR(MAPIAllocateBuffer(sizeof(SRestriction), (LPVOID*)&myResPtr), "MAPIAllocateMore", "myResPtr");
                ta::ScopedResource<LPSRestriction> myScopedResPtr(myResPtr, MAPIFreeBuffer);

                LPSPropValue mySpvSvcNamePtr = NULL;
                CHECK_HR(MAPIAllocateMore(sizeof(SPropValue), myResPtr, (LPVOID*)&mySpvSvcNamePtr), "MAPIAllocateMore", "mySpvSvcNamePtr");
                ta::ScopedResource<LPSPropValue> myScopedSpvSvcNamePtr(mySpvSvcNamePtr, MAPIFreeBuffer);

                ZeroMemory(myResPtr, sizeof(SRestriction));
                ZeroMemory(mySpvSvcNamePtr, sizeof(SPropValue));

                myResPtr->rt = RES_CONTENT;
                myResPtr->res.resContent.ulFuzzyLevel = FL_FULLSTRING;
                myResPtr->res.resContent.ulPropTag = PR_SERVICE_NAME;
                myResPtr->res.resContent.lpProp = mySpvSvcNamePtr;
                mySpvSvcNamePtr->ulPropTag = PR_SERVICE_NAME;
                mySpvSvcNamePtr->Value.lpszA = "EMABLT";

                // Query the table to get the entry for EMABLT type services.
                LPSRowSet mySvcRowsPtr = NULL;
                CHECK_HR(HrQueryAllRows(myMsgSvcTablePtr, (LPSPropTagArray)&sptaProps, myResPtr, NULL, 0, &mySvcRowsPtr), "HrQueryAllRows");
                ta::ScopedResource<LPSRowSet> myScopedSvcRowsPtr(mySvcRowsPtr, FreeProws);

                if (mySvcRowsPtr->cRows > 0)
                {
                    for (unsigned int i = 0; i < mySvcRowsPtr->cRows; i++)
                    {
                        LPPROFSECT myProfSectPtr = NULL;
                        CHECK_HR(aSvcAdminPtr->OpenProfileSection(LPMAPIUID(mySvcRowsPtr->aRow[i].lpProps[iServiceUid].Value.bin.lpb), NULL, MAPI_MODIFY | MAPI_FORCE_ACCESS, &myProfSectPtr),
                                 "MAPIAllocateMore",
                                 str(boost::format("row %d") % i));
                        ta::SmartComPointer<IMAPITable> myMsgSvcTableSmartPtr(myMsgSvcTablePtr);

                        ULONG myPropVal = 0; // not used
                        LPSPropValue mySPropValuesPtr = NULL;
                        CHECK_HR(myProfSectPtr->GetProps((LPSPropTagArray)&sptaProps, NULL, &myPropVal, &mySPropValuesPtr), "MAPIAllocateMore", str(boost::format("row %d") % i));
                        ta::ScopedResource<LPSPropValue> myScopedSPropValuesPtr(mySPropValuesPtr, MAPIFreeBuffer);

                        // Actual check
                        if (mySPropValuesPtr != NULL &&
                                mySPropValuesPtr[iAbServerName].Value.lpszA && mySPropValuesPtr[iAbServerName].Value.lpszA == anAddressBook.ldap_svr_url &&
                                mySPropValuesPtr[iAbSearchBase].Value.lpszA && mySPropValuesPtr[iAbSearchBase].Value.lpszA == anAddressBook.search_base)
                        {
                            return true;
                        }
                    }
                }

                return false;
            } // doesABServiceExist

            // Creates a new EMABLT service and populates the parameters
            void createABService(LPSERVICEADMIN aSvcAdminPtr, const resept::AddressBook& anAddressBook, const string& aDisplayName)
            {
                const string myServiceName = "EMABLT";
                const string mySearchTimeout = "60";
                const string myMaxEntries = "100";
                const string myServerPort = "389";
                const string myUsername = ""; // Not supported for public ABs
                const string myPassword = ""; // Not supported for public ABs

                const bool myUseSsl = false;
                const bool myRequireSpa = false;
                const bool myEnableBrowsing = false;
                const unsigned long myUseDefaultSearchBase = 1; // 1 for Custom: (alternative is 0 for Default)

                // Retrieves pointers to the supported interfaces on an object.
                LPSERVICEADMIN2 mySvcAdminPtr2 = NULL;
                CHECK_HR(aSvcAdminPtr->QueryInterface(IID_IMsgServiceAdmin2, (LPVOID*)&mySvcAdminPtr2), "QueryInterface");
                ta::SmartComPointer<IMsgServiceAdmin2> mySvcAdminSmartPtr2(mySvcAdminPtr2);

                // Adds a message service to the current profile and returns that newly added service UID.
                MAPIUID myUidService = { 0 };
                LPMAPIUID myUidServicePtr = &myUidService;
                CHECK_HR(mySvcAdminPtr2->CreateMsgServiceEx(LPSTR(myServiceName.c_str()), LPSTR(aDisplayName.c_str()), NULL, 0, &myUidService), "CreateMsgServiceEx");
                ta::ScopedResource<LPMAPIUID> myScopedUidServicePtr(myUidServicePtr, MAPIFreeBuffer);

                // Set up the new props
                SPropValue myPropValues[12];

                ZeroMemory(&myPropValues[0], sizeof(SPropValue));
                myPropValues[0].ulPropTag = PROP_AB_PROVIDER_DISPLAY_NAME;
                myPropValues[0].Value.lpszA = LPSTR(aDisplayName.c_str());

                ZeroMemory(&myPropValues[1], sizeof(SPropValue));
                myPropValues[1].ulPropTag = PROP_AB_PROVIDER_SERVER_NAME;
                myPropValues[1].Value.lpszA = LPSTR(anAddressBook.ldap_svr_url.c_str());

                ZeroMemory(&myPropValues[2], sizeof(SPropValue));
                myPropValues[2].ulPropTag = PROP_AB_PROVIDER_SERVER_PORT;
                myPropValues[2].Value.lpszA = LPSTR(myServerPort.c_str());

                ZeroMemory(&myPropValues[3], sizeof(SPropValue));
                myPropValues[3].ulPropTag = PROP_AB_PROVIDER_USER_NAME;
                myPropValues[3].Value.lpszA = LPSTR(myUsername.c_str());

                ZeroMemory(&myPropValues[4], sizeof(SPropValue));
                myPropValues[4].ulPropTag = PROP_AB_PROVIDER_SEARCH_BASE;
                myPropValues[4].Value.lpszA = LPSTR(anAddressBook.search_base.c_str());

                ZeroMemory(&myPropValues[5], sizeof(SPropValue));
                myPropValues[5].ulPropTag = PROP_AB_PROVIDER_SEARCH_TIMEOUT;
                myPropValues[5].Value.lpszA = LPSTR(mySearchTimeout.c_str());

                ZeroMemory(&myPropValues[6], sizeof(SPropValue));
                myPropValues[6].ulPropTag = PROP_AB_PROVIDER_MAX_ENTRIES;
                myPropValues[6].Value.lpszA = LPSTR(myMaxEntries.c_str());

                ZeroMemory(&myPropValues[7], sizeof(SPropValue));
                myPropValues[7].ulPropTag = PROP_AB_PROVIDER_USE_SSL;
                myPropValues[7].Value.b = static_cast<unsigned short>(myUseSsl);

                ZeroMemory(&myPropValues[8], sizeof(SPropValue));
                myPropValues[8].ulPropTag = PROP_AB_PROVIDER_SERVER_SPA;
                myPropValues[8].Value.b = static_cast<unsigned short>(myRequireSpa);

                DATA_BLOB myDataBlobIn = { 0 };
                DATA_BLOB myDataBlobOut = { 0 };
                LPWSTR lpszwPassword = LPWSTR(ta::Strings::utf8ToWide(myPassword).c_str());
                // Encrypt the password if supplied
                if (0 < wcslen(lpszwPassword))
                {
                    LPBYTE pbData = (LPBYTE)lpszwPassword;
                    DWORD cbData = boost::numeric_cast<DWORD>((wcslen(lpszwPassword) + 1) * sizeof(WCHAR));

                    myDataBlobIn.pbData = pbData;
                    myDataBlobIn.cbData = cbData;

                    if (!CryptProtectData(
                                &myDataBlobIn,
                                L"",                        // desc
                                NULL,                       // optional
                                NULL,                       // reserver
                                NULL,                       // prompt struct
                                0,                          // flags
                                &myDataBlobOut))
                    {
                        TA_THROW_MSG(std::runtime_error, "Encrypt pwd failed");
                    }
                }

                ZeroMemory(&myPropValues[9], sizeof(SPropValue));
                myPropValues[9].ulPropTag = PROP_AB_PROVIDER_USER_PASSWORD_ENCODED;
                myPropValues[9].Value.bin.cb = myDataBlobOut.cbData;
                myPropValues[9].Value.bin.lpb = myDataBlobOut.pbData;

                ZeroMemory(&myPropValues[10], sizeof(SPropValue));
                myPropValues[10].ulPropTag = PROP_AB_PROVIDER_ENABLE_BROWSING;
                myPropValues[10].Value.b = static_cast<unsigned short>(myEnableBrowsing);

                ZeroMemory(&myPropValues[11], sizeof(SPropValue));
                myPropValues[11].ulPropTag = PROP_AB_PROVIDER_SEARCH_BASE_DEFAULT;
                myPropValues[11].Value.ul = myUseDefaultSearchBase;

                // Reconfigures a message service with the new props.
                HRESULT myRes = mySvcAdminPtr2->ConfigureMsgService(myUidServicePtr, NULL, 0, 12, myPropValues);
                if (FAILED(myRes))
                {
                    if (myRes == MAPI_E_EXTENDED_ERROR)
                        TA_THROW_MSG(std::runtime_error, boost::format("Failed to Configure Address Book. HRESULT=%d. %s") % myRes % getMsgServiceLastErrorStr(mySvcAdminPtr2, myRes));
                    CHECK_HR(myRes, "ConfigureMsgService");
                }

            } // createABService

            void applyAddressBook(const resept::AddressBook& anAddressBook, const string& aDisplayName)
            {
                try
                {
                    const std::string myProfileName = getDefaultProfileName();

                    // Get Service Admin
                    LPPROFADMIN myProfAdminPtr = NULL;
                    CHECK_HR(MAPIAdminProfiles(0, &myProfAdminPtr), "MAPIAdminProfiles");
                    ta::SmartComPointer<IProfAdmin> myProfAdminSmartPtr(myProfAdminPtr);

                    LPSERVICEADMIN myServiceAdminPtr = NULL;
                    CHECK_HR(myProfAdminPtr->AdminServices(LPTSTR(myProfileName.c_str()), NULL, NULL, 0, &myServiceAdminPtr), "AdminServices");
                    ta::SmartComPointer<IMsgServiceAdmin> myServiceAdminSmartPtr(myServiceAdminPtr);

                    // Check whether AB present in Outlook
                    if (!doesABServiceExist(myServiceAdminPtr, anAddressBook))
                    {
                        createABService(myServiceAdminPtr, anAddressBook, aDisplayName);
                    }
                    DEBUGLOG(boost::format("Successfully applied Address Book with Server Address %s, Search Base %s and Display Name %s to Outlook")
                             % anAddressBook.ldap_svr_url
                             % anAddressBook.search_base
                             % aDisplayName);
                }
                catch (std::exception)
                {
                    ERRORLOG(boost::format("Failed to apply Address Book with Server Address %s, Search Base %s and Display Name %s to Outlook")
                             % anAddressBook.ldap_svr_url
                             % anAddressBook.search_base
                             % aDisplayName);
                    throw;
                }
            } // registerAddressBook
        } // private

        // Public functions
        void winApplyAddressBooks(const AddressBookConfig& anAddressBookConfig)
        {
            MAPIINIT_0  MAPIINIT = { 0, MAPI_MULTITHREAD_NOTIFICATIONS };
            HRESULT myRes = MAPIInitialize(&MAPIINIT);
            if (FAILED(myRes))
            {
                ERRORLOG(boost::format("MAPI failed to initialize. HRESULT=%d") % myRes);
                return;
            }

            resept::AddressBooks myHandledAddressBooks; // For logging remaining/skipped Address Books on error. Includes potentially failed Address Book
            try
            {
                if (!anAddressBookConfig.applyAddressBooks || anAddressBookConfig.addressBooks.empty())
                {
                    return;
                }

                DEBUGLOG("Applying the following Address Books:");
                foreach(const resept::AddressBook& addressBook, anAddressBookConfig.addressBooks)
                {
                    DEBUGLOG(boost::format("- Address Book with Server Address %s and Search Base %s to Outlook") % addressBook.ldap_svr_url % addressBook.search_base);
                }

                std::map<string, int> myUsedFqdnCounts;
                foreach(const resept::AddressBook& addressBook, anAddressBookConfig.addressBooks)
                {
                    myHandledAddressBooks.push_back(addressBook);
                    const string myDisplayName = getDisplayName(addressBook, myUsedFqdnCounts);
                    applyAddressBook(addressBook, myDisplayName);
                }
            }
            catch (std::exception& e)
            {
                ERRORLOG2("Error occured while registering Address Books", e.what());
                // Log each remaining/skipped Address Book
                foreach(const resept::AddressBook& addressBook, anAddressBookConfig.addressBooks)
                {
                    if (!ta::isElemExist(addressBook, myHandledAddressBooks))
                    {
                        ERRORLOG(boost::format("Skipped applying Address Book with Server Address %s and Search Base %s because of prior error") % addressBook.ldap_svr_url % addressBook.search_base);
                    }
                }
            }
            MAPIUninitialize();
        }
    } // WinMailClientManager
} // rclient
#endif // _WIN32
